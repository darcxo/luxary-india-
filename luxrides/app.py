"""
LuxRide India — Full-Stack Flask Backend
Auth | Bookings | AI Concierge | Vehicles | News | Offers
"""

import os, json, secrets, hashlib, hmac, uuid, re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
import sqlite3
import urllib.request
import urllib.error

from database import init_db, get_conn, DB_PATH

# ─────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR  = os.path.join(BASE_DIR, 'static')
SECRET_KEY  = os.environ.get('LUXRIDE_SECRET', 'luxride-india-secret-key-2026-v1')
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
TOKEN_EXPIRY_HOURS = 72

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='')
app.config['SECRET_KEY'] = SECRET_KEY
app.config['JSON_SORT_KEYS'] = False

# CORS — allow all for dev
@app.after_request
def cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Session-Key'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response

@app.before_request
def options_handler():
    if request.method == 'OPTIONS':
        return jsonify(ok=True), 200

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000)
    return f"{salt}${h.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split('$')
        check = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000)
        return hmac.compare_digest(h, check.hex())
    except Exception:
        return False

def generate_token() -> str:
    return secrets.token_urlsafe(48)

def generate_booking_ref() -> str:
    return 'LR' + datetime.now().strftime('%y%m%d') + secrets.token_hex(3).upper()

def row_to_dict(row) -> dict:
    if row is None:
        return None
    return dict(row)

def rows_to_list(rows) -> list:
    return [dict(r) for r in rows]

def err(msg, code=400):
    return jsonify(error=msg), code

def ok(data=None, **kwargs):
    resp = {'success': True}
    if data is not None:
        resp['data'] = data
    resp.update(kwargs)
    return jsonify(resp)

def validate_email(email):
    return re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email)

def validate_phone(phone):
    digits = re.sub(r'\D', '', phone)
    return 10 <= len(digits) <= 13

# ─────────────────────────────────────────────
# Auth Middleware
# ─────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if not token:
            return err('Authentication required', 401)
        db = get_conn()
        session = row_to_dict(db.execute(
            "SELECT s.*, u.id as uid, u.name, u.email, u.role, u.is_active "
            "FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires_at > datetime('now','localtime')",
            (token,)
        ).fetchone())
        db.close()
        if not session or not session['is_active']:
            return err('Session expired or invalid', 401)
        g.user = session
        g.user_id = session['uid']
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if g.user.get('role') != 'admin':
            return err('Admin access required', 403)
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    name  = (data.get('name','') or '').strip()
    email = (data.get('email','') or '').strip().lower()
    phone = (data.get('phone','') or '').strip()
    pw    = data.get('password','') or ''

    if not all([name, email, phone, pw]):
        return err('All fields are required')
    if len(name) < 2:
        return err('Name must be at least 2 characters')
    if not validate_email(email):
        return err('Invalid email address')
    if not validate_phone(phone):
        return err('Invalid phone number (10-13 digits)')
    if len(pw) < 8:
        return err('Password must be at least 8 characters')

    db = get_conn()
    try:
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            return err('Email already registered. Please login.')

        pw_hash = hash_password(pw)
        cur = db.execute(
            "INSERT INTO users (name,email,phone,password) VALUES (?,?,?,?)",
            (name, email, phone, pw_hash)
        )
        user_id = cur.lastrowid
        db.commit()

        # Auto-login
        token = generate_token()
        expires = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
        db.execute(
            "INSERT INTO sessions (user_id,token,expires_at,ip_address,user_agent) VALUES (?,?,?,?,?)",
            (user_id, token, expires.strftime('%Y-%m-%d %H:%M:%S'),
             request.remote_addr, request.user_agent.string[:200])
        )
        db.commit()

        user = row_to_dict(db.execute(
            "SELECT id,name,email,phone,role,wallet,created_at FROM users WHERE id=?", (user_id,)
        ).fetchone())

        return ok({'token': token, 'user': user}), 201

    except Exception as e:
        return err(f'Registration failed: {str(e)}')
    finally:
        db.close()


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = (data.get('email','') or '').strip().lower()
    pw    = data.get('password','') or ''

    if not email or not pw:
        return err('Email and password required')

    db = get_conn()
    try:
        user = row_to_dict(db.execute(
            "SELECT * FROM users WHERE email=?", (email,)
        ).fetchone())

        if not user or not verify_password(pw, user['password']):
            return err('Invalid email or password', 401)
        if not user['is_active']:
            return err('Account is deactivated. Contact support.', 403)

        # Invalidate old sessions (keep last 3)
        old_sessions = db.execute(
            "SELECT id FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT -1 OFFSET 3",
            (user['id'],)
        ).fetchall()
        if old_sessions:
            ids = tuple(s['id'] for s in old_sessions)
            db.execute(f"DELETE FROM sessions WHERE id IN ({','.join('?'*len(ids))})", ids)

        token = generate_token()
        expires = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
        db.execute(
            "INSERT INTO sessions (user_id,token,expires_at,ip_address,user_agent) VALUES (?,?,?,?,?)",
            (user['id'], token, expires.strftime('%Y-%m-%d %H:%M:%S'),
             request.remote_addr, request.user_agent.string[:200])
        )
        db.execute("UPDATE users SET last_login=datetime('now','localtime') WHERE id=?", (user['id'],))
        db.commit()

        safe_user = {k: v for k, v in user.items() if k != 'password'}
        return ok({'token': token, 'user': safe_user})

    except Exception as e:
        return err(f'Login failed: {str(e)}')
    finally:
        db.close()


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    db = get_conn()
    db.execute("DELETE FROM sessions WHERE token=?", (token,))
    db.commit()
    db.close()
    return ok(message='Logged out successfully')


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    db = get_conn()
    user = row_to_dict(db.execute(
        "SELECT id,name,email,phone,role,wallet,avatar,created_at,last_login FROM users WHERE id=?",
        (g.user_id,)
    ).fetchone())
    db.close()
    return ok(user)


@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def change_password():
    data = request.get_json() or {}
    old_pw = data.get('old_password','')
    new_pw = data.get('new_password','')
    if not old_pw or not new_pw:
        return err('Both old and new passwords required')
    if len(new_pw) < 8:
        return err('New password must be at least 8 characters')
    db = get_conn()
    try:
        user = row_to_dict(db.execute("SELECT * FROM users WHERE id=?", (g.user_id,)).fetchone())
        if not verify_password(old_pw, user['password']):
            return err('Old password is incorrect', 401)
        db.execute("UPDATE users SET password=? WHERE id=?", (hash_password(new_pw), g.user_id))
        db.execute("DELETE FROM sessions WHERE user_id=?", (g.user_id,))
        db.commit()
        return ok(message='Password changed. Please login again.')
    finally:
        db.close()

# ─────────────────────────────────────────────
# Vehicles
# ─────────────────────────────────────────────
@app.route('/api/vehicles', methods=['GET'])
def get_vehicles():
    db = get_conn()
    vehicles = rows_to_list(db.execute("SELECT * FROM vehicles WHERE available=1 ORDER BY rate_per_km").fetchall())
    db.close()
    for v in vehicles:
        try: v['features'] = json.loads(v['features'])
        except: v['features'] = []
    return ok(vehicles)


@app.route('/api/vehicles/<int:vid>', methods=['GET'])
def get_vehicle(vid):
    db = get_conn()
    v = row_to_dict(db.execute("SELECT * FROM vehicles WHERE id=?", (vid,)).fetchone())
    db.close()
    if not v: return err('Vehicle not found', 404)
    try: v['features'] = json.loads(v['features'])
    except: v['features'] = []
    return ok(v)

# ─────────────────────────────────────────────
# Fare Calculator
# ─────────────────────────────────────────────
CITIES_COORDS = {
    "Mumbai": (19.076, 72.877), "Delhi": (28.6139, 77.2090),
    "Bengaluru": (12.9716, 77.5946), "Chennai": (13.0827, 80.2707),
    "Hyderabad": (17.3850, 78.4867), "Pune": (18.5204, 73.8567),
    "Kolkata": (22.5726, 88.3639), "Ahmedabad": (23.0225, 72.5714),
    "Jaipur": (26.9124, 75.7873), "Surat": (21.1702, 72.8311),
    "Lucknow": (26.8467, 80.9462), "Kanpur": (26.4499, 80.3319),
    "Nagpur": (21.1458, 79.0882), "Indore": (22.7196, 75.8577),
    "Bhopal": (23.2599, 77.4126), "Visakhapatnam": (17.6868, 83.2185),
    "Patna": (25.5941, 85.1376), "Vadodara": (22.3072, 73.1812),
    "Goa": (15.2993, 74.1240), "Agra": (27.1767, 78.0081),
    "Chandigarh": (30.7333, 76.7794), "Coimbatore": (11.0168, 76.9558),
    "Varanasi": (25.3176, 82.9739), "Rajkot": (22.3039, 70.8022),
    "Madurai": (9.9252, 78.1198), "Amritsar": (31.6340, 74.8723),
    "Jodhpur": (26.2389, 73.0243), "Udaipur": (24.5854, 73.7125),
    "Shimla": (31.1048, 77.1734), "Manali": (32.2396, 77.1887),
    "Dehradun": (30.3165, 78.0322), "Rishikesh": (30.0869, 78.2676),
    "Leh": (34.1526, 77.5771), "Srinagar": (34.0837, 74.7973),
    "Guwahati": (26.1445, 91.7362), "Kochi": (9.9312, 76.2673),
    "Thiruvananthapuram": (8.5241, 76.9366), "Bhubaneswar": (20.2961, 85.8245),
    "Nashik": (19.9975, 73.7898), "Mysuru": (12.2958, 76.6394),
}

import math

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


@app.route('/api/fare/calculate', methods=['POST'])
def calculate_fare():
    data = request.get_json() or {}
    from_city = (data.get('from_city','') or '').strip().title()
    to_city   = (data.get('to_city','') or '').strip().title()
    vehicle_id = data.get('vehicle_id')

    if from_city not in CITIES_COORDS:
        return err(f'City "{from_city}" not found. Check spelling.')
    if to_city not in CITIES_COORDS:
        return err(f'City "{to_city}" not found. Check spelling.')
    if from_city == to_city:
        return err('Pickup and drop cities must be different')

    lat1, lon1 = CITIES_COORDS[from_city]
    lat2, lon2 = CITIES_COORDS[to_city]
    straight_km = haversine(lat1, lon1, lat2, lon2)
    road_km = round(straight_km * 1.35)
    duration_hrs = round(road_km / 60, 1)

    db = get_conn()
    if vehicle_id:
        v = row_to_dict(db.execute("SELECT * FROM vehicles WHERE id=?", (vehicle_id,)).fetchone())
    else:
        v = row_to_dict(db.execute("SELECT * FROM vehicles ORDER BY rate_per_km LIMIT 1").fetchone())
    db.close()

    if not v:
        return err('Vehicle not found', 404)

    rate = v['rate_per_km']
    base_fare = round(road_km * rate)
    toll_charge = round(road_km * 1.5)
    driver_charge = 300 if road_km > 300 else 0
    total = base_fare + toll_charge + driver_charge

    return ok({
        'from_city': from_city,
        'to_city': to_city,
        'straight_km': round(straight_km),
        'road_km': road_km,
        'duration_hrs': duration_hrs,
        'vehicle': {k: v[k] for k in ['id','name','category','rate_per_km','emoji','capacity']},
        'fare_breakdown': {
            'base_fare': base_fare,
            'toll_charge': toll_charge,
            'driver_charge': driver_charge,
            'total': total,
        },
        'from_coords': CITIES_COORDS[from_city],
        'to_coords': CITIES_COORDS[to_city],
    })

# ─────────────────────────────────────────────
# Bookings
# ─────────────────────────────────────────────
@app.route('/api/bookings', methods=['POST'])
@require_auth
def create_booking():
    data = request.get_json() or {}
    required = ['pickup_city','drop_city','travel_date','vehicle_id']
    for f in required:
        if not data.get(f):
            return err(f'Missing field: {f}')

    pickup = data['pickup_city'].strip().title()
    drop   = data['drop_city'].strip().title()
    vid    = data['vehicle_id']

    if pickup not in CITIES_COORDS or drop not in CITIES_COORDS:
        return err('Invalid city names')

    db = get_conn()
    try:
        v = row_to_dict(db.execute("SELECT * FROM vehicles WHERE id=?", (vid,)).fetchone())
        if not v:
            return err('Vehicle not found', 404)

        lat1, lon1 = CITIES_COORDS[pickup]
        lat2, lon2 = CITIES_COORDS[drop]
        road_km = round(haversine(lat1, lon1, lat2, lon2) * 1.35)
        duration = round(road_km / 60, 1)
        base_fare = round(road_km * v['rate_per_km'])
        toll = round(road_km * 1.5)
        driver_charge = 300 if road_km > 300 else 0

        # Apply coupon
        coupon_code = (data.get('coupon','') or '').strip().upper()
        discount = 0
        if coupon_code:
            offer = row_to_dict(db.execute(
                "SELECT * FROM offers WHERE code=? AND is_active=1 AND (expires_at IS NULL OR expires_at > datetime('now','localtime')) AND used_count < max_uses",
                (coupon_code,)
            ).fetchone())
            if offer:
                subtotal = base_fare + toll + driver_charge
                if subtotal >= offer['min_amount']:
                    if offer['discount_pct'] > 0:
                        discount = round(subtotal * offer['discount_pct'] / 100)
                    elif offer['discount_flat'] > 0:
                        discount = min(offer['discount_flat'], subtotal)
                    db.execute("UPDATE offers SET used_count=used_count+1 WHERE id=?", (offer['id'],))

        total = base_fare + toll + driver_charge - discount
        booking_ref = generate_booking_ref()
        tracking_code = secrets.token_hex(4).upper()

        # Fake driver assignment
        drivers = [
            ('Rajesh Kumar', '+91 98765 43210'),
            ('Amit Singh', '+91 87654 32109'),
            ('Priya Sharma', '+91 76543 21098'),
            ('Mohammed Ali', '+91 65432 10987'),
            ('Suresh Nair', '+91 54321 09876'),
        ]
        import random
        drv_name, drv_phone = random.choice(drivers)

        db.execute("""
            INSERT INTO bookings
            (booking_ref,user_id,vehicle_id,pickup_city,drop_city,pickup_address,
             travel_date,distance_km,duration_hrs,base_fare,toll_charge,driver_charge,
             total_amount,special_req,driver_name,driver_phone,tracking_code,status,payment_status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'confirmed','pending')
        """, (
            booking_ref, g.user_id, vid, pickup, drop,
            data.get('pickup_address',''), data['travel_date'],
            road_km, duration, base_fare, toll, driver_charge, total,
            data.get('special_req',''), drv_name, drv_phone, tracking_code
        ))
        db.commit()

        booking = row_to_dict(db.execute(
            "SELECT b.*, v.name as vehicle_name, v.emoji, v.category FROM bookings b JOIN vehicles v ON v.id=b.vehicle_id WHERE b.id=last_insert_rowid()"
        ).fetchone())

        return ok({
            'booking': booking,
            'discount': discount,
            'message': f'Booking confirmed! Ref: {booking_ref}. Driver {drv_name} will contact you at your number.'
        }), 201

    except Exception as e:
        return err(f'Booking failed: {str(e)}')
    finally:
        db.close()


@app.route('/api/bookings', methods=['GET'])
@require_auth
def get_my_bookings():
    db = get_conn()
    bookings = rows_to_list(db.execute("""
        SELECT b.*, v.name as vehicle_name, v.emoji, v.category
        FROM bookings b JOIN vehicles v ON v.id=b.vehicle_id
        WHERE b.user_id=? ORDER BY b.created_at DESC
    """, (g.user_id,)).fetchall())
    db.close()
    return ok(bookings)


@app.route('/api/bookings/<ref>', methods=['GET'])
@require_auth
def get_booking(ref):
    db = get_conn()
    b = row_to_dict(db.execute("""
        SELECT b.*, v.name as vehicle_name, v.emoji, v.category, v.features,
               u.name as passenger_name, u.phone as passenger_phone
        FROM bookings b
        JOIN vehicles v ON v.id=b.vehicle_id
        JOIN users u ON u.id=b.user_id
        WHERE b.booking_ref=? AND (b.user_id=? OR ?='admin')
    """, (ref, g.user_id, g.user.get('role'))).fetchone())
    db.close()
    if not b: return err('Booking not found', 404)
    return ok(b)


@app.route('/api/bookings/<ref>/cancel', methods=['POST'])
@require_auth
def cancel_booking(ref):
    db = get_conn()
    b = row_to_dict(db.execute(
        "SELECT * FROM bookings WHERE booking_ref=? AND user_id=?", (ref, g.user_id)
    ).fetchone())
    if not b: return err('Booking not found', 404)
    if b['status'] in ('completed','cancelled'):
        return err(f'Cannot cancel a {b["status"]} booking')
    db.execute("UPDATE bookings SET status='cancelled' WHERE booking_ref=?", (ref,))
    db.commit()
    db.close()
    return ok(message='Booking cancelled successfully')


# ─────────────────────────────────────────────
# AI Concierge (Aria)
# ─────────────────────────────────────────────
ARIA_SYSTEM = """You are Aria, the AI travel concierge for LuxRide India — India's premier luxury travel booking platform. 

You help users:
- Plan road trips and outstation journeys across India
- Suggest the right vehicle (sedan ₹11/km, XUV ₹15/km, MPV ₹14/km, 8-seater shuttle ₹20/km, mini bus ₹28/km, luxury coach ₹45/km)
- Estimate fares (base = distance × rate + tolls ≈ ₹1.5/km + driver charge ₹300 for >300km)
- Recommend routes, pit stops, and travel tips
- Provide information about cities, highways, and distances

Rules:
- Keep responses concise (2-3 short paragraphs max)
- Use relevant Indian city names, highways (NH48, NH44, etc.), and landmarks
- Always mention LuxRide booking option when relevant
- Use emojis sparingly but effectively
- Never mention flights or airlines — we only do ground transport
- Be warm, professional, and knowledgeable about India's roads"""

AI_FALLBACK = {
    'route': "I can suggest optimal routes between any Indian cities! Popular routes include Delhi→Agra (200km), Mumbai→Pune (150km), Bengaluru→Mysuru (140km). Which cities are you traveling between? 🗺️",
    'fare': "Our fares start at ₹11/km for sedans. For a quick estimate: multiply road distance by vehicle rate + ~₹1.5/km for tolls. Use our Fare Calculator for exact numbers! 💰",
    'vehicle': "For 1-4 people: Executive Sedan. For 5-6: XUV/SUV. For 7: Innova MPV. For groups up to 8: Shuttle. Up to 17: Mini Bus. Large groups 35+: Luxury Coach. Need help choosing? 🚗",
    'book': "Ready to book? Go to our booking section, enter your pickup/drop cities, select date and vehicle type, and confirm. Driver details are shared instantly! 📱",
    'default': "Namaste! 🙏 I'm Aria, your LuxRide AI concierge. I can help with route planning, fare estimates, vehicle recommendations, and booking guidance across India. What would you like to know?"
}

@app.route('/api/ai/chat', methods=['POST'])
def ai_chat():
    data = request.get_json() or {}
    user_msg = (data.get('message','') or '').strip()
    session_key = data.get('session_key', secrets.token_hex(8))
    history = data.get('history', [])

    if not user_msg:
        return err('Message is required')
    if len(user_msg) > 1000:
        return err('Message too long')

    # Build messages
    messages = []
    for h in history[-10:]:  # last 10 turns
        if h.get('role') in ('user','assistant') and h.get('content'):
            messages.append({'role': h['role'], 'content': str(h['content'])[:500]})
    messages.append({'role': 'user', 'content': user_msg})

    ai_reply = None

    # Try Anthropic API
    if ANTHROPIC_KEY:
        try:
            payload = json.dumps({
                'model': 'claude-sonnet-4-20250514',
                'max_tokens': 500,
                'system': ARIA_SYSTEM,
                'messages': messages
            }).encode()
            req = urllib.request.Request(
                'https://api.anthropic.com/v1/messages',
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                    'x-api-key': ANTHROPIC_KEY,
                    'anthropic-version': '2023-06-01'
                }
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                ai_reply = result['content'][0]['text']
        except Exception as e:
            ai_reply = None

    # Fallback to rule-based
    if not ai_reply:
        lower = user_msg.lower()
        for key in ('route','fare','vehicle','book'):
            if key in lower:
                ai_reply = AI_FALLBACK[key]
                break
        if not ai_reply:
            ai_reply = AI_FALLBACK['default']

    # Save chat to DB (optional, non-blocking)
    try:
        user_id = None
        token = request.headers.get('Authorization','').replace('Bearer ','')
        if token:
            db = get_conn()
            s = db.execute("SELECT user_id FROM sessions WHERE token=? AND expires_at > datetime('now','localtime')", (token,)).fetchone()
            if s: user_id = s['user_id']
            db.execute("INSERT INTO ai_chats (user_id,session_key,role,content) VALUES (?,?,?,?)",
                       (user_id, session_key, 'user', user_msg))
            db.execute("INSERT INTO ai_chats (user_id,session_key,role,content) VALUES (?,?,?,?)",
                       (user_id, session_key, 'assistant', ai_reply))
            db.commit()
            db.close()
    except:
        pass

    return ok({'reply': ai_reply, 'session_key': session_key})

# ─────────────────────────────────────────────
# Cities Autocomplete
# ─────────────────────────────────────────────
@app.route('/api/cities', methods=['GET'])
def get_cities():
    q = request.args.get('q','').strip().lower()
    all_cities = [{'name': k, 'lat': v[0], 'lng': v[1]} for k, v in CITIES_COORDS.items()]
    if q:
        all_cities = [c for c in all_cities if c['name'].lower().startswith(q)]
    return ok(sorted(all_cities, key=lambda x: x['name'])[:10])

# ─────────────────────────────────────────────
# News & Offers
# ─────────────────────────────────────────────
@app.route('/api/news', methods=['GET'])
def get_news():
    db = get_conn()
    news = rows_to_list(db.execute("SELECT * FROM news WHERE published=1 ORDER BY created_at DESC").fetchall())
    db.close()
    return ok(news)


@app.route('/api/offers/validate', methods=['POST'])
@require_auth
def validate_offer():
    data = request.get_json() or {}
    code = (data.get('code','') or '').strip().upper()
    amount = float(data.get('amount', 0) or 0)
    if not code:
        return err('Coupon code required')
    db = get_conn()
    offer = row_to_dict(db.execute(
        "SELECT * FROM offers WHERE code=? AND is_active=1 AND (expires_at IS NULL OR expires_at > datetime('now','localtime')) AND used_count < max_uses",
        (code,)
    ).fetchone())
    db.close()
    if not offer:
        return err('Invalid or expired coupon code', 404)
    if amount < offer['min_amount']:
        return err(f'Minimum booking amount ₹{offer["min_amount"]:.0f} required for this code')

    discount = 0
    if offer['discount_pct'] > 0:
        discount = round(amount * offer['discount_pct'] / 100)
    elif offer['discount_flat'] > 0:
        discount = min(offer['discount_flat'], amount)

    return ok({'offer': offer, 'discount': discount, 'final_amount': amount - discount})

# ─────────────────────────────────────────────
# Admin Routes
# ─────────────────────────────────────────────
@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    db = get_conn()
    stats = {
        'total_users': db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'total_bookings': db.execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
        'confirmed_bookings': db.execute("SELECT COUNT(*) FROM bookings WHERE status='confirmed'").fetchone()[0],
        'total_revenue': db.execute("SELECT COALESCE(SUM(total_amount),0) FROM bookings WHERE status!='cancelled'").fetchone()[0],
        'today_bookings': db.execute("SELECT COUNT(*) FROM bookings WHERE DATE(created_at)=DATE('now','localtime')").fetchone()[0],
        'active_sessions': db.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now','localtime')").fetchone()[0],
    }
    db.close()
    return ok(stats)


@app.route('/api/admin/bookings', methods=['GET'])
@require_admin
def admin_bookings():
    db = get_conn()
    bookings = rows_to_list(db.execute("""
        SELECT b.*, v.name as vehicle_name, v.emoji, u.name as user_name, u.phone as user_phone
        FROM bookings b
        JOIN vehicles v ON v.id=b.vehicle_id
        JOIN users u ON u.id=b.user_id
        ORDER BY b.created_at DESC LIMIT 100
    """).fetchall())
    db.close()
    return ok(bookings)


@app.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_users():
    db = get_conn()
    users = rows_to_list(db.execute(
        "SELECT id,name,email,phone,role,wallet,is_active,created_at,last_login FROM users ORDER BY created_at DESC"
    ).fetchall())
    db.close()
    return ok(users)

# ─────────────────────────────────────────────
# Serve Frontend
# ─────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/health')
def health():
    db = get_conn()
    db.execute("SELECT 1")
    db.close()
    return ok({'status': 'healthy', 'db': 'connected', 'ai': bool(ANTHROPIC_KEY), 'time': datetime.now().isoformat()})

# ─────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return err('Resource not found', 404)

@app.errorhandler(405)
def method_not_allowed(e):
    return err('Method not allowed', 405)

@app.errorhandler(500)
def server_error(e):
    return err('Internal server error', 500)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"""
╔══════════════════════════════════════════════╗
║         LuxRide India Backend v1.0           ║
╠══════════════════════════════════════════════╣
║  🌐  http://localhost:{port}                    ║
║  📊  API: /api/*                             ║
║  🗄️   DB: {DB_PATH[:30]}...  ║
║  🤖  AI: {'Connected ✅' if ANTHROPIC_KEY else 'Fallback mode ⚠️ '}              ║
╚══════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=port)
