"""
LuxRide India - Database Layer
SQLite3 with full schema for users, bookings, vehicles, sessions
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'luxride.db')

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL COLLATE NOCASE,
    phone       TEXT NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT DEFAULT 'user' CHECK(role IN ('user','admin','driver')),
    avatar      TEXT DEFAULT NULL,
    wallet      REAL DEFAULT 0.0,
    is_active   INTEGER DEFAULT 1,
    created_at  DATETIME DEFAULT (datetime('now','localtime')),
    last_login  DATETIME DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token       TEXT UNIQUE NOT NULL,
    expires_at  DATETIME NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  DATETIME DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS vehicles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    capacity    INTEGER NOT NULL,
    bags        INTEGER DEFAULT 2,
    rate_per_km REAL NOT NULL,
    base_fare   REAL DEFAULT 0,
    features    TEXT DEFAULT '[]',
    emoji       TEXT DEFAULT '🚗',
    badge       TEXT DEFAULT NULL,
    available   INTEGER DEFAULT 1,
    created_at  DATETIME DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS bookings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_ref     TEXT UNIQUE NOT NULL,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vehicle_id      INTEGER NOT NULL REFERENCES vehicles(id),
    pickup_city     TEXT NOT NULL,
    drop_city       TEXT NOT NULL,
    pickup_address  TEXT,
    travel_date     DATETIME NOT NULL,
    distance_km     REAL,
    duration_hrs    REAL,
    base_fare       REAL,
    toll_charge     REAL DEFAULT 0,
    driver_charge   REAL DEFAULT 0,
    total_amount    REAL NOT NULL,
    status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','confirmed','in_progress','completed','cancelled')),
    payment_status  TEXT DEFAULT 'pending' CHECK(payment_status IN ('pending','paid','refunded')),
    special_req     TEXT,
    driver_name     TEXT DEFAULT NULL,
    driver_phone    TEXT DEFAULT NULL,
    tracking_code   TEXT DEFAULT NULL,
    created_at      DATETIME DEFAULT (datetime('now','localtime')),
    updated_at      DATETIME DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS ai_chats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    session_key TEXT NOT NULL,
    role        TEXT NOT NULL CHECK(role IN ('user','assistant')),
    content     TEXT NOT NULL,
    created_at  DATETIME DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS news (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    excerpt     TEXT,
    category    TEXT DEFAULT 'Update',
    badge       TEXT DEFAULT NULL,
    published   INTEGER DEFAULT 1,
    created_at  DATETIME DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS offers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT UNIQUE NOT NULL COLLATE NOCASE,
    description TEXT,
    discount_pct REAL DEFAULT 0,
    discount_flat REAL DEFAULT 0,
    min_amount  REAL DEFAULT 0,
    max_uses    INTEGER DEFAULT 100,
    used_count  INTEGER DEFAULT 0,
    is_active   INTEGER DEFAULT 1,
    expires_at  DATETIME DEFAULT NULL,
    created_at  DATETIME DEFAULT (datetime('now','localtime'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sessions_token   ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_bookings_user    ON bookings(user_id);
CREATE INDEX IF NOT EXISTS idx_bookings_ref     ON bookings(booking_ref);
CREATE INDEX IF NOT EXISTS idx_chats_session    ON ai_chats(session_key);
"""

SEED_VEHICLES = [
    ('Executive Sedan',   'Honda Accord / Camry',              'Premium comfort for business travel. Climate control, leather seats, and professional chauffeurs.', 4,  3, 11.0, 200,  '["AC","WiFi","USB","Leather"]',       '🚗', 'Most Booked'),
    ('XUV / SUV',         'Mercedes GLS / BMW X7',             'Ultra-luxury SUV for premium outstation travel. Perfect for family trips and corporate groups.', 6,  5, 15.0, 300,  '["AC","HiFi","WiFi","LED"]',           '🚙', 'Luxury'),
    ('Business MPV',      "Toyota Innova Crysta",              "India's most trusted long-distance vehicle. Spacious, robust, and reliable for all terrain types.", 7, 6, 14.0, 250, '["AC","USB","Sunroof","Spacious"]',    '🚐', 'Popular'),
    ('Premium Shuttle',   'Force Traveller — 8 Pax',           'Ideal for corporate shuttle services and small group transfers with luggage space.', 8, 8, 20.0, 400,              '["AC","TV","Music","GPS"]',             '🚌', 'New'),
    ('Mini Bus',          'Tempo Traveller — 17 Pax',          'Best for large groups, pilgrimages, college tours, and team outings across India.', 17, 12, 28.0, 600,             '["AC","Music","Reclining","GPS"]',      '🚎', 'Groups'),
    ('Luxury Coach',      'Volvo / Scania Coach — 35+',        '5-star coach for weddings, events, pilgrimages. Full amenities including toilet.', 40, 30, 45.0, 1200,            '["AC","TV","Toilet","Reclining","WiFi"]','🚍', 'Premium'),
]

SEED_NEWS = [
    ('AI-Powered Smart Routing Now Live Across All Routes', 'Our new ML model processes 10M+ data points daily to predict optimal routes and estimate fuel-accurate ETAs.', 'Product Launch', 'NEW'),
    ('LuxRide Launches Exclusive Leh-Ladakh Mountain Route Service', 'Specially equipped high-altitude vehicles with experienced mountain drivers for India\'s most scenic routes.', 'Expansion', None),
    ('LuxRide Wins "Best Premium Travel Platform" at India Travel Awards 2026', 'Recognized for excellence in customer experience, safety standards, and technological innovation.', 'Award', None),
    ('Strategic Partnership with 5-Star Hotels for Seamless Guest Transfers', 'LuxRide is now the exclusive transportation partner for 150+ luxury hotels across 30 Indian cities.', 'Partnership', None),
    ('Remote Rental Program: Book a Car for Days or Weeks Anywhere', 'Introducing long-term vehicle rental with door delivery — choose your car, select dates, deliver to doorstep.', 'Feature Update', None),
    ('LuxRide Introduces Women Safety Shield — 24/7 Live Monitoring', 'New safety feature with real-time journey monitoring, SOS integration, and direct police coordination.', 'Safety', None),
]

SEED_OFFERS = [
    ('LUXRIDE20', '20% off on first outstation booking',      20.0, 0,    500,  1000),
    ('AIRPORT999','Flat ₹999 airport transfer within city',   0,    999,  999,  0),
    ('CORP15',    '15% off on corporate bookings',            15.0, 0,    2000, 10000),
    ('MONSOON10', '10% off during monsoon travel',            10.0, 0,    300,  500),
]


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)

    # Seed vehicles if empty
    if conn.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO vehicles (category,name,description,capacity,bags,rate_per_km,base_fare,features,emoji,badge) VALUES (?,?,?,?,?,?,?,?,?,?)",
            SEED_VEHICLES
        )

    # Seed news if empty
    if conn.execute("SELECT COUNT(*) FROM news").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO news (title,excerpt,category,badge) VALUES (?,?,?,?)",
            SEED_NEWS
        )

    # Seed offers if empty
    if conn.execute("SELECT COUNT(*) FROM offers").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO offers (code,description,discount_pct,discount_flat,min_amount,max_uses) VALUES (?,?,?,?,?,?)",
            SEED_OFFERS
        )

    conn.commit()
    conn.close()
    print("✅ Database initialized at", DB_PATH)


if __name__ == '__main__':
    init_db()
