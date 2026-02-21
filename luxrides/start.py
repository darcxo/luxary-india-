#!/usr/bin/env python3
"""
LuxRide India — Quick Start Script
Run this to initialize DB and start the server
"""
import os, sys

def main():
    print("╔══════════════════════════════════════════════╗")
    print("║      LuxRide India — Backend Startup         ║")
    print("╚══════════════════════════════════════════════╝\n")

    # Set working dir to script location
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Set API key if provided as argument
    if len(sys.argv) > 1:
        os.environ['ANTHROPIC_API_KEY'] = sys.argv[1]
        print(f"✅ Anthropic API key set")
    else:
        print("ℹ️  No API key provided — AI will use fallback responses")
        print("   Usage: python start.py YOUR_ANTHROPIC_API_KEY\n")

    # Init DB
    from database import init_db
    init_db()

    # Start server
    print("\n🚀 Starting LuxRide server...")
    print("🌐 Open: http://localhost:5000\n")

    from app import app
    app.run(debug=False, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
