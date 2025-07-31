#!/usr/bin/env python3
"""
RotaryShield Web Dashboard

Isolated web dashboard for RotaryShield security monitoring.
This is a standalone dashboard that reads from the main RotaryShield database
but operates independently.
"""

import os
import sys
import sqlite3
import time
import json
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory

# Optional CORS support
try:
    from flask_cors import CORS
    CORS_AVAILABLE = True
except ImportError:
    CORS_AVAILABLE = False

# Import configuration
from config import *

class DashboardDatabase:
    """Dashboard database manager for reading RotaryShield data."""
    
    def __init__(self, rotaryshield_db_path: str, dashboard_db_path: str):
        """
        Initialize database connections.
        
        Args:
            rotaryshield_db_path: Path to main RotaryShield database
            dashboard_db_path: Path to dashboard cache database
        """
        self.rotaryshield_db = rotaryshield_db_path
        self.dashboard_db = dashboard_db_path
        
        # Ensure dashboard database directory exists
        Path(dashboard_db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize dashboard cache database
        self._init_dashboard_db()
    
    def _init_dashboard_db(self):
        """Initialize dashboard cache database."""
        with sqlite3.connect(self.dashboard_db) as conn:
            cursor = conn.cursor()
            
            # Create dashboard metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_stats (
                    id INTEGER PRIMARY KEY,
                    active_bans INTEGER,
                    total_events_24h INTEGER,
                    total_events_1h INTEGER,
                    total_bans INTEGER,
                    last_updated REAL
                )
            """)
            
            # Create cached events table for faster queries
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cached_events (
                    id INTEGER PRIMARY KEY,
                    event_type TEXT,
                    source_ip TEXT,
                    severity TEXT,
                    description TEXT,
                    timestamp REAL,
                    created_at REAL
                )
            """)
            
            conn.commit()
    
    def get_connection(self, db_path: str):
        """Get database connection."""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_stats(self):
        """Get dashboard statistics."""
        try:
            # Check if RotaryShield database exists
            if not os.path.exists(self.rotaryshield_db):
                return {
                    'success': False, 
                    'error': 'RotaryShield database not found',
                    'data': {
                        'active_bans': 0,
                        'total_bans': 0,
                        'events_24h': 0,
                        'events_1h': 0
                    }
                }
            
            with self.get_connection(self.rotaryshield_db) as conn:
                cursor = conn.cursor()
                
                # Get active bans
                cursor.execute("SELECT COUNT(*) FROM ip_bans WHERE status = 'active'")
                active_bans = cursor.fetchone()[0]
                
                # Get total bans
                cursor.execute("SELECT COUNT(*) FROM ip_bans")
                total_bans = cursor.fetchone()[0]
                
                # Get events from last 24 hours
                cursor.execute("SELECT COUNT(*) FROM security_events WHERE timestamp > ?", 
                             (time.time() - 86400,))
                events_24h = cursor.fetchone()[0]
                
                # Get events from last 1 hour
                cursor.execute("SELECT COUNT(*) FROM security_events WHERE timestamp > ?", 
                             (time.time() - 3600,))
                events_1h = cursor.fetchone()[0]
                
                return {
                    'success': True,
                    'data': {
                        'active_bans': active_bans,
                        'total_bans': total_bans,
                        'events_24h': events_24h,
                        'events_1h': events_1h
                    }
                }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_top_attackers(self, limit=10):
        """Get top attacking IPs."""
        try:
            if not os.path.exists(self.rotaryshield_db):
                return {'success': True, 'data': []}
            
            with self.get_connection(self.rotaryshield_db) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT source_ip, COUNT(*) as attempts,
                           GROUP_CONCAT(DISTINCT event_type) as attack_types
                    FROM security_events 
                    WHERE timestamp > ? AND source_ip IS NOT NULL
                    GROUP BY source_ip 
                    ORDER BY attempts DESC 
                    LIMIT ?
                """, (time.time() - 86400, limit))
                
                attackers = []
                for row in cursor.fetchall():
                    attack_types = row[2].split(',') if row[2] else []
                    primary_type = attack_types[0] if attack_types else 'unknown'
                    
                    # Determine threat level
                    attempts = row[1]
                    if attempts >= 20:
                        threat_level = 'critical'
                    elif attempts >= 10:
                        threat_level = 'high'
                    elif attempts >= 5:
                        threat_level = 'medium'
                    else:
                        threat_level = 'low'
                    
                    attackers.append({
                        'ip_address': row[0],
                        'attempts': attempts,
                        'primary_type': primary_type,
                        'threat_level': threat_level
                    })
                
                return {'success': True, 'data': attackers}
        
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': []}
    
    def get_blocked_ips(self, limit=15):
        """Get blocked IPs."""
        try:
            if not os.path.exists(self.rotaryshield_db):
                return {'success': True, 'data': []}
            
            with self.get_connection(self.rotaryshield_db) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT ip_address, ban_reason as reason, ban_count as attempts,
                           status, created_at, expires_at
                    FROM ip_bans 
                    WHERE status = 'active'
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (limit,))
                
                blocked_ips = []
                for row in cursor.fetchall():
                    blocked_ips.append({
                        'ip_address': row[0],
                        'reason': row[1],
                        'attempts': row[2],
                        'status': row[3],
                        'created_at': row[4],
                        'expires_at': row[5]
                    })
                
                return {'success': True, 'data': blocked_ips}
        
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': []}
    
    def get_recent_events(self, limit=30):
        """Get recent security events."""
        try:
            if not os.path.exists(self.rotaryshield_db):
                return {'success': True, 'data': []}
            
            with self.get_connection(self.rotaryshield_db) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT event_type, source_ip as ip_address, severity,
                           description, timestamp as created_at
                    FROM security_events 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                events = []
                for row in cursor.fetchall():
                    events.append({
                        'event_type': row[0],
                        'ip_address': row[1],
                        'severity': row[2],
                        'description': row[3],
                        'created_at': row[4]
                    })
                
                return {'success': True, 'data': events}
        
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': []}


# Initialize Flask app
app = Flask(__name__)

# Enable CORS if available
if CORS_AVAILABLE:
    CORS(app)

# Initialize database
db = DashboardDatabase(str(ROTARYSHIELD_DB_PATH), str(DASHBOARD_DB_PATH))

@app.route('/')
def dashboard():
    """Main dashboard page."""
    return render_template('index.html', 
                         title=DASHBOARD_TITLE,
                         version=DASHBOARD_VERSION,
                         organization=ORGANIZATION_NAME)

@app.route('/api/stats')
def api_stats():
    """API endpoint for dashboard statistics."""
    return jsonify(db.get_stats())

@app.route('/api/top-attackers')
def api_top_attackers():
    """API endpoint for top attacking IPs."""
    limit = request.args.get('limit', MAX_TOP_ATTACKERS, type=int)
    return jsonify(db.get_top_attackers(limit))

@app.route('/api/blocked-ips')
def api_blocked_ips():
    """API endpoint for blocked IPs."""
    limit = request.args.get('limit', MAX_BLOCKED_IPS, type=int)
    return jsonify(db.get_blocked_ips(limit))

@app.route('/api/recent-events')
def api_recent_events():
    """API endpoint for recent security events."""
    limit = request.args.get('limit', MAX_RECENT_EVENTS, type=int)
    return jsonify(db.get_recent_events(limit))

@app.route('/api/health')
def api_health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'version': DASHBOARD_VERSION,
        'rotaryshield_db_exists': os.path.exists(ROTARYSHIELD_DB_PATH)
    })

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files."""
    return send_from_directory('static', filename)

def main():
    """Main function to run the dashboard."""
    print("🛡️  RotaryShield Web Dashboard")
    print("📊 Isolated Security Monitoring Interface")
    print("="*60)
    print(f"📁 Dashboard DB: {DASHBOARD_DB_PATH}")
    print(f"🔗 RotaryShield DB: {ROTARYSHIELD_DB_PATH}")
    print(f"🌐 Dashboard URL: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"🎯 Auto-refresh: {AUTO_REFRESH_INTERVAL}s")
    print()
    
    # Check if RotaryShield database exists
    if not ROTARYSHIELD_DB_PATH.exists():
        print("⚠️  WARNING: RotaryShield database not found!")
        print(f"   Expected: {ROTARYSHIELD_DB_PATH}")
        print("   Dashboard will show empty data until monitoring starts.")
        print()
    
    print("🚀 Starting dashboard server...")
    print("📱 Dashboard features:")
    print("   • Real-time attack monitoring")
    print("   • IP ban management")
    print("   • Security event timeline")
    print("   • Top attackers analysis")
    print("   • Responsive design")
    print()
    print("Press Ctrl+C to stop the dashboard")
    print("="*60)
    
    try:
        app.run(
            host=DASHBOARD_HOST,
            port=DASHBOARD_PORT,
            debug=DEBUG_MODE,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
    except Exception as e:
        print(f"\n❌ Dashboard error: {e}")

if __name__ == "__main__":
    main()