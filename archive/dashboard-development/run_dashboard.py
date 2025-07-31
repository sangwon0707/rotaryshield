#!/usr/bin/env python3
"""
RotaryShield Dashboard Runner

Stable version that runs the dashboard reliably on MacOS.
"""

import sys
import os
import sqlite3
import json
import time
from pathlib import Path
from flask import Flask, render_template_string, jsonify
import threading

# Simple HTML template with embedded CSS and JavaScript
DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ RotaryShield - Real-time Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff; min-height: 100vh; overflow-x: hidden;
        }
        .header { 
            background: rgba(0,0,0,0.3); padding: 20px 0; border-bottom: 2px solid #00d4aa;
            backdrop-filter: blur(10px); position: sticky; top: 0; z-index: 100;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 0 20px; }
        .header-content { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
        .logo { display: flex; align-items: center; gap: 15px; }
        .logo h1 { font-size: 2.2rem; color: #00d4aa; text-shadow: 0 0 20px rgba(0,212,170,0.5); }
        .status { display: flex; align-items: center; gap: 10px; }
        .status-dot { width: 12px; height: 12px; border-radius: 50%; background: #28a745; 
                     box-shadow: 0 0 10px #28a745; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        
        .main { padding: 30px 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
                     gap: 20px; margin-bottom: 30px; }
        .stat-card { 
            background: rgba(255,255,255,0.1); border-radius: 15px; padding: 25px;
            border: 1px solid rgba(255,255,255,0.2); position: relative; overflow: hidden;
            transition: transform 0.3s ease; backdrop-filter: blur(5px);
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-card::before { 
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
            background: linear-gradient(90deg, #00d4aa, #0099cc, #00d4aa);
        }
        .stat-number { font-size: 3rem; font-weight: 700; color: #00d4aa; 
                      text-shadow: 0 0 10px rgba(0,212,170,0.5); margin-bottom: 5px; }
        .stat-label { font-size: 0.95rem; color: #b0b0b0; text-transform: uppercase; letter-spacing: 1px; }
        .stat-icon { position: absolute; right: 20px; top: 20px; font-size: 2rem; opacity: 0.3; }
        
        .section { margin-bottom: 30px; }
        .section-title { font-size: 1.4rem; color: #00d4aa; margin-bottom: 20px; 
                        display: flex; align-items: center; gap: 10px; }
        .section-title::before { content: ''; width: 4px; height: 20px; background: #00d4aa; }
        
        .table-container { 
            background: rgba(255,255,255,0.1); border-radius: 15px; overflow: hidden;
            border: 1px solid rgba(255,255,255,0.2); backdrop-filter: blur(5px);
        }
        .table-header { background: rgba(0,0,0,0.3); padding: 20px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .table-header h3 { color: #00d4aa; font-size: 1.2rem; }
        .table-wrapper { max-height: 400px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 15px 20px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
        th { background: rgba(0,0,0,0.2); color: #00d4aa; font-weight: 600; position: sticky; top: 0; }
        tbody tr:hover { background: rgba(255,255,255,0.05); }
        .severity-critical { color: #dc3545; font-weight: 600; }
        .severity-high { color: #fd7e14; font-weight: 600; }
        .severity-medium { color: #ffc107; font-weight: 600; }
        .severity-low { color: #28a745; font-weight: 600; }
        .ip-highlight { color: #00d4aa; font-weight: 600; }
        .status-active { color: #dc3545; font-weight: 600; }
        
        .refresh-info { text-align: center; padding: 20px; color: #b0b0b0; font-size: 0.9rem; }
        .loading { text-align: center; color: #b0b0b0; font-style: italic; padding: 40px; }
        .error { text-align: center; color: #dc3545; padding: 40px; }
        
        .footer { background: rgba(0,0,0,0.3); padding: 20px 0; text-align: center; 
                 color: #b0b0b0; font-size: 0.9rem; border-top: 1px solid rgba(255,255,255,0.1); }
        
        @media (max-width: 768px) {
            .header-content { flex-direction: column; gap: 15px; text-align: center; }
            .stats-grid { grid-template-columns: 1fr; }
            .container { padding: 0 15px; }
            th, td { padding: 10px; font-size: 0.9rem; }
        }
        
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.1); }
        ::-webkit-scrollbar-thumb { background: rgba(0,212,170,0.5); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(0,212,170,0.7); }
    </style>
</head>
<body>
    <header class="header">
        <div class="container">
            <div class="header-content">
                <div class="logo">
                    <h1>🛡️ RotaryShield</h1>
                    <div>
                        <div style="font-size: 1rem; color: #b0b0b0;">Real-time Security Dashboard</div>
                        <div style="font-size: 0.9rem; color: #00d4aa;">Phase 2 Complete - Enterprise Ready</div>
                    </div>
                </div>
                <div class="status">
                    <div class="status-dot"></div>
                    <div>
                        <div>System Active</div>
                        <div style="font-size: 0.8rem; color: #b0b0b0;">
                            Last Updated: <span id="last-update">Loading...</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <main class="main">
        <div class="container">
            <!-- Statistics Cards -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">🚫</div>
                    <div class="stat-number" id="active-bans">--</div>
                    <div class="stat-label">Active IP Bans</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚠️</div>
                    <div class="stat-number" id="events-24h">--</div>
                    <div class="stat-label">Events (24 Hours)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🔥</div>
                    <div class="stat-number" id="events-1h">--</div>
                    <div class="stat-label">Events (1 Hour)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">📊</div>
                    <div class="stat-number" id="total-bans">--</div>
                    <div class="stat-label">Total Bans</div>
                </div>
            </div>

            <!-- Top Attackers Section -->
            <div class="section">
                <h2 class="section-title">🎯 Top Attacking IPs (24 Hours)</h2>
                <div class="table-container">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Attack Attempts</th>
                                    <th>Primary Attack Type</th>
                                    <th>Threat Level</th>
                                </tr>
                            </thead>
                            <tbody id="top-attackers-tbody">
                                <tr><td colspan="4" class="loading">Loading top attackers...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Blocked IPs Section -->
            <div class="section">
                <h2 class="section-title">🚫 Currently Blocked IPs</h2>
                <div class="table-container">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Block Reason</th>
                                    <th>Attempts</th>
                                    <th>Status</th>
                                    <th>Blocked Time</th>
                                </tr>
                            </thead>
                            <tbody id="blocked-ips-tbody">
                                <tr><td colspan="5" class="loading">Loading blocked IPs...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Recent Events Section -->
            <div class="section">
                <h2 class="section-title">📈 Recent Security Events</h2>
                <div class="table-container">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Event Type</th>
                                    <th>Source IP</th>
                                    <th>Severity</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody id="recent-events-tbody">
                                <tr><td colspan="5" class="loading">Loading recent events...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="refresh-info">
                📡 Dashboard auto-refreshes every 10 seconds | 🛡️ RotaryShield Phase 2 - Enterprise Security Monitoring
            </div>
        </div>
    </main>

    <footer class="footer">
        <div class="container">
            RotaryShield Dashboard | Phase 2 Complete - Enterprise Ready | Real-time Attack Monitoring & Visualization
        </div>
    </footer>

    <script>
        let refreshInterval;
        
        // Initialize dashboard
        function initDashboard() {
            console.log('🛡️ Initializing RotaryShield Dashboard...');
            loadAllData();
            
            // Auto-refresh every 10 seconds
            refreshInterval = setInterval(loadAllData, 10000);
        }
        
        // Load all dashboard data
        async function loadAllData() {
            try {
                await Promise.all([
                    loadStats(),
                    loadTopAttackers(),
                    loadBlockedIPs(),
                    loadRecentEvents()
                ]);
                
                document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
            } catch (error) {
                console.error('Error loading dashboard data:', error);
            }
        }
        
        // Load statistics
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('active-bans').textContent = data.data.active_bans || 0;
                    document.getElementById('events-24h').textContent = data.data.events_24h || 0;
                    document.getElementById('events-1h').textContent = data.data.events_1h || 0;
                    document.getElementById('total-bans').textContent = data.data.total_bans || 0;
                }
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        // Load top attackers
        async function loadTopAttackers() {
            try {
                const response = await fetch('/api/top-attackers');
                const data = await response.json();
                
                const tbody = document.getElementById('top-attackers-tbody');
                if (data.success && data.data.length > 0) {
                    tbody.innerHTML = data.data.map(attacker => `
                        <tr>
                            <td><span class="ip-highlight">${attacker.ip_address}</span></td>
                            <td><strong>${attacker.attempts}</strong></td>
                            <td>${attacker.primary_type || 'Multiple'}</td>
                            <td><span class="severity-${attacker.threat_level || 'high'}">${(attacker.threat_level || 'HIGH').toUpperCase()}</span></td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = '<tr><td colspan="4" class="loading">No attack data available</td></tr>';
                }
            } catch (error) {
                document.getElementById('top-attackers-tbody').innerHTML = 
                    '<tr><td colspan="4" class="error">Error loading data</td></tr>';
            }
        }
        
        // Load blocked IPs
        async function loadBlockedIPs() {
            try {
                const response = await fetch('/api/blocked-ips');
                const data = await response.json();
                
                const tbody = document.getElementById('blocked-ips-tbody');
                if (data.success && data.data.length > 0) {
                    tbody.innerHTML = data.data.map(ip => `
                        <tr>
                            <td><span class="ip-highlight">${ip.ip_address}</span></td>
                            <td>${ip.reason}</td>
                            <td><strong>${ip.attempts}</strong></td>
                            <td><span class="status-active">ACTIVE</span></td>
                            <td>${new Date(ip.created_at).toLocaleDateString()} ${new Date(ip.created_at).toLocaleTimeString()}</td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = '<tr><td colspan="5" class="loading">No blocked IPs</td></tr>';
                }
            } catch (error) {
                document.getElementById('blocked-ips-tbody').innerHTML = 
                    '<tr><td colspan="5" class="error">Error loading data</td></tr>';
            }
        }
        
        // Load recent events
        async function loadRecentEvents() {
            try {
                const response = await fetch('/api/recent-events');
                const data = await response.json();
                
                const tbody = document.getElementById('recent-events-tbody');
                if (data.success && data.data.length > 0) {
                    tbody.innerHTML = data.data.slice(0, 20).map(event => `
                        <tr>
                            <td>${new Date(event.created_at).toLocaleTimeString()}</td>
                            <td><strong>${event.event_type}</strong></td>
                            <td><span class="ip-highlight">${event.ip_address}</span></td>
                            <td><span class="severity-${event.severity.toLowerCase()}">${event.severity}</span></td>
                            <td>${event.description}</td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = '<tr><td colspan="5" class="loading">No recent events</td></tr>';
                }
            } catch (error) {
                document.getElementById('recent-events-tbody').innerHTML = 
                    '<tr><td colspan="5" class="error">Error loading data</td></tr>';
            }
        }
        
        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', initDashboard);
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        });
    </script>
</body>
</html>"""

class RotaryShieldDashboard:
    """Stable RotaryShield Dashboard."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.app = Flask(__name__)
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.route('/')
        def dashboard():
            return render_template_string(DASHBOARD_TEMPLATE)
        
        @self.app.route('/api/stats')
        def api_stats():
            return jsonify(self._get_stats())
        
        @self.app.route('/api/top-attackers')
        def api_top_attackers():
            return jsonify(self._get_top_attackers())
        
        @self.app.route('/api/blocked-ips')
        def api_blocked_ips():
            return jsonify(self._get_blocked_ips())
        
        @self.app.route('/api/recent-events')
        def api_recent_events():
            return jsonify(self._get_recent_events())
    
    def _get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _get_stats(self):
        """Get dashboard statistics."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Basic counts - using live database schema
            cursor.execute("SELECT COUNT(*) FROM ip_bans WHERE status = 'active'")
            active_bans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM ip_bans")
            total_bans = cursor.fetchone()[0]
            
            # Events from last 24 hours (using REAL timestamp)
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE timestamp > ?", (time.time() - 86400,))
            events_24h = cursor.fetchone()[0]
            
            # Events from last 1 hour
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE timestamp > ?", (time.time() - 3600,))
            events_1h = cursor.fetchone()[0]
            
            conn.close()
            
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
    
    def _get_top_attackers(self):
        """Get top attacking IPs."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT source_ip, COUNT(*) as attempts,
                       GROUP_CONCAT(DISTINCT event_type) as attack_types
                FROM security_events 
                WHERE timestamp > ? AND source_ip IS NOT NULL
                GROUP BY source_ip 
                ORDER BY attempts DESC 
                LIMIT 10
            """, (time.time() - 86400,))
            
            attackers = []
            for row in cursor.fetchall():
                attack_types = row[2].split(',') if row[2] else []
                primary_type = attack_types[0] if attack_types else 'unknown'
                
                # Determine threat level based on attempts
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
            
            conn.close()
            return {'success': True, 'data': attackers}
            
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': []}
    
    def _get_blocked_ips(self):
        """Get blocked IPs."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT ip_address, ban_reason as reason, ban_count as attempts, 
                       status, created_at
                FROM ip_bans 
                WHERE status = 'active'
                ORDER BY created_at DESC 
                LIMIT 15
            """)
            
            blocked_ips = []
            for row in cursor.fetchall():
                blocked_ips.append({
                    'ip_address': row[0],
                    'reason': row[1],
                    'attempts': row[2],
                    'status': row[3],
                    'created_at': row[4]
                })
            
            conn.close()
            
            return {'success': True, 'data': blocked_ips}
            
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': []}
    
    def _get_recent_events(self):
        """Get recent security events."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT event_type, source_ip as ip_address, severity, 
                       description, timestamp as created_at
                FROM security_events 
                ORDER BY timestamp DESC 
                LIMIT 30
            """)
            
            events = []
            for row in cursor.fetchall():
                events.append({
                    'event_type': row[0],
                    'ip_address': row[1],
                    'severity': row[2],
                    'description': row[3],
                    'created_at': row[4]
                })
            
            conn.close()
            
            return {'success': True, 'data': events}
            
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': []}
    
    def run(self):
        """Run the dashboard server."""
        print("🛡️  RotaryShield Dashboard - Phase 2 Complete")
        print("🚀 Enterprise-grade Real-time Security Monitoring")
        print("="*65)
        print(f"📁 Database: {self.db_path}")
        print(f"🌐 Dashboard URL: http://127.0.0.1:8082")
        print(f"📊 Features: Live attack data, IP bans, security events")
        print()
        print("🎯 Dashboard includes:")
        print("   • Real-time statistics with auto-refresh")
        print("   • Top attacking IPs with threat levels")
        print("   • Currently blocked IPs and reasons")
        print("   • Recent security events feed")
        print("   • Responsive design for all devices")
        print()
        print("Press Ctrl+C to stop the dashboard")
        print("="*65)
        
        # Use built-in Flask server (simpler and more reliable)
        self.app.run(
            host='127.0.0.1',
            port=8082,
            debug=False,
            use_reloader=False,
            threaded=True
        )

def main():
    """Main function."""
    db_path = Path(__file__).parent / "rotaryshield_live.db"
    
    if not db_path.exists():
        print("❌ Live database not found!")
        print("💡 First run: python run_live_monitoring.py")
        return 1
    
    dashboard = RotaryShieldDashboard(str(db_path))
    
    try:
        dashboard.run()
    except KeyboardInterrupt:
        print("\n\n🛑 Dashboard stopped by user")
        print("✅ RotaryShield Dashboard shutdown complete")
        return 0
    except Exception as e:
        print(f"\n❌ Dashboard error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())