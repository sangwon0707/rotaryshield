#!/usr/bin/env python3
"""
Simple RotaryShield Dashboard Server

Simplified version for MacOS demo with minimal dependencies.
"""

import sys
import json
import time
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, jsonify, request
from flask_socketio import SocketIO, emit

# HTML Template (embedded for simplicity)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RotaryShield Dashboard - Live Security Monitoring</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #ffffff; line-height: 1.6; min-height: 100vh;
        }
        .header { 
            background: rgba(26, 26, 46, 0.95); padding: 1rem 0; 
            border-bottom: 2px solid #0f3460; position: sticky; top: 0; z-index: 1000;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 0 20px; }
        .header-content { display: flex; justify-content: space-between; align-items: center; }
        .logo { display: flex; align-items: center; gap: 15px; }
        .logo h1 { font-size: 2rem; color: #00d4aa; margin: 0; }
        .subtitle { font-size: 0.9rem; color: #b0b0b0; }
        .status { display: flex; align-items: center; gap: 10px; }
        .status-dot { width: 12px; height: 12px; border-radius: 50%; background: #28a745; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        .main { padding: 2rem 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { 
            background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 1.5rem;
            border: 1px solid rgba(255, 255, 255, 0.1); position: relative; overflow: hidden;
            display: flex; align-items: center; gap: 1rem;
        }
        .stat-card::before { 
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
            background: linear-gradient(90deg, #00d4aa, #0099cc);
        }
        .stat-number { font-size: 2.5rem; font-weight: 700; color: #00d4aa; }
        .stat-label { font-size: 0.9rem; color: #b0b0b0; text-transform: uppercase; }
        
        .charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .chart-container { 
            background: rgba(255, 255, 255, 0.05); border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1); overflow: hidden;
        }
        .chart-header { 
            background: rgba(0, 0, 0, 0.2); padding: 1rem 1.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .chart-header h3 { font-size: 1.1rem; color: #00d4aa; }
        .chart-content { padding: 1.5rem; height: 300px; }
        
        .table-container { 
            background: rgba(255, 255, 255, 0.05); border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1); margin-bottom: 2rem;
        }
        .table-header { 
            background: rgba(0, 0, 0, 0.2); padding: 1rem 1.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .table-header h3 { color: #00d4aa; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 1rem; border-bottom: 1px solid rgba(255, 255, 255, 0.1); }
        th { background: rgba(0, 0, 0, 0.2); color: #00d4aa; }
        tr:hover { background: rgba(255, 255, 255, 0.05); }
        
        .footer { 
            background: rgba(26, 26, 46, 0.95); padding: 1rem 0;
            border-top: 2px solid #0f3460; margin-top: auto;
        }
        .footer-content { text-align: center; color: #b0b0b0; }
        
        @media (max-width: 768px) {
            .header-content { flex-direction: column; gap: 1rem; }
            .stats-grid, .charts-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="container">
            <div class="header-content">
                <div class="logo">
                    <h1>🛡️ RotaryShield</h1>
                    <div>
                        <div class="subtitle">Real-time Security Dashboard</div>
                        <div class="subtitle">Phase 2 Complete - Enterprise Ready</div>
                    </div>
                </div>
                <div class="status">
                    <div class="status-dot"></div>
                    <span>System Active</span>
                    <div style="margin-left: 15px; font-size: 0.8rem;">
                        Last Updated: <span id="last-update">--:--:--</span>
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
                    <div>
                        <div class="stat-number" id="active-bans">--</div>
                        <div class="stat-label">Active Bans</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div>
                        <div class="stat-number" id="events-24h">--</div>
                        <div class="stat-label">Events (24h)</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div>
                        <div class="stat-number" id="events-1h">--</div>
                        <div class="stat-label">Events (1h)</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div>
                        <div class="stat-number" id="total-bans">--</div>
                        <div class="stat-label">Total Bans</div>
                    </div>
                </div>
            </div>

            <!-- Charts -->
            <div class="charts-grid">
                <div class="chart-container">
                    <div class="chart-header">
                        <h3>📈 Attack Timeline (24h)</h3>
                    </div>
                    <div class="chart-content">
                        <canvas id="timeline-chart"></canvas>
                    </div>
                </div>
                <div class="chart-container">
                    <div class="chart-header">
                        <h3>🎯 Attack Types Distribution</h3>
                    </div>
                    <div class="chart-content">
                        <canvas id="attack-types-chart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Data Tables -->
            <div class="table-container">
                <div class="table-header">
                    <h3>🚫 Recently Blocked IPs</h3>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Attempts</th>
                            <th>Status</th>
                            <th>Blocked At</th>
                        </tr>
                    </thead>
                    <tbody id="blocked-ips-tbody">
                        <tr><td colspan="5" style="text-align: center;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="table-container">
                <div class="table-header">
                    <h3>📊 Recent Security Events</h3>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Type</th>
                            <th>IP Address</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody id="events-tbody">
                        <tr><td colspan="5" style="text-align: center;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <footer class="footer">
        <div class="container">
            <div class="footer-content">
                <p>RotaryShield Dashboard | Phase 2 Complete - Enterprise Ready | Real-time Security Monitoring</p>
            </div>
        </div>
    </footer>

    <script>
        // Dashboard JavaScript
        let socket;
        let charts = {};
        
        // Initialize dashboard
        function initDashboard() {
            console.log('🛡️ Initializing RotaryShield Dashboard...');
            
            // Initialize WebSocket
            socket = io();
            socket.on('connect', () => {
                console.log('✅ WebSocket connected');
                loadData();
            });
            
            socket.on('stats_update', updateStats);
            
            // Initialize charts
            initCharts();
            
            // Load initial data
            loadData();
            
            // Auto-refresh every 10 seconds
            setInterval(loadData, 10000);
        }
        
        // Initialize charts
        function initCharts() {
            // Timeline chart
            const timelineCtx = document.getElementById('timeline-chart');
            charts.timeline = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => i + ':00'),
                    datasets: [{
                        label: 'Security Events',
                        data: new Array(24).fill(0),
                        borderColor: '#00d4aa',
                        backgroundColor: '#00d4aa20',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#ffffff' } } },
                    scales: {
                        x: { ticks: { color: '#b0b0b0' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } },
                        y: { ticks: { color: '#b0b0b0' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } }
                    }
                }
            });
            
            // Attack types chart
            const attackTypesCtx = document.getElementById('attack-types-chart');
            charts.attackTypes = new Chart(attackTypesCtx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: ['#dc3545', '#ffc107', '#17a2b8', '#28a745', '#6f42c1', '#fd7e14']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#ffffff', padding: 15 }
                        }
                    }
                }
            });
        }
        
        // Load data from API
        async function loadData() {
            try {
                // Load stats
                const statsRes = await fetch('/api/stats');
                const statsData = await statsRes.json();
                if (statsData.success) {
                    updateStats(statsData.data);
                }
                
                // Load blocked IPs
                const blockedRes = await fetch('/api/blocked-ips');
                const blockedData = await blockedRes.json();
                if (blockedData.success) {
                    updateBlockedIPs(blockedData.data);
                }
                
                // Load recent events
                const eventsRes = await fetch('/api/recent-events');
                const eventsData = await eventsRes.json();
                if (eventsData.success) {
                    updateRecentEvents(eventsData.data);
                }
                
            } catch (error) {
                console.error('Error loading data:', error);
            }
        }
        
        // Update statistics
        function updateStats(data) {
            document.getElementById('active-bans').textContent = data.active_bans || 0;
            document.getElementById('events-24h').textContent = data.events_24h || 0;
            document.getElementById('events-1h').textContent = data.events_1h || 0;
            document.getElementById('total-bans').textContent = data.total_bans || 0;
            
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
            
            // Update charts
            if (data.hourly_trend && charts.timeline) {
                const hours = Array.from({length: 24}, (_, i) => i);
                const counts = new Array(24).fill(0);
                data.hourly_trend.forEach(item => {
                    if (item.hour >= 0 && item.hour < 24) {
                        counts[item.hour] = item.count;
                    }
                });
                charts.timeline.data.datasets[0].data = counts;
                charts.timeline.update('none');
            }
            
            if (data.attack_types && charts.attackTypes) {
                charts.attackTypes.data.labels = data.attack_types.map(item => item.type);
                charts.attackTypes.data.datasets[0].data = data.attack_types.map(item => item.count);
                charts.attackTypes.update('none');
            }
        }
        
        // Update blocked IPs table
        function updateBlockedIPs(data) {
            const tbody = document.getElementById('blocked-ips-tbody');
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No blocked IPs</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.slice(0, 10).map(ip => `
                <tr>
                    <td><strong>${ip.ip_address}</strong></td>
                    <td>${ip.reason}</td>
                    <td>${ip.attempts}</td>
                    <td style="color: #dc3545;">ACTIVE</td>
                    <td>${new Date(ip.created_at).toLocaleDateString()}</td>
                </tr>
            `).join('');
        }
        
        // Update recent events table
        function updateRecentEvents(data) {
            const tbody = document.getElementById('events-tbody');
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No recent events</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.slice(0, 15).map(event => `
                <tr>
                    <td>${new Date(event.created_at).toLocaleTimeString()}</td>
                    <td>${event.event_type}</td>
                    <td><strong>${event.ip_address}</strong></td>
                    <td style="color: ${getSeverityColor(event.severity)}">${event.severity}</td>
                    <td>${event.description}</td>
                </tr>
            `).join('');
        }
        
        function getSeverityColor(severity) {
            switch (severity) {
                case 'CRITICAL': return '#dc3545';
                case 'HIGH': return '#fd7e14';
                case 'MEDIUM': return '#ffc107';
                case 'LOW': return '#28a745';
                default: return '#ffffff';
            }
        }
        
        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', initDashboard);
    </script>
</body>
</html>
"""

class SimpleDashboard:
    """Simplified dashboard server for MacOS demo."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'demo-secret-key'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        self._setup_routes()
        self._setup_websocket()
    
    def _setup_routes(self):
        """Setup web routes."""
        
        @self.app.route('/')
        def dashboard():
            return render_template_string(DASHBOARD_HTML)
        
        @self.app.route('/api/stats')
        def api_stats():
            try:
                stats = self._get_stats()
                return jsonify({'success': True, 'data': stats})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/blocked-ips')
        def api_blocked_ips():
            try:
                blocked_ips = self._get_blocked_ips()
                return jsonify({'success': True, 'data': blocked_ips})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/recent-events')
        def api_recent_events():
            try:
                events = self._get_recent_events()
                return jsonify({'success': True, 'data': events})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
    
    def _setup_websocket(self):
        """Setup WebSocket handlers."""
        
        @self.socketio.on('connect')
        def handle_connect():
            print(f"📱 Dashboard client connected: {request.remote_addr}")
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            print(f"📱 Dashboard client disconnected")
    
    def _get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _get_stats(self):
        """Get dashboard statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Basic counts
            cursor.execute("SELECT COUNT(*) FROM banned_ips WHERE status = 'active'")
            active_bans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM banned_ips")
            total_bans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE created_at > datetime('now', '-24 hours')")
            events_24h = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE created_at > datetime('now', '-1 hour')")
            events_1h = cursor.fetchone()[0]
            
            # Hourly trend
            cursor.execute("""
                SELECT strftime('%H', created_at) as hour, COUNT(*) as count
                FROM security_events 
                WHERE created_at > datetime('now', '-24 hours')
                GROUP BY hour 
                ORDER BY hour
            """)
            hourly_trend = [{'hour': int(row[0]), 'count': row[1]} for row in cursor.fetchall()]
            
            # Attack types
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM security_events 
                WHERE created_at > datetime('now', '-24 hours')
                GROUP BY event_type 
                ORDER BY count DESC
            """)
            attack_types = [{'type': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            return {
                'active_bans': active_bans,
                'total_bans': total_bans,
                'events_24h': events_24h,
                'events_1h': events_1h,
                'hourly_trend': hourly_trend,
                'attack_types': attack_types,
                'system_status': 'active'
            }
        finally:
            conn.close()
    
    def _get_blocked_ips(self):
        """Get blocked IPs."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT ip_address, reason, attempts, status, created_at
                FROM banned_ips 
                WHERE status = 'active'
                ORDER BY created_at DESC 
                LIMIT 20
            """)
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def _get_recent_events(self):
        """Get recent security events."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT event_type, ip_address, severity, description, created_at
                FROM security_events 
                ORDER BY created_at DESC 
                LIMIT 50
            """)
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def run(self):
        """Run the dashboard server."""
        print("🚀 Starting RotaryShield Dashboard...")
        print(f"📊 Dashboard URL: http://127.0.0.1:8080")
        print("🎯 Features: Real-time stats, attack visualization, live data")
        print()
        print("Press Ctrl+C to stop")
        print("="*60)
        
        self.socketio.run(self.app, host='127.0.0.1', port=8080, debug=False, allow_unsafe_werkzeug=True)

def main():
    """Main function."""
    db_path = Path(__file__).parent / "rotaryshield_demo.db"
    
    if not db_path.exists():
        print("❌ Demo database not found!")
        print("💡 Run: python simple_demo_setup.py")
        return 1
    
    print("🛡️  RotaryShield Dashboard Demo")
    print("🚀 Phase 2 Complete - Real-time Security Monitoring")
    print("="*60)
    print(f"📁 Database: {db_path}")
    
    dashboard = SimpleDashboard(str(db_path))
    
    try:
        dashboard.run()
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped")
        return 0

if __name__ == "__main__":
    sys.exit(main())