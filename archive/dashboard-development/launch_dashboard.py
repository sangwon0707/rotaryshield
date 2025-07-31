#!/usr/bin/env python3
"""
Launch RotaryShield Dashboard with Demo Data

This script launches the web dashboard using our demo database
for testing on MacOS.
"""

import sys
import os
import time
import threading
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

try:
    from rotaryshield.dashboard.server import DashboardServer
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're in the RotaryShield directory")
    sys.exit(1)

def launch_dashboard():
    """Launch the dashboard with demo database."""
    print("🛡️  RotaryShield Dashboard Launcher")
    print("🚀 Phase 2 Complete - Real-time Security Monitoring")
    print("="*60)
    
    # Check if demo database exists
    db_path = Path(__file__).parent / "rotaryshield_demo.db"
    if not db_path.exists():
        print("❌ Demo database not found!")
        print("💡 Run: python simple_demo_setup.py")
        return 1
    
    print(f"📁 Using database: {db_path}")
    print(f"📊 Dashboard URL: http://127.0.0.1:8080")
    print(f"🎯 Features: Real-time stats, attack visualization, live updates")
    print()
    
    try:
        # Create custom dashboard server that uses our demo database
        class DemoDashboardServer(DashboardServer):
            def __init__(self):
                super().__init__(host="127.0.0.1", port=8080)
                # Override database manager to use our demo database
                from rotaryshield.database.manager import DatabaseManager
                self.db_manager = DatabaseManager(str(db_path))
                self.db_manager.initialize()  # Initialize the database
        
        print("🚀 Starting RotaryShield Dashboard...")
        print("📈 Loading real-time attack data and visualizations...")
        print()
        print("Dashboard Features:")
        print("  📊 Real-time Statistics - Active bans, event counts")
        print("  🎯 Attack Visualization - Charts showing attack patterns")
        print("  📋 Live Data Tables - Recent attacks and blocked IPs")
        print("  🔌 WebSocket Updates - Real-time data without refresh")
        print("  📱 Responsive Design - Works on all devices")
        print()
        print("Press Ctrl+C to stop the dashboard")
        print("="*60)
        
        # Create and run server
        dashboard = DemoDashboardServer()
        dashboard.run(debug=False)
        
    except KeyboardInterrupt:
        print("\n🛑 Dashboard shutdown requested")
        print("✅ RotaryShield Dashboard stopped")
        return 0
    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        print(f"💡 Check that Flask dependencies are installed")
        return 1

if __name__ == "__main__":
    sys.exit(launch_dashboard())