#!/usr/bin/env python3
"""
RotaryShield Live Monitoring Runner

This script starts the live monitoring service that detects real attacks
from system logs and updates the dashboard in real-time.
"""

import sys
import time
import threading
import signal
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from rotaryshield.monitor_service import RotaryShieldMonitorService
import logging

# Global monitoring service
monitor_service = None

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global monitor_service
    print(f"\n🛑 Received shutdown signal ({signum})")
    if monitor_service:
        print("🔄 Stopping monitoring service...")
        monitor_service.stop()
    print("✅ Shutdown complete")
    sys.exit(0)

def main():
    """Main function to run live monitoring."""
    global monitor_service
    
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('rotaryshield_monitor.log')
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        print("🛡️  RotaryShield LIVE Monitoring System")
        print("🔥 Real-time Attack Detection & Response")
        print("="*70)
        
        # Use live database for real-time monitoring
        db_path = Path(__file__).parent / "rotaryshield_live.db"
        
        print(f"📁 Database: {db_path}")
        print(f"🎯 Monitoring system logs for real attacks...")
        print(f"📊 Dashboard: http://127.0.0.1:8082")
        print()
        
        # Initialize and start monitoring service
        logger.info("Initializing RotaryShield Live Monitor")
        monitor_service = RotaryShieldMonitorService(str(db_path))
        monitor_service.initialize()
        
        # Start monitoring
        logger.info("Starting live attack detection")
        monitor_service.start()
        
        print("🎯 RotaryShield is now monitoring for LIVE attacks!")
        print("📈 Events will be logged to database in real-time")
        print("🌐 Dashboard will show live data automatically")
        print()
        print("🧪 Demonstration: Adding some test attacks...")
        
        # Add demonstration attacks
        time.sleep(2)
        
        # Simulate SSH brute force
        print("   🚨 Simulating SSH brute force attack...")
        for i in range(6):  # Will trigger ban after 5 attempts
            monitor_service.add_test_attack("203.0.113.100", "ssh_failed_password")
            time.sleep(0.5)
        
        # Simulate web attacks
        print("   🚨 Simulating web admin scanning...")
        for i in range(3):
            monitor_service.add_test_attack("198.51.100.200", "web_admin_scan")
            time.sleep(0.5)
        
        # Simulate SQL injection
        print("   🚨 Simulating SQL injection attacks...")
        for i in range(4):  # Will trigger ban after 3 attempts
            monitor_service.add_test_attack("172.16.0.150", "web_sql_injection")
            time.sleep(0.5)
        
        print()
        print("✅ Test attacks completed! Check dashboard for live updates.")
        print("🔥 Service continues monitoring for REAL attacks...")
        print("⚠️  Press Ctrl+C to stop monitoring")
        print("="*70)
        
        # Keep service running and show periodic stats
        last_stats_time = time.time()
        
        while monitor_service._running:
            current_time = time.time()
            
            # Show stats every 30 seconds
            if current_time - last_stats_time > 30:
                stats = monitor_service.get_statistics()
                print(f"\n📊 Status Update:")
                print(f"   • Total events detected: {stats['total_events']}")
                print(f"   • Events last hour: {stats['events_last_hour']}")
                print(f"   • Blocked IPs: {stats['blocked_ips']}")
                print(f"   • Active bans: {stats['banned_ips_count']}")
                print(f"   • Monitored log files: {stats['monitored_files']}")
                last_stats_time = current_time
            
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user...")
    except Exception as e:
        logger.error(f"❌ Critical error: {e}")
        print(f"❌ Service error: {e}")
    finally:
        if monitor_service:
            print("🔄 Cleaning up monitoring service...")
            monitor_service.stop()
        print("✅ RotaryShield Live Monitoring stopped")

if __name__ == "__main__":
    main()