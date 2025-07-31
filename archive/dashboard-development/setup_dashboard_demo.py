#!/usr/bin/env python3
"""
RotaryShield Dashboard Demo Setup

This script sets up the database and creates realistic test data
for demonstrating the web dashboard on MacOS.
"""

import sys
import sqlite3
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / "src"))

try:
    from rotaryshield.database.manager import DatabaseManager
    from rotaryshield.database.models import BanStatus, EventSeverity
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're in the RotaryShield directory")
    sys.exit(1)

class DashboardDemoSetup:
    """Setup realistic test data for dashboard demonstration."""
    
    def __init__(self):
        # Create database in current directory for demo
        db_path = Path(__file__).parent / "rotaryshield_demo.db"
        self.db_manager = DatabaseManager(str(db_path))
        
        # Realistic attack patterns
        self.attack_ips = [
            "192.168.1.100", "10.0.0.25", "172.16.0.50", "203.0.113.15",
            "198.51.100.42", "192.0.2.100", "185.220.100.240", "95.211.198.69",
            "159.89.49.60", "46.101.166.19", "159.203.176.62", "198.199.64.217",
            "134.209.24.42", "167.71.13.196", "68.183.61.125", "143.198.156.27"
        ]
        
        self.attack_types = [
            ("ssh_fail", "SSH brute force attempt", EventSeverity.HIGH),
            ("http_scan", "HTTP vulnerability scan", EventSeverity.MEDIUM),
            ("port_scan", "Port scanning activity", EventSeverity.MEDIUM),
            ("brute_force", "Login brute force attack", EventSeverity.HIGH),
            ("web_exploit", "Web application exploit attempt", EventSeverity.HIGH),
            ("dos_attempt", "Denial of service attempt", EventSeverity.CRITICAL),
            ("malware_drop", "Malware download attempt", EventSeverity.CRITICAL),
            ("data_exfil", "Data exfiltration attempt", EventSeverity.CRITICAL)
        ]
        
        self.ban_reasons = [
            "SSH brute force - 15 failed attempts",
            "HTTP scanning - automated vulnerability probe",
            "Port scanning - systematic port enumeration",
            "Login brute force - credential stuffing attack",
            "Web exploit - SQL injection attempt",
            "DoS attack - excessive connection requests",
            "Malware distribution - hosting malicious files",
            "Data breach - unauthorized access attempt"
        ]
    
    def setup_database(self):
        """Initialize the database with proper schema."""
        print("🔧 Setting up database schema...")
        
        try:
            # Database initialization is handled by DatabaseManager
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Verify tables exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                required_tables = ['banned_ips', 'security_events', 'audit_logs']
                missing_tables = [t for t in required_tables if t not in tables]
                
                if missing_tables:
                    print(f"⚠️  Missing tables: {missing_tables}")
                    print("📋 Creating database tables...")
                    
                    # Create tables if they don't exist
                    self._create_tables(conn)
                
                print("✅ Database schema ready")
                return True
                
        except Exception as e:
            print(f"❌ Database setup failed: {e}")
            return False
    
    def _create_tables(self, conn):
        """Create necessary database tables."""
        cursor = conn.cursor()
        
        # Create banned_ips table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT NOT NULL,
                ban_time INTEGER DEFAULT 3600,
                unban_time TEXT,
                attempts INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create security_events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                metadata TEXT DEFAULT '{}',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create audit_logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
    
    def create_test_data(self):
        """Create realistic test data for dashboard demonstration."""
        print("📊 Creating test attack data...")
        
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Clear existing test data
                cursor.execute("DELETE FROM banned_ips")
                cursor.execute("DELETE FROM security_events")
                cursor.execute("DELETE FROM audit_logs")
                
                # Create security events (last 24 hours)
                self._create_security_events(cursor)
                
                # Create banned IPs
                self._create_banned_ips(cursor)
                
                # Create audit logs
                self._create_audit_logs(cursor)
                
                conn.commit()
                
                # Show summary
                cursor.execute("SELECT COUNT(*) FROM security_events")
                events_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM banned_ips WHERE status = ?", (BanStatus.ACTIVE.value,))
                banned_count = cursor.fetchone()[0]
                
                print(f"✅ Created {events_count} security events")
                print(f"✅ Created {banned_count} active IP bans")
                print("🎯 Test data ready for dashboard visualization!")
                
                return True
                
        except Exception as e:
            print(f"❌ Test data creation failed: {e}")
            return False
    
    def _create_security_events(self, cursor):
        """Create realistic security events over the last 24 hours."""
        now = datetime.now()
        
        # Create events with realistic time distribution
        for hour in range(24):
            # More attacks during business hours (9 AM - 6 PM)
            if 9 <= hour <= 18:
                events_per_hour = random.randint(8, 15)
            else:
                events_per_hour = random.randint(2, 8)
            
            for _ in range(events_per_hour):
                # Random time within the hour
                event_time = now - timedelta(hours=23-hour, 
                                           minutes=random.randint(0, 59),
                                           seconds=random.randint(0, 59))
                
                # Select random attack
                attack_type, description, severity = random.choice(self.attack_types)
                ip_address = random.choice(self.attack_ips)
                
                # Add some variation to descriptions
                descriptions = [
                    f"{description} from {ip_address}",
                    f"Multiple {description.lower()} detected",
                    f"Persistent {description.lower()} - escalating response",
                    f"Automated {description.lower()} blocked"
                ]
                
                cursor.execute("""
                    INSERT INTO security_events 
                    (event_type, ip_address, severity, description, metadata, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    attack_type,
                    ip_address, 
                    severity.value,
                    random.choice(descriptions),
                    '{"source": "test_data", "confidence": 0.95}',
                    event_time.isoformat()
                ))
    
    def _create_banned_ips(self, cursor):
        """Create realistic banned IP entries."""
        # Select some IPs that had many events
        high_activity_ips = random.sample(self.attack_ips, 8)
        
        for ip in high_activity_ips:
            attempts = random.randint(5, 25)
            reason = random.choice(self.ban_reasons)
            
            # Some IPs banned recently, others hours ago
            ban_time = datetime.now() - timedelta(hours=random.randint(1, 12))
            
            cursor.execute("""
                INSERT INTO banned_ips 
                (ip_address, reason, attempts, status, ban_time, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                reason,
                attempts,
                BanStatus.ACTIVE.value,
                3600,  # 1 hour ban
                ban_time.isoformat(),
                ban_time.isoformat()
            ))
    
    def _create_audit_logs(self, cursor):
        """Create audit log entries."""
        actions = [
            "IP_BANNED", "IP_UNBANNED", "CONFIG_UPDATED", 
            "SERVICE_STARTED", "SERVICE_STOPPED", "PATTERN_ADDED"
        ]
        
        for _ in range(20):
            action = random.choice(actions)
            ip = random.choice(self.attack_ips) if "IP_" in action else None
            log_time = datetime.now() - timedelta(hours=random.randint(1, 24))
            
            cursor.execute("""
                INSERT INTO audit_logs 
                (action, ip_address, details, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                action,
                ip,
                f"Automated {action.lower().replace('_', ' ')} action",
                log_time.isoformat()
            ))
    
    def display_summary(self):
        """Display a summary of the test data."""
        print("\n" + "="*60)
        print("🎯 DASHBOARD DEMO DATA SUMMARY")
        print("="*60)
        
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Security events by type
                cursor.execute("""
                    SELECT event_type, COUNT(*) as count 
                    FROM security_events 
                    GROUP BY event_type 
                    ORDER BY count DESC
                """)
                print("\n📊 Security Events by Type:")
                for event_type, count in cursor.fetchall():
                    print(f"   {event_type}: {count} events")
                
                # Top attacking IPs
                cursor.execute("""
                    SELECT ip_address, COUNT(*) as attempts 
                    FROM security_events 
                    GROUP BY ip_address 
                    ORDER BY attempts DESC 
                    LIMIT 5
                """)
                print("\n🎯 Top Attacking IPs:")
                for ip, attempts in cursor.fetchall():
                    print(f"   {ip}: {attempts} attempts")
                
                # Recent bans
                cursor.execute("""
                    SELECT ip_address, reason, attempts 
                    FROM banned_ips 
                    WHERE status = ? 
                    ORDER BY created_at DESC 
                    LIMIT 5
                """, (BanStatus.ACTIVE.value,))
                print("\n🚫 Recent IP Bans:")
                for ip, reason, attempts in cursor.fetchall():
                    print(f"   {ip}: {reason[:40]}... ({attempts} attempts)")
                
        except Exception as e:
            print(f"❌ Summary display failed: {e}")

def main():
    """Main setup function."""
    print("🛡️  RotaryShield Dashboard Demo Setup")
    print("🚀 Creating realistic test data for visualization")
    print("="*60)
    
    setup = DashboardDemoSetup()
    
    # Setup database
    if not setup.setup_database():
        return 1
    
    # Create test data
    if not setup.create_test_data():
        return 1
    
    # Display summary
    setup.display_summary()
    
    print("\n" + "="*60)
    print("✅ DASHBOARD DEMO SETUP COMPLETE!")
    print("\n🚀 Next steps:")
    print("   1. Run: python -m rotaryshield.dashboard.server")
    print("   2. Open: http://127.0.0.1:8080")
    print("   3. Enjoy the real-time security dashboard!")
    print("="*60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())