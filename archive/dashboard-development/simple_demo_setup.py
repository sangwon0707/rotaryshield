#!/usr/bin/env python3
"""
Simple RotaryShield Dashboard Demo Setup

Creates test data directly with SQLite for dashboard demonstration.
"""

import sqlite3
import random
import json
from datetime import datetime, timedelta
from pathlib import Path

def setup_demo_database():
    """Create database with realistic test data."""
    print("🛡️  RotaryShield Dashboard Demo Setup")
    print("🚀 Creating realistic test data for visualization")
    print("="*60)
    
    # Create database
    db_path = Path(__file__).parent / "rotaryshield_demo.db"
    print(f"📁 Database: {db_path}")
    
    # Remove existing database
    if db_path.exists():
        db_path.unlink()
        print("🗑️  Removed existing database")
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    try:
        # Create tables
        print("🔧 Creating database tables...")
        
        # Banned IPs table (matching expected schema)
        cursor.execute("""
            CREATE TABLE banned_ips (
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
        
        # Security events table
        cursor.execute("""
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                metadata TEXT DEFAULT '{}',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Audit logs table
        cursor.execute("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        print("✅ Database tables created")
        
        # Create realistic test data
        print("📊 Generating realistic test data...")
        
        # Attack IPs from different countries/sources
        attack_ips = [
            "192.168.1.100", "10.0.0.25", "172.16.0.50", "203.0.113.15",
            "198.51.100.42", "192.0.2.100", "185.220.100.240", "95.211.198.69",
            "159.89.49.60", "46.101.166.19", "159.203.176.62", "198.199.64.217",
            "134.209.24.42", "167.71.13.196", "68.183.61.125", "143.198.156.27",
            "165.227.88.15", "178.128.83.165", "64.227.67.81", "128.199.202.122"
        ]
        
        attack_types = [
            ("ssh_fail", "SSH brute force attempt", "HIGH"),
            ("http_scan", "HTTP vulnerability scan", "MEDIUM"),
            ("port_scan", "Port scanning activity", "MEDIUM"),
            ("brute_force", "Login brute force attack", "HIGH"),
            ("web_exploit", "Web application exploit attempt", "HIGH"),
            ("dos_attempt", "Denial of service attempt", "CRITICAL"),
            ("malware_drop", "Malware download attempt", "CRITICAL"),
            ("data_exfil", "Data exfiltration attempt", "CRITICAL"),
            ("sql_injection", "SQL injection attempt", "HIGH"),
            ("xss_attempt", "Cross-site scripting attempt", "MEDIUM")
        ]
        
        # Generate security events over last 24 hours
        now = datetime.now()
        events_created = 0
        
        for hour in range(24):
            # More attacks during business hours
            if 9 <= hour <= 18:
                events_per_hour = random.randint(12, 25)
            elif 22 <= hour <= 6:  # Night time
                events_per_hour = random.randint(3, 8)
            else:
                events_per_hour = random.randint(6, 15)
            
            for _ in range(events_per_hour):
                event_time = now - timedelta(
                    hours=23-hour,
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59)
                )
                
                attack_type, base_desc, severity = random.choice(attack_types)
                ip_address = random.choice(attack_ips)
                
                descriptions = [
                    f"{base_desc} from {ip_address}",
                    f"Multiple {base_desc.lower()} detected",
                    f"Persistent {base_desc.lower()} - escalating response",
                    f"Automated {base_desc.lower()} blocked",
                    f"High-volume {base_desc.lower()} detected",
                    f"Suspicious {base_desc.lower()} pattern"
                ]
                
                cursor.execute("""
                    INSERT INTO security_events 
                    (event_type, ip_address, severity, description, metadata, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    attack_type,
                    ip_address,
                    severity,
                    random.choice(descriptions),
                    json.dumps({"source": "rotaryshield", "confidence": random.uniform(0.8, 1.0)}),
                    event_time.isoformat()
                ))
                events_created += 1
        
        print(f"✅ Created {events_created} security events")
        
        # Create banned IPs (select high-activity attackers)
        banned_ips = random.sample(attack_ips, 12)
        
        ban_reasons = [
            "SSH brute force - 15+ failed attempts",
            "HTTP vulnerability scanning - automated probe",
            "Port scanning - systematic enumeration", 
            "Login brute force - credential stuffing",
            "Web exploit attempts - SQL injection",
            "DoS attack - excessive requests",
            "Malware distribution detected",
            "Data exfiltration attempt",
            "Multiple attack vectors detected",
            "Persistent unauthorized access attempts"
        ]
        
        bans_created = 0
        for ip in banned_ips:
            attempts = random.randint(8, 35)
            reason = random.choice(ban_reasons)
            ban_time = now - timedelta(hours=random.randint(1, 18))
            
            cursor.execute("""
                INSERT INTO banned_ips 
                (ip_address, reason, attempts, status, ban_time, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                reason,
                attempts,
                'active',
                3600,  # 1 hour ban duration
                ban_time.isoformat(),
                ban_time.isoformat()
            ))
            bans_created += 1
        
        print(f"✅ Created {bans_created} active IP bans")
        
        # Create audit logs
        audit_actions = [
            "IP_BANNED", "IP_UNBANNED", "CONFIG_UPDATED",
            "SERVICE_STARTED", "SERVICE_STOPPED", "PATTERN_ADDED",
            "THRESHOLD_UPDATED", "FIREWALL_RULE_ADDED"
        ]
        
        audit_created = 0
        for _ in range(30):
            action = random.choice(audit_actions)
            ip = random.choice(attack_ips) if "IP_" in action else None
            log_time = now - timedelta(hours=random.randint(1, 48))
            
            cursor.execute("""
                INSERT INTO audit_logs 
                (action, ip_address, details, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                action,
                ip,
                f"Automated {action.lower().replace('_', ' ')} by RotaryShield",
                log_time.isoformat()
            ))
            audit_created += 1
        
        print(f"✅ Created {audit_created} audit log entries")
        
        conn.commit()
        
        # Display summary
        print("\n" + "="*60)
        print("🎯 DASHBOARD DEMO DATA SUMMARY")
        print("="*60)
        
        # Events by type
        cursor.execute("""
            SELECT event_type, COUNT(*) as count 
            FROM security_events 
            GROUP BY event_type 
            ORDER BY count DESC
        """)
        print("\n📊 Security Events by Type:")
        for event_type, count in cursor.fetchall():
            print(f"   {event_type}: {count} events")
        
        # Top attackers
        cursor.execute("""
            SELECT ip_address, COUNT(*) as attempts 
            FROM security_events 
            GROUP BY ip_address 
            ORDER BY attempts DESC 
            LIMIT 8
        """)
        print("\n🎯 Top Attacking IPs:")
        for ip, attempts in cursor.fetchall():
            print(f"   {ip}: {attempts} attempts")
        
        # Hourly distribution
        cursor.execute("""
            SELECT strftime('%H', created_at) as hour, COUNT(*) as count
            FROM security_events 
            GROUP BY hour 
            ORDER BY hour
        """)
        print("\n⏰ Events by Hour:")
        hourly_data = cursor.fetchall()
        for hour, count in hourly_data[:12]:  # Show first 12 hours
            bar = "█" * min(count // 2, 20)  # Simple bar chart
            print(f"   {hour}:00 │{bar} {count}")
        
        print("\n" + "="*60)
        print("✅ DASHBOARD DEMO SETUP COMPLETE!")
        print(f"\n📁 Database created: {db_path}")
        print(f"📊 Total events: {events_created}")
        print(f"🚫 Active bans: {bans_created}")
        print(f"📝 Audit logs: {audit_created}")
        print("\n🚀 Ready to launch dashboard!")
        print("="*60)
        
        return str(db_path)
        
    except Exception as e:
        print(f"❌ Error creating demo data: {e}")
        return None
    
    finally:
        conn.close()

if __name__ == "__main__":
    setup_demo_database()