#!/usr/bin/env python3
"""
RotaryShield Live Monitoring Service

This service provides real-time log monitoring, attack detection, and database logging
for live security events. It integrates all components for full monitoring capability.
"""

import os
import sys
import time
import signal
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import uuid

# Add RotaryShield modules to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rotaryshield.monitoring.log_monitor import LogMonitor, LogEvent
from rotaryshield.monitoring.pattern_matcher import PatternMatcher
from rotaryshield.database.manager import DatabaseManager
from rotaryshield.database.models import SecurityEventRecord, EventSeverity, IPBanRecord, BanStatus
from rotaryshield.utils.logging import setup_logging


class RotaryShieldMonitorService:
    """
    Main monitoring service that coordinates live attack detection.
    
    This service monitors log files in real-time, detects attack patterns,
    stores events in database, and updates the dashboard dynamically.
    """
    
    # Default configuration
    DEFAULT_LOG_FILES = [
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/httpd/access_log',
        '/var/log/httpd/error_log',
    ]
    
    # Attack patterns (real patterns from security tools)
    ATTACK_PATTERNS = {
        # SSH Brute Force Detection
        'ssh_failed_password': r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
        'ssh_invalid_user': r'Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)',
        'ssh_connection_refused': r'Did not receive identification string from (\d+\.\d+\.\d+\.\d+)',
        'ssh_auth_failure': r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+).*user=(\w+)',
        
        # Web Attack Detection  
        'web_admin_scan': r'(\d+\.\d+\.\d+\.\d+).*\"(?:GET|POST).*(?:/admin|/wp-admin|/phpmyadmin|/administrator)',
        'web_file_discovery': r'(\d+\.\d+\.\d+\.\d+).*\"(?:GET|POST).*(?:\.env|config\.php|\.git|\.svn|backup)',
        'web_sql_injection': r'(\d+\.\d+\.\d+\.\d+).*\".*(?:UNION|SELECT.*FROM|OR 1=1|\' OR|\" OR)',
        'web_path_traversal': r'(\d+\.\d+\.\d+\.\d+).*\".*(?:\.\./|etc/passwd|etc/shadow|\.\.\\\\)',
        'web_webshell': r'(\d+\.\d+\.\d+\.\d+).*\".*(?:shell\.php|cmd\.php|webshell|c99\.php)',
        'web_xss_attempt': r'(\d+\.\d+\.\d+\.\d+).*\".*(?:<script|javascript:|onload=|onerror=)',
        
        # General Attack Patterns
        'brute_force_generic': r'(\d+\.\d+\.\d+\.\d+).*(?:brute.?force|dictionary.?attack)',
        'port_scan': r'(\d+\.\d+\.\d+\.\d+).*(?:port.?scan|nmap|masscan)',
        'dos_attack': r'(\d+\.\d+\.\d+\.\d+).*(?:denial.?of.?service|flood|dos.?attack)',
        
        # Web Server Error Patterns (potential attacks)
        'http_404_scan': r'(\d+\.\d+\.\d+\.\d+).*\" 404 ',
        'http_403_blocked': r'(\d+\.\d+\.\d+\.\d+).*\" 403 ',
        'http_500_exploit': r'(\d+\.\d+\.\d+\.\d+).*\" 500 ',
    }
    
    # IP blocking thresholds
    BLOCKING_THRESHOLDS = {
        'ssh_failed_password': 5,      # Block after 5 failed SSH attempts
        'ssh_invalid_user': 3,         # Block after 3 invalid user attempts  
        'web_admin_scan': 10,          # Block after 10 admin scans
        'web_sql_injection': 3,        # Block after 3 SQL injection attempts
        'web_path_traversal': 2,       # Block after 2 path traversal attempts
        'web_webshell': 1,             # Block immediately on webshell attempts
        'default': 15                  # Default threshold for other attacks
    }
    
    def __init__(self, db_path: str, log_files: Optional[List[str]] = None):
        """
        Initialize monitoring service.
        
        Args:
            db_path: Path to database file
            log_files: List of log files to monitor (uses defaults if None)
        """
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.log_files = log_files or self._get_available_log_files()
        
        # Components
        self.db_manager: Optional[DatabaseManager] = None
        self.log_monitor: Optional[LogMonitor] = None
        
        # Service state
        self._running = False
        self._stop_event = threading.Event()
        self._service_thread: Optional[threading.Thread] = None
        
        # Attack tracking
        self._ip_attack_counts: Dict[str, Dict[str, int]] = {}  # IP -> {attack_type: count}
        self._banned_ips: set = set()
        self._attack_stats = {
            'total_events': 0,
            'events_last_hour': 0,
            'blocked_ips': 0,
            'last_reset': time.time()
        }
        
        # Thread safety
        self._stats_lock = threading.Lock()
        
        self.logger.info(f"RotaryShield Monitor Service initialized")
        self.logger.info(f"Database: {db_path}")
        self.logger.info(f"Monitoring {len(self.log_files)} log files")
    
    def _get_available_log_files(self) -> List[str]:
        """Get list of available log files on the system."""
        available_files = []
        
        # Check common log file locations
        for log_file in self.DEFAULT_LOG_FILES:
            if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                available_files.append(log_file)
                self.logger.info(f"Found log file: {log_file}")
        
        # For demo/testing, also check local test logs
        test_log_dir = Path(__file__).parent.parent.parent.parent / "test_logs"
        if test_log_dir.exists():
            for test_log in test_log_dir.glob("*.log"):
                if test_log.is_file():
                    available_files.append(str(test_log))
                    self.logger.info(f"Found test log file: {test_log}")
        
        if not available_files:
            self.logger.warning("No log files found! Creating test log for demonstration")
            # Create a test log file for demonstration
            test_log = Path(__file__).parent.parent.parent.parent / "live_monitor.log"
            test_log.touch()
            available_files.append(str(test_log))
        
        return available_files
    
    def initialize(self) -> None:
        """Initialize all service components."""
        try:
            self.logger.info("Initializing RotaryShield Monitor Service...")
            
            # Initialize database
            self.db_manager = DatabaseManager(self.db_path)
            self.db_manager.initialize()
            
            # Load existing banned IPs
            self._load_banned_ips()
            
            # Initialize log monitor with patterns
            self.log_monitor = LogMonitor(self.log_files, self.ATTACK_PATTERNS)
            self.log_monitor.set_event_callback(self._handle_security_event)
            self.log_monitor.initialize()
            
            self.logger.info("RotaryShield Monitor Service initialization complete")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize monitor service: {e}")
            raise
    
    def _load_banned_ips(self) -> None:
        """Load currently banned IPs from database."""
        try:
            with self.db_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ip_address FROM ip_bans 
                    WHERE status = 'active' AND expires_at > ?
                """, (time.time(),))
                
                for row in cursor.fetchall():
                    self._banned_ips.add(row[0])
                
                self.logger.info(f"Loaded {len(self._banned_ips)} active IP bans")
        
        except Exception as e:
            self.logger.error(f"Failed to load banned IPs: {e}")
    
    def start(self) -> None:
        """Start the monitoring service."""
        if self._running:
            self.logger.warning("Monitor service is already running")
            return
        
        try:
            self.logger.info("Starting RotaryShield Monitor Service...")
            
            # Start log monitoring
            self.log_monitor.start()
            
            # Start service thread for periodic tasks
            self._running = True
            self._stop_event.clear()
            self._service_thread = threading.Thread(
                target=self._service_loop,
                name="rotaryshield-service",
                daemon=True
            )
            self._service_thread.start()
            
            self.logger.info("🛡️  RotaryShield Monitor Service STARTED")
            self.logger.info("🎯 Live attack detection and blocking enabled")
        
        except Exception as e:
            self.logger.error(f"Failed to start monitor service: {e}")
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop the monitoring service."""
        if not self._running:
            return
        
        self.logger.info("Stopping RotaryShield Monitor Service...")
        
        # Signal stop
        self._running = False
        self._stop_event.set()
        
        # Stop log monitor
        if self.log_monitor:
            self.log_monitor.stop()
        
        # Wait for service thread
        if self._service_thread and self._service_thread.is_alive():
            self._service_thread.join(timeout=5)
        
        self.logger.info("RotaryShield Monitor Service stopped")
    
    def _service_loop(self) -> None:
        """Main service loop for periodic tasks."""
        while self._running and not self._stop_event.is_set():
            try:
                # Clean up expired bans
                self._cleanup_expired_bans()
                
                # Update statistics
                self._update_stats()
                
                # Sleep for 60 seconds between cycles
                self._stop_event.wait(60)
                
            except Exception as e:
                self.logger.error(f"Error in service loop: {e}")
                time.sleep(10)  # Brief pause on error
    
    def _handle_security_event(self, event: LogEvent) -> None:
        """
        Handle detected security event.
        
        Args:
            event: Log event with pattern match
        """
        try:
            # Extract IP address from matched groups
            ip_address = self._extract_ip_from_event(event)
            if not ip_address:
                return
            
            # Skip if IP is already banned
            if ip_address in self._banned_ips:
                return
            
            # Determine event type and severity
            event_type, severity = self._classify_event(event.pattern_name)
            
            # Store security event in database
            event_id = self._store_security_event(event, ip_address, event_type, severity)
            
            # Track attack count for this IP
            self._track_ip_attack(ip_address, event.pattern_name)
            
            # Check if IP should be banned
            self._check_and_ban_ip(ip_address, event.pattern_name)
            
            # Update statistics
            with self._stats_lock:
                self._attack_stats['total_events'] += 1
                self._attack_stats['events_last_hour'] += 1
            
            self.logger.info(
                f"🚨 ATTACK DETECTED: {event_type} from {ip_address} "
                f"(pattern: {event.pattern_name})"
            )
        
        except Exception as e:
            self.logger.error(f"Error handling security event: {e}")
    
    def _extract_ip_from_event(self, event: LogEvent) -> Optional[str]:
        """Extract IP address from event matched groups."""
        if not event.matched_groups:
            return None
        
        # Look for IP address in matched groups
        for group in event.matched_groups:
            if self._is_valid_ip(group):
                return group
        
        return None
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _classify_event(self, pattern_name: str) -> tuple:
        """Classify event type and severity based on pattern name."""
        if 'ssh' in pattern_name:
            return 'SSH_BRUTE_FORCE', EventSeverity.HIGH
        elif 'sql_injection' in pattern_name:
            return 'SQL_INJECTION', EventSeverity.CRITICAL
        elif 'webshell' in pattern_name:
            return 'WEBSHELL', EventSeverity.CRITICAL
        elif 'path_traversal' in pattern_name:
            return 'PATH_TRAVERSAL', EventSeverity.HIGH
        elif 'admin_scan' in pattern_name:
            return 'ADMIN_SCAN', EventSeverity.MEDIUM
        elif 'xss' in pattern_name:
            return 'XSS_ATTEMPT', EventSeverity.MEDIUM
        elif 'brute_force' in pattern_name:
            return 'BRUTE_FORCE', EventSeverity.HIGH
        elif 'port_scan' in pattern_name:
            return 'PORT_SCAN', EventSeverity.MEDIUM
        elif 'dos' in pattern_name:
            return 'DOS_ATTACK', EventSeverity.HIGH
        else:
            return 'SECURITY_EVENT', EventSeverity.MEDIUM
    
    def _store_security_event(self, event: LogEvent, ip_address: str, 
                            event_type: str, severity: EventSeverity) -> str:
        """Store security event in database."""
        try:
            event_id = str(uuid.uuid4())
            current_time = time.time()
            
            with self.db_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO security_events (
                        event_id, event_type, severity, timestamp, processed_at,
                        source_ip, description, raw_log_data, pattern_matched,
                        detection_source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id,
                    event_type,
                    severity.value,
                    event.timestamp,
                    current_time,
                    ip_address,
                    f"{event_type} detected from {ip_address}",
                    event.log_line[:1000],  # Truncate long log lines
                    event.pattern_name,
                    f"{Path(event.log_file).name}:{event.line_number}"
                ))
                conn.commit()
            
            return event_id
        
        except Exception as e:
            self.logger.error(f"Failed to store security event: {e}")
            return ""
    
    def _track_ip_attack(self, ip_address: str, pattern_name: str) -> None:
        """Track attack count for IP address."""
        if ip_address not in self._ip_attack_counts:
            self._ip_attack_counts[ip_address] = {}
        
        if pattern_name not in self._ip_attack_counts[ip_address]:
            self._ip_attack_counts[ip_address][pattern_name] = 0
        
        self._ip_attack_counts[ip_address][pattern_name] += 1
    
    def _check_and_ban_ip(self, ip_address: str, pattern_name: str) -> None:
        """Check if IP should be banned based on attack count."""
        if ip_address in self._banned_ips:
            return
        
        # Get attack count for this pattern
        attack_count = self._ip_attack_counts.get(ip_address, {}).get(pattern_name, 0)
        
        # Get threshold for this pattern
        threshold = self.BLOCKING_THRESHOLDS.get(pattern_name, self.BLOCKING_THRESHOLDS['default'])
        
        # Check if threshold exceeded
        if attack_count >= threshold:
            self._ban_ip(ip_address, pattern_name, attack_count)
    
    def _ban_ip(self, ip_address: str, reason_pattern: str, attack_count: int) -> None:
        """Ban an IP address."""
        try:
            current_time = time.time()
            ban_duration = 3600  # 1 hour ban
            expires_at = current_time + ban_duration
            
            # Create ban reason
            event_type, _ = self._classify_event(reason_pattern)
            ban_reason = f"{event_type} - {attack_count} attacks detected"
            
            with self.db_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO ip_bans (
                        ip_address, ban_reason, ban_duration, created_at, 
                        expires_at, updated_at, status, ban_count, last_offense_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip_address,
                    ban_reason,
                    ban_duration,
                    current_time,
                    expires_at,
                    current_time,
                    BanStatus.ACTIVE.value,
                    attack_count,
                    event_type
                ))
                conn.commit()
            
            # Add to banned set
            self._banned_ips.add(ip_address)
            
            # Update statistics
            with self._stats_lock:
                self._attack_stats['blocked_ips'] += 1
            
            self.logger.warning(
                f"🚫 IP BANNED: {ip_address} - {ban_reason} "
                f"(duration: {ban_duration//60} minutes)"
            )
        
        except Exception as e:
            self.logger.error(f"Failed to ban IP {ip_address}: {e}")
    
    def _cleanup_expired_bans(self) -> None:
        """Clean up expired IP bans."""
        try:
            current_time = time.time()
            
            with self.db_manager._get_connection() as conn:
                cursor = conn.cursor()
                
                # Find expired bans
                cursor.execute("""
                    SELECT ip_address FROM ip_bans 
                    WHERE status = 'active' AND expires_at <= ?
                """, (current_time,))
                
                expired_ips = [row[0] for row in cursor.fetchall()]
                
                if expired_ips:
                    # Update status to expired
                    cursor.executemany("""
                        UPDATE ip_bans 
                        SET status = 'expired', updated_at = ? 
                        WHERE ip_address = ? AND status = 'active'
                    """, [(current_time, ip) for ip in expired_ips])
                    
                    conn.commit()
                    
                    # Remove from banned set
                    for ip in expired_ips:
                        self._banned_ips.discard(ip)
                    
                    self.logger.info(f"Expired {len(expired_ips)} IP bans")
        
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired bans: {e}")
    
    def _update_stats(self) -> None:
        """Update service statistics."""
        try:
            current_time = time.time()
            
            with self._stats_lock:
                # Reset hourly counter if needed
                if current_time - self._attack_stats['last_reset'] > 3600:  # 1 hour
                    self._attack_stats['events_last_hour'] = 0
                    self._attack_stats['last_reset'] = current_time
        
        except Exception as e:
            self.logger.error(f"Failed to update stats: {e}")
    
    def get_statistics(self) -> Dict[str, any]:
        """Get service statistics."""
        with self._stats_lock:
            stats = self._attack_stats.copy()
        
        # Add component statistics
        stats.update({
            'is_running': self._running,
            'monitored_files': len(self.log_files),
            'banned_ips_count': len(self._banned_ips),
            'tracked_ips': len(self._ip_attack_counts),
        })
        
        if self.log_monitor:
            stats['log_monitor'] = self.log_monitor.get_statistics()
        
        return stats
    
    def add_test_attack(self, ip_address: str = "192.168.1.100", 
                       attack_type: str = "ssh_failed_password") -> None:
        """
        Add a test attack for demonstration purposes.
        
        Args:
            ip_address: IP to simulate attack from
            attack_type: Type of attack to simulate
        """
        # Create fake log event
        test_log_line = f"Jul 30 23:45:01 server sshd[12345]: Failed password for root from {ip_address} port 22 ssh2"
        
        fake_event = LogEvent(
            log_file="test_log",
            line_number=1,
            log_line=test_log_line,
            timestamp=time.time(),
            pattern_name=attack_type,
            matched_groups=[ip_address]
        )
        
        # Process as if it were a real attack
        self._handle_security_event(fake_event)
        
        self.logger.info(f"🧪 TEST ATTACK: Simulated {attack_type} from {ip_address}")


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    global monitor_service
    print(f"\n🛑 Received signal {signum}, shutting down...")
    if monitor_service:
        monitor_service.stop()
    sys.exit(0)


# Global variable for signal handler
monitor_service: Optional[RotaryShieldMonitorService] = None


def main():
    """Main function to run the monitoring service."""
    global monitor_service
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Database path - use live database
        db_path = Path(__file__).parent.parent.parent.parent / "rotaryshield_live.db"
        
        # Initialize service
        logger.info("🛡️  Starting RotaryShield Live Monitoring Service")
        logger.info("="*60)
        
        monitor_service = RotaryShieldMonitorService(str(db_path))
        monitor_service.initialize()
        monitor_service.start()
        
        logger.info("🎯 RotaryShield is now monitoring for live attacks!")
        logger.info("📊 Dashboard will show real-time data at: http://127.0.0.1:8082")
        logger.info("🔥 Press Ctrl+C to stop monitoring")
        logger.info("="*60)
        
        # Add some test attacks to demonstrate functionality
        logger.info("🧪 Adding test attacks for demonstration...")
        time.sleep(2)
        monitor_service.add_test_attack("192.168.1.100", "ssh_failed_password")
        time.sleep(1)
        monitor_service.add_test_attack("10.0.0.25", "ssh_failed_password") 
        time.sleep(1)
        monitor_service.add_test_attack("192.168.1.50", "web_admin_scan")
        
        # Keep service running
        while monitor_service._running:
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("\n🛑 Shutdown requested...")
    except Exception as e:
        logger.error(f"❌ Service error: {e}")
    finally:
        if monitor_service:
            monitor_service.stop()
        logger.info("✅ RotaryShield Monitor Service shutdown complete")


if __name__ == "__main__":
    main()