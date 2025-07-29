#!/usr/bin/env python3
"""
Unit tests for RotaryShield validators with security focus.
"""

import unittest
import ipaddress
import re
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from rotaryshield.utils.validators import (
    validate_ip_address,
    validate_port,
    sanitize_string,
    validate_file_path,
    validate_regex_pattern,
    validate_email,
    validate_hostname,
    validate_url,
    sanitize_filename,
    validate_json_string
)


class TestIPAddressValidation(unittest.TestCase):
    """Test IP address validation functionality."""
    
    def test_valid_ipv4_addresses(self):
        """Test valid IPv4 addresses."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "203.0.113.1",  # RFC5737 test address
            "8.8.8.8",
            "255.255.255.255"
        ]
        
        for ip in valid_ips:
            with self.subTest(ip=ip):
                is_valid, normalized, ip_obj = validate_ip_address(ip)
                self.assertTrue(is_valid, f"IP {ip} should be valid")
                self.assertEqual(normalized, ip)
                self.assertIsInstance(ip_obj, ipaddress.IPv4Address)
    
    def test_valid_ipv6_addresses(self):
        """Test valid IPv6 addresses."""
        valid_ips = [
            "2001:db8::1",
            "::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fe80::1%lo0"  # Link-local with zone
        ]
        
        for ip in valid_ips:
            with self.subTest(ip=ip):
                is_valid, normalized, ip_obj = validate_ip_address(ip)
                if ip == "fe80::1%lo0":
                    # Zone identifiers are not supported by ipaddress module
                    self.assertFalse(is_valid)
                else:
                    self.assertTrue(is_valid, f"IP {ip} should be valid")
                    self.assertIsInstance(ip_obj, ipaddress.IPv6Address)
    
    def test_invalid_ip_addresses(self):
        """Test invalid IP addresses."""
        invalid_ips = [
            "",
            "   ",
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "not.an.ip.address",
            "192.168.1.1/24",  # CIDR notation not allowed
            "localhost",
            "..1",
            None,
            123,
            []
        ]
        
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                is_valid, error, ip_obj = validate_ip_address(ip)
                self.assertFalse(is_valid, f"IP {ip} should be invalid")
                self.assertIsNone(ip_obj)
                self.assertIn("Invalid", error)
    
    def test_special_addresses(self):
        """Test special IP addresses that should be rejected."""
        special_addresses = [
            "127.0.0.1",  # Loopback - should be rejected
            "224.0.0.1",  # Multicast
            "255.255.255.255",  # Broadcast (might be allowed)
            "0.0.0.0"     # Unspecified
        ]
        
        # Loopback should be rejected
        is_valid, error, _ = validate_ip_address("127.0.0.1")
        self.assertFalse(is_valid)
        self.assertIn("loopback", error.lower())
        
        # Multicast should be rejected
        is_valid, error, _ = validate_ip_address("224.0.0.1")
        self.assertFalse(is_valid)
        self.assertIn("multicast", error.lower())
    
    def test_private_addresses(self):
        """Test private IP addresses (should be allowed with warning)."""
        private_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1"
        ]
        
        for ip in private_ips:
            with self.subTest(ip=ip):
                is_valid, normalized, ip_obj = validate_ip_address(ip)
                # Private IPs should be allowed
                self.assertTrue(is_valid)
                self.assertEqual(normalized, ip)


class TestPortValidation(unittest.TestCase):
    """Test port number validation."""
    
    def test_valid_ports(self):
        """Test valid port numbers."""
        valid_ports = [1, 22, 80, 443, 8080, 65535, "22", "443"]
        
        for port in valid_ports:
            with self.subTest(port=port):
                is_valid, error, port_num = validate_port(port)
                self.assertTrue(is_valid, f"Port {port} should be valid")
                self.assertEqual(error, "")
                self.assertIsInstance(port_num, int)
                self.assertGreaterEqual(port_num, 1)
                self.assertLessEqual(port_num, 65535)
    
    def test_invalid_ports(self):
        """Test invalid port numbers."""
        invalid_ports = [0, -1, 65536, 99999, "abc", "", None, [], {}]
        
        for port in invalid_ports:
            with self.subTest(port=port):
                is_valid, error, port_num = validate_port(port)
                self.assertFalse(is_valid, f"Port {port} should be invalid")
                self.assertNotEqual(error, "")
                self.assertIsNone(port_num)
    
    def test_edge_cases(self):
        """Test edge cases for port validation."""
        # String with whitespace
        is_valid, error, port_num = validate_port("  443  ")
        self.assertTrue(is_valid)
        self.assertEqual(port_num, 443)
        
        # Floating point (should fail)
        is_valid, error, port_num = validate_port(22.5)
        self.assertFalse(is_valid)


class TestStringSanitization(unittest.TestCase):
    """Test string sanitization functionality."""
    
    def test_basic_sanitization(self):
        """Test basic string sanitization."""
        test_cases = [
            ("normal text", "normal text"),
            ("", ""),
            ("text with\nnewlines", "text with\nnewlines"),  # With newlines allowed
            ("text\x00with\x01null", "textwithnull"),  # Control chars removed
            ("text with\ttabs", "text with\ttabs"),
        ]
        
        for input_str, expected in test_cases:
            with self.subTest(input=input_str):
                result = sanitize_string(input_str, allow_newlines=True)
                self.assertEqual(result, expected)
    
    def test_injection_prevention(self):
        """Test prevention of injection attacks."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "\x1b[31mRed text\x1b[0m",  # ANSI escape sequences
            "normal\x00\x01\x02\x03text",  # Null bytes and control chars
        ]
        
        for malicious in malicious_inputs:
            with self.subTest(input=malicious):
                result = sanitize_string(malicious)
                # Should not contain control characters
                self.assertNotIn('\x00', result)
                self.assertNotIn('\x01', result)
                # ANSI sequences should be removed
                self.assertNotIn('\x1b', result)
    
    def test_length_limits(self):
        """Test string length limiting."""
        long_string = "a" * 2000
        result = sanitize_string(long_string, max_length=100)
        self.assertLessEqual(len(result), 103)  # 100 + "..."
        self.assertTrue(result.endswith("..."))
    
    def test_special_characters(self):
        """Test handling of special characters."""
        # With special chars allowed
        text_with_special = "email@domain.com [info]"
        result = sanitize_string(text_with_special, allow_special_chars=True)
        self.assertIn("@", result)
        self.assertIn("[", result)
        
        # Without special chars allowed
        result = sanitize_string(text_with_special, allow_special_chars=False)
        self.assertIn("email", result)
        self.assertNotIn("@", result)


class TestFilePathValidation(unittest.TestCase):
    """Test file path validation."""
    
    def test_valid_paths(self):
        """Test valid file paths."""
        valid_paths = [
            "/var/log/auth.log",
            "/home/user/file.txt",
            "relative/path/file.txt"
        ]
        
        for path in valid_paths:
            with self.subTest(path=path):
                is_valid, error, normalized = validate_file_path(path)
                self.assertTrue(is_valid, f"Path {path} should be valid")
                self.assertEqual(error, "")
                self.assertIsNotNone(normalized)
    
    def test_path_traversal_attacks(self):
        """Test prevention of path traversal attacks."""
        malicious_paths = [
            "../../../etc/passwd",
            "/var/log/../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/var/log/../../etc/shadow"
        ]
        
        for path in malicious_paths:
            with self.subTest(path=path):
                is_valid, error, normalized = validate_file_path(path)
                self.assertFalse(is_valid, f"Path {path} should be invalid")
                self.assertIn("traversal", error.lower())
                self.assertIsNone(normalized)
    
    def test_allowed_directories(self):
        """Test allowed directory restrictions."""
        allowed_dirs = ["/var/log", "/opt/rotaryshield"]
        
        # Valid path in allowed directory
        is_valid, error, normalized = validate_file_path(
            "/var/log/auth.log", allowed_dirs
        )
        self.assertTrue(is_valid)
        
        # Invalid path outside allowed directories
        is_valid, error, normalized = validate_file_path(
            "/etc/passwd", allowed_dirs
        )
        self.assertFalse(is_valid)
        self.assertIn("allowed directories", error)
    
    def test_invalid_paths(self):
        """Test invalid file paths."""
        invalid_paths = ["", None, 123, [], {}]
        
        for path in invalid_paths:
            with self.subTest(path=path):
                is_valid, error, normalized = validate_file_path(path)
                self.assertFalse(is_valid)
                self.assertIsNone(normalized)


class TestRegexValidation(unittest.TestCase):
    """Test regex pattern validation."""
    
    def test_valid_patterns(self):
        """Test valid regex patterns."""
        valid_patterns = [
            r"Failed password.*from (\d+\.\d+\.\d+\.\d+)",
            r"HTTP/1\.[01]\" [45]\d\d",
            r"^[a-zA-Z0-9]+$",
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        ]
        
        for pattern in valid_patterns:
            with self.subTest(pattern=pattern):
                is_valid, error, compiled = validate_regex_pattern(pattern)
                self.assertTrue(is_valid, f"Pattern {pattern} should be valid")
                self.assertEqual(error, "")
                self.assertIsNotNone(compiled)
                self.assertIsInstance(compiled, re.Pattern)
    
    def test_invalid_patterns(self):
        """Test invalid regex patterns."""
        invalid_patterns = [
            "[unclosed bracket",
            "*invalid quantifier",
            "(?P<invalid group name>)",
            "",
            None,
            123
        ]
        
        for pattern in invalid_patterns:
            with self.subTest(pattern=pattern):
                is_valid, error, compiled = validate_regex_pattern(pattern)
                self.assertFalse(is_valid, f"Pattern {pattern} should be invalid")
                self.assertNotEqual(error, "")
                self.assertIsNone(compiled)
    
    def test_complexity_limits(self):
        """Test regex complexity limiting."""
        # Simple pattern should pass
        simple_pattern = r"test"
        is_valid, error, compiled = validate_regex_pattern(simple_pattern, max_complexity=10)
        self.assertTrue(is_valid)
        
        # Complex pattern should fail
        complex_pattern = r"(a+)+(b+)+(c+)+(d+)+(e+)+(f+)+"  # Catastrophic backtracking
        is_valid, error, compiled = validate_regex_pattern(complex_pattern, max_complexity=10)
        self.assertFalse(is_valid)
        self.assertIn("complex", error.lower())
    
    def test_long_patterns(self):
        """Test very long regex patterns."""
        long_pattern = "a" * 2000
        is_valid, error, compiled = validate_regex_pattern(long_pattern)
        self.assertFalse(is_valid)
        self.assertIn("too long", error.lower())


class TestEmailValidation(unittest.TestCase):
    """Test email address validation."""
    
    def test_valid_emails(self):
        """Test valid email addresses."""
        valid_emails = [
            "user@example.com",
            "test.email@domain.co.uk",
            "user+tag@example.org",
            "123@numbers.com"
        ]
        
        for email in valid_emails:
            with self.subTest(email=email):
                is_valid, error = validate_email(email)
                self.assertTrue(is_valid, f"Email {email} should be valid")
                self.assertEqual(error, "")
    
    def test_invalid_emails(self):
        """Test invalid email addresses."""
        invalid_emails = [
            "",
            "invalid",
            "@domain.com",
            "user@",
            "user@domain",
            "user@domain.",
            "user..double@domain.com",
            "user@domain..com",
            None,
            123
        ]
        
        for email in invalid_emails:
            with self.subTest(email=email):
                is_valid, error = validate_email(email)
                self.assertFalse(is_valid, f"Email {email} should be invalid")
                self.assertNotEqual(error, "")


class TestHostnameValidation(unittest.TestCase):
    """Test hostname validation."""
    
    def test_valid_hostnames(self):
        """Test valid hostnames."""
        valid_hostnames = [
            "example.com",
            "sub.example.com",
            "test-server",
            "server01.internal.local",
            "a" * 63 + ".com"  # Max label length
        ]
        
        for hostname in valid_hostnames:
            with self.subTest(hostname=hostname):
                is_valid, error = validate_hostname(hostname)
                self.assertTrue(is_valid, f"Hostname {hostname} should be valid")
                self.assertEqual(error, "")
    
    def test_invalid_hostnames(self):
        """Test invalid hostnames."""
        invalid_hostnames = [
            "",
            "-invalid",
            "invalid-",
            "invalid..double",
            "a" * 64,  # Too long label
            "a" * 254,  # Too long overall
            "invalid_underscore",
            None,
            123
        ]
        
        for hostname in invalid_hostnames:
            with self.subTest(hostname=hostname):
                is_valid, error = validate_hostname(hostname)
                self.assertFalse(is_valid, f"Hostname {hostname} should be invalid")
                self.assertNotEqual(error, "")


class TestURLValidation(unittest.TestCase):
    """Test URL validation."""
    
    def test_valid_urls(self):
        """Test valid URLs."""
        valid_urls = [
            "http://example.com",
            "https://secure.example.com/path",
            "https://example.com:8080/path?query=value",
            "http://192.168.1.1:3000"
        ]
        
        for url in valid_urls:
            with self.subTest(url=url):
                is_valid, error = validate_url(url)
                self.assertTrue(is_valid, f"URL {url} should be valid")
                self.assertEqual(error, "")
    
    def test_invalid_urls(self):
        """Test invalid URLs."""
        invalid_urls = [
            "",
            "not-a-url",
            "ftp://example.com",  # FTP not in default allowed schemes
            "javascript:alert('xss')",
            "http://",
            "https://",
            None,
            123
        ]
        
        for url in invalid_urls:
            with self.subTest(url=url):
                is_valid, error = validate_url(url)
                self.assertFalse(is_valid, f"URL {url} should be invalid")
                self.assertNotEqual(error, "")
    
    def test_scheme_restrictions(self):
        """Test URL scheme restrictions."""
        # FTP should be allowed when explicitly permitted
        is_valid, error = validate_url("ftp://example.com", ["ftp", "http", "https"])
        self.assertTrue(is_valid)
        
        # JavaScript should never be allowed
        is_valid, error = validate_url("javascript:alert(1)", ["javascript"])
        self.assertFalse(is_valid)


class TestFilenameSanitization(unittest.TestCase):
    """Test filename sanitization."""
    
    def test_valid_filenames(self):
        """Test valid filename sanitization."""
        test_cases = [
            ("normal_file.txt", "normal_file.txt"),
            ("file-with-dashes.log", "file-with-dashes.log"),
            ("file.with.dots.txt", "file.with.dots.txt")
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = sanitize_filename(input_name)
                self.assertEqual(result, expected)
    
    def test_dangerous_filenames(self):
        """Test sanitization of dangerous filenames."""
        dangerous_names = [
            "../../../etc/passwd",
            "file<>with|bad*chars?.txt",
            "con.txt",  # Reserved Windows name
            "prn.log",  # Reserved Windows name
            "",  # Empty name
            "   ",  # Whitespace only
            ".hidden",  # Leading dot
            "file.",  # Trailing dot
        ]
        
        for name in dangerous_names:
            with self.subTest(input=name):
                result = sanitize_filename(name)
                # Should not contain dangerous characters
                self.assertNotIn("..", result)
                self.assertNotIn("/", result)
                self.assertNotIn("\\", result)
                self.assertNotIn("<", result)
                self.assertNotIn(">", result)
                self.assertNotIn("|", result)
                self.assertNotIn("*", result)
                self.assertNotIn("?", result)
                # Should not be empty
                self.assertNotEqual(result, "")
                # Should not start with dot
                self.assertFalse(result.startswith("."))
    
    def test_length_limits(self):
        """Test filename length limiting."""
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name, max_length=255)
        self.assertLessEqual(len(result), 255)
        self.assertTrue(result.endswith(".txt"))


class TestJSONValidation(unittest.TestCase):
    """Test JSON string validation."""
    
    def test_valid_json(self):
        """Test valid JSON strings."""
        valid_json = [
            '{"key": "value"}',
            '[]',
            '[1, 2, 3]',
            '{"nested": {"key": "value"}}',
            'null',
            'true',
            '"string"',
            '123'
        ]
        
        for json_str in valid_json:
            with self.subTest(json=json_str):
                is_valid, error, data = validate_json_string(json_str)
                self.assertTrue(is_valid, f"JSON {json_str} should be valid")
                self.assertEqual(error, "")
                self.assertIsNotNone(data)
    
    def test_invalid_json(self):
        """Test invalid JSON strings."""
        invalid_json = [
            "{invalid json}",
            "{'single': 'quotes'}",
            "{trailing: comma,}",
            "",
            None,
            123,
            "unclosed {",
            '"unclosed string'
        ]
        
        for json_str in invalid_json:
            with self.subTest(json=json_str):
                is_valid, error, data = validate_json_string(json_str)
                self.assertFalse(is_valid, f"JSON {json_str} should be invalid")
                self.assertNotEqual(error, "")
                self.assertIsNone(data)
    
    def test_json_length_limits(self):
        """Test JSON length limiting."""
        long_json = '{"key": "' + "a" * 20000 + '"}'
        is_valid, error, data = validate_json_string(long_json, max_length=1000)
        self.assertFalse(is_valid)
        self.assertIn("too long", error.lower())


if __name__ == '__main__':
    unittest.main()