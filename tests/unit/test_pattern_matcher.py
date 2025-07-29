#!/usr/bin/env python3
"""
Unit tests for RotaryShield PatternMatcher with security focus.
"""

import unittest
import time
import re
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from rotaryshield.monitoring.pattern_matcher import (
    PatternMatcher,
    CompiledPattern,
    PatternError,
    PatternComplexityError
)


class TestCompiledPattern(unittest.TestCase):
    """Test CompiledPattern data class."""
    
    def test_compiled_pattern_creation(self):
        """Test creation of CompiledPattern objects."""
        pattern = re.compile(r"test pattern")
        compiled_pattern = CompiledPattern(
            name="test_pattern",
            pattern=pattern,
            original_regex="test pattern",
            compilation_time=0.001,
            complexity_score=5
        )
        
        self.assertEqual(compiled_pattern.name, "test_pattern")
        self.assertEqual(compiled_pattern.pattern, pattern)
        self.assertEqual(compiled_pattern.original_regex, "test pattern")
        self.assertEqual(compiled_pattern.compilation_time, 0.001)
        self.assertEqual(compiled_pattern.complexity_score, 5)
        self.assertEqual(compiled_pattern.match_count, 0)
        self.assertEqual(compiled_pattern.total_match_time, 0.0)
    
    def test_average_match_time_calculation(self):
        """Test average match time calculation."""
        pattern = re.compile(r"test")
        compiled_pattern = CompiledPattern(
            name="test",
            pattern=pattern,
            original_regex="test",
            compilation_time=0.001,
            complexity_score=1
        )
        
        # No matches yet
        self.assertEqual(compiled_pattern.get_average_match_time(), 0.0)
        
        # Add some match data
        compiled_pattern.match_count = 5
        compiled_pattern.total_match_time = 0.01  # 10ms total
        
        # Should return 2ms average (converted to milliseconds)
        self.assertEqual(compiled_pattern.get_average_match_time(), 2.0)


class TestPatternMatcher(unittest.TestCase):
    """Test PatternMatcher functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.matcher = PatternMatcher()
    
    def tearDown(self):
        """Clean up after tests."""
        self.matcher.clear_all_patterns()
    
    def test_initialization(self):
        """Test PatternMatcher initialization."""
        self.assertIsInstance(self.matcher, PatternMatcher)
        self.assertEqual(len(self.matcher._patterns), 0)
        self.assertEqual(self.matcher._total_matches, 0)
        self.assertEqual(self.matcher._total_match_time, 0.0)
        self.assertEqual(self.matcher._timeout_count, 0)
    
    def test_add_valid_pattern(self):
        """Test adding valid regex patterns."""
        test_cases = [
            ("ssh_fail", r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"),
            ("http_error", r"HTTP/1\.[01]\" [45]\d\d"),
            ("simple", r"test"),
            ("ip_pattern", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        ]
        
        for name, pattern in test_cases:
            with self.subTest(name=name, pattern=pattern):
                success = self.matcher.add_pattern(name, pattern)
                self.assertTrue(success, f"Should successfully add pattern {name}")
                self.assertIn(name, self.matcher._patterns)
                
                # Verify pattern was compiled correctly
                compiled_pattern = self.matcher._patterns[name]
                self.assertEqual(compiled_pattern.name, name)
                self.assertEqual(compiled_pattern.original_regex, pattern)
                self.assertIsInstance(compiled_pattern.pattern, re.Pattern)
    
    def test_add_invalid_pattern(self):
        """Test adding invalid regex patterns."""
        invalid_patterns = [
            ("", "empty_name"),
            ("valid_name", ""),
            ("brackets", "[unclosed bracket"),
            ("quantifier", "*invalid start"),
            ("group", "(?P<invalid group>)"),
            (None, "valid_pattern"),
            ("valid_name", None),
            (123, "valid_pattern"),
            ("valid_name", 123)
        ]
        
        for name, pattern in invalid_patterns:
            with self.subTest(name=name, pattern=pattern):
                success = self.matcher.add_pattern(name, pattern)
                self.assertFalse(success, f"Should reject invalid pattern {name}/{pattern}")
    
    def test_pattern_complexity_analysis(self):
        """Test regex pattern complexity analysis."""
        # Simple pattern should have low complexity
        simple_complexity = self.matcher._analyze_pattern_complexity("test")
        self.assertLess(simple_complexity, 10)
        
        # Complex pattern should have high complexity
        complex_pattern = r"(a+)+(b+)+(c+)+(d+)+"  # Potential catastrophic backtracking
        complex_complexity = self.matcher._analyze_pattern_complexity(complex_pattern)
        self.assertGreater(complex_complexity, 50)
        
        # Very long pattern should get penalty
        long_pattern = "a" * 200
        long_complexity = self.matcher._analyze_pattern_complexity(long_pattern)
        self.assertGreater(long_complexity, 10)
    
    def test_pattern_length_limit(self):
        """Test pattern length limiting."""
        # Very long pattern should be rejected
        long_pattern = "a" * 2000
        success = self.matcher.add_pattern("long", long_pattern)
        self.assertFalse(success)
    
    def test_pattern_count_limit(self):
        """Test maximum pattern count limit."""
        # Add patterns up to the limit
        for i in range(self.matcher.MAX_PATTERNS):
            success = self.matcher.add_pattern(f"pattern_{i}", f"test{i}")
            self.assertTrue(success)
        
        # Adding one more should fail
        success = self.matcher.add_pattern("overflow", "test_overflow")
        self.assertFalse(success)
    
    def test_complexity_limit(self):
        """Test pattern complexity limiting."""
        # Create a pattern that exceeds complexity limit
        complex_pattern = r"(a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p*q*r*s*t*u*v*w*x*y*z*)+"
        
        success = self.matcher.add_pattern("complex", complex_pattern)
        self.assertFalse(success)
    
    def test_match_line_basic(self):
        """Test basic line matching functionality."""
        # Add test patterns
        self.matcher.add_pattern("ssh_fail", r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
        self.matcher.add_pattern("ip_only", r"(\d+\.\d+\.\d+\.\d+)")
        
        # Test matching
        test_log = "Failed password for user from 192.168.1.100 port 22"
        matches = self.matcher.match_line(test_log)
        
        # Should match both patterns
        self.assertEqual(len(matches), 2)
        
        # Check SSH fail match
        ssh_match = next((m for m in matches if m[0] == "ssh_fail"), None)
        self.assertIsNotNone(ssh_match)
        self.assertEqual(ssh_match[1], ["192.168.1.100"])
        
        # Check IP match
        ip_match = next((m for m in matches if m[0] == "ip_only"), None)
        self.assertIsNotNone(ip_match)
        self.assertEqual(ip_match[1], ["192.168.1.100"])
    
    def test_match_line_no_matches(self):
        """Test line matching with no matches."""
        self.matcher.add_pattern("ssh_fail", r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
        
        # Log line that doesn't match
        test_log = "Successful login for user admin"
        matches = self.matcher.match_line(test_log)
        
        self.assertEqual(len(matches), 0)
    
    def test_match_line_sanitization(self):
        """Test log line sanitization during matching."""
        self.matcher.add_pattern("simple", r"test")
        
        # Test with control characters
        malicious_log = "test\x00\x01\x02message"
        matches = self.matcher.match_line(malicious_log)
        
        # Should still match after sanitization
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "simple")
    
    def test_log_line_sanitization(self):
        """Test log line sanitization method."""
        test_cases = [
            ("normal text", "normal text"),
            ("text\x00with\x01null", "textwithfull"),
            ("very" + "long" * 2000 + "line", None),  # Should be truncated
            ("text\nwith\nnewlines", "text\nwith\nnewlines"),
            ("", "")
        ]
        
        for input_text, expected in test_cases:
            with self.subTest(input=input_text):
                result = self.matcher._sanitize_log_line(input_text)
                if expected is None:
                    # Should be truncated
                    self.assertLessEqual(len(result), 10003)  # 10000 + "...[truncated]"
                    self.assertTrue(result.endswith("...[truncated]"))
                else:
                    self.assertEqual(result, expected)
    
    def test_invalid_input_handling(self):
        """Test handling of invalid inputs."""
        self.matcher.add_pattern("test", r"test")
        
        # Test with None input
        matches = self.matcher.match_line(None)
        self.assertEqual(len(matches), 0)
        
        # Test with non-string input
        matches = self.matcher.match_line(123)
        self.assertEqual(len(matches), 0)
        
        # Test with empty string
        matches = self.matcher.match_line("")
        self.assertEqual(len(matches), 0)
    
    def test_pattern_statistics_tracking(self):
        """Test pattern statistics tracking."""
        self.matcher.add_pattern("test", r"test")
        
        # Initial stats
        pattern = self.matcher._patterns["test"]
        self.assertEqual(pattern.match_count, 0)
        self.assertEqual(pattern.total_match_time, 0.0)
        
        # Perform some matches
        self.matcher.match_line("test message")
        self.matcher.match_line("another test")
        self.matcher.match_line("no match here")
        
        # Check updated stats
        self.assertEqual(pattern.match_count, 2)
        self.assertGreater(pattern.total_match_time, 0)
        self.assertGreater(pattern.last_match_time, 0)
    
    def test_remove_pattern(self):
        """Test pattern removal."""
        self.matcher.add_pattern("test", r"test")
        self.assertIn("test", self.matcher._patterns)
        
        # Remove existing pattern
        success = self.matcher.remove_pattern("test")
        self.assertTrue(success)
        self.assertNotIn("test", self.matcher._patterns)
        
        # Try to remove non-existent pattern
        success = self.matcher.remove_pattern("nonexistent")
        self.assertFalse(success)
    
    def test_get_pattern_info(self):
        """Test getting pattern information."""
        self.matcher.add_pattern("test", r"test pattern")
        
        info = self.matcher.get_pattern_info("test")
        self.assertIsNotNone(info)
        self.assertEqual(info['name'], "test")
        self.assertEqual(info['original_regex'], "test pattern")
        self.assertGreaterEqual(info['complexity_score'], 0)
        self.assertGreaterEqual(info['compilation_time'], 0)
        
        # Non-existent pattern
        info = self.matcher.get_pattern_info("nonexistent")
        self.assertIsNone(info)
    
    def test_get_all_patterns_info(self):
        """Test getting all patterns information."""
        patterns = [
            ("ssh", r"ssh.*failed"),
            ("http", r"HTTP.*error"),
            ("ftp", r"ftp.*denied")
        ]
        
        for name, pattern in patterns:
            self.matcher.add_pattern(name, pattern)
        
        all_info = self.matcher.get_all_patterns_info()
        self.assertEqual(len(all_info), 3)
        
        for name, _ in patterns:
            self.assertIn(name, all_info)
            self.assertIsNotNone(all_info[name])
    
    def test_get_statistics(self):
        """Test getting matcher statistics."""
        # Add some patterns and perform matches
        self.matcher.add_pattern("test1", r"test1")
        self.matcher.add_pattern("test2", r"test2")
        
        self.matcher.match_line("test1 message")
        self.matcher.match_line("test2 message")
        self.matcher.match_line("no match")
        
        stats = self.matcher.get_statistics()
        
        self.assertEqual(stats['total_patterns'], 2)
        self.assertEqual(stats['total_matches'], 2)
        self.assertGreater(stats['total_match_time'], 0)
        self.assertGreater(stats['average_match_time_ms'], 0)
        self.assertEqual(stats['timeout_count'], 0)
        self.assertIn('patterns_info', stats)
    
    def test_clear_all_patterns(self):
        """Test clearing all patterns."""
        # Add some patterns
        self.matcher.add_pattern("test1", r"test1")
        self.matcher.add_pattern("test2", r"test2")
        
        self.assertEqual(len(self.matcher._patterns), 2)
        
        # Clear all
        self.matcher.clear_all_patterns()
        self.assertEqual(len(self.matcher._patterns), 0)
    
    def test_validate_pattern(self):
        """Test pattern validation without adding."""
        # Valid pattern
        is_valid, error = self.matcher.validate_pattern(r"test.*pattern")
        self.assertTrue(is_valid)
        self.assertEqual(error, "Pattern is valid")
        
        # Invalid pattern (syntax error)
        is_valid, error = self.matcher.validate_pattern("[unclosed")
        self.assertFalse(is_valid)
        self.assertIn("Invalid regex", error)
        
        # Pattern too long
        long_pattern = "a" * 2000
        is_valid, error = self.matcher.validate_pattern(long_pattern)
        self.assertFalse(is_valid)
        self.assertIn("too long", error)
        
        # Pattern too complex
        complex_pattern = r"(a+)+(b+)+(c+)+(d+)+(e+)+(f+)+"
        is_valid, error = self.matcher.validate_pattern(complex_pattern, max_complexity=10)
        self.assertFalse(is_valid)
        self.assertIn("too complex", error)
    
    def test_pattern_name_sanitization(self):
        """Test pattern name sanitization."""
        # Pattern with special characters in name
        success = self.matcher.add_pattern("test@#$%name", r"test")
        self.assertTrue(success)
        
        # Should be sanitized to safe name
        sanitized_names = [name for name in self.matcher._patterns.keys() if "test" in name]
        self.assertEqual(len(sanitized_names), 1)
        
        # Name should not contain special characters
        sanitized_name = sanitized_names[0]
        self.assertNotIn("@", sanitized_name)
        self.assertNotIn("#", sanitized_name)
        self.assertNotIn("$", sanitized_name)
    
    def test_concurrent_access_safety(self):
        """Test thread safety of pattern operations."""
        import threading
        import time
        
        # Add initial pattern
        self.matcher.add_pattern("base", r"base")
        
        def add_patterns():
            for i in range(10):
                self.matcher.add_pattern(f"thread_pattern_{i}", f"pattern{i}")
        
        def match_lines():
            for i in range(10):
                self.matcher.match_line(f"test pattern{i} message")
        
        # Run concurrent operations
        threads = []
        for _ in range(3):
            threads.append(threading.Thread(target=add_patterns))
            threads.append(threading.Thread(target=match_lines))
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join(timeout=5)
        
        # Verify no crashes occurred and some patterns were added
        self.assertGreaterEqual(len(self.matcher._patterns), 1)
    
    @patch('time.time')
    def test_performance_monitoring(self, mock_time):
        """Test performance monitoring functionality."""
        # Mock time progression
        mock_time.side_effect = [0.0, 0.001, 0.002, 0.003]  # 1ms per operation
        
        self.matcher.add_pattern("test", r"test")
        
        # Perform match
        self.matcher.match_line("test message")
        
        # Check timing was recorded
        pattern = self.matcher._patterns["test"]
        self.assertGreater(pattern.total_match_time, 0)
        self.assertEqual(pattern.match_count, 1)
    
    def test_safe_pattern_match_timeout_handling(self):
        """Test timeout handling in pattern matching."""
        # This is difficult to test directly, but we can verify the method exists
        # and handles exceptions properly
        
        self.matcher.add_pattern("test", r"test")
        pattern = self.matcher._patterns["test"]
        
        # Should handle normal matching
        result = self.matcher._safe_pattern_match(pattern, "test message")
        self.assertIsNotNone(result)
        
        # Should handle exceptions gracefully
        with patch.object(pattern.pattern, 'search', side_effect=Exception("Test error")):
            result = self.matcher._safe_pattern_match(pattern, "test message")
            self.assertIsNone(result)
            self.assertGreater(self.matcher._timeout_count, 0)


if __name__ == '__main__':
    unittest.main()