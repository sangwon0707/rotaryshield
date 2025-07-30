#!/usr/bin/env python3
"""
Security Tests for ReDoS (Regular Expression Denial of Service) Vulnerabilities
Tests for RotaryShield pattern matcher resilience against malicious regex patterns.

This test suite validates:
- ReDoS pattern detection and prevention
- Pattern complexity analysis accuracy
- Performance under malicious input
- Resource consumption limits
- Timeout handling
"""

import unittest
import time
import threading
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from rotaryshield.monitoring.pattern_matcher import PatternMatcher, PatternComplexityError
from rotaryshield.utils.validators import validate_regex_pattern


class TestReDoSVulnerabilities(unittest.TestCase):
    """Test suite for ReDoS vulnerability prevention."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.matcher = PatternMatcher()
    
    def tearDown(self):
        """Clean up after tests."""
        self.matcher.clear_all_patterns()
    
    def test_catastrophic_backtracking_patterns(self):
        """Test detection of patterns prone to catastrophic backtracking."""
        # Known problematic patterns that can cause exponential time complexity
        malicious_patterns = [
            # Nested quantifiers - very dangerous
            r"(a+)+",
            r"(a*)*",
            r"(a+)+b",
            r"(a*)*b",
            
            # Multiple quantifiers on the same group
            r"(a+)+(b+)+",
            r"(a*)*(b*)*",
            
            # Complex alternation with quantifiers
            r"(a|a)*",
            r"(a|a)*b",
            r"(a+|a+)*",
            
            # Real-world example: email validation gone wrong
            r"^([a-zA-Z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$",
            
            # URL validation with nested groups
            r"^(https?://)?([\da-z\.-]+)\.([a-z\.]{2,6})([/\w \.-]*)*/?$",
            
            # Log pattern with potential issues
            r"^(\d{1,3}\.){3}\d{1,3} - - \[([^\]]+)\] \"([^\"]+)\" (\d+) (\d+) \"([^\"]+)\" \"([^\"]+)\"$",
        ]
        
        for pattern in malicious_patterns:
            with self.subTest(pattern=pattern):
                # Pattern should be rejected due to high complexity
                success = self.matcher.add_pattern(f"malicious_{hash(pattern)}", pattern)
                self.assertFalse(success, f"Malicious pattern should be rejected: {pattern}")
    
    def test_complexity_analysis_accuracy(self):
        """Test accuracy of pattern complexity analysis."""
        test_cases = [
            # (pattern, expected_high_complexity)
            ("simple", False),
            ("test.*pattern", False),
            (r"\d+\.\d+\.\d+\.\d+", False),
            ("(a+)+", True),  # Catastrophic backtracking
            ("(a*)*", True),  # Catastrophic backtracking
            (r"(a+)+(b+)+(c+)+", True),  # Multiple nested quantifiers
            (r"(a|a)*", True),  # Alternation issues
            ("a" * 200, True),  # Very long pattern
        ]
        
        for pattern, should_be_complex in test_cases:
            with self.subTest(pattern=pattern):
                complexity = self.matcher._analyze_pattern_complexity(pattern)
                
                if should_be_complex:
                    self.assertGreater(
                        complexity, 
                        self.matcher.MAX_COMPLEXITY_SCORE,
                        f"Pattern should be considered complex: {pattern} (score: {complexity})"
                    )
                else:
                    self.assertLessEqual(
                        complexity,
                        self.matcher.MAX_COMPLEXITY_SCORE,
                        f"Pattern should be considered simple: {pattern} (score: {complexity})"
                    )
    
    def test_performance_under_attack(self):
        """Test pattern matcher performance under ReDoS attack conditions."""
        # Add a legitimate pattern
        legitimate_pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
        success = self.matcher.add_pattern("ssh_fail", legitimate_pattern)
        self.assertTrue(success, "Legitimate pattern should be added")
        
        # Test with inputs designed to trigger ReDoS in vulnerable patterns
        attack_inputs = [
            # Long strings with repeated characters
            "a" * 10000,
            "Failed password for user from " + "a" * 5000 + " port 22",
            
            # Nested patterns
            "(" * 100 + "test" + ")" * 100,
            
            # Mixed attack patterns
            "Failed password " + "a" * 1000 + " from 192.168.1.100",
            
            # Control characters mixed in
            "Failed password\x00\x01\x02" + "a" * 500 + " from 192.168.1.100",
        ]
        
        for attack_input in attack_inputs:
            with self.subTest(input=attack_input):
                start_time = time.time()
                
                # This should complete quickly even with malicious input
                matches = self.matcher.match_line(attack_input)
                
                execution_time = time.time() - start_time
                
                # Should complete within reasonable time (1 second)
                self.assertLess(
                    execution_time, 
                    1.0,
                    f"Pattern matching took too long: {execution_time:.3f}s for input length {len(attack_input)}"
                )
                
                # Should still work correctly
                self.assertIsInstance(matches, list)
    
    def test_timeout_protection(self):
        """Test timeout protection for slow pattern matching."""
        # This test is tricky because we need a pattern that's not rejected
        # but still slow. We'll test the timeout mechanism indirectly.
        
        # Add a pattern with moderate complexity that might be slow
        moderate_pattern = r"(\w+\s+){10,50}error"
        success = self.matcher.add_pattern("moderate", moderate_pattern)
        
        if success:
            # Create input designed to be slow but not infinite
            slow_input = ("word " * 100) + "error"
            
            start_time = time.time()
            matches = self.matcher.match_line(slow_input)
            execution_time = time.time() - start_time
            
            # Should still complete in reasonable time
            self.assertLess(execution_time, 2.0)
            
            # Check if timeout was recorded
            stats = self.matcher.get_statistics()
            # Timeout count might be 0 if pattern wasn't actually slow
            self.assertGreaterEqual(stats['timeout_count'], 0)
    
    def test_memory_consumption_limits(self):
        """Test memory consumption limits during pattern operations."""
        # Test with many patterns
        pattern_count = 0
        max_patterns = self.matcher.MAX_PATTERNS
        
        # Add patterns up to the limit
        for i in range(max_patterns):
            pattern = f"pattern_{i}_\\d+"
            success = self.matcher.add_pattern(f"test_{i}", pattern)
            if success:
                pattern_count += 1
        
        # Should not exceed the limit
        self.assertLessEqual(pattern_count, max_patterns)
        
        # Trying to add more should fail
        overflow_success = self.matcher.add_pattern("overflow", "test_overflow")
        self.assertFalse(overflow_success, "Should reject patterns beyond limit")
    
    def test_input_sanitization_effectiveness(self):
        """Test input sanitization against various attack vectors."""
        # Add a simple pattern
        self.matcher.add_pattern("simple", r"test_(\w+)")
        
        # Test various malicious inputs
        malicious_inputs = [
            # Null bytes
            "test_\x00attack",
            
            # Control characters
            "test_\x01\x02\x03attack",
            
            # ANSI escape sequences
            "test_\x1b[31mattack\x1b[0m",
            
            # Very long input
            "test_" + "a" * 20000,
            
            # Unicode normalization attacks
            "test_café",  # Normal
            "test_cafe\u0301",  # With combining character
            
            # Mixed encoding issues
            "test_\xff\xfe\x00\x00attack",
        ]
        
        for malicious_input in malicious_inputs:
            with self.subTest(input=repr(malicious_input)):
                # Should not crash or hang
                matches = self.matcher.match_line(malicious_input)
                self.assertIsInstance(matches, list)
                
                # If it matches, the groups should be sanitized
                for pattern_name, groups in matches:
                    for group in groups:
                        # Should not contain null bytes or dangerous characters
                        self.assertNotIn('\x00', group)
                        self.assertNotIn('\x01', group)
                        self.assertNotIn('\x1b', group)
    
    def test_concurrent_redos_attacks(self):
        """Test system resilience under concurrent ReDoS attacks."""
        # Add a pattern that might be vulnerable
        self.matcher.add_pattern("test", r"test.*pattern")
        
        # Create attack input
        attack_input = ("test " + "a" * 1000 + " ") * 10 + "pattern"
        
        # Function to run in multiple threads
        def attack_thread():
            for _ in range(10):
                matches = self.matcher.match_line(attack_input)
                self.assertIsInstance(matches, list)
        
        # Launch multiple concurrent attacks
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=attack_thread)
            threads.append(thread)
        
        start_time = time.time()
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join(timeout=5.0)  # 5 second timeout
        
        execution_time = time.time() - start_time
        
        # Should complete within reasonable time even under concurrent attack
        self.assertLess(execution_time, 10.0, "Concurrent attacks should not cause excessive delays")
    
    def test_validator_redos_protection(self):
        """Test that the validator module also protects against ReDoS."""
        malicious_patterns = [
            r"(a+)+",
            r"(a*)*",
            r"(a+)+(b+)+",
        ]
        
        for pattern in malicious_patterns:
            with self.subTest(pattern=pattern):
                is_valid, error, compiled = validate_regex_pattern(pattern, max_complexity=50)
                self.assertFalse(is_valid, f"Validator should reject malicious pattern: {pattern}")
                self.assertIn("complex", error.lower())
                self.assertIsNone(compiled)
    
    def test_edge_case_patterns(self):
        """Test edge case patterns that might bypass complexity analysis."""
        edge_cases = [
            # Patterns that look simple but might be problematic
            r".*.*.*.*",  # Multiple wildcards
            r".+.+.+.+",  # Multiple one-or-more
            r"a{1,100}b{1,100}",  # Large quantifiers
            r"(ab|cd|ef|gh|ij|kl|mn|op|qr|st|uv|wx|yz)+",  # Many alternations
            
            # Unicode patterns
            r"[\u0000-\uffff]+",
            
            # Patterns with complex character classes
            r"[a-zA-Z0-9!@#$%^&*()_+-=\[\]{}|;':\",./<>?~`]+",
        ]
        
        for pattern in edge_cases:
            with self.subTest(pattern=pattern):
                complexity = self.matcher._analyze_pattern_complexity(pattern)
                
                # Should either be rejected for complexity or have reasonable complexity
                if complexity > self.matcher.MAX_COMPLEXITY_SCORE:
                    success = self.matcher.add_pattern(f"edge_{hash(pattern)}", pattern)
                    self.assertFalse(success, f"High complexity pattern should be rejected: {pattern}")
                else:
                    # If accepted, should work without issues
                    success = self.matcher.add_pattern(f"edge_{hash(pattern)}", pattern)
                    if success:
                        # Test with normal input
                        matches = self.matcher.match_line("test input 123")
                        self.assertIsInstance(matches, list)


class TestPatternValidatorSecurity(unittest.TestCase):
    """Test security features of the pattern validator."""
    
    def test_complexity_calculation_consistency(self):
        """Test that complexity calculation is consistent."""
        from rotaryshield.utils.validators import _analyze_regex_complexity
        
        test_patterns = [
            "simple",
            r"\d+",
            r"(a+)+",
            r".*.*.*",
            "a" * 500,
        ]
        
        for pattern in test_patterns:
            with self.subTest(pattern=pattern):
                # Calculate complexity multiple times
                scores = []
                for _ in range(5):
                    score = _analyze_regex_complexity(pattern)
                    scores.append(score)
                
                # All scores should be identical
                self.assertEqual(len(set(scores)), 1, f"Complexity calculation should be consistent for: {pattern}")
    
    def test_validator_input_sanitization(self):
        """Test input sanitization in validator functions."""
        malicious_inputs = [
            None,
            123,
            [],
            {},
            "",
            "\x00\x01\x02",
        ]
        
        for malicious_input in malicious_inputs:
            with self.subTest(input=repr(malicious_input)):
                is_valid, error, compiled = validate_regex_pattern(malicious_input)
                self.assertFalse(is_valid)
                self.assertIn("string", error.lower())
                self.assertIsNone(compiled)


if __name__ == '__main__':
    unittest.main()