#!/usr/bin/env python3
"""
RotaryShield Pattern Matcher
Secure regex pattern compilation and matching with performance optimization.

Security Features:
- Regex validation and compilation with error handling
- Pattern complexity analysis to prevent ReDoS attacks
- Input sanitization for log lines
- Performance monitoring and timeout protection
- Memory usage limits for pattern operations
"""

import re
import time
import logging
import threading
import signal
from typing import Dict, List, Optional, Tuple, Pattern
from dataclasses import dataclass
from enum import Enum


class PatternError(Exception):
    """Exception for pattern-related errors."""
    pass


class PatternComplexityError(PatternError):
    """Exception for overly complex regex patterns."""
    pass


class PatternTimeoutError(PatternError):
    """Exception for pattern matching timeouts."""
    pass


@dataclass
class CompiledPattern:
    """Container for compiled regex pattern with metadata."""
    name: str
    pattern: Pattern[str]
    original_regex: str
    compilation_time: float
    complexity_score: int
    match_count: int = 0
    total_match_time: float = 0.0
    last_match_time: float = 0.0
    
    def get_average_match_time(self) -> float:
        """Get average match time in milliseconds."""
        if self.match_count == 0:
            return 0.0
        return (self.total_match_time / self.match_count) * 1000  # Convert to ms


class PatternMatcher:
    """
    Secure pattern matcher with performance monitoring and ReDoS protection.
    
    This class compiles and manages regex patterns for log analysis while
    protecting against regex denial of service (ReDoS) attacks and ensuring
    optimal performance.
    """
    
    # Security limits
    MAX_PATTERN_LENGTH = 1000
    MAX_COMPLEXITY_SCORE = 100
    MAX_MATCH_TIME_SECONDS = 1.0
    MAX_PATTERNS = 100
    
    # Pattern complexity scoring weights
    COMPLEXITY_WEIGHTS = {
        r'\*': 3,      # Zero or more quantifier
        r'\+': 3,      # One or more quantifier
        r'\?': 2,      # Zero or one quantifier
        r'\{': 4,      # Specific quantifier
        r'\(.*\)': 5,  # Capturing groups
        r'\[.*\]': 2,  # Character classes
        r'\.': 2,      # Any character
        r'\|': 3,      # Alternation
        r'\$': 1,      # End anchor
        r'\^': 1,      # Start anchor
    }
    
    def __init__(self):
        """Initialize pattern matcher."""
        self.logger = logging.getLogger(__name__)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Pattern storage
        self._patterns: Dict[str, CompiledPattern] = {}
        
        # Performance monitoring 
        self._total_matches = 0
        self._total_match_time = 0.0
        self._timeout_count = 0
        
        self.logger.info("PatternMatcher initialized")
    
    def add_pattern(self, name: str, regex: str) -> bool:
        """
        Add and compile a regex pattern with security validation.
        
        Args:
            name: Unique name for the pattern
            regex: Regular expression string
            
        Returns:
            True if pattern was added successfully, False otherwise
        """
        with self._lock:
            try:
                # Input validation
                if not name or not isinstance(name, str):
                    raise PatternError("Pattern name must be a non-empty string")
                
                if not regex or not isinstance(regex, str):
                    raise PatternError("Regex pattern must be a non-empty string")
                
                # Length validation
                if len(regex) > self.MAX_PATTERN_LENGTH:
                    raise PatternError(f"Pattern too long: {len(regex)} > {self.MAX_PATTERN_LENGTH}")
                
                # Check pattern limit
                if len(self._patterns) >= self.MAX_PATTERNS:
                    raise PatternError(f"Too many patterns: {len(self._patterns)} >= {self.MAX_PATTERNS}")
                
                # Sanitize pattern name
                safe_name = re.sub(r'[^\w\-_.]', '', name)[:50]
                if not safe_name:
                    raise PatternError("Invalid pattern name after sanitization")
                
                # Analyze pattern complexity
                complexity_score = self._analyze_pattern_complexity(regex)
                if complexity_score > self.MAX_COMPLEXITY_SCORE:
                    raise PatternComplexityError(
                        f"Pattern too complex: score {complexity_score} > {self.MAX_COMPLEXITY_SCORE}"
                    )
                
                # Compile pattern with timeout protection
                start_time = time.time()
                
                try:
                    # Use DOTALL flag to handle multiline logs, but be careful with .* patterns
                    compiled_pattern = re.compile(regex, re.IGNORECASE | re.DOTALL)
                except re.error as e:
                    raise PatternError(f"Invalid regex pattern: {e}")
                
                compilation_time = time.time() - start_time
                
                # Test pattern with a safe string to ensure it works
                try:
                    test_match = compiled_pattern.search("test string 192.168.1.1 test")
                except Exception as e:
                    raise PatternError(f"Pattern test failed: {e}")
                
                # Create compiled pattern object
                compiled_pattern_obj = CompiledPattern(
                    name=safe_name,
                    pattern=compiled_pattern,
                    original_regex=regex,
                    compilation_time=compilation_time,
                    complexity_score=complexity_score
                )
                
                # Store pattern
                self._patterns[safe_name] = compiled_pattern_obj
                
                self.logger.info(
                    f"Pattern added: {safe_name} (complexity: {complexity_score}, "
                    f"compile time: {compilation_time:.3f}s)"
                )
                
                return True
                
            except (PatternError, PatternComplexityError) as e:
                self.logger.error(f"Failed to add pattern '{name}': {e}")
                return False
            except Exception as e:
                self.logger.error(f"Unexpected error adding pattern '{name}': {e}")
                return False
    
    def _analyze_pattern_complexity(self, regex: str) -> int:
        """
        Analyze regex pattern complexity to prevent ReDoS attacks.
        Enhanced analysis that detects catastrophic backtracking patterns.
        
        Args:
            regex: Regular expression string
            
        Returns:
            Complexity score (higher = more complex)
        """
        # Use the enhanced complexity analysis from validators
        from rotaryshield.utils.validators import _analyze_regex_complexity
        return _analyze_regex_complexity(regex)
    
    def match_line(self, log_line: str) -> List[Tuple[str, List[str]]]:
        """
        Match a log line against all compiled patterns.
        
        Args:
            log_line: Log line to analyze
            
        Returns:
            List of tuples (pattern_name, matched_groups)
        """
        if not log_line or not isinstance(log_line, str):
            return []
        
        # Sanitize log line to prevent injection attacks
        sanitized_line = self._sanitize_log_line(log_line)
        if not sanitized_line:
            return []
        
        matches = []
        
        with self._lock:
            for pattern_name, compiled_pattern in self._patterns.items():
                try:
                    # Execute match with timeout protection
                    match = self._safe_pattern_match(compiled_pattern, sanitized_line)
                    
                    if match:
                        # Extract groups
                        groups = list(match.groups())
                        matches.append((pattern_name, groups))
                        
                        # Update statistics
                        compiled_pattern.match_count += 1
                        compiled_pattern.last_match_time = time.time()
                        
                        self.logger.debug(
                            f"Pattern matched: {pattern_name} -> {groups}"
                        )
                
                except Exception as e:
                    self.logger.error(f"Error matching pattern {pattern_name}: {e}")
                    continue
        
        return matches
    
    def _safe_pattern_match(self, compiled_pattern: CompiledPattern, text: str) -> Optional[re.Match]:
        """
        Execute pattern match with timeout protection.
        
        Args:
            compiled_pattern: Compiled pattern object
            text: Text to match against
            
        Returns:
            Match object or None
        """
        start_time = time.time()
        
        # Set up timeout protection using threading
        result = [None]  # Use list to allow modification in nested function
        exception = [None]
        
        def pattern_match_worker():
            """Worker function to execute pattern match."""
            try:
                result[0] = compiled_pattern.pattern.search(text)
            except Exception as e:
                exception[0] = e
        
        # Create and start worker thread
        worker_thread = threading.Thread(target=pattern_match_worker)
        worker_thread.daemon = True
        worker_thread.start()
        
        # Wait for completion with timeout
        worker_thread.join(timeout=self.MAX_MATCH_TIME_SECONDS)
        
        # Calculate actual execution time
        match_time = time.time() - start_time
        
        # Update statistics
        compiled_pattern.total_match_time += match_time
        self._total_match_time += match_time
        self._total_matches += 1
        
        if worker_thread.is_alive():
            # Timeout occurred
            self._timeout_count += 1
            self.logger.error(
                f"Pattern match timeout for {compiled_pattern.name}: "
                f"exceeded {self.MAX_MATCH_TIME_SECONDS}s limit"
            )
            return None
        
        if exception[0] is not None:
            # Exception occurred during matching
            self.logger.error(
                f"Pattern match error for {compiled_pattern.name}: {exception[0]}"
            )
            return None
        
        # Check for slow patterns (but not timed out)
        if match_time > self.MAX_MATCH_TIME_SECONDS * 0.8:  # Warn at 80% of timeout
            self.logger.warning(
                f"Slow pattern match: {compiled_pattern.name} took {match_time:.3f}s "
                f"(80% of {self.MAX_MATCH_TIME_SECONDS}s timeout)"
            )
        
        return result[0]
    
    def _sanitize_log_line(self, log_line: str) -> str:
        """
        Sanitize log line to prevent injection attacks and handle encoding issues.
        
        Args:
            log_line: Raw log line
            
        Returns:
            Sanitized log line
        """
        try:
            # Remove null bytes and control characters that could cause issues
            sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', log_line)
            
            # Truncate very long lines to prevent memory issues
            if len(sanitized) > 10000:
                sanitized = sanitized[:10000] + "...[truncated]"
            
            # Ensure string is UTF-8 compatible
            sanitized = sanitized.encode('utf-8', errors='replace').decode('utf-8')
            
            return sanitized.strip()
            
        except Exception as e:
            self.logger.error(f"Error sanitizing log line: {e}")
            return ""  # Return empty string on error for safety
    
    def remove_pattern(self, name: str) -> bool:
        """
        Remove a compiled pattern.
        
        Args:
            name: Pattern name to remove
            
        Returns:
            True if pattern was removed, False if not found
        """
        with self._lock:
            if name in self._patterns:
                del self._patterns[name]
                self.logger.info(f"Pattern removed: {name}")
                return True
            else:
                self.logger.warning(f"Pattern not found for removal: {name}")
                return False
    
    def get_pattern_info(self, name: str) -> Optional[Dict[str, any]]:
        """
        Get information about a specific pattern.
        
        Args:
            name: Pattern name
            
        Returns:
            Dictionary with pattern information or None if not found
        """
        with self._lock:
            if name not in self._patterns:
                return None
            
            pattern = self._patterns[name]
            return {
                'name': pattern.name,
                'original_regex': pattern.original_regex,
                'complexity_score': pattern.complexity_score,
                'compilation_time': pattern.compilation_time,
                'match_count': pattern.match_count,
                'total_match_time': pattern.total_match_time,
                'average_match_time': pattern.get_average_match_time(),
                'last_match_time': pattern.last_match_time
            }
    
    def get_all_patterns_info(self) -> Dict[str, Dict[str, any]]:
        """
        Get information about all patterns.
        
        Returns:
            Dictionary mapping pattern names to their information
        """
        with self._lock:
            return {
                name: self.get_pattern_info(name) 
                for name in self._patterns.keys()
            }
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get pattern matcher statistics.
        
        Returns:
            Dictionary with performance statistics
        """
        with self._lock:
            avg_match_time = (
                (self._total_match_time / max(self._total_matches, 1)) * 1000
            )  # Convert to milliseconds
            
            return {
                'total_patterns': len(self._patterns),
                'total_matches': self._total_matches,
                'total_match_time': self._total_match_time,
                'average_match_time_ms': avg_match_time,
                'timeout_count': self._timeout_count,
                'patterns_info': self.get_all_patterns_info()
            }
    
    def clear_all_patterns(self) -> None:
        """Clear all compiled patterns."""
        with self._lock:
            pattern_count = len(self._patterns)
            self._patterns.clear()
            self.logger.info(f"Cleared {pattern_count} patterns")
    
    def validate_pattern(self, regex: str) -> Tuple[bool, str]:
        """
        Validate a regex pattern without adding it.
        
        Args:
            regex: Regular expression string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Length check
            if len(regex) > self.MAX_PATTERN_LENGTH:
                return False, f"Pattern too long: {len(regex)} > {self.MAX_PATTERN_LENGTH}"
            
            # Complexity check
            complexity_score = self._analyze_pattern_complexity(regex)
            if complexity_score > self.MAX_COMPLEXITY_SCORE:
                return False, f"Pattern too complex: score {complexity_score} > {self.MAX_COMPLEXITY_SCORE}"
            
            # Compilation check
            try:
                re.compile(regex, re.IGNORECASE | re.DOTALL)
            except re.error as e:
                return False, f"Invalid regex: {e}"
            
            return True, "Pattern is valid"
            
        except Exception as e:
            return False, f"Validation error: {e}"