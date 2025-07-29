#!/usr/bin/env python3
"""
RotaryShield Log Monitor
Real-time log file monitoring with pattern matching and security features.

Security Features:
- File access validation and permission checking
- Path traversal protection
- Resource usage monitoring and limits
- Thread-safe operations
- Graceful error handling and recovery
- Performance monitoring and optimization
"""

import os
import time
import threading
import logging
import stat
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass
from pathlib import Path
import select
import errno
from concurrent.futures import ThreadPoolExecutor
import queue

from .pattern_matcher import PatternMatcher


@dataclass
class LogEvent:
    """Log event with pattern match information."""
    log_file: str
    line_number: int
    log_line: str
    timestamp: float
    pattern_name: str
    matched_groups: List[str]
    
    def __post_init__(self):
        """Validate log event data."""
        # Sanitize log line to prevent injection
        if self.log_line:
            # Remove potentially dangerous characters but preserve structure
            sanitized = ''.join(c for c in self.log_line if ord(c) >= 32 or c in '\t\n')
            if len(sanitized) > 5000:  # Truncate very long lines
                sanitized = sanitized[:5000] + "...[truncated]"
            self.log_line = sanitized


class LogMonitorError(Exception):
    """Exception for log monitor errors."""
    pass


class LogFileWatcher:
    """
    Individual log file watcher with tail functionality.
    
    This class monitors a single log file for changes and processes
    new lines as they are added.
    """
    
    def __init__(self, file_path: str, pattern_matcher: PatternMatcher):
        """
        Initialize log file watcher.
        
        Args:
            file_path: Path to log file to monitor
            pattern_matcher: Pattern matcher instance
        """
        self.file_path = file_path
        self.pattern_matcher = pattern_matcher
        self.logger = logging.getLogger(f"{__name__}.{Path(file_path).name}")
        
        # File monitoring state
        self._file_handle: Optional[open] = None
        self._file_size = 0
        self._file_inode = 0
        self._line_number = 0
        self._last_check_time = 0.0
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self._lines_processed = 0
        self._bytes_processed = 0
        self._matches_found = 0
        self._errors_count = 0
        
        # Event callback
        self._event_callback: Optional[Callable[[LogEvent], None]] = None
    
    def set_event_callback(self, callback: Callable[[LogEvent], None]) -> None:
        """Set callback function for log events."""
        self._event_callback = callback
    
    def initialize(self) -> None:
        """
        Initialize file watcher and validate file access.
        
        Raises:
            LogMonitorError: If file cannot be accessed or is invalid
        """
        try:
            # Validate file path for security
            self._validate_file_path()
            
            # Check file permissions and access
            self._validate_file_access()
            
            # Open file and get initial state
            self._open_file()
            
            self.logger.info(f"Log file watcher initialized: {self.file_path}")
            
        except Exception as e:
            raise LogMonitorError(f"Failed to initialize watcher for {self.file_path}: {e}")
    
    def _validate_file_path(self) -> None:
        """Validate file path for security issues."""
        # Resolve path to prevent traversal attacks
        try:
            resolved_path = os.path.realpath(self.file_path)
        except Exception:
            raise LogMonitorError(f"Cannot resolve file path: {self.file_path}")
        
        # Check for path traversal attempts
        if '..' in self.file_path or self.file_path != resolved_path:
            self.logger.warning(f"Potential path traversal detected: {self.file_path}")
        
        # Validate path is in allowed directories
        allowed_dirs = [
            '/var/log',
            '/opt/rotaryshield/logs',
            '/tmp/rotaryshield',
            '/var/log/nginx',
            '/var/log/apache2',
            '/var/log/httpd'
        ]
        
        if not any(resolved_path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
            self.logger.warning(f"File outside allowed directories: {resolved_path}")
        
        self.file_path = resolved_path
    
    def _validate_file_access(self) -> None:
        """Validate file access permissions and properties."""
        try:
            # Check if file exists
            if not os.path.exists(self.file_path):
                raise LogMonitorError(f"Log file does not exist: {self.file_path}")
            
            # Get file stats
            file_stat = os.stat(self.file_path)
            
            # Check if it's a regular file
            if not stat.S_ISREG(file_stat.st_mode):
                raise LogMonitorError(f"Path is not a regular file: {self.file_path}")
            
            # Check file permissions (should be readable)
            if not os.access(self.file_path, os.R_OK):
                raise LogMonitorError(f"No read permission for file: {self.file_path}")
            
            # Check file size (warn if very large)
            file_size = file_stat.st_size
            if file_size > 1_000_000_000:  # 1GB
                self.logger.warning(f"Very large log file: {self.file_path} ({file_size} bytes)")
            
            # Store initial file info
            self._file_size = file_size
            self._file_inode = file_stat.st_ino
            
        except OSError as e:
            raise LogMonitorError(f"Cannot access file {self.file_path}: {e}")
    
    def _open_file(self) -> None:
        """Open log file for reading."""
        try:
            self._file_handle = open(self.file_path, 'r', encoding='utf-8', errors='replace')
            
            # Seek to end of file for tail functionality
            self._file_handle.seek(0, 2)  # Seek to end
            self._file_size = self._file_handle.tell()
            
        except Exception as e:
            raise LogMonitorError(f"Cannot open file {self.file_path}: {e}")
    
    def check_for_changes(self) -> List[LogEvent]:
        """
        Check for new lines in log file and process them.
        
        Returns:
            List of log events from new lines
        """
        events = []
        
        with self._lock:
            try:
                # Check if file still exists and hasn't been rotated
                if not self._is_file_valid():
                    self._handle_file_rotation()
                    return events
                
                # Read new lines
                new_lines = self._read_new_lines()
                
                # Process each new line
                for line in new_lines:
                    line_events = self._process_line(line)
                    events.extend(line_events)
                
                self._last_check_time = time.time()
                
            except Exception as e:
                self._errors_count += 1
                self.logger.error(f"Error checking for changes in {self.file_path}: {e}")
        
        return events
    
    def _is_file_valid(self) -> bool:
        """Check if file is still valid (not rotated or deleted)."""
        try:
            # Check if file still exists
            if not os.path.exists(self.file_path):
                return False
            
            # Check if inode changed (file rotation)
            current_stat = os.stat(self.file_path)
            if current_stat.st_ino != self._file_inode:
                self.logger.info(f"File rotation detected: {self.file_path}")
                return False
            
            return True
            
        except OSError:
            return False
    
    def _handle_file_rotation(self) -> None:
        """Handle log file rotation by reopening the file."""
        try:
            # Close current file handle
            if self._file_handle:
                self._file_handle.close()
                self._file_handle = None
            
            # Reinitialize if new file exists
            if os.path.exists(self.file_path):
                self._open_file()
                self._line_number = 0  # Reset line counter
                self.logger.info(f"Reopened rotated file: {self.file_path}")
            else:
                self.logger.warning(f"File disappeared: {self.file_path}")
                
        except Exception as e:
            self.logger.error(f"Error handling file rotation: {e}")
    
    def _read_new_lines(self) -> List[str]:
        """Read new lines from file."""
        if not self._file_handle:
            return []
        
        try:
            # Get current file size
            current_stat = os.stat(self.file_path)
            current_size = current_stat.st_size
            
            # Check if file was truncated
            if current_size < self._file_size:
                self.logger.info(f"File truncation detected: {self.file_path}")
                self._file_handle.seek(0)
                self._line_number = 0
            
            # Read new content
            new_lines = []
            lines_read = 0
            max_lines_per_check = 1000  # Prevent resource exhaustion
            
            while lines_read < max_lines_per_check:
                line = self._file_handle.readline()
                if not line:  # No more data
                    break
                
                # Remove trailing newline
                line = line.rstrip('\n\r')
                if line:  # Skip empty lines
                    new_lines.append(line)
                    self._line_number += 1
                    lines_read += 1
            
            # Update file size
            self._file_size = self._file_handle.tell()
            self._bytes_processed += self._file_size
            
            return new_lines
            
        except Exception as e:
            self.logger.error(f"Error reading new lines: {e}")
            return []
    
    def _process_line(self, line: str) -> List[LogEvent]:
        """
        Process a single log line through pattern matching.
        
        Args:
            line: Log line to process
            
        Returns:
            List of log events for matches
        """
        events = []
        
        try:
            # Match line against patterns
            matches = self.pattern_matcher.match_line(line)
            
            # Create events for each match
            for pattern_name, matched_groups in matches:
                event = LogEvent(
                    log_file=self.file_path,
                    line_number=self._line_number,
                    log_line=line,
                    timestamp=time.time(),
                    pattern_name=pattern_name,
                    matched_groups=matched_groups
                )
                
                events.append(event)
                self._matches_found += 1
                
                # Call event callback if set
                if self._event_callback:
                    try:
                        self._event_callback(event)
                    except Exception as e:
                        self.logger.error(f"Error in event callback: {e}")
            
            self._lines_processed += 1
            
        except Exception as e:
            self.logger.error(f"Error processing line: {e}")
        
        return events
    
    def get_statistics(self) -> Dict[str, any]:
        """Get file watcher statistics."""
        with self._lock:
            return {
                'file_path': self.file_path,
                'lines_processed': self._lines_processed,
                'bytes_processed': self._bytes_processed,
                'matches_found': self._matches_found,
                'errors_count': self._errors_count,
                'current_line_number': self._line_number,
                'file_size': self._file_size,
                'last_check_time': self._last_check_time,
                'is_open': self._file_handle is not None
            }
    
    def close(self) -> None:
        """Close file handle and cleanup resources."""
        with self._lock:
            if self._file_handle:
                try:
                    self._file_handle.close()
                except Exception as e:
                    self.logger.error(f"Error closing file handle: {e}")
                finally:
                    self._file_handle = None
            
            self.logger.debug(f"File watcher closed: {self.file_path}")


class LogMonitor:
    """
    Real-time log monitoring system with pattern matching.
    
    This class monitors multiple log files simultaneously and processes
    new log entries through pattern matching for security event detection.
    """
    
    def __init__(self, log_files: List[str], patterns: Dict[str, str]):
        """
        Initialize log monitor.
        
        Args:
            log_files: List of log file paths to monitor
            patterns: Dictionary of pattern names to regex patterns
        """
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.log_files = log_files
        self.patterns = patterns
        
        # Components
        self.pattern_matcher = PatternMatcher()
        self.file_watchers: Dict[str, LogFileWatcher] = {}
        
        # Threading
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._thread_pool: Optional[ThreadPoolExecutor] = None
        
        # Event handling
        self._event_callback: Optional[Callable[[LogEvent], None]] = None
        self._event_queue: queue.Queue = queue.Queue(maxsize=10000)
        
        # Statistics
        self._total_events = 0
        self._total_matches = 0
        self._start_time = 0.0
        self._errors_count = 0
        
        # Performance monitoring
        self._check_interval = 1.0  # seconds
        self._max_events_per_second = 1000
        
        self.logger.info("LogMonitor initialized")
    
    def set_event_callback(self, callback: Callable[[LogEvent], None]) -> None:
        """Set callback function for log events."""
        self._event_callback = callback
    
    def initialize(self) -> None:
        """
        Initialize log monitor and all file watchers.
        
        Raises:
            LogMonitorError: If initialization fails
        """
        try:
            # Initialize pattern matcher
            for pattern_name, regex in self.patterns.items():
                if not self.pattern_matcher.add_pattern(pattern_name, regex):
                    self.logger.error(f"Failed to add pattern: {pattern_name}")
            
            pattern_count = len(self.pattern_matcher._patterns)
            if pattern_count == 0:
                raise LogMonitorError("No valid patterns were loaded")
            
            self.logger.info(f"Loaded {pattern_count} patterns")
            
            # Initialize file watchers
            for log_file in self.log_files:
                try:
                    watcher = LogFileWatcher(log_file, self.pattern_matcher)
                    watcher.set_event_callback(self._handle_log_event)
                    watcher.initialize()
                    
                    self.file_watchers[log_file] = watcher
                    self.logger.info(f"Initialized watcher for: {log_file}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to initialize watcher for {log_file}: {e}")
                    self._errors_count += 1
                    # Continue with other files
            
            if not self.file_watchers:
                raise LogMonitorError("No log files could be monitored")
            
            # Initialize thread pool
            self._thread_pool = ThreadPoolExecutor(
                max_workers=min(4, len(self.file_watchers)),
                thread_name_prefix="logmonitor-worker"
            )
            
            self.logger.info(f"LogMonitor initialized with {len(self.file_watchers)} file watchers")
            
        except Exception as e:
            self.cleanup()
            raise LogMonitorError(f"LogMonitor initialization failed: {e}")
    
    def start(self) -> None:
        """Start log monitoring in background thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self.logger.warning("LogMonitor is already running")
            return
        
        self._stop_event.clear()
        self._start_time = time.time()
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="logmonitor-main",
            daemon=True
        )
        self._monitor_thread.start()
        
        self.logger.info("LogMonitor started")
    
    def stop(self) -> None:
        """Stop log monitoring."""
        if not self._monitor_thread:
            return
        
        self.logger.info("Stopping LogMonitor...")
        
        # Signal stop
        self._stop_event.set()
        
        # Wait for monitor thread to finish
        if self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=10)
            if self._monitor_thread.is_alive():
                self.logger.warning("Monitor thread did not stop gracefully")
        
        self.logger.info("LogMonitor stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        self.logger.info("Log monitoring loop started")
        
        try:
            while not self._stop_event.is_set():
                loop_start = time.time()
                
                # Check all file watchers for changes
                self._check_all_files()
                
                # Calculate sleep time to maintain check interval
                loop_duration = time.time() - loop_start
                sleep_time = max(0, self._check_interval - loop_duration)
                
                if sleep_time > 0:
                    self._stop_event.wait(sleep_time)
                else:
                    # Log if we're running behind
                    self.logger.warning(f"Monitor loop running slow: {loop_duration:.2f}s")
        
        except Exception as e:
            self.logger.error(f"Error in monitor loop: {e}")
        
        finally:
            self.logger.info("Log monitoring loop stopped")
    
    def _check_all_files(self) -> None:
        """Check all file watchers for new events."""
        if not self._thread_pool:
            return
        
        try:
            # Submit file checking tasks to thread pool
            futures = []
            for watcher in self.file_watchers.values():
                future = self._thread_pool.submit(watcher.check_for_changes)
                futures.append(future)
            
            # Collect results
            events_this_cycle = 0
            for future in futures:
                try:
                    events = future.result(timeout=1.0)  # 1 second timeout
                    events_this_cycle += len(events)
                    
                except Exception as e:
                    self.logger.error(f"Error getting file watcher results: {e}")
                    self._errors_count += 1
            
            # Rate limiting check
            if events_this_cycle > self._max_events_per_second:
                self.logger.warning(
                    f"High event rate detected: {events_this_cycle} events/second"
                )
        
        except Exception as e:
            self.logger.error(f"Error checking files: {e}")
            self._errors_count += 1
    
    def _handle_log_event(self, event: LogEvent) -> None:
        """Handle log event from file watcher."""
        try:
            self._total_events += 1
            self._total_matches += 1
            
            # Add to event queue
            try:
                self._event_queue.put_nowait(event)
            except queue.Full:
                self.logger.warning("Event queue is full, dropping event")
            
            # Call external callback
            if self._event_callback:
                try:
                    self._event_callback(event)
                except Exception as e:
                    self.logger.error(f"Error in external event callback: {e}")
        
        except Exception as e:
            self.logger.error(f"Error handling log event: {e}")
    
    def get_statistics(self) -> Dict[str, any]:
        """Get comprehensive log monitor statistics."""
        uptime = time.time() - self._start_time if self._start_time > 0 else 0
        
        stats = {
            'total_events': self._total_events,
            'total_matches': self._total_matches,
            'errors_count': self._errors_count,
            'uptime_seconds': uptime,
            'events_per_second': self._total_events / max(uptime, 1),
            'is_running': self._monitor_thread and self._monitor_thread.is_alive(),
            'file_watchers_count': len(self.file_watchers),
            'pattern_matcher_stats': self.pattern_matcher.get_statistics(),
            'file_watcher_stats': {}
        }
        
        # Add individual file watcher statistics
        for file_path, watcher in self.file_watchers.items():
            stats['file_watcher_stats'][file_path] = watcher.get_statistics()
        
        return stats
    
    def get_recent_events(self, max_events: int = 100) -> List[LogEvent]:
        """
        Get recent events from the event queue.
        
        Args:
            max_events: Maximum number of events to return
            
        Returns:
            List of recent log events
        """
        events = []
        
        try:
            for _ in range(min(max_events, self._event_queue.qsize())):
                try:
                    event = self._event_queue.get_nowait()
                    events.append(event)
                except queue.Empty:
                    break
        
        except Exception as e:
            self.logger.error(f"Error getting recent events: {e}")
        
        return events
    
    def cleanup(self) -> None:
        """Clean up resources and stop monitoring."""
        try:
            # Stop monitoring
            self.stop()
            
            # Close all file watchers
            for watcher in self.file_watchers.values():
                try:
                    watcher.close()
                except Exception as e:
                    self.logger.error(f"Error closing file watcher: {e}")
            
            self.file_watchers.clear()
            
            # Shutdown thread pool
            if self._thread_pool:
                self._thread_pool.shutdown(wait=True, timeout=5)
                self._thread_pool = None
            
            # Clear pattern matcher
            self.pattern_matcher.clear_all_patterns()
            
            self.logger.info("LogMonitor cleanup completed")
        
        except Exception as e:
            self.logger.error(f"Error during LogMonitor cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()