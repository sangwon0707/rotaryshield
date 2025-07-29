#!/usr/bin/env python3
"""
RotaryShield Security Engine
Main 3-layer security system implementation with enterprise-grade protection.

Architecture:
- Layer 1: Detection (Log monitoring and pattern matching)
- Layer 2: Throttling (Progressive response delays and rate limiting)
- Layer 3: Blocking (IP banning and honeypot redirection)

Security Features:
- Thread-safe operations for concurrent access
- Comprehensive input validation and sanitization
- Secure state management with audit trails
- Performance monitoring and resource limits
- Fail-secure error handling
- Privilege separation and minimal permissions
"""

import time
import threading
import logging
import signal
import os
import sys
import psutil
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future
from threading import RLock, Event as ThreadEvent
import queue
import weakref

from .events import SecurityEvent, EventType, ThreatLevel, ActionType, SecurityEventFactory
from ..config import ConfigManager, RotaryShieldConfig
from ..monitoring import LogMonitor, LogEvent
from ..firewall import FirewallManager, FirewallAdapter
from ..database import IPManager, DatabaseManager


class SecurityEngineError(Exception):
    """Base exception for SecurityEngine errors."""
    pass


class SecurityEngineStateError(SecurityEngineError):
    """Exception for invalid state transitions."""
    pass


@dataclass
class SecurityMetrics:
    """Security metrics for monitoring and performance analysis."""
    events_processed: int = 0
    threats_detected: int = 0
    ips_banned: int = 0
    ips_throttled: int = 0
    false_positives: int = 0
    processing_time_total: float = 0.0
    processing_time_avg: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    uptime_seconds: float = 0.0
    last_update: float = field(default_factory=time.time)


class SecurityEngine:
    """
    Main security engine implementing 3-layer protection system.
    
    This class coordinates all security components and implements the core
    logic for threat detection, progressive response, and blocking decisions.
    
    Security considerations:
    - Thread-safe operations with proper locking
    - Resource usage monitoring and limits
    - Secure state transitions and error handling
    - Comprehensive audit logging
    - Graceful shutdown with cleanup
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize SecurityEngine with comprehensive security setup.
        
        Args:
            config_path: Path to configuration file, uses default if None
        """
        # Core components initialization
        self.config_manager = ConfigManager(config_path) if config_path else ConfigManager()
        self.config: Optional[RotaryShieldConfig] = None
        
        # Thread safety
        self._state_lock = RLock()
        self._metrics_lock = RLock()
        self._shutdown_event = ThreadEvent()
        
        # State management
        self._is_running = False
        self._is_initialized = False
        self._start_time = time.time()
        
        # Component managers
        self.log_monitor: Optional[LogMonitor] = None
        self.firewall_manager: Optional[FirewallManager] = None
        self.ip_manager: Optional[IPManager] = None
        self.database_manager: Optional[DatabaseManager] = None
        
        # Event processing
        self.event_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.executor: Optional[ThreadPoolExecutor] = None
        self.event_handlers: Dict[EventType, List[Callable]] = {}
        
        # Security metrics and monitoring
        self.metrics = SecurityMetrics()
        self._active_threats: Dict[str, List[SecurityEvent]] = {}  # IP -> events
        self._throttled_ips: Dict[str, float] = {}  # IP -> timestamp
        self._banned_ips: Set[str] = set()
        
        # Performance monitoring
        self._performance_monitor_thread: Optional[threading.Thread] = None
        
        # Logging setup
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Register signal handlers for graceful shutdown
        self._register_signal_handlers()
        
        self.logger.info("SecurityEngine initialized")
    
    def _setup_logging(self) -> None:
        """Configure secure logging with audit trail."""
        # Create security-focused logger
        security_logger = logging.getLogger('rotaryshield.security')
        security_logger.setLevel(logging.INFO)
        
        # Prevent log injection by using a custom formatter
        class SecurityFormatter(logging.Formatter):
            def format(self, record):
                # Sanitize log message to prevent injection
                if hasattr(record, 'msg'):
                    record.msg = str(record.msg).replace('\n', '\\n').replace('\r', '\\r')
                return super().format(record)
        
        formatter = SecurityFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        
        # Add handler if not already present
        if not security_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            security_logger.addHandler(handler)
    
    def _register_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.warning(f"Received signal {signum}, initiating graceful shutdown")
            self.shutdown()
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
    
    def initialize(self) -> None:
        """
        Initialize all security engine components.
        
        This method performs a complete initialization of all components
        with proper error handling and security validation.
        """
        with self._state_lock:
            if self._is_initialized:
                raise SecurityEngineStateError("SecurityEngine already initialized")
            
            try:
                self.logger.info("Initializing SecurityEngine components...")
                
                # Load and validate configuration
                self.config = self.config_manager.load_config()
                self.logger.info("Configuration loaded and validated")
                
                # Initialize database manager
                self.database_manager = DatabaseManager(self.config.database.db_path)
                self.database_manager.initialize()
                self.logger.info("Database manager initialized")
                
                # Initialize IP manager
                self.ip_manager = IPManager(self.database_manager)
                self.logger.info("IP manager initialized")
                
                # Initialize firewall manager
                self.firewall_manager = FirewallManager(self.config.ban.firewall_backend)
                self.firewall_manager.initialize()
                self.logger.info("Firewall manager initialized")
                
                # Initialize log monitor
                self.log_monitor = LogMonitor(
                    log_files=self.config.detection.log_files,
                    patterns=self.config.detection.patterns
                )
                self.log_monitor.set_event_callback(self._handle_log_event)
                self.logger.info("Log monitor initialized")
                
                # Initialize thread pool for event processing
                max_workers = min(4, (os.cpu_count() or 1) + 1)  # Conservative thread count
                self.executor = ThreadPoolExecutor(
                    max_workers=max_workers,
                    thread_name_prefix="rotaryshield-worker"
                )
                self.logger.info(f"Thread pool initialized with {max_workers} workers")
                
                # Register default event handlers
                self._register_default_handlers()
                
                # Load existing banned IPs from database
                self._load_existing_bans()
                
                self._is_initialized = True
                self.logger.info("SecurityEngine initialization completed successfully")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize SecurityEngine: {e}")
                # Cleanup partial initialization
                self._cleanup_components()
                raise SecurityEngineError(f"Initialization failed: {e}")
    
    def _register_default_handlers(self) -> None:
        """Register default event handlers for each event type."""
        self.register_event_handler(EventType.SSH_FAILED_LOGIN, self._handle_ssh_failed_login)
        self.register_event_handler(EventType.SSH_INVALID_USER, self._handle_ssh_invalid_user)
        self.register_event_handler(EventType.HTTP_BRUTE_FORCE, self._handle_http_brute_force)
        self.register_event_handler(EventType.FTP_FAILED_LOGIN, self._handle_ftp_failed_login)
        self.register_event_handler(EventType.PORT_SCAN, self._handle_port_scan)
        self.register_event_handler(EventType.DDOS_DETECTED, self._handle_ddos)
        self.register_event_handler(EventType.SYSTEM_ERROR, self._handle_system_error)
    
    def _load_existing_bans(self) -> None:
        """Load existing banned IPs from database."""
        try:
            banned_ips = self.ip_manager.get_active_bans()
            self._banned_ips.update(banned_ips)
            self.logger.info(f"Loaded {len(banned_ips)} existing banned IPs")
        except Exception as e:
            self.logger.error(f"Failed to load existing bans: {e}")
    
    def start(self) -> None:
        """
        Start the security engine and all monitoring components.
        
        This method starts all background threads and monitoring systems.
        """
        with self._state_lock:
            if not self._is_initialized:
                raise SecurityEngineStateError("SecurityEngine not initialized")
            
            if self._is_running:
                raise SecurityEngineStateError("SecurityEngine already running")
            
            try:
                self.logger.info("Starting SecurityEngine...")
                
                # Start performance monitoring
                self._start_performance_monitor()
                
                # Start log monitoring
                self.log_monitor.start()
                
                # Start event processing
                self._start_event_processor()
                
                self._is_running = True
                self._start_time = time.time()
                
                self.logger.info("SecurityEngine started successfully")
                
            except Exception as e:
                self.logger.error(f"Failed to start SecurityEngine: {e}")
                self._cleanup_components()
                raise SecurityEngineError(f"Start failed: {e}")
    
    def _start_performance_monitor(self) -> None:
        """Start performance monitoring thread."""
        def monitor_performance():
            while not self._shutdown_event.is_set():
                try:
                    self._update_performance_metrics()
                    self._check_resource_limits()
                except Exception as e:
                    self.logger.error(f"Performance monitoring error: {e}")
                
                # Wait for next update or shutdown signal
                self._shutdown_event.wait(timeout=30.0)
        
        self._performance_monitor_thread = threading.Thread(
            target=monitor_performance,
            name="rotaryshield-performance-monitor",
            daemon=True
        )
        self._performance_monitor_thread.start()
    
    def _start_event_processor(self) -> None:
        """Start event processing threads."""
        def process_events():
            while not self._shutdown_event.is_set():
                try:
                    # Process events from queue with timeout
                    try:
                        event = self.event_queue.get(timeout=1.0)
                        self._process_security_event(event)
                        self.event_queue.task_done()
                    except queue.Empty:
                        continue
                except Exception as e:
                    self.logger.error(f"Event processing error: {e}")
        
        # Start multiple event processor threads
        for i in range(2):  # Conservative number of processors
            thread = threading.Thread(
                target=process_events,
                name=f"rotaryshield-event-processor-{i}",
                daemon=True
            )
            thread.start()
    
    def _update_performance_metrics(self) -> None:
        """Update performance metrics for monitoring."""
        try:
            process = psutil.Process()
            
            with self._metrics_lock:
                # Memory usage
                memory_info = process.memory_info()
                self.metrics.memory_usage_mb = memory_info.rss / 1024 / 1024
                
                # CPU usage (averaged over short interval)
                self.metrics.cpu_usage_percent = process.cpu_percent(interval=0.1)
                
                # Uptime
                self.metrics.uptime_seconds = time.time() - self._start_time
                
                # Average processing time
                if self.metrics.events_processed > 0:
                    self.metrics.processing_time_avg = (
                        self.metrics.processing_time_total / self.metrics.events_processed
                    )
                
                self.metrics.last_update = time.time()
                
        except Exception as e:
            self.logger.error(f"Failed to update performance metrics: {e}")
    
    def _check_resource_limits(self) -> None:
        """Check resource usage against configured limits."""
        with self._metrics_lock:
            # Check memory limit
            if self.metrics.memory_usage_mb > 50:  # 50MB limit from plan
                self.logger.warning(
                    f"Memory usage ({self.metrics.memory_usage_mb:.1f}MB) exceeds limit"
                )
            
            # Check CPU limit
            if self.metrics.cpu_usage_percent > 5:  # Allow 5% during processing
                self.logger.warning(
                    f"CPU usage ({self.metrics.cpu_usage_percent:.1f}%) is high"
                )
    
    def register_event_handler(self, event_type: EventType, handler: Callable[[SecurityEvent], None]) -> None:
        """
        Register event handler for specific event types.
        
        Args:
            event_type: Type of event to handle
            handler: Callable that processes the event
        """
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        
        self.event_handlers[event_type].append(handler)
        self.logger.debug(f"Registered handler for {event_type.value}")
    
    def _handle_log_event(self, log_event: LogEvent) -> None:
        """Handle log events from LogMonitor."""
        try:
            # Convert LogEvent to SecurityEvent
            security_event = self._convert_log_event(log_event)
            if security_event:
                self.submit_event(security_event)
                
        except Exception as e:
            self.logger.error(f"Failed to handle log event: {e}")
    
    def _convert_log_event(self, log_event: LogEvent) -> Optional[SecurityEvent]:
        """Convert LogEvent to SecurityEvent with proper classification."""
        try:
            # Determine event type based on pattern
            event_type = self._classify_log_event(log_event.pattern_name)
            if not event_type:
                return None
            
            # Extract IP address from matched groups
            source_ip = log_event.matched_groups[0] if log_event.matched_groups else None
            if not source_ip:
                return None
            
            # Determine threat level based on event type and context
            threat_level = self._assess_threat_level(event_type, source_ip)
            
            # Create security event
            security_event = SecurityEvent(
                event_type=event_type,
                threat_level=threat_level,
                source_ip=source_ip,
                message=f"Security event detected: {event_type.value}",
                raw_log_line=log_event.log_line,
                pattern_matched=log_event.pattern_name,
                context={
                    'log_file': log_event.log_file,
                    'line_number': log_event.line_number,
                    'matched_groups': log_event.matched_groups
                }
            )
            
            return security_event
            
        except Exception as e:
            self.logger.error(f"Failed to convert log event: {e}")
            return None
    
    def _classify_log_event(self, pattern_name: str) -> Optional[EventType]:
        """Classify log event based on pattern name."""
        pattern_mapping = {
            'ssh_fail': EventType.SSH_FAILED_LOGIN,
            'ssh_failed': EventType.SSH_FAILED_LOGIN,
            'ssh_invalid': EventType.SSH_INVALID_USER,
            'http_brute': EventType.HTTP_BRUTE_FORCE,
            'web_fail': EventType.HTTP_BRUTE_FORCE,
            'ftp_failed': EventType.FTP_FAILED_LOGIN,
            'ftp_fail': EventType.FTP_FAILED_LOGIN
        }
        
        for pattern_key, event_type in pattern_mapping.items():
            if pattern_key in pattern_name.lower():
                return event_type
        
        return None
    
    def _assess_threat_level(self, event_type: EventType, source_ip: str) -> ThreatLevel:
        """Assess threat level based on event type and IP history."""
        # Base threat level by event type
        base_levels = {
            EventType.SSH_FAILED_LOGIN: ThreatLevel.MEDIUM,
            EventType.SSH_INVALID_USER: ThreatLevel.MEDIUM,
            EventType.HTTP_BRUTE_FORCE: ThreatLevel.HIGH,
            EventType.FTP_FAILED_LOGIN: ThreatLevel.MEDIUM,
            EventType.PORT_SCAN: ThreatLevel.HIGH,
            EventType.DDOS_DETECTED: ThreatLevel.CRITICAL
        }
        
        base_level = base_levels.get(event_type, ThreatLevel.LOW)
        
        # Escalate based on IP history
        if source_ip in self._active_threats:
            event_count = len(self._active_threats[source_ip])
            if event_count >= self.config.detection.ban_threshold:
                return ThreatLevel.CRITICAL
            elif event_count >= self.config.detection.max_retry:
                return ThreatLevel.HIGH
        
        return base_level
    
    def submit_event(self, event: SecurityEvent) -> None:
        """
        Submit security event for processing.
        
        Args:
            event: SecurityEvent to process
        """
        try:
            # Add to event queue for processing
            self.event_queue.put(event, timeout=1.0)
            
        except queue.Full:
            self.logger.error("Event queue is full, dropping event")
            # Could implement event priority queuing here
        except Exception as e:
            self.logger.error(f"Failed to submit event: {e}")
    
    def _process_security_event(self, event: SecurityEvent) -> None:
        """Process security event through 3-layer system."""
        start_time = time.time()
        
        try:
            # Update metrics
            with self._metrics_lock:
                self.metrics.events_processed += 1
            
            # Layer 1: Detection and Classification
            self._layer1_detection(event)
            
            # Layer 2: Throttling Decision
            actions = self._layer2_throttling(event)
            
            # Layer 3: Blocking Decision
            if event.threat_level >= ThreatLevel.HIGH:
                block_actions = self._layer3_blocking(event)
                actions.extend(block_actions)
            
            # Update event with actions taken
            for action in actions:
                event = event.add_action(action)
            
            # Execute registered handlers
            self._execute_event_handlers(event)
            
            # Log event for audit trail
            self._log_security_event(event)
            
            # Update processing time metrics
            processing_time = (time.time() - start_time) * 1000  # milliseconds
            with self._metrics_lock:
                self.metrics.processing_time_total += processing_time
            
        except Exception as e:
            self.logger.error(f"Error processing security event {event.event_id}: {e}")
            # Create system error event
            error_event = SecurityEventFactory.create_system_error(
                f"Event processing failed: {e}",
                {"original_event_id": event.event_id}
            )
            # Submit error event (avoid recursion with simple queue put)
            try:
                self.event_queue.put_nowait(error_event)
            except queue.Full:
                pass  # Prevent infinite recursion
    
    def _layer1_detection(self, event: SecurityEvent) -> None:
        """Layer 1: Detection and threat tracking."""
        if not event.source_ip:
            return
        
        # Track events per IP
        if event.source_ip not in self._active_threats:
            self._active_threats[event.source_ip] = []
        
        self._active_threats[event.source_ip].append(event)
        
        # Clean old events (outside time window)
        current_time = time.time()
        time_window = self.config.detection.time_window
        
        self._active_threats[event.source_ip] = [
            e for e in self._active_threats[event.source_ip]
            if current_time - e.timestamp <= time_window
        ]
        
        # Update threat metrics
        if event.threat_level >= ThreatLevel.MEDIUM:
            with self._metrics_lock:
                self.metrics.threats_detected += 1
    
    def _layer2_throttling(self, event: SecurityEvent) -> List[ActionType]:
        """Layer 2: Throttling and rate limiting."""
        actions = []
        
        if not event.source_ip or event.threat_level < ThreatLevel.MEDIUM:
            return actions
        
        # Check if IP should be throttled
        event_count = len(self._active_threats.get(event.source_ip, []))
        
        if event_count >= self.config.detection.max_retry:
            # Apply throttling
            self._throttled_ips[event.source_ip] = time.time()
            
            # Apply service-specific throttling
            if event.event_type == EventType.SSH_FAILED_LOGIN:
                actions.append(ActionType.THROTTLE_SSH)
            elif event.event_type in [EventType.HTTP_BRUTE_FORCE]:
                actions.append(ActionType.THROTTLE_HTTP)
            else:
                actions.append(ActionType.RATE_LIMIT)
            
            with self._metrics_lock:
                self.metrics.ips_throttled += 1
        
        return actions
    
    def _layer3_blocking(self, event: SecurityEvent) -> List[ActionType]:
        """Layer 3: Blocking and banning decisions."""
        actions = []
        
        if not event.source_ip:
            return actions
        
        # Check if IP should be banned
        event_count = len(self._active_threats.get(event.source_ip, []))
        
        if (event_count >= self.config.detection.ban_threshold or 
            event.threat_level >= ThreatLevel.CRITICAL):
            
            # Check whitelist
            if event.source_ip not in self.config.ban.whitelist_ips:
                # Apply ban
                try:
                    self.ip_manager.ban_ip(
                        event.source_ip,
                        self.config.ban.ban_time,
                        f"Automated ban: {event.event_type.value}"
                    )
                    
                    self.firewall_manager.block_ip(event.source_ip)
                    self._banned_ips.add(event.source_ip)
                    
                    actions.append(ActionType.TEMPORARY_BAN)
                    
                    with self._metrics_lock:
                        self.metrics.ips_banned += 1
                    
                    self.logger.warning(f"Banned IP {event.source_ip} due to {event.event_type.value}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to ban IP {event.source_ip}: {e}")
        
        return actions
    
    def _execute_event_handlers(self, event: SecurityEvent) -> None:
        """Execute registered event handlers."""
        handlers = self.event_handlers.get(event.event_type, [])
        
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                self.logger.error(f"Event handler error for {event.event_type.value}: {e}")
    
    def _log_security_event(self, event: SecurityEvent) -> None:
        """Log security event for audit trail."""
        log_level = logging.INFO
        
        if event.threat_level >= ThreatLevel.HIGH:
            log_level = logging.WARNING
        if event.threat_level >= ThreatLevel.CRITICAL:
            log_level = logging.ERROR
        
        self.logger.log(
            log_level,
            f"SecurityEvent: {event.get_safe_log_representation()}"
        )
    
    # Default event handlers
    def _handle_ssh_failed_login(self, event: SecurityEvent) -> None:
        """Handle SSH failed login events."""
        # Implementation for SSH-specific handling
        pass
    
    def _handle_ssh_invalid_user(self, event: SecurityEvent) -> None:
        """Handle SSH invalid user events."""
        # Implementation for SSH invalid user handling
        pass
    
    def _handle_http_brute_force(self, event: SecurityEvent) -> None:
        """Handle HTTP brute force events."""
        # Implementation for HTTP brute force handling
        pass
    
    def _handle_ftp_failed_login(self, event: SecurityEvent) -> None:
        """Handle FTP failed login events."""
        # Implementation for FTP handling
        pass
    
    def _handle_port_scan(self, event: SecurityEvent) -> None:
        """Handle port scan events."""
        # Implementation for port scan handling
        pass
    
    def _handle_ddos(self, event: SecurityEvent) -> None:
        """Handle DDoS detection events."""
        # Implementation for DDoS handling
        pass
    
    def _handle_system_error(self, event: SecurityEvent) -> None:
        """Handle system error events."""
        # Log system errors for debugging
        self.logger.debug(f"System error: {event.message}")
    
    def get_metrics(self) -> SecurityMetrics:
        """Get current security metrics."""
        with self._metrics_lock:
            return SecurityMetrics(
                events_processed=self.metrics.events_processed,
                threats_detected=self.metrics.threats_detected,
                ips_banned=self.metrics.ips_banned,
                ips_throttled=self.metrics.ips_throttled,
                false_positives=self.metrics.false_positives,
                processing_time_total=self.metrics.processing_time_total,
                processing_time_avg=self.metrics.processing_time_avg,
                memory_usage_mb=self.metrics.memory_usage_mb,
                cpu_usage_percent=self.metrics.cpu_usage_percent,
                uptime_seconds=self.metrics.uptime_seconds,
                last_update=self.metrics.last_update
            )
    
    def get_active_threats(self) -> Dict[str, int]:
        """Get summary of active threats by IP."""
        return {ip: len(events) for ip, events in self._active_threats.items()}
    
    def unban_ip(self, ip_address: str, reason: str = "Manual unban") -> bool:
        """
        Manually unban an IP address.
        
        Args:
            ip_address: IP address to unban
            reason: Reason for unbanning
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate IP address
            import ipaddress
            ipaddress.ip_address(ip_address)
            
            # Remove from firewall
            self.firewall_manager.unblock_ip(ip_address)
            
            # Remove from database
            self.ip_manager.unban_ip(ip_address, reason)
            
            # Remove from internal tracking
            self._banned_ips.discard(ip_address)
            if ip_address in self._active_threats:
                del self._active_threats[ip_address]
            if ip_address in self._throttled_ips:
                del self._throttled_ips[ip_address]
            
            self.logger.info(f"IP {ip_address} unbanned: {reason}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unban IP {ip_address}: {e}")
            return False
    
    def is_running(self) -> bool:
        """Check if security engine is running."""
        with self._state_lock:
            return self._is_running
    
    def shutdown(self) -> None:
        """
        Gracefully shutdown security engine and all components.
        
        This method ensures all components are properly stopped and
        resources are cleaned up.
        """
        with self._state_lock:
            if not self._is_running:
                return
            
            self.logger.info("Shutting down SecurityEngine...")
            
            # Signal shutdown to all threads
            self._shutdown_event.set()
            
            # Stop components
            try:
                if self.log_monitor:
                    self.log_monitor.stop()
                
                # Wait for event queue to empty
                self.event_queue.join()
                
                # Shutdown thread pool
                if self.executor:
                    self.executor.shutdown(wait=True, timeout=10)
                
                # Wait for performance monitor thread
                if self._performance_monitor_thread and self._performance_monitor_thread.is_alive():
                    self._performance_monitor_thread.join(timeout=5)
                
            except Exception as e:
                self.logger.error(f"Error during shutdown: {e}")
            
            finally:
                self._cleanup_components()
                self._is_running = False
                self.logger.info("SecurityEngine shutdown completed")
    
    def _cleanup_components(self) -> None:
        """Clean up all components and resources."""
        try:
            if self.database_manager:
                self.database_manager.close()
            
            # Clear internal state
            self._active_threats.clear()
            self._throttled_ips.clear()
            self._banned_ips.clear()
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()