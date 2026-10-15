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
from dataclasses import dataclass, field, replace
from concurrent.futures import ThreadPoolExecutor, Future
from threading import RLock, Event as ThreadEvent
import queue
import weakref
import json

from .bans import BanController, select_backend, remember_backend
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
        self._event_threads = []
        self.ban_controller = None
        self._event_lock = RLock()
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
        # The daemon owns process signals; embedding an engine must not replace them.
        
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
                backend = select_backend(self.database_manager, self.config.ban.firewall_backend)
                self.firewall_manager = FirewallManager(backend)
                self.firewall_manager.initialize()
                remember_backend(self.database_manager, self.firewall_manager.get_current_backend())
                self.logger.info("Firewall manager initialized")
                
                # Initialize log monitor
                self.log_monitor = LogMonitor(
                    log_files=self.config.detection.log_files,
                    patterns=self.config.detection.patterns
                )
                self.log_monitor.set_event_callback(self._handle_log_event)
                self.log_monitor.initialize()
                self.ban_controller = BanController(
                    self.database_manager, self.firewall_manager, self.config.ban.whitelist_ips)
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
        self._banned_ips = self.ban_controller.reconcile(restore=True)
        self.logger.info("Reconciled %d existing bans", len(self._banned_ips))

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
                self._shutdown_event.clear()
                
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
                self.shutdown()
                raise SecurityEngineError(f"Start failed: {e}")
    
    def _start_performance_monitor(self) -> None:
        """Start performance monitoring thread."""
        def monitor_performance():
            while not self._shutdown_event.is_set():
                try:
                    self._update_performance_metrics()
                    self._check_resource_limits()
                    self._maintain_bans()
                except Exception as e:
                    self.logger.error(f"Performance monitoring error: {e}")
                
                # Wait for next update or shutdown signal
                self._shutdown_event.wait(timeout=5.0)
        
        self._performance_monitor_thread = threading.Thread(
            target=monitor_performance,
            name="rotaryshield-performance-monitor",
            daemon=True
        )
        self._performance_monitor_thread.start()
    
    def _start_event_processor(self) -> None:
        """Start event processing threads."""
        def process_events():
            # Drain accepted events before exiting, including during shutdown.
            while not self._shutdown_event.is_set() or not self.event_queue.empty():
                try:
                    event = self.event_queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    self._process_security_event(event)
                except Exception:
                    self.logger.exception("Event processing failed")
                finally:
                    self.event_queue.task_done()

        thread = threading.Thread(target=process_events, name="rotaryshield-events", daemon=True)
        self._event_threads = [thread]
        thread.start()

    def _maintain_bans(self):
        with self._event_lock:
            active = self.ban_controller.reconcile()
            for address in self._banned_ips - active:
                self._active_threats.pop(address, None)
                self._throttled_ips.pop(address, None)
            self._banned_ips = active
            cutoff = time.time() - self.config.detection.time_window
            for address in list(self._active_threats):
                events = [event for event in self._active_threats[address] if event.timestamp >= cutoff]
                if events:
                    self._active_threats[address] = events
                else:
                    self._active_threats.pop(address, None)
                    self._throttled_ips.pop(address, None)

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
            if self._shutdown_event.is_set():
                return
            # Add to event queue for processing
            self.event_queue.put(event, timeout=1.0)
            
        except queue.Full:
            self.logger.error("Event queue is full, dropping event")
            # Could implement event priority queuing here
        except Exception as e:
            self.logger.error(f"Failed to submit event: {e}")
    
    def _process_security_event(self, event: SecurityEvent) -> None:
        with self._event_lock:
            self._process_event_locked(event)

    def _process_event_locked(self, event: SecurityEvent) -> None:
        """Process security event through 3-layer system."""
        start_time = time.time()
        
        try:
            # Update metrics
            with self._metrics_lock:
                self.metrics.events_processed += 1
            
            if event.source_ip and self.ban_controller.is_whitelisted(event.source_ip):
                return
            # Clear manual removals/expiry before considering a new decision.
            if event.source_ip in self._banned_ips:
                rows = self.database_manager.execute_query(
                    "SELECT status, expires_at FROM ip_bans WHERE ip_address = ?", (event.source_ip,))
                if rows and rows['status'] == 'active' and rows['expires_at'] > time.time():
                    return
                self._banned_ips.discard(event.source_ip)
                self._active_threats.pop(event.source_ip, None)
            # Layer 1: Detection and Classification
            self._layer1_detection(event)
            if event.source_ip:
                event = replace(event, threat_level=self._assess_threat_level(event.event_type, event.source_ip))
            
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
            
            # Persist the result, including actions that actually succeeded.
            self.database_manager.execute_query(
                """INSERT INTO security_events
                (event_id, event_type, severity, timestamp, processed_at, source_ip,
                 description, raw_log_data, pattern_matched, actions_taken, detection_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.event_id, event.event_type.value, event.threat_level.name.lower(),
                 event.timestamp, time.time(), event.source_ip, event.message,
                 event.raw_log_line, event.pattern_matched,
                 json.dumps([action.value for action in event.actions_taken]), 'log_monitor'))
            self._log_security_event(event)
            
            # Update processing time metrics
            processing_time = (time.time() - start_time) * 1000  # milliseconds
            with self._metrics_lock:
                self.metrics.processing_time_total += processing_time
            
        except Exception as e:
            self.logger.error(f"Error processing security event {event.event_id}: {e}")

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
        # No backend currently enforces service-level throttling. Emit a warning
        # once per observation window without claiming to have limited traffic.
        if not event.source_ip:
            return []
        count = len(self._active_threats.get(event.source_ip, []))
        if count >= self.config.detection.max_retry and event.source_ip not in self._throttled_ips:
            self._throttled_ips[event.source_ip] = time.time()
            self.logger.warning("Repeated failures from %s; observing until ban threshold (throttling is unavailable)",
                                event.source_ip)
        return []

    def _layer3_blocking(self, event: SecurityEvent) -> List[ActionType]:
        if not event.source_ip or event.source_ip in self._banned_ips:
            return []
        count = len(self._active_threats.get(event.source_ip, []))
        if count < self.config.detection.ban_threshold and event.threat_level < ThreatLevel.CRITICAL:
            return []
        try:
            if self.ban_controller.ban(event.source_ip, self.config.ban.ban_time,
                                       "Automated ban: " + event.event_type.value):
                self._banned_ips.add(event.source_ip)
                with self._metrics_lock:
                    self.metrics.ips_banned += 1
                return [ActionType.TEMPORARY_BAN]
        except Exception:
            self.logger.exception("Failed to enforce ban for %s", event.source_ip)
        return []

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
        with self._event_lock:
            try:
                import ipaddress
                address = str(ipaddress.ip_address(ip_address))
                if not self.ban_controller.unban(address, reason):
                    return False
                self._banned_ips.discard(address)
                self._active_threats.pop(address, None)
                self._throttled_ips.pop(address, None)
                return True
            except Exception:
                self.logger.exception("Failed to unban %s", ip_address)
                return False

    def is_running(self) -> bool:
        """Check if security engine is running."""
        with self._state_lock:
            return self._is_running
    
    def shutdown(self) -> None:
        # Never hold the state/event lock while joining workers that need it.
        # Stop and join producers before asking the consumer to drain and exit.
        if self.log_monitor:
            self.log_monitor.cleanup()
        self._shutdown_event.set()
        for thread in self._event_threads:
            if thread is not threading.current_thread():
                thread.join()
        if self._performance_monitor_thread and self._performance_monitor_thread is not threading.current_thread():
            self._performance_monitor_thread.join()
        self._cleanup_components()
        with self._state_lock:
            self._is_running = False
            self._is_initialized = False
        self.logger.info("SecurityEngine shutdown completed")

    def _cleanup_components(self) -> None:
        for component in (self.log_monitor, self.ip_manager, self.firewall_manager):
            if component:
                try:
                    component.cleanup()
                except Exception:
                    self.logger.exception("Component cleanup failed")
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None
        if self.database_manager:
            self.database_manager.close()
        self._active_threats.clear()
        self._throttled_ips.clear()
        self._banned_ips.clear()

    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
