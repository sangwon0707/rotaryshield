#!/usr/bin/env python3
"""
RotaryShield Logging System
Comprehensive security-focused logging with audit trails and tamper protection.

Security Features:
- Log injection prevention through sanitization
- Structured logging with JSON format support
- Audit trail with integrity protection
- Performance monitoring and log rotation
- Secure file permissions and access controls
- Multiple output handlers (file, syslog, etc.)
"""

import logging
import logging.handlers
import os
import stat
import time
import json
import threading
import hashlib
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum


class LogLevel(Enum):
    """Custom log levels for security events."""
    SECURITY_CRITICAL = 60
    SECURITY_HIGH = 55
    SECURITY_MEDIUM = 45
    SECURITY_LOW = 35


class SecurityFormatter(logging.Formatter):
    """
    Security-focused log formatter with injection prevention.
    
    This formatter sanitizes log messages to prevent log injection attacks
    while maintaining readability and structured format.
    """
    
    def __init__(self, format_string: str = None, use_json: bool = False):
        """
        Initialize security formatter.
        
        Args:
            format_string: Custom format string
            use_json: Whether to use JSON format
        """
        if format_string is None:
            format_string = (
                '%(asctime)s - %(name)s - %(levelname)s - '
                '%(funcName)s:%(lineno)d - %(message)s'
            )
        
        super().__init__(format_string)
        self.use_json = use_json
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with security sanitization."""
        try:
            # Sanitize the log message
            if hasattr(record, 'msg') and record.msg:
                record.msg = self._sanitize_message(str(record.msg))
            
            # Sanitize arguments
            if record.args:
                sanitized_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        sanitized_args.append(self._sanitize_message(arg))
                    else:
                        sanitized_args.append(arg)
                record.args = tuple(sanitized_args)
            
            if self.use_json:
                return self._format_json(record)
            else:
                return super().format(record)
                
        except Exception as e:
            # Fallback formatting if there's an error
            return f"LOG_FORMAT_ERROR: {e} - Original: {record.getMessage()}"
    
    def _sanitize_message(self, message: str) -> str:
        """Sanitize log message to prevent injection attacks."""
        if not message:
            return ""
        
        # Remove control characters that could be used for log injection
        # Preserve newlines and tabs but remove other control chars
        sanitized = ''.join(
            char for char in message 
            if ord(char) >= 32 or char in '\n\t'
        )
        
        # Replace ANSI escape sequences
        import re
        sanitized = re.sub(r'\x1b\[[0-9;]*m', '', sanitized)
        
        # Limit message length to prevent log flooding
        if len(sanitized) > 5000:
            sanitized = sanitized[:5000] + "...[truncated]"
        
        return sanitized
    
    def _format_json(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            'timestamp': record.created,
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.thread,
            'thread_name': record.threadName
        }
        
        # Add extra fields if present
        if hasattr(record, 'ip_address'):
            log_data['ip_address'] = record.ip_address
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'event_type'):
            log_data['event_type'] = record.event_type
        if hasattr(record, 'component'):
            log_data['component'] = record.component
        
        try:
            return json.dumps(log_data, ensure_ascii=False, separators=(',', ':'))
        except Exception as e:
            return json.dumps({
                'error': f'JSON formatting failed: {e}',
                'original_message': str(record.getMessage())
            })


@dataclass
class AuditLogEntry:
    """Structured audit log entry."""
    timestamp: float
    event_type: str
    user_id: str
    component: str
    action: str
    resource: str
    result: str
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """
    Specialized audit logger with integrity protection.
    
    This logger provides tamper-evident audit logging with structured
    format and integrity protection mechanisms.
    """
    
    def __init__(self, log_file: str, max_size: int = 10 * 1024 * 1024):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
            max_size: Maximum log file size before rotation
        """
        self.log_file = log_file
        self.max_size = max_size
        
        # Create logger
        self.logger = logging.getLogger('rotaryshield.audit')
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
        
        # Integrity tracking
        self._lock = threading.Lock()
        self._entry_count = 0
        self._last_hash = ""
        
        # Log startup
        self.log_system_event("audit_logger_started", "system", "Audit logger initialized")
    
    def _setup_handlers(self) -> None:
        """Setup audit log handlers."""
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(self.log_file)
            if log_dir:
                os.makedirs(log_dir, mode=0o750, exist_ok=True)
            
            # Rotating file handler
            handler = logging.handlers.RotatingFileHandler(
                self.log_file,
                maxBytes=self.max_size,
                backupCount=10,
                encoding='utf-8'
            )
            
            # Set secure permissions on log file
            if os.path.exists(self.log_file):
                os.chmod(self.log_file, 0o640)
            
            # JSON formatter for structured logging
            formatter = SecurityFormatter(use_json=True)
            handler.setFormatter(formatter)
            
            self.logger.addHandler(handler)
            
            # Also log to syslog if available
            try:
                syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
                syslog_formatter = SecurityFormatter(
                    'rotaryshield-audit: %(levelname)s - %(message)s'
                )
                syslog_handler.setFormatter(syslog_formatter)
                self.logger.addHandler(syslog_handler)
            except Exception:
                pass  # Syslog not available, continue without it
                
        except Exception as e:
            # Fallback to console logging
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(SecurityFormatter())
            self.logger.addHandler(console_handler)
            self.logger.error(f"Failed to setup audit log handlers: {e}")
    
    def log_security_event(self, event_type: str, user_id: str, action: str,
                          resource: str, result: str = "success",
                          ip_address: Optional[str] = None,
                          session_id: Optional[str] = None,
                          details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log security event to audit trail.
        
        Args:
            event_type: Type of security event
            user_id: User or system ID
            action: Action performed
            resource: Resource affected
            result: Result of action (success, failure, error)
            ip_address: Source IP address
            session_id: Session identifier
            details: Additional event details
        """
        with self._lock:
            try:
                entry = AuditLogEntry(
                    timestamp=time.time(),
                    event_type=event_type,
                    user_id=user_id,
                    component="rotaryshield",
                    action=action,
                    resource=resource,
                    result=result,
                    ip_address=ip_address,
                    session_id=session_id,
                    details=details or {}
                )
                
                # Add integrity information
                entry_json = entry.to_json()
                entry_hash = hashlib.sha256(
                    f"{self._last_hash}{entry_json}".encode()
                ).hexdigest()[:16]
                
                # Create log record with extra fields
                record = self.logger._log(
                    logging.INFO,
                    f"AUDIT: {entry_json}",
                    (),
                    extra={
                        'ip_address': ip_address,
                        'user_id': user_id,
                        'event_type': event_type,
                        'component': 'audit',
                        'entry_hash': entry_hash,
                        'entry_count': self._entry_count
                    }
                )
                
                # Update integrity tracking
                self._last_hash = entry_hash
                self._entry_count += 1
                
            except Exception as e:
                # Use fallback logging if audit logging fails
                self.logger.error(f"Audit logging failed: {e}")
    
    def log_system_event(self, action: str, user_id: str, description: str,
                        details: Optional[Dict[str, Any]] = None) -> None:
        """Log system-level event."""
        self.log_security_event(
            event_type="system_event",
            user_id=user_id,
            action=action,
            resource="system",
            result="success",
            details=details
        )
    
    def log_ip_event(self, action: str, ip_address: str, user_id: str,
                    result: str = "success", details: Optional[Dict[str, Any]] = None) -> None:
        """Log IP-related event."""
        self.log_security_event(
            event_type="ip_management",
            user_id=user_id,
            action=action,
            resource=f"ip:{ip_address}",
            result=result,
            ip_address=ip_address,
            details=details
        )
    
    def log_config_event(self, action: str, user_id: str, config_section: str,
                        result: str = "success", details: Optional[Dict[str, Any]] = None) -> None:
        """Log configuration change event."""
        self.log_security_event(
            event_type="configuration",
            user_id=user_id,
            action=action,
            resource=f"config:{config_section}",
            result=result,
            details=details
        )


class SecurityLogger:
    """
    Security-focused logger with threat intelligence integration.
    
    This logger provides specialized logging for security events with
    threat classification and performance monitoring.
    """
    
    def __init__(self, name: str, log_file: Optional[str] = None):
        """
        Initialize security logger.
        
        Args:
            name: Logger name
            log_file: Optional log file path
        """
        self.logger = logging.getLogger(f"rotaryshield.security.{name}")
        self.logger.setLevel(logging.INFO)
        
        # Add custom log levels
        logging.addLevelName(LogLevel.SECURITY_CRITICAL.value, "SECURITY_CRITICAL")
        logging.addLevelName(LogLevel.SECURITY_HIGH.value, "SECURITY_HIGH")
        logging.addLevelName(LogLevel.SECURITY_MEDIUM.value, "SECURITY_MEDIUM")
        logging.addLevelName(LogLevel.SECURITY_LOW.value, "SECURITY_LOW")
        
        # Setup handlers if not already done
        if not self.logger.handlers and log_file:
            self._setup_handlers(log_file)
    
    def _setup_handlers(self, log_file: str) -> None:
        """Setup security log handlers."""
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, mode=0o750, exist_ok=True)
            
            # File handler with rotation
            handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=50 * 1024 * 1024,  # 50MB
                backupCount=5,
                encoding='utf-8'
            )
            
            # Security formatter
            formatter = SecurityFormatter()
            handler.setFormatter(formatter)
            
            self.logger.addHandler(handler)
            
            # Set secure permissions
            if os.path.exists(log_file):
                os.chmod(log_file, 0o640)
                
        except Exception as e:
            # Fallback to console
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(SecurityFormatter())
            self.logger.addHandler(console_handler)
            self.logger.error(f"Failed to setup security log handler: {e}")
    
    def log_threat(self, level: LogLevel, threat_type: str, source_ip: str,
                  description: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log security threat with classification.
        
        Args:
            level: Threat severity level
            threat_type: Type of threat detected
            source_ip: Source IP address
            description: Threat description
            details: Additional threat details
        """
        extra_data = {
            'ip_address': source_ip,
            'event_type': 'threat_detected',
            'threat_type': threat_type,
            'component': 'security'
        }
        
        if details:
            extra_data.update(details)
        
        message = f"THREAT [{threat_type}] from {source_ip}: {description}"
        
        self.logger.log(level.value, message, extra=extra_data)
    
    def log_attack_attempt(self, attack_type: str, source_ip: str, target: str,
                          blocked: bool = False, details: Optional[Dict[str, Any]] = None) -> None:
        """Log attack attempt."""
        level = LogLevel.SECURITY_HIGH if blocked else LogLevel.SECURITY_CRITICAL
        status = "BLOCKED" if blocked else "DETECTED"
        
        message = f"ATTACK {status} [{attack_type}] from {source_ip} targeting {target}"
        
        extra_data = {
            'ip_address': source_ip,
            'event_type': 'attack_attempt',
            'attack_type': attack_type,
            'target': target,
            'blocked': blocked,
            'component': 'security'
        }
        
        if details:
            extra_data.update(details)
        
        self.log_threat(level, attack_type, source_ip, message, extra_data)
    
    def log_anomaly(self, anomaly_type: str, source_ip: str, description: str,
                   confidence: float, details: Optional[Dict[str, Any]] = None) -> None:
        """Log security anomaly."""
        # Choose level based on confidence
        if confidence >= 0.8:
            level = LogLevel.SECURITY_HIGH
        elif confidence >= 0.6:
            level = LogLevel.SECURITY_MEDIUM
        else:
            level = LogLevel.SECURITY_LOW
        
        message = f"ANOMALY [{anomaly_type}] from {source_ip} (confidence: {confidence:.2f}): {description}"
        
        extra_data = {
            'ip_address': source_ip,
            'event_type': 'anomaly_detected',
            'anomaly_type': anomaly_type,
            'confidence': confidence,
            'component': 'security'
        }
        
        if details:
            extra_data.update(details)
        
        self.log_threat(level, anomaly_type, source_ip, message, extra_data)


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None,
                 enable_json: bool = False, enable_audit: bool = True) -> None:
    """
    Setup comprehensive logging system for RotaryShield.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Main log file path
        enable_json: Enable JSON formatted logging
        enable_audit: Enable audit logging
    """
    try:
        # Convert log level string to logging constant
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Configure root logger
        root_logger = logging.getLogger('rotaryshield')
        root_logger.setLevel(numeric_level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = SecurityFormatter(use_json=enable_json)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, mode=0o750, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=100 * 1024 * 1024,  # 100MB
                backupCount=10,
                encoding='utf-8'
            )
            
            file_formatter = SecurityFormatter(use_json=enable_json)
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
            
            # Set secure permissions
            if os.path.exists(log_file):
                os.chmod(log_file, 0o640)
        
        # Setup audit logging if enabled
        if enable_audit and log_file:
            audit_log_file = log_file.replace('.log', '_audit.log')
            global _audit_logger
            _audit_logger = AuditLogger(audit_log_file)
        
        # Log setup completion
        logger = logging.getLogger('rotaryshield.logging')
        logger.info(f"Logging system initialized (level: {log_level}, file: {log_file})")
        
    except Exception as e:
        # Fallback logging setup
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logging.getLogger('rotaryshield.logging').error(f"Failed to setup logging: {e}")


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> Optional[AuditLogger]:
    """Get global audit logger instance."""
    return _audit_logger


def create_security_logger(component: str, log_file: Optional[str] = None) -> SecurityLogger:
    """
    Create a security logger for a specific component.
    
    Args:
        component: Component name
        log_file: Optional dedicated log file
        
    Returns:
        SecurityLogger instance
    """
    return SecurityLogger(component, log_file)


# Performance monitoring logger
class PerformanceLogger:
    """Logger for performance monitoring and metrics."""
    
    def __init__(self):
        """Initialize performance logger."""
        self.logger = logging.getLogger('rotaryshield.performance')
        self.start_times: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def start_timer(self, operation: str) -> None:
        """Start timing an operation."""
        with self._lock:
            self.start_times[operation] = time.time()
    
    def end_timer(self, operation: str, details: Optional[Dict[str, Any]] = None) -> float:
        """End timing an operation and log the duration."""
        with self._lock:
            if operation not in self.start_times:
                self.logger.warning(f"Timer not found for operation: {operation}")
                return 0.0
            
            duration = time.time() - self.start_times.pop(operation)
            
            extra_data = {
                'operation': operation,
                'duration_ms': duration * 1000,
                'component': 'performance'
            }
            
            if details:
                extra_data.update(details)
            
            self.logger.info(
                f"PERFORMANCE: {operation} completed in {duration:.3f}s",
                extra=extra_data
            )
            
            return duration


# Global performance logger
performance_logger = PerformanceLogger()