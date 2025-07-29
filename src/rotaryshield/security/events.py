#!/usr/bin/env python3
"""
RotaryShield Security Events System
Defines security events and threat levels for the 3-layer architecture.

Security Features:
- Input validation for all event data
- Sanitized logging to prevent log injection
- Immutable event objects for audit integrity
- Comprehensive threat level classification
"""

import time
import uuid
import ipaddress
import logging
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import re


class EventType(Enum):
    """Security event types for classification and processing."""
    SSH_FAILED_LOGIN = "ssh_failed_login"
    SSH_INVALID_USER = "ssh_invalid_user"
    HTTP_BRUTE_FORCE = "http_brute_force"
    FTP_FAILED_LOGIN = "ftp_failed_login"
    DDOS_DETECTED = "ddos_detected"
    PORT_SCAN = "port_scan"
    HONEYPOT_TRIGGER = "honeypot_trigger"
    CONFIG_CHANGE = "config_change"
    SYSTEM_ERROR = "system_error"
    WHITELIST_BYPASS = "whitelist_bypass"


class ThreatLevel(IntEnum):
    """Threat levels for progressive response system."""
    INFO = 1        # Information only, no action required
    LOW = 2         # Minor threat, logging only
    MEDIUM = 3      # Moderate threat, enter throttling mode
    HIGH = 4        # High threat, immediate throttling
    CRITICAL = 5    # Critical threat, immediate ban
    EMERGENCY = 6   # Emergency response, system-wide protection


class ActionType(Enum):
    """Actions taken by RotaryShield in response to events."""
    LOG_ONLY = "log_only"
    THROTTLE_SSH = "throttle_ssh"
    THROTTLE_HTTP = "throttle_http"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_BAN = "temporary_ban"
    PERMANENT_BAN = "permanent_ban"
    HONEYPOT_REDIRECT = "honeypot_redirect"
    NOTIFICATION_SENT = "notification_sent"
    CONFIG_RELOAD = "config_reload"


@dataclass(frozen=True)
class SecurityEvent:
    """
    Immutable security event record with comprehensive validation.
    
    Security considerations:
    - All fields are validated and sanitized
    - Immutable to prevent tampering
    - Safe string representation for logging
    - IP address validation and normalization
    """
    
    # Core event identification
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: EventType = EventType.SYSTEM_ERROR
    threat_level: ThreatLevel = ThreatLevel.INFO
    
    # Source information
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    source_hostname: Optional[str] = None
    
    # Target information
    target_service: Optional[str] = None
    target_port: Optional[int] = None
    target_user: Optional[str] = None
    
    # Event details
    message: str = ""
    raw_log_line: str = ""
    pattern_matched: Optional[str] = None
    
    # Context and metadata
    context: Dict[str, Any] = field(default_factory=dict)
    actions_taken: List[ActionType] = field(default_factory=list)
    
    # Audit trail
    created_by: str = "rotaryshield"
    processing_time_ms: Optional[float] = None
    
    def __post_init__(self):
        """Post-initialization validation and sanitization."""
        # Validate and normalize IP address
        if self.source_ip:
            object.__setattr__(self, 'source_ip', self._validate_ip_address(self.source_ip))
        
        # Validate ports
        if self.source_port is not None:
            self._validate_port(self.source_port)
        if self.target_port is not None:
            self._validate_port(self.target_port)
        
        # Sanitize string fields to prevent injection attacks
        object.__setattr__(self, 'message', self._sanitize_string(self.message))
        object.__setattr__(self, 'raw_log_line', self._sanitize_log_line(self.raw_log_line))
        object.__setattr__(self, 'source_hostname', self._sanitize_hostname(self.source_hostname))
        object.__setattr__(self, 'target_service', self._sanitize_string(self.target_service))
        object.__setattr__(self, 'target_user', self._sanitize_username(self.target_user))
        object.__setattr__(self, 'pattern_matched', self._sanitize_string(self.pattern_matched))
        
        # Validate context dictionary
        object.__setattr__(self, 'context', self._validate_context(self.context))
        
        # Log creation for audit trail
        logger = logging.getLogger(__name__)
        logger.debug(f"SecurityEvent created: {self.event_id} - {self.event_type.value}")
    
    def _validate_ip_address(self, ip: str) -> str:
        """Validate and normalize IP address."""
        if not ip or not isinstance(ip, str):
            raise ValueError("IP address must be a non-empty string")
        
        # Remove any whitespace
        ip = ip.strip()
        
        # Validate IP address format
        try:
            ip_obj = ipaddress.ip_address(ip)
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {ip}")
    
    def _validate_port(self, port: int) -> None:
        """Validate port number range."""
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError(f"Port must be an integer between 1 and 65535, got: {port}")
    
    def _sanitize_string(self, value: Optional[str], max_length: int = 1000) -> Optional[str]:
        """Sanitize string value to prevent injection attacks."""
        if value is None:
            return None
        
        if not isinstance(value, str):
            value = str(value)
        
        # Remove potentially dangerous characters
        # Allow alphanumeric, spaces, and basic punctuation
        sanitized = re.sub(r'[^\w\s\-_.:/=\[\]()@]', '', value)
        
        # Truncate to prevent log flooding
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized.strip()
    
    def _sanitize_log_line(self, log_line: Optional[str]) -> Optional[str]:
        """Sanitize raw log line for safe storage."""
        if log_line is None:
            return None
        
        if not isinstance(log_line, str):
            log_line = str(log_line)
        
        # Remove control characters that could be used for log injection
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', log_line)
        
        # Truncate very long log lines
        if len(sanitized) > 2000:
            sanitized = sanitized[:2000] + "...[truncated]"
        
        return sanitized.strip()
    
    def _sanitize_hostname(self, hostname: Optional[str]) -> Optional[str]:
        """Sanitize hostname with strict validation."""
        if hostname is None:
            return None
        
        if not isinstance(hostname, str):
            hostname = str(hostname)
        
        # Validate hostname format (RFC 1123)
        hostname = hostname.lower().strip()
        if len(hostname) > 253:
            return None
        
        # Allow only valid hostname characters
        if not re.match(r'^[a-z0-9\-\.]+$', hostname):
            return None
        
        return hostname
    
    def _sanitize_username(self, username: Optional[str]) -> Optional[str]:
        """Sanitize username for security."""
        if username is None:
            return None
        
        if not isinstance(username, str):
            username = str(username)
        
        # Remove dangerous characters, allow alphanumeric and basic symbols
        sanitized = re.sub(r'[^\w\-@.]', '', username)
        
        # Truncate long usernames
        if len(sanitized) > 64:
            sanitized = sanitized[:64]
        
        return sanitized.strip()
    
    def _validate_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize context dictionary."""
        if not isinstance(context, dict):
            return {}
        
        sanitized_context = {}
        max_context_items = 20
        max_key_length = 100
        max_value_length = 1000
        
        item_count = 0
        for key, value in context.items():
            if item_count >= max_context_items:
                break
            
            # Sanitize key
            if not isinstance(key, str) or len(key) > max_key_length:
                continue
            
            clean_key = re.sub(r'[^\w\-_]', '', key)
            if not clean_key:
                continue
            
            # Sanitize value
            if isinstance(value, (str, int, float, bool)):
                if isinstance(value, str):
                    if len(value) > max_value_length:
                        value = value[:max_value_length] + "..."
                    value = self._sanitize_string(value)
                
                sanitized_context[clean_key] = value
                item_count += 1
        
        return sanitized_context
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'event_type': self.event_type.value,
            'threat_level': self.threat_level.value,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'source_hostname': self.source_hostname,
            'target_service': self.target_service,
            'target_port': self.target_port,
            'target_user': self.target_user,
            'message': self.message,
            'raw_log_line': self.raw_log_line,
            'pattern_matched': self.pattern_matched,
            'context': self.context,
            'actions_taken': [action.value for action in self.actions_taken],
            'created_by': self.created_by,
            'processing_time_ms': self.processing_time_ms
        }
    
    def get_safe_log_representation(self) -> str:
        """Get a safe string representation for logging."""
        # Create safe representation that prevents log injection
        return (
            f"SecurityEvent(id={self.event_id[:8]}..., "
            f"type={self.event_type.value}, "
            f"level={self.threat_level.name}, "
            f"source_ip={self.source_ip or 'unknown'}, "
            f"timestamp={self.timestamp})"
        )
    
    def is_high_severity(self) -> bool:
        """Check if event is high severity requiring immediate action."""
        return self.threat_level >= ThreatLevel.HIGH
    
    def requires_notification(self) -> bool:
        """Check if event requires external notification."""
        return self.threat_level >= ThreatLevel.MEDIUM
    
    def add_action(self, action: ActionType) -> 'SecurityEvent':
        """Create new event with additional action (immutable pattern)."""
        new_actions = list(self.actions_taken)
        if action not in new_actions:
            new_actions.append(action)
        
        # Create new instance with updated actions
        return SecurityEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            event_type=self.event_type,
            threat_level=self.threat_level,
            source_ip=self.source_ip,
            source_port=self.source_port,
            source_hostname=self.source_hostname,
            target_service=self.target_service,
            target_port=self.target_port,
            target_user=self.target_user,
            message=self.message,
            raw_log_line=self.raw_log_line,
            pattern_matched=self.pattern_matched,
            context=self.context,
            actions_taken=new_actions,
            created_by=self.created_by,
            processing_time_ms=self.processing_time_ms
        )


class SecurityEventFactory:
    """Factory for creating security events with proper validation and defaults."""
    
    @staticmethod
    def create_ssh_failed_login(source_ip: str, username: str, raw_log: str) -> SecurityEvent:
        """Create SSH failed login event."""
        return SecurityEvent(
            event_type=EventType.SSH_FAILED_LOGIN,
            threat_level=ThreatLevel.MEDIUM,
            source_ip=source_ip,
            target_service="ssh",
            target_port=22,
            target_user=username,
            message=f"SSH login failed for user {username}",
            raw_log_line=raw_log,
            pattern_matched="ssh_failed_login"
        )
    
    @staticmethod
    def create_http_brute_force(source_ip: str, target_path: str, raw_log: str) -> SecurityEvent:
        """Create HTTP brute force event."""
        return SecurityEvent(
            event_type=EventType.HTTP_BRUTE_FORCE,
            threat_level=ThreatLevel.HIGH,
            source_ip=source_ip,
            target_service="http",
            target_port=80,
            message=f"HTTP brute force attempt on {target_path}",
            raw_log_line=raw_log,
            pattern_matched="http_brute_force",
            context={"target_path": target_path}
        )
    
    @staticmethod
    def create_port_scan(source_ip: str, ports_scanned: List[int]) -> SecurityEvent:
        """Create port scan event."""
        return SecurityEvent(
            event_type=EventType.PORT_SCAN,
            threat_level=ThreatLevel.HIGH,
            source_ip=source_ip,
            message=f"Port scan detected from {source_ip}",
            context={
                "ports_scanned": ports_scanned[:20],  # Limit to prevent large context
                "port_count": len(ports_scanned)
            }
        )
    
    @staticmethod
    def create_system_error(message: str, context: Optional[Dict[str, Any]] = None) -> SecurityEvent:
        """Create system error event."""
        return SecurityEvent(
            event_type=EventType.SYSTEM_ERROR,
            threat_level=ThreatLevel.LOW,
            message=f"System error: {message}",
            context=context or {}
        )