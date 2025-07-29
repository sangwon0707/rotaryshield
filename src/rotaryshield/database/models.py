#!/usr/bin/env python3
"""
RotaryShield Database Models
Data models for persistent storage with comprehensive validation.

Security Features:
- Input validation and sanitization for all fields
- SQL injection prevention through parameterized queries
- Data integrity constraints and validation
- Audit trail support for all operations
- Performance optimization for large datasets
"""

import time
import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from enum import Enum
import re


class BanStatus(Enum):
    """Status of IP ban records."""
    ACTIVE = "active"
    EXPIRED = "expired"
    MANUALLY_REMOVED = "manually_removed"
    SYSTEM_REMOVED = "system_removed"


class AuditAction(Enum):
    """Types of audit actions."""
    IP_BANNED = "ip_banned"
    IP_UNBANNED = "ip_unbanned"
    CONFIG_CHANGED = "config_changed"
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    SECURITY_EVENT = "security_event"
    ERROR_OCCURRED = "error_occurred"


class EventSeverity(Enum):
    """Severity levels for security events."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IPBanRecord:
    """
    Record for IP ban information with comprehensive validation.
    
    Security considerations:
    - IP address validation and normalization
    - Input sanitization for all string fields
    - Timestamp validation and consistency
    - Data integrity checks
    """
    
    # Primary key (auto-generated)
    id: Optional[int] = None
    
    # Core IP ban information
    ip_address: str = ""
    ban_reason: str = ""
    ban_duration: int = 3600  # seconds
    
    # Timestamps
    created_at: float = 0.0
    expires_at: float = 0.0
    updated_at: float = 0.0
    
    # Status and metadata
    status: BanStatus = BanStatus.ACTIVE
    ban_count: int = 1
    last_offense_type: str = ""
    
    # System information
    created_by: str = "rotaryshield"
    removed_reason: str = ""
    
    def __post_init__(self):
        """Post-initialization validation and normalization."""
        # Set default timestamps
        current_time = time.time()
        if self.created_at == 0.0:
            self.created_at = current_time
        if self.updated_at == 0.0:
            self.updated_at = current_time
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + self.ban_duration
        
        # Validate and normalize IP address
        self.ip_address = self._validate_ip_address(self.ip_address)
        
        # Sanitize string fields
        self.ban_reason = self._sanitize_string(self.ban_reason, 500)
        self.last_offense_type = self._sanitize_string(self.last_offense_type, 100)
        self.created_by = self._sanitize_string(self.created_by, 100)
        self.removed_reason = self._sanitize_string(self.removed_reason, 500)
        
        # Validate numeric fields
        if self.ban_duration < 0 or self.ban_duration > 31536000:  # Max 1 year
            raise ValueError(f"Invalid ban duration: {self.ban_duration}")
        
        if self.ban_count < 0 or self.ban_count > 1000000:
            raise ValueError(f"Invalid ban count: {self.ban_count}")
        
        # Validate timestamp consistency
        if self.expires_at < self.created_at:
            raise ValueError("Expiration time cannot be before creation time")
    
    def _validate_ip_address(self, ip: str) -> str:
        """Validate and normalize IP address."""
        if not ip or not isinstance(ip, str):
            raise ValueError("IP address must be a non-empty string")
        
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {ip}")
    
    def _sanitize_string(self, value: str, max_length: int) -> str:
        """Sanitize string value for database storage."""
        if not value:
            return ""
        
        if not isinstance(value, str):
            value = str(value)
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[^\w\s\-_.:/=\[\]()@]', '', value)
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized.strip()
    
    def is_expired(self) -> bool:
        """Check if ban record has expired."""
        return self.expires_at < time.time()
    
    def is_active(self) -> bool:
        """Check if ban record is active."""
        return self.status == BanStatus.ACTIVE and not self.is_expired()
    
    def extend_ban(self, additional_seconds: int, reason: str = "") -> None:
        """Extend ban duration."""
        if additional_seconds <= 0:
            raise ValueError("Additional ban time must be positive")
        
        self.expires_at += additional_seconds
        self.updated_at = time.time()
        if reason:
            self.ban_reason += f" | Extended: {reason}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for serialization."""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'ban_reason': self.ban_reason,
            'ban_duration': self.ban_duration,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'updated_at': self.updated_at,
            'status': self.status.value,
            'ban_count': self.ban_count,
            'last_offense_type': self.last_offense_type,
            'created_by': self.created_by,
            'removed_reason': self.removed_reason
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPBanRecord':
        """Create record from dictionary."""
        record = cls()
        
        record.id = data.get('id')
        record.ip_address = data.get('ip_address', '')
        record.ban_reason = data.get('ban_reason', '')
        record.ban_duration = data.get('ban_duration', 3600)
        record.created_at = data.get('created_at', time.time())
        record.expires_at = data.get('expires_at', 0.0)
        record.updated_at = data.get('updated_at', time.time())
        
        # Handle status enum
        status_str = data.get('status', 'active')
        record.status = BanStatus(status_str) if status_str in [s.value for s in BanStatus] else BanStatus.ACTIVE
        
        record.ban_count = data.get('ban_count', 1)
        record.last_offense_type = data.get('last_offense_type', '')
        record.created_by = data.get('created_by', 'rotaryshield')
        record.removed_reason = data.get('removed_reason', '')
        
        return record


@dataclass
class AuditLogRecord:
    """
    Audit log record for tracking all system operations.
    
    Security considerations:
    - Comprehensive logging of all security-relevant operations
    - Tamper-evident audit trail
    - Performance optimization for high-volume logging
    - Data retention and archival support
    """
    
    # Primary key (auto-generated)
    id: Optional[int] = None
    
    # Core audit information
    timestamp: float = 0.0
    action: AuditAction = AuditAction.SECURITY_EVENT
    user_id: str = "system"
    ip_address: str = ""
    
    # Action details
    description: str = ""
    details: str = ""  # JSON string for structured data
    result: str = "success"  # success, failure, error
    
    # System context
    component: str = "rotaryshield"
    session_id: str = ""
    
    def __post_init__(self):
        """Post-initialization validation and normalization."""
        # Set default timestamp
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        
        # Validate and normalize IP address if provided
        if self.ip_address:
            try:
                ip_obj = ipaddress.ip_address(self.ip_address.strip())
                self.ip_address = str(ip_obj)
            except ValueError:
                # Don't fail for invalid IP, just log warning
                logging.getLogger(__name__).warning(f"Invalid IP in audit log: {self.ip_address}")
                self.ip_address = ""
        
        # Sanitize string fields
        self.user_id = self._sanitize_string(self.user_id, 100)
        self.description = self._sanitize_string(self.description, 500)
        self.details = self._sanitize_json_string(self.details, 2000)
        self.result = self._sanitize_string(self.result, 50)
        self.component = self._sanitize_string(self.component, 100)
        self.session_id = self._sanitize_string(self.session_id, 100)
    
    def _sanitize_string(self, value: str, max_length: int) -> str:
        """Sanitize string value for audit log."""
        if not value:
            return ""
        
        if not isinstance(value, str):
            value = str(value)
        
        # For audit logs, be more permissive but still secure
        # Remove control characters but allow more punctuation
        sanitized = ''.join(c for c in value if ord(c) >= 32 or c in '\t\n')
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "...[truncated]"
        
        return sanitized.strip()
    
    def _sanitize_json_string(self, value: str, max_length: int) -> str:
        """Sanitize JSON string for audit log details."""
        if not value:
            return ""
        
        # Basic JSON string validation and sanitization
        sanitized = self._sanitize_string(value, max_length)
        
        # Ensure it's valid JSON-like (basic check)
        if sanitized and not (sanitized.startswith('{') or sanitized.startswith('[')):
            # If it's not JSON, wrap it as a simple string value
            sanitized = f'"{sanitized}"'
        
        return sanitized
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'action': self.action.value,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'description': self.description,
            'details': self.details,
            'result': self.result,
            'component': self.component,
            'session_id': self.session_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditLogRecord':
        """Create record from dictionary."""
        record = cls()
        
        record.id = data.get('id')
        record.timestamp = data.get('timestamp', time.time())
        
        # Handle action enum
        action_str = data.get('action', 'security_event')
        record.action = AuditAction(action_str) if action_str in [a.value for a in AuditAction] else AuditAction.SECURITY_EVENT
        
        record.user_id = data.get('user_id', 'system')
        record.ip_address = data.get('ip_address', '')
        record.description = data.get('description', '')
        record.details = data.get('details', '')
        record.result = data.get('result', 'success')
        record.component = data.get('component', 'rotaryshield')
        record.session_id = data.get('session_id', '')
        
        return record


@dataclass
class SecurityEventRecord:
    """
    Security event record for detailed threat analysis.
    
    This model stores detailed information about security events
    for analysis, reporting, and threat intelligence.
    """
    
    # Primary key (auto-generated)
    id: Optional[int] = None
    
    # Event identification
    event_id: str = ""
    event_type: str = ""
    severity: EventSeverity = EventSeverity.INFO
    
    # Timestamp information
    timestamp: float = 0.0
    processed_at: float = 0.0
    
    # Source information
    source_ip: str = ""
    source_port: Optional[int] = None
    source_country: str = ""
    
    # Target information
    target_service: str = ""
    target_port: Optional[int] = None
    
    # Event details
    description: str = ""
    raw_log_data: str = ""
    pattern_matched: str = ""
    
    # Analysis results
    threat_score: int = 0
    false_positive: bool = False
    actions_taken: str = ""  # JSON array of actions
    
    # System context
    detection_source: str = ""  # log file or detection method
    
    def __post_init__(self):
        """Post-initialization validation and normalization."""
        # Set default timestamps
        current_time = time.time()
        if self.timestamp == 0.0:
            self.timestamp = current_time
        if self.processed_at == 0.0:
            self.processed_at = current_time
        
        # Generate event ID if not provided
        if not self.event_id:
            import uuid
            self.event_id = str(uuid.uuid4())
        
        # Validate and normalize IP address
        if self.source_ip:
            try:
                ip_obj = ipaddress.ip_address(self.source_ip.strip())
                self.source_ip = str(ip_obj)
            except ValueError:
                logging.getLogger(__name__).warning(f"Invalid source IP: {self.source_ip}")
                self.source_ip = ""
        
        # Validate ports
        if self.source_port is not None:
            if not (1 <= self.source_port <= 65535):
                raise ValueError(f"Invalid source port: {self.source_port}")
        
        if self.target_port is not None:
            if not (1 <= self.target_port <= 65535):
                raise ValueError(f"Invalid target port: {self.target_port}")
        
        # Sanitize string fields
        self.event_type = self._sanitize_string(self.event_type, 100)
        self.source_country = self._sanitize_string(self.source_country, 10)
        self.target_service = self._sanitize_string(self.target_service, 100)
        self.description = self._sanitize_string(self.description, 1000)
        self.raw_log_data = self._sanitize_log_data(self.raw_log_data, 5000)
        self.pattern_matched = self._sanitize_string(self.pattern_matched, 100)
        self.actions_taken = self._sanitize_json_string(self.actions_taken, 1000)
        self.detection_source = self._sanitize_string(self.detection_source, 200)
        
        # Validate threat score
        if not (0 <= self.threat_score <= 100):
            self.threat_score = max(0, min(100, self.threat_score))
    
    def _sanitize_string(self, value: str, max_length: int) -> str:
        """Sanitize string value."""
        if not value:
            return ""
        
        if not isinstance(value, str):
            value = str(value)
        
        # Remove control characters
        sanitized = re.sub(r'[^\w\s\-_.:/=\[\]()@]', '', value)
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "...[truncated]"
        
        return sanitized.strip()
    
    def _sanitize_log_data(self, value: str, max_length: int) -> str:
        """Sanitize raw log data while preserving structure."""
        if not value:
            return ""
        
        if not isinstance(value, str):
            value = str(value)
        
        # For log data, preserve more characters but remove dangerous ones
        sanitized = ''.join(c for c in value if ord(c) >= 32 or c in '\t\n\r')
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "...[truncated]"
        
        return sanitized
    
    def _sanitize_json_string(self, value: str, max_length: int) -> str:
        """Sanitize JSON string for actions."""
        if not value:
            return "[]"  # Default to empty array
        
        sanitized = self._sanitize_string(value, max_length)
        
        # Ensure it looks like a JSON array
        if sanitized and not (sanitized.startswith('[') or sanitized.startswith('{')):
            sanitized = f'["{sanitized}"]'
        
        return sanitized
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for serialization."""
        return {
            'id': self.id,
            'event_id': self.event_id,
            'event_type': self.event_type,
            'severity': self.severity.value,
            'timestamp': self.timestamp,
            'processed_at': self.processed_at,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'source_country': self.source_country,
            'target_service': self.target_service,
            'target_port': self.target_port,
            'description': self.description,
            'raw_log_data': self.raw_log_data,
            'pattern_matched': self.pattern_matched,
            'threat_score': self.threat_score,
            'false_positive': self.false_positive,
            'actions_taken': self.actions_taken,
            'detection_source': self.detection_source
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEventRecord':
        """Create record from dictionary."""
        record = cls()
        
        record.id = data.get('id')
        record.event_id = data.get('event_id', '')
        record.event_type = data.get('event_type', '')
        
        # Handle severity enum
        severity_str = data.get('severity', 'info')
        record.severity = EventSeverity(severity_str) if severity_str in [s.value for s in EventSeverity] else EventSeverity.INFO
        
        record.timestamp = data.get('timestamp', time.time())
        record.processed_at = data.get('processed_at', time.time())
        record.source_ip = data.get('source_ip', '')
        record.source_port = data.get('source_port')
        record.source_country = data.get('source_country', '')
        record.target_service = data.get('target_service', '')
        record.target_port = data.get('target_port')
        record.description = data.get('description', '')
        record.raw_log_data = data.get('raw_log_data', '')
        record.pattern_matched = data.get('pattern_matched', '')
        record.threat_score = data.get('threat_score', 0)
        record.false_positive = data.get('false_positive', False)
        record.actions_taken = data.get('actions_taken', '[]')
        record.detection_source = data.get('detection_source', '')
        
        return record