#!/usr/bin/env python3
"""
RotaryShield Firewall Adapter Interface
Abstract base class for firewall implementations with comprehensive security measures.

Security Features:
- Input validation for all IP addresses and rules
- Command injection prevention
- Privilege validation and error handling
- Comprehensive audit logging
- Rate limiting for firewall operations
- Rollback capability for failed operations
"""

import logging
import time
import ipaddress
import threading
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import subprocess
import shlex
import re


class FirewallError(Exception):
    """Base exception for firewall-related errors."""
    pass


class FirewallOperationError(FirewallError):
    """Exception for firewall operation failures."""
    pass


class FirewallPermissionError(FirewallError):
    """Exception for permission-related firewall errors."""
    pass


class RuleAction(Enum):
    """Firewall rule actions."""
    BLOCK = "block"
    ALLOW = "allow" 
    REJECT = "reject"
    DROP = "drop"


@dataclass
class FirewallRule:
    """Represents a firewall rule with validation."""
    ip_address: str
    action: RuleAction
    port: Optional[int] = None
    protocol: Optional[str] = None
    comment: Optional[str] = None
    created_at: float = None
    
    def __post_init__(self):
        """Validate firewall rule parameters."""
        if self.created_at is None:
            self.created_at = time.time()
        
        # Validate IP address
        try:
            ipaddress.ip_address(self.ip_address)
        except ValueError:
            raise FirewallError(f"Invalid IP address: {self.ip_address}")
        
        # Validate port if specified
        if self.port is not None:
            if not isinstance(self.port, int) or self.port < 1 or self.port > 65535:
                raise FirewallError(f"Invalid port number: {self.port}")
        
        # Validate protocol if specified
        if self.protocol is not None:
            valid_protocols = ['tcp', 'udp', 'icmp']
            if self.protocol.lower() not in valid_protocols:
                raise FirewallError(f"Invalid protocol: {self.protocol}")
            self.protocol = self.protocol.lower()
        
        # Sanitize comment
        if self.comment:
            # Remove potentially dangerous characters
            self.comment = re.sub(r'[^\w\s\-_.:()[\]]', '', self.comment)[:100]


class FirewallAdapter(ABC):
    """
    Abstract base class for firewall adapters.
    
    This class defines the interface that all firewall implementations
    must follow, with built-in security measures and validation.
    """
    
    def __init__(self, name: str):
        """
        Initialize firewall adapter.
        
        Args:
            name: Name of the firewall system
        """
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
        # Thread safety for concurrent operations
        self._operation_lock = threading.RLock()
        
        # Rate limiting for firewall operations
        self._operation_timestamps: List[float] = []
        self._max_operations_per_minute = 100
        
        # Track active rules for rollback capability
        self._active_rules: Set[str] = set()
        
        # Performance metrics
        self._operation_count = 0
        self._failure_count = 0
        self._last_operation_time = 0.0
        
        self.logger.info(f"Initialized {name} firewall adapter")
    
    def _validate_rate_limit(self) -> None:
        """Check if operation rate limit is exceeded."""
        current_time = time.time()
        
        # Clean old timestamps (older than 1 minute)
        self._operation_timestamps = [
            ts for ts in self._operation_timestamps 
            if current_time - ts <= 60
        ]
        
        # Check rate limit
        if len(self._operation_timestamps) >= self._max_operations_per_minute:
            raise FirewallOperationError(
                f"Rate limit exceeded: {self._max_operations_per_minute} operations per minute"
            )
        
        # Add current operation timestamp
        self._operation_timestamps.append(current_time)
    
    def _execute_command(self, command: List[str], timeout: int = 30) -> Tuple[str, str, int]:
        """
        Safely execute firewall command with comprehensive security measures.
        
        Args:
            command: Command arguments as list (prevents injection)
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        # Validate command arguments
        if not command or not isinstance(command, list):
            raise FirewallError("Command must be a non-empty list")
        
        # Sanitize command arguments
        sanitized_command = []
        for arg in command:
            if not isinstance(arg, str):
                arg = str(arg)
            
            # Prevent command injection
            if any(char in arg for char in ['&', '|', ';', '`', '$', '(', ')', '<', '>']):
                raise FirewallError(f"Dangerous characters detected in command argument: {arg}")
                
            sanitized_command.append(arg)
        
        # Log command execution (without sensitive data)
        safe_command = [arg if not self._is_sensitive_arg(arg) else "[REDACTED]" 
                      for arg in sanitized_command]
        self.logger.debug(f"Executing command: {' '.join(safe_command)}")
        
        try:
            # Execute with security measures
            process = subprocess.run(
                sanitized_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={'PATH': '/usr/sbin:/sbin:/usr/bin:/bin'}  # Restricted PATH
            )
            
            stdout = process.stdout.strip()
            stderr = process.stderr.strip()
            return_code = process.returncode
            
            # Log result
            if return_code == 0:
                self.logger.debug(f"Command executed successfully")
            else:
                self.logger.warning(f"Command failed with code {return_code}: {stderr}")
            
            return stdout, stderr, return_code
            
        except subprocess.TimeoutExpired:
            raise FirewallOperationError(f"Command timed out after {timeout} seconds")
        except subprocess.SubprocessError as e:
            raise FirewallOperationError(f"Command execution failed: {e}")
        except Exception as e:
            raise FirewallOperationError(f"Unexpected error executing command: {e}")
    
    def _is_sensitive_arg(self, arg: str) -> bool:
        """Check if command argument contains sensitive information."""
        # Define patterns that might contain sensitive data
        sensitive_patterns = [
            r'password',
            r'secret',
            r'key',
            r'token'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, arg.lower()):
                return True
        
        return False
    
    def _track_operation(self, operation: str, success: bool, duration: float) -> None:
        """Track operation metrics for monitoring."""
        self._operation_count += 1
        self._last_operation_time = duration
        
        if not success:
            self._failure_count += 1
        
        # Log operation for audit trail
        status = "SUCCESS" if success else "FAILURE" 
        self.logger.info(
            f"Firewall operation: {operation} - {status} - {duration:.3f}s"
        )
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if this firewall system is available and functional.
        
        Returns:
            True if firewall is available, False otherwise
        """
        pass
    
    @abstractmethod
    def initialize(self) -> None:
        """
        Initialize the firewall system and verify permissions.
        
        Raises:
            FirewallError: If initialization fails
            FirewallPermissionError: If insufficient privileges
        """
        pass
    
    @abstractmethod
    def block_ip(self, ip_address: str, comment: Optional[str] = None) -> bool:
        """
        Block an IP address.
        
        Args:
            ip_address: IP address to block
            comment: Optional comment for the rule
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            FirewallError: If operation fails
        """
        pass
    
    @abstractmethod
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            FirewallError: If operation fails
        """
        pass
    
    @abstractmethod
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        pass
    
    @abstractmethod
    def list_blocked_ips(self) -> List[str]:
        """
        Get list of all blocked IP addresses.
        
        Returns:
            List of blocked IP addresses
        """
        pass
    
    @abstractmethod
    def get_rule_count(self) -> int:
        """
        Get total number of active firewall rules.
        
        Returns:
            Number of active rules
        """
        pass
    
    def block_ip_with_validation(self, ip_address: str, comment: Optional[str] = None) -> bool:
        """
        Block IP with comprehensive validation and error handling.
        
        Args:
            ip_address: IP address to block
            comment: Optional comment for the rule
            
        Returns:
            True if successful, False otherwise
        """
        with self._operation_lock:
            start_time = time.time()
            success = False
            
            try:
                # Rate limiting check
                self._validate_rate_limit()
                
                # Validate IP address
                try:
                    ip_obj = ipaddress.ip_address(ip_address)
                    normalized_ip = str(ip_obj)
                except ValueError:
                    raise FirewallError(f"Invalid IP address format: {ip_address}")
                
                # Check if IP is already blocked
                if self.is_blocked(normalized_ip):
                    self.logger.debug(f"IP {normalized_ip} is already blocked")
                    return True
                
                # Execute block operation
                success = self.block_ip(normalized_ip, comment)
                
                if success:
                    self._active_rules.add(normalized_ip)
                    self.logger.info(f"Successfully blocked IP: {normalized_ip}")
                else:
                    self.logger.error(f"Failed to block IP: {normalized_ip}")
                
                return success
                
            except Exception as e:
                self.logger.error(f"Error blocking IP {ip_address}: {e}")
                return False
            
            finally:
                duration = time.time() - start_time
                self._track_operation(f"block_ip({ip_address})", success, duration)
    
    def unblock_ip_with_validation(self, ip_address: str) -> bool:
        """
        Unblock IP with comprehensive validation and error handling.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        with self._operation_lock:
            start_time = time.time()
            success = False
            
            try:
                # Rate limiting check
                self._validate_rate_limit()
                
                # Validate IP address
                try:
                    ip_obj = ipaddress.ip_address(ip_address)
                    normalized_ip = str(ip_obj)
                except ValueError:
                    raise FirewallError(f"Invalid IP address format: {ip_address}")
                
                # Check if IP is actually blocked
                if not self.is_blocked(normalized_ip):
                    self.logger.debug(f"IP {normalized_ip} is not blocked")
                    return True
                
                # Execute unblock operation
                success = self.unblock_ip(normalized_ip)
                
                if success:
                    self._active_rules.discard(normalized_ip)
                    self.logger.info(f"Successfully unblocked IP: {normalized_ip}")
                else:
                    self.logger.error(f"Failed to unblock IP: {normalized_ip}")
                
                return success
                
            except Exception as e:
                self.logger.error(f"Error unblocking IP {ip_address}: {e}")
                return False
            
            finally:
                duration = time.time() - start_time
                self._track_operation(f"unblock_ip({ip_address})", success, duration)
    
    def get_statistics(self) -> Dict[str, any]:
        """Get firewall adapter statistics."""
        return {
            'name': self.name,
            'operation_count': self._operation_count,
            'failure_count': self._failure_count,
            'success_rate': (
                (self._operation_count - self._failure_count) / max(self._operation_count, 1) * 100
            ),
            'active_rules': len(self._active_rules),
            'last_operation_time': self._last_operation_time,
            'operations_per_minute_limit': self._max_operations_per_minute
        }
    
    def cleanup(self) -> None:
        """Clean up adapter resources and temporary rules."""
        with self._operation_lock:
            try:
                # Remove any temporary rules if needed
                # This is adapter-specific and should be overridden
                self.logger.info(f"Cleaned up {self.name} firewall adapter")
            except Exception as e:
                self.logger.error(f"Error during cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()