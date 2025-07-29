#!/usr/bin/env python3
"""
RotaryShield Firewall Manager
Auto-detection and management of firewall systems with failover capability.

Security Features:
- Automatic firewall system detection with priority ordering
- Failover support between multiple firewall backends
- Comprehensive validation and error handling
- Performance monitoring and statistics
- Thread-safe operations
- Audit logging for all firewall operations
"""

import logging
import threading
import time
from typing import Optional, List, Dict, Type, Union
from dataclasses import dataclass

from .adapter import FirewallAdapter, FirewallError, FirewallOperationError
from .ufw_adapter import UFWAdapter
from .firewalld_adapter import FirewalldAdapter
from .iptables_adapter import IptablesAdapter


@dataclass
class FirewallBackend:
    """Information about a firewall backend."""
    name: str
    adapter_class: Type[FirewallAdapter]
    priority: int
    description: str


class FirewallManager:
    """
    Firewall manager with automatic detection and failover.
    
    This class automatically detects available firewall systems and
    manages operations through the most appropriate adapter. It provides
    failover capabilities and comprehensive error handling.
    """
    
    # Firewall backends in priority order (highest priority first)
    FIREWALL_BACKENDS = [
        FirewallBackend(
            name="ufw",
            adapter_class=UFWAdapter,
            priority=100,
            description="UFW (Uncomplicated Firewall) - Ubuntu/Debian default"
        ),
        FirewallBackend(
            name="firewalld", 
            adapter_class=FirewalldAdapter,
            priority=90,
            description="Firewalld - RHEL/CentOS/Fedora default"
        ),
        FirewallBackend(
            name="iptables",
            adapter_class=IptablesAdapter,
            priority=80,
            description="Direct iptables - Universal Linux support"
        )
    ]
    
    def __init__(self, preferred_backend: Optional[str] = None):
        """
        Initialize firewall manager.
        
        Args:
            preferred_backend: Preferred firewall backend name, or None for auto-detection
        """
        self.logger = logging.getLogger(__name__)
        self.preferred_backend = preferred_backend
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Current adapter
        self._adapter: Optional[FirewallAdapter] = None
        self._backend_name: Optional[str] = None
        
        # Available backends (populated during detection)
        self._available_backends: Dict[str, FirewallBackend] = {}
        
        # Statistics
        self._operations_count = 0
        self._failures_count = 0
        self._last_operation_time = 0.0
        
        # Detection cache
        self._detection_cache: Dict[str, bool] = {}
        self._cache_timeout = 300  # 5 minutes
        self._last_detection_time = 0.0
        
        self.logger.info("FirewallManager initialized")
    
    def detect_firewall_systems(self, force_refresh: bool = False) -> Dict[str, bool]:
        """
        Detect available firewall systems.
        
        Args:
            force_refresh: Force re-detection even if cache is valid
            
        Returns:
            Dictionary mapping backend names to availability status
        """
        current_time = time.time()
        
        # Check cache validity
        if (not force_refresh and 
            self._detection_cache and 
            current_time - self._last_detection_time < self._cache_timeout):
            return self._detection_cache.copy()
        
        self.logger.info("Detecting available firewall systems...")
        
        detection_results = {}
        
        for backend in self.FIREWALL_BACKENDS:
            try:
                # Create temporary adapter instance for detection
                adapter = backend.adapter_class()
                is_available = adapter.is_available()
                
                detection_results[backend.name] = is_available
                
                if is_available:
                    self._available_backends[backend.name] = backend
                    self.logger.info(f"Detected firewall: {backend.name} - {backend.description}")
                else:
                    self.logger.debug(f"Firewall not available: {backend.name}")
                    
            except Exception as e:
                self.logger.error(f"Error detecting firewall {backend.name}: {e}")
                detection_results[backend.name] = False
        
        # Update cache
        self._detection_cache = detection_results
        self._last_detection_time = current_time
        
        available_count = sum(1 for available in detection_results.values() if available)
        self.logger.info(f"Firewall detection completed: {available_count} systems available")
        
        return detection_results.copy()
    
    def initialize(self) -> None:
        """
        Initialize firewall manager and select the best available adapter.
        
        Raises:
            FirewallError: If no firewall systems are available
        """
        with self._lock:
            # Detect available firewall systems
            available_systems = self.detect_firewall_systems()
            
            if not any(available_systems.values()):
                raise FirewallError("No supported firewall systems found")
            
            # Select the best adapter
            selected_backend = self._select_best_backend(available_systems)
            
            if not selected_backend:
                raise FirewallError("No suitable firewall backend could be selected")
            
            # Initialize the selected adapter
            try:
                adapter_class = selected_backend.adapter_class
                self._adapter = adapter_class()
                self._adapter.initialize()
                self._backend_name = selected_backend.name
                
                self.logger.info(
                    f"Firewall manager initialized with {selected_backend.name} adapter"
                )
                
            except Exception as e:
                self.logger.error(f"Failed to initialize {selected_backend.name} adapter: {e}")
                # Try fallback adapters
                if not self._try_fallback_adapters(available_systems, selected_backend.name):
                    raise FirewallError(f"Failed to initialize any firewall adapter: {e}")
    
    def _select_best_backend(self, available_systems: Dict[str, bool]) -> Optional[FirewallBackend]:
        """
        Select the best available firewall backend.
        
        Args:
            available_systems: Dictionary of backend availability
            
        Returns:
            Selected backend or None if none available
        """
        # If preferred backend is specified and available, use it
        if (self.preferred_backend and 
            self.preferred_backend in available_systems and
            available_systems[self.preferred_backend]):
            
            backend = next(
                (b for b in self.FIREWALL_BACKENDS if b.name == self.preferred_backend),
                None
            )
            if backend:
                self.logger.info(f"Using preferred firewall backend: {self.preferred_backend}")
                return backend
        
        # Otherwise, select by priority
        for backend in sorted(self.FIREWALL_BACKENDS, key=lambda b: b.priority, reverse=True):
            if backend.name in available_systems and available_systems[backend.name]:
                self.logger.info(f"Selected firewall backend: {backend.name} (priority {backend.priority})")
                return backend
        
        return None
    
    def _try_fallback_adapters(self, available_systems: Dict[str, bool], failed_backend: str) -> bool:
        """
        Try to initialize fallback adapters after a failure.
        
        Args:
            available_systems: Dictionary of backend availability
            failed_backend: Name of the backend that failed
            
        Returns:
            True if a fallback adapter was successfully initialized
        """
        self.logger.warning(f"Trying fallback adapters after {failed_backend} failure")
        
        # Try remaining backends in priority order
        for backend in sorted(self.FIREWALL_BACKENDS, key=lambda b: b.priority, reverse=True):
            if (backend.name != failed_backend and
                backend.name in available_systems and
                available_systems[backend.name]):
                
                try:
                    adapter_class = backend.adapter_class
                    self._adapter = adapter_class()
                    self._adapter.initialize()
                    self._backend_name = backend.name
                    
                    self.logger.info(f"Successfully initialized fallback adapter: {backend.name}")
                    return True
                    
                except Exception as e:
                    self.logger.error(f"Fallback adapter {backend.name} also failed: {e}")
                    continue
        
        self.logger.error("All available firewall adapters failed to initialize")
        return False
    
    def block_ip(self, ip_address: str, comment: Optional[str] = None) -> bool:
        """
        Block an IP address using the active firewall adapter.
        
        Args:
            ip_address: IP address to block
            comment: Optional comment for the rule
            
        Returns:
            True if successful, False otherwise
        """
        return self._execute_with_fallback(
            "block_ip",
            lambda adapter: adapter.block_ip_with_validation(ip_address, comment),
            ip_address=ip_address
        )
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address using the active firewall adapter.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        return self._execute_with_fallback(
            "unblock_ip",
            lambda adapter: adapter.unblock_ip_with_validation(ip_address),
            ip_address=ip_address
        )
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        return self._execute_with_fallback(
            "is_blocked",
            lambda adapter: adapter.is_blocked(ip_address),
            ip_address=ip_address,
            default_return=False
        )
    
    def list_blocked_ips(self) -> List[str]:
        """
        Get list of all blocked IP addresses.
        
        Returns:
            List of blocked IP addresses
        """
        return self._execute_with_fallback(
            "list_blocked_ips",
            lambda adapter: adapter.list_blocked_ips(),
            default_return=[]
        )
    
    def get_rule_count(self) -> int:
        """
        Get total number of firewall rules.
        
        Returns:
            Number of active rules
        """
        return self._execute_with_fallback(
            "get_rule_count",
            lambda adapter: adapter.get_rule_count(),
            default_return=0
        )
    
    def _execute_with_fallback(self, operation_name: str, operation_func, 
                              default_return=None, **kwargs) -> any:
        """
        Execute firewall operation with fallback support.
        
        Args:
            operation_name: Name of the operation for logging
            operation_func: Function to execute on the adapter
            default_return: Default value to return on failure
            **kwargs: Additional arguments for logging
            
        Returns:
            Operation result or default_return on failure
        """
        with self._lock:
            start_time = time.time()
            
            try:
                if not self._adapter:
                    raise FirewallError("No firewall adapter initialized")
                
                # Execute operation
                result = operation_func(self._adapter)
                
                # Update statistics
                self._operations_count += 1
                self._last_operation_time = time.time() - start_time
                
                # Log successful operation
                self.logger.debug(
                    f"Firewall operation successful: {operation_name} "
                    f"({self._backend_name}) - {self._last_operation_time:.3f}s"
                )
                
                return result
                
            except Exception as e:
                # Update failure statistics
                self._failures_count += 1
                
                # Log failure
                ip_info = f" for IP {kwargs.get('ip_address', 'N/A')}" if 'ip_address' in kwargs else ""
                self.logger.error(
                    f"Firewall operation failed: {operation_name}{ip_info} "
                    f"({self._backend_name or 'unknown'}): {e}"
                )
                
                # Try to reinitialize if adapter seems broken
                if isinstance(e, (FirewallOperationError, FirewallError)):
                    try:
                        self.logger.info("Attempting to reinitialize firewall manager after error")
                        self.initialize()
                        
                        # Retry operation once with new adapter
                        result = operation_func(self._adapter)
                        self.logger.info(f"Operation succeeded after reinitialization: {operation_name}")
                        return result
                        
                    except Exception as reinit_error:
                        self.logger.error(f"Reinitialization failed: {reinit_error}")
                
                return default_return
    
    def get_current_backend(self) -> Optional[str]:
        """
        Get the name of the currently active firewall backend.
        
        Returns:
            Backend name or None if not initialized
        """
        with self._lock:
            return self._backend_name
    
    def get_adapter_statistics(self) -> Dict[str, any]:
        """
        Get statistics from the current adapter.
        
        Returns:
            Dictionary with adapter statistics
        """
        with self._lock:
            if not self._adapter:
                return {"error": "No adapter initialized"}
            
            try:
                adapter_stats = self._adapter.get_statistics()
                adapter_stats.update({
                    "manager_operations": self._operations_count,
                    "manager_failures": self._failures_count,
                    "manager_success_rate": (
                        (self._operations_count - self._failures_count) / 
                        max(self._operations_count, 1) * 100
                    ),
                    "last_operation_time": self._last_operation_time
                })
                return adapter_stats
                
            except Exception as e:
                return {"error": f"Failed to get adapter statistics: {e}"}
    
    def get_system_info(self) -> Dict[str, any]:
        """
        Get comprehensive firewall system information.
        
        Returns:
            Dictionary with system information
        """
        with self._lock:
            # Get detection results
            available_systems = self.detect_firewall_systems()
            
            info = {
                "current_backend": self._backend_name,
                "available_backends": available_systems,
                "total_backends": len(self.FIREWALL_BACKENDS),
                "initialized": self._adapter is not None,
                "adapter_statistics": self.get_adapter_statistics()
            }
            
            # Add backend details
            info["backend_details"] = {}
            for backend in self.FIREWALL_BACKENDS:
                info["backend_details"][backend.name] = {
                    "priority": backend.priority,
                    "description": backend.description,
                    "available": available_systems.get(backend.name, False)
                }
            
            return info
    
    def switch_backend(self, backend_name: str) -> bool:
        """
        Switch to a different firewall backend.
        
        Args:
            backend_name: Name of the backend to switch to
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                # Check if backend is available
                available_systems = self.detect_firewall_systems()
                
                if backend_name not in available_systems or not available_systems[backend_name]:
                    self.logger.error(f"Backend {backend_name} is not available")
                    return False
                
                # Find backend configuration
                backend = next(
                    (b for b in self.FIREWALL_BACKENDS if b.name == backend_name),
                    None
                )
                
                if not backend:
                    self.logger.error(f"Unknown backend: {backend_name}")
                    return False
                
                # Clean up current adapter
                if self._adapter:
                    try:
                        self._adapter.cleanup()
                    except Exception as e:
                        self.logger.warning(f"Error cleaning up current adapter: {e}")
                
                # Initialize new adapter
                adapter_class = backend.adapter_class
                new_adapter = adapter_class()
                new_adapter.initialize()
                
                # Switch to new adapter
                self._adapter = new_adapter
                self._backend_name = backend.name
                
                self.logger.info(f"Successfully switched to firewall backend: {backend_name}")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to switch to backend {backend_name}: {e}")
                return False
    
    def cleanup(self) -> None:
        """Clean up firewall manager and adapter resources."""
        with self._lock:
            try:
                if self._adapter:
                    self._adapter.cleanup()
                    self._adapter = None
                
                self._backend_name = None
                self._available_backends.clear()
                self._detection_cache.clear()
                
                self.logger.info("FirewallManager cleanup completed")
                
            except Exception as e:
                self.logger.error(f"Error during firewall manager cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()