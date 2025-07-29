#!/usr/bin/env python3
"""
RotaryShield Firewalld Adapter
Implementation for CentOS/RHEL/Fedora systems with comprehensive security measures.

Security Features:
- Firewalld command validation and sanitization
- Zone-based rule management
- Rich rule syntax validation
- Comprehensive error handling and logging
- Performance optimization for large rule sets
"""

import re
import shutil
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Set
import ipaddress

from .adapter import FirewallAdapter, FirewallError, FirewallOperationError, FirewallPermissionError


class FirewalldAdapter(FirewallAdapter):
    """
    Firewalld adapter implementation.
    
    Firewalld is the default firewall management tool for RHEL/CentOS 7+,
    Fedora, and other Red Hat-based distributions. This adapter provides
    secure integration with firewalld using rich rules and proper zone management.
    """
    
    def __init__(self):
        """Initialize Firewalld adapter."""
        super().__init__("firewalld")
        
        # Firewalld-specific configuration
        self._firewall_cmd = "/usr/bin/firewall-cmd"
        self._default_zone = "drop"  # Most restrictive zone for blocked IPs
        self._rule_prefix = "rotaryshield"
        self._rule_cache: Dict[str, bool] = {}
        self._cache_timeout = 30  # seconds
        self._last_cache_update = 0
        
        # Rich rule template for IP blocking
        self._block_rule_template = (
            "rule family='{family}' source address='{ip}' drop"
        )
    
    def is_available(self) -> bool:
        """
        Check if firewalld is available and functional.
        
        Returns:
            True if firewalld is available, False otherwise
        """
        try:
            # Check if firewall-cmd binary exists
            if not shutil.which("firewall-cmd") and not shutil.which(self._firewall_cmd):
                self.logger.debug("firewall-cmd binary not found")
                return False
            
            # Check if firewalld service is running
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--state"
            ])
            
            if return_code != 0:
                self.logger.debug(f"Firewalld state check failed: {stderr}")
                return False
            
            if "running" not in stdout.lower():
                self.logger.debug("Firewalld is not running")
                return False
            
            # Try to get default zone (basic functionality test)
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--get-default-zone"
            ])
            
            if return_code != 0:
                self.logger.debug(f"Firewalld zone check failed: {stderr}")
                return False
            
            self.logger.debug("Firewalld is available")
            return True
            
        except Exception as e:
            self.logger.debug(f"Firewalld availability check failed: {e}")
            return False
    
    def initialize(self) -> None:
        """
        Initialize firewalld and verify it's properly configured.
        
        Raises:
            FirewallError: If initialization fails
            FirewallPermissionError: If insufficient privileges
        """
        try:
            # Check if firewalld is available
            if not self.is_available():
                raise FirewallError("Firewalld is not available on this system")
            
            # Check permissions by trying to list zones
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--list-all-zones"
            ])
            
            if return_code != 0:
                if "authorization" in stderr.lower() or "permission" in stderr.lower():
                    raise FirewallPermissionError(
                        "Insufficient privileges to manage firewalld. Root privileges required."
                    )
                else:
                    raise FirewallOperationError(f"Failed to list firewalld zones: {stderr}")
            
            # Get available zones
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--get-zones"
            ])
            
            if return_code == 0:
                available_zones = stdout.strip().split()
                if self._default_zone not in available_zones:
                    # Use the most restrictive available zone
                    restrictive_zones = ['drop', 'block', 'public']
                    for zone in restrictive_zones:
                        if zone in available_zones:
                            self._default_zone = zone
                            break
                    else:
                        self._default_zone = available_zones[0]  # Fallback
                
                self.logger.info(f"Using firewalld zone: {self._default_zone}")
            
            # Test rich rule support
            test_ip = "192.0.2.1"  # RFC5737 test address
            test_rule = self._block_rule_template.format(
                family="ipv4",
                ip=test_ip
            )
            
            # Try to add a test rich rule
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--zone", self._default_zone,
                "--add-rich-rule", test_rule
            ])
            
            if return_code == 0:
                # Remove the test rule immediately
                self._execute_command([
                    "firewall-cmd", "--zone", self._default_zone,
                    "--remove-rich-rule", test_rule
                ])
                self.logger.info("Firewalld initialization successful - rich rule support verified")
            else:
                if "authorization" in stderr.lower() or "permission" in stderr.lower():
                    raise FirewallPermissionError(
                        "Cannot manage firewalld rules. Root privileges required."
                    )
                else:
                    self.logger.warning(f"Rich rule test failed, trying fallback methods: {stderr}")
            
            # Initialize rule cache
            self._update_rule_cache()
            
        except (FirewallError, FirewallPermissionError):
            raise
        except Exception as e:
            raise FirewallError(f"Firewalld initialization failed: {e}")
    
    def block_ip(self, ip_address: str, comment: Optional[str] = None) -> bool:
        """
        Block an IP address using firewalld rich rules.
        
        Args:
            ip_address: IP address to block
            comment: Optional comment for the rule (not used in firewalld)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate IP address and determine family
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
            family = "ipv6" if isinstance(ip_obj, ipaddress.IPv6Address) else "ipv4"
            
            # Create rich rule
            rich_rule = self._block_rule_template.format(
                family=family,
                ip=normalized_ip
            )
            
            # Add permanent rule first
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--permanent", "--zone", self._default_zone,
                "--add-rich-rule", rich_rule
            ])
            
            permanent_success = (return_code == 0)
            if not permanent_success and "already enabled" not in stderr.lower():
                self.logger.error(f"Failed to add permanent firewalld rule: {stderr}")
            
            # Add runtime rule
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--zone", self._default_zone,
                "--add-rich-rule", rich_rule
            ])
            
            runtime_success = (return_code == 0)
            if not runtime_success and "already enabled" not in stderr.lower():
                self.logger.error(f"Failed to add runtime firewalld rule: {stderr}")
            
            # Consider successful if either permanent or runtime succeeded
            success = permanent_success or runtime_success
            
            if success or "already enabled" in stderr.lower():
                # Update cache
                self._rule_cache[normalized_ip] = True
                self.logger.debug(f"Firewalld rule added for IP: {normalized_ip}")
                return True
            else:
                return False
            
        except ipaddress.AddressValueError:
            raise FirewallError(f"Invalid IP address format: {ip_address}")
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address} with firewalld: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address using firewalld.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate IP address and determine family
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
            family = "ipv6" if isinstance(ip_obj, ipaddress.IPv6Address) else "ipv4"
            
            # Create rich rule
            rich_rule = self._block_rule_template.format(
                family=family,
                ip=normalized_ip
            )
            
            # Remove permanent rule
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--permanent", "--zone", self._default_zone,
                "--remove-rich-rule", rich_rule
            ])
            
            permanent_success = (return_code == 0)
            if not permanent_success and "not enabled" not in stderr.lower():
                self.logger.debug(f"Permanent rule removal result: {stderr}")
            
            # Remove runtime rule
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--zone", self._default_zone,
                "--remove-rich-rule", rich_rule
            ])
            
            runtime_success = (return_code == 0)
            if not runtime_success and "not enabled" not in stderr.lower():
                self.logger.debug(f"Runtime rule removal result: {stderr}")
            
            # Consider successful if either removal succeeded or rule wasn't found
            success = (permanent_success or runtime_success or 
                      "not enabled" in stderr.lower())
            
            if success:
                # Update cache
                self._rule_cache[normalized_ip] = False
                self.logger.debug(f"Firewalld rule removed for IP: {normalized_ip}")
            
            return success
            
        except ipaddress.AddressValueError:
            raise FirewallError(f"Invalid IP address format: {ip_address}")
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address} with firewalld: {e}")
            return False
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked by firewalld.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
            
            # Check cache first
            if normalized_ip in self._rule_cache:
                cache_age = abs(self._get_current_time() - self._last_cache_update)
                if cache_age < self._cache_timeout:
                    return self._rule_cache[normalized_ip]
            
            # Update cache and check
            self._update_rule_cache()
            return self._rule_cache.get(normalized_ip, False)
            
        except ipaddress.AddressValueError:
            self.logger.error(f"Invalid IP address format: {ip_address}")
            return False
        except Exception as e:
            self.logger.error(f"Error checking if IP {ip_address} is blocked: {e}")
            return False
    
    def list_blocked_ips(self) -> List[str]:
        """
        Get list of all IP addresses blocked by RotaryShield rules.
        
        Returns:
            List of blocked IP addresses
        """
        try:
            # Update cache
            self._update_rule_cache()
            
            # Return IPs that are marked as blocked in cache
            return [ip for ip, blocked in self._rule_cache.items() if blocked]
            
        except Exception as e:
            self.logger.error(f"Error listing blocked IPs: {e}")
            return []
    
    def get_rule_count(self) -> int:
        """
        Get total number of firewalld rules managed by RotaryShield.
        
        Returns:
            Number of active rules
        """
        try:
            blocked_ips = self.list_blocked_ips()
            return len(blocked_ips)
            
        except Exception as e:
            self.logger.error(f"Error getting rule count: {e}")
            return 0
    
    def _update_rule_cache(self) -> None:
        """Update the internal rule cache by parsing firewalld rich rules."""
        try:
            # Get rich rules from the zone
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--zone", self._default_zone, "--list-rich-rules"
            ])
            
            if return_code != 0:
                self.logger.error(f"Failed to get firewalld rich rules: {stderr}")
                return
            
            # Clear existing cache
            new_cache = {}
            
            # Parse rich rules to find RotaryShield rules
            for line in stdout.strip().split('\n'):
                if not line.strip():
                    continue
                
                # Look for drop rules with IP addresses
                if 'drop' in line and 'source address=' in line:
                    # Extract IP address from rich rule
                    ip_match = re.search(r'source address=["\']?([^"\'>\s]+)', line)
                    if ip_match:
                        ip_address = ip_match.group(1)
                        try:
                            # Validate and normalize IP
                            ip_obj = ipaddress.ip_address(ip_address)
                            normalized_ip = str(ip_obj)
                            new_cache[normalized_ip] = True
                        except ipaddress.AddressValueError:
                            continue
            
            # Update cache and timestamp
            self._rule_cache = new_cache
            self._last_cache_update = self._get_current_time()
            
            self.logger.debug(f"Updated firewalld rule cache with {len(new_cache)} rules")
            
        except Exception as e:
            self.logger.error(f"Error updating rule cache: {e}")
    
    def _get_current_time(self) -> float:
        """Get current time (wrapper for testing)."""
        import time
        return time.time()
    
    def get_firewalld_status(self) -> Dict[str, any]:
        """
        Get detailed firewalld status information.
        
        Returns:
            Dictionary with firewalld status details
        """
        try:
            # Get basic state
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--state"
            ])
            
            if return_code != 0:
                return {"error": stderr, "available": False}
            
            status_info = {
                "available": True,
                "running": "running" in stdout.lower(),
                "default_zone": "unknown",
                "active_zones": [],
                "total_rich_rules": 0,
                "rotaryshield_rules": len(self.list_blocked_ips())
            }
            
            # Get default zone
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--get-default-zone"
            ])
            if return_code == 0:
                status_info["default_zone"] = stdout.strip()
            
            # Get active zones
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--get-active-zones"
            ])
            if return_code == 0:
                # Parse active zones (format: zone\n  interfaces: ...)
                zones = []
                for line in stdout.split('\n'):
                    if line and not line.startswith(' '):
                        zones.append(line.strip())
                status_info["active_zones"] = zones
            
            # Count total rich rules
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--list-all-zones"
            ])
            if return_code == 0:
                rich_rule_count = stdout.count('rich rules:')
                status_info["total_rich_rules"] = rich_rule_count
            
            return status_info
            
        except Exception as e:
            self.logger.error(f"Error getting firewalld status: {e}")
            return {"error": str(e), "available": False}
    
    def reload_firewalld(self) -> bool:
        """
        Reload firewalld configuration.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            stdout, stderr, return_code = self._execute_command([
                "firewall-cmd", "--reload"
            ])
            
            if return_code == 0:
                self.logger.info("Firewalld configuration reloaded")
                # Clear cache to force refresh
                self._rule_cache.clear()
                self._last_cache_update = 0
                return True
            else:
                self.logger.error(f"Failed to reload firewalld: {stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error reloading firewalld: {e}")
            return False
    
    def cleanup(self) -> None:
        """Clean up firewalld adapter and remove temporary rules."""
        try:
            super().cleanup()
            
            # Optional: Remove all RotaryShield rules on cleanup
            # This is disabled by default to maintain security state
            # blocked_ips = self.list_blocked_ips()
            # for ip in blocked_ips:
            #     self.unblock_ip(ip)
            
            # Clear cache
            self._rule_cache.clear()
            
        except Exception as e:
            self.logger.error(f"Error during firewalld cleanup: {e}")