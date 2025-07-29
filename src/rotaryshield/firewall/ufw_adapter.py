#!/usr/bin/env python3
"""
RotaryShield UFW (Uncomplicated Firewall) Adapter
Implementation for Ubuntu/Debian systems with comprehensive security measures.

Security Features:
- UFW command validation and sanitization
- Privilege escalation detection and prevention
- Rule conflict detection and resolution
- Comprehensive error handling and logging
- Performance optimization for large rule sets
"""

import re
import shutil
from typing import List, Optional, Dict, Set
import ipaddress

from .adapter import FirewallAdapter, FirewallError, FirewallOperationError, FirewallPermissionError


class UFWAdapter(FirewallAdapter):
    """
    UFW (Uncomplicated Firewall) adapter implementation.
    
    UFW is the default firewall configuration tool for Ubuntu and is used
    extensively in Debian-based systems. This adapter provides secure
    integration with UFW while maintaining comprehensive security measures.
    """
    
    def __init__(self):
        """Initialize UFW adapter."""
        super().__init__("ufw")
        
        # UFW-specific configuration
        self._ufw_binary = "/usr/sbin/ufw"
        self._rule_prefix = "rotaryshield"
        self._rule_cache: Dict[str, bool] = {}
        self._cache_timeout = 30  # seconds
        self._last_cache_update = 0
        
        # UFW rule patterns for parsing
        self._block_rule_pattern = re.compile(
            r'^\s*\[\s*\d+\]\s+DENY\s+IN\s+.*?(\d+\.\d+\.\d+\.\d+)'
        )
    
    def is_available(self) -> bool:
        """
        Check if UFW is available and functional.
        
        Returns:
            True if UFW is available, False otherwise
        """
        try:
            # Check if UFW binary exists
            if not shutil.which("ufw") and not shutil.which(self._ufw_binary):
                self.logger.debug("UFW binary not found")
                return False
            
            # Try to get UFW status
            stdout, stderr, return_code = self._execute_command(["ufw", "--version"])
            
            if return_code != 0:
                self.logger.debug(f"UFW version check failed: {stderr}")
                return False
            
            # Check if we can read UFW status (doesn't require root)
            stdout, stderr, return_code = self._execute_command(["ufw", "status"])
            
            # UFW might return non-zero if firewall is inactive, but that's OK
            if "ERROR" in stderr.upper() or "COMMAND NOT FOUND" in stderr.upper():
                self.logger.debug(f"UFW status check failed: {stderr}")
                return False
            
            self.logger.debug("UFW is available")
            return True
            
        except Exception as e:
            self.logger.debug(f"UFW availability check failed: {e}")
            return False
    
    def initialize(self) -> None:
        """
        Initialize UFW and verify it's properly configured.
        
        Raises:
            FirewallError: If initialization fails
            FirewallPermissionError: If insufficient privileges
        """
        try:
            # Check if UFW is available
            if not self.is_available():
                raise FirewallError("UFW is not available on this system")
            
            # Check UFW status and permissions
            stdout, stderr, return_code = self._execute_command(["ufw", "status", "verbose"])
            
            if return_code != 0 and "you need to be root" in stderr.lower():
                raise FirewallPermissionError(
                    "Insufficient privileges to manage UFW. Root privileges required."
                )
            
            # Parse UFW status
            if "Status: inactive" in stdout:
                self.logger.warning("UFW is inactive. RotaryShield rules will be added but not enforced until UFW is enabled.")
            elif "Status: active" in stdout:
                self.logger.info("UFW is active and ready")
            
            # Verify we can add/remove rules (test with a safe operation)
            test_ip = "192.0.2.1"  # RFC5737 test address
            
            # Try to add a test rule
            stdout, stderr, return_code = self._execute_command([
                "ufw", "insert", "1", "deny", "from", test_ip, 
                "comment", f"{self._rule_prefix}-test"
            ])
            
            if return_code == 0:
                # Remove the test rule immediately
                self._execute_command([
                    "ufw", "--force", "delete", "deny", "from", test_ip
                ])
                self.logger.info("UFW initialization successful - rule management verified")
            else:
                if "you need to be root" in stderr.lower():
                    raise FirewallPermissionError(
                        "Cannot manage UFW rules. Root privileges required."
                    )
                else:
                    raise FirewallOperationError(f"UFW rule test failed: {stderr}")
            
            # Initialize rule cache
            self._update_rule_cache()
            
        except (FirewallError, FirewallPermissionError):
            raise
        except Exception as e:
            raise FirewallError(f"UFW initialization failed: {e}")
    
    def block_ip(self, ip_address: str, comment: Optional[str] = None) -> bool:
        """
        Block an IP address using UFW.
        
        Args:
            ip_address: IP address to block
            comment: Optional comment for the rule
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
            
            # Create comment with RotaryShield identifier
            rule_comment = f"{self._rule_prefix}"
            if comment:
                # Sanitize comment for UFW
                sanitized_comment = re.sub(r'[^\w\s\-_.]', '', comment)[:50]
                rule_comment += f"-{sanitized_comment}"
            
            # Build UFW command
            ufw_command = [
                "ufw", "insert", "1", "deny", "from", normalized_ip,
                "comment", rule_comment
            ]
            
            # Execute UFW command
            stdout, stderr, return_code = self._execute_command(ufw_command)
            
            if return_code == 0:
                # Update cache
                self._rule_cache[normalized_ip] = True
                self.logger.debug(f"UFW rule added for IP: {normalized_ip}")
                return True
            else:
                # Handle specific UFW errors
                if "existing rule" in stderr.lower() or "duplicate" in stderr.lower():
                    self.logger.debug(f"UFW rule already exists for IP: {normalized_ip}")
                    self._rule_cache[normalized_ip] = True
                    return True
                elif "invalid" in stderr.lower():
                    raise FirewallError(f"Invalid IP address for UFW: {normalized_ip}")
                else:
                    self.logger.error(f"UFW block command failed: {stderr}")
                    return False
            
        except ipaddress.AddressValueError:
            raise FirewallError(f"Invalid IP address format: {ip_address}")
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address} with UFW: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address using UFW.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
            
            # UFW delete command - try multiple approaches
            delete_commands = [
                # Try deleting by rule specification
                ["ufw", "--force", "delete", "deny", "from", normalized_ip],
                # Try deleting by rule number (requires finding the rule first)
            ]
            
            success = False
            for command in delete_commands:
                stdout, stderr, return_code = self._execute_command(command)
                
                if return_code == 0:
                    success = True
                    break
                elif "could not delete non-existent rule" in stderr.lower():
                    # Rule doesn't exist, which is fine
                    success = True
                    break
                elif "rule not found" in stderr.lower():
                    # Try next approach
                    continue
            
            # If standard deletion failed, try finding by rule number
            if not success:
                rule_number = self._find_rule_number(normalized_ip)
                if rule_number:
                    stdout, stderr, return_code = self._execute_command([
                        "ufw", "--force", "delete", str(rule_number)
                    ])
                    success = (return_code == 0)
            
            if success:
                # Update cache
                self._rule_cache[normalized_ip] = False
                self.logger.debug(f"UFW rule removed for IP: {normalized_ip}")
            else:
                self.logger.error(f"Failed to remove UFW rule for IP: {normalized_ip}")
            
            return success
            
        except ipaddress.AddressValueError:
            raise FirewallError(f"Invalid IP address format: {ip_address}")
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address} with UFW: {e}")
            return False
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked by UFW.
        
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
        Get total number of UFW rules managed by RotaryShield.
        
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
        """Update the internal rule cache by parsing UFW status."""
        try:
            # Get UFW status with rule numbers
            stdout, stderr, return_code = self._execute_command([
                "ufw", "status", "numbered"
            ])
            
            if return_code != 0:
                self.logger.error(f"Failed to get UFW status: {stderr}")
                return
            
            # Clear existing cache
            new_cache = {}
            
            # Parse UFW output to find RotaryShield rules
            for line in stdout.split('\n'):
                # Look for DENY rules with our prefix in comment
                if 'DENY' in line and self._rule_prefix in line:
                    # Extract IP address from the rule
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
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
            
            self.logger.debug(f"Updated UFW rule cache with {len(new_cache)} rules")
            
        except Exception as e:
            self.logger.error(f"Error updating rule cache: {e}")
    
    def _find_rule_number(self, ip_address: str) -> Optional[int]:
        """
        Find UFW rule number for a specific IP address.
        
        Args:
            ip_address: IP address to find
            
        Returns:
            Rule number if found, None otherwise
        """
        try:
            # Get UFW status with rule numbers
            stdout, stderr, return_code = self._execute_command([
                "ufw", "status", "numbered"
            ])
            
            if return_code != 0:
                return None
            
            # Parse output to find rule number
            for line in stdout.split('\n'):
                if ip_address in line and 'DENY' in line:
                    # Extract rule number from beginning of line
                    number_match = re.match(r'^\s*\[\s*(\d+)\s*\]', line)
                    if number_match:
                        return int(number_match.group(1))
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding rule number for {ip_address}: {e}")
            return None
    
    def _get_current_time(self) -> float:
        """Get current time (wrapper for testing)."""
        import time
        return time.time()
    
    def get_ufw_status(self) -> Dict[str, any]:
        """
        Get detailed UFW status information.
        
        Returns:
            Dictionary with UFW status details
        """
        try:
            stdout, stderr, return_code = self._execute_command([
                "ufw", "status", "verbose"
            ])
            
            if return_code != 0:
                return {"error": stderr, "available": False}
            
            # Parse status
            status_info = {
                "available": True,
                "active": "Status: active" in stdout,
                "default_incoming": "unknown",
                "default_outgoing": "unknown",
                "default_routed": "unknown",
                "total_rules": 0,
                "rotaryshield_rules": len(self.list_blocked_ips())
            }
            
            # Extract default policies
            for line in stdout.split('\n'):
                if "Default:" in line:
                    if "incoming" in line.lower():
                        status_info["default_incoming"] = "deny" if "deny" in line.lower() else "allow"
                    elif "outgoing" in line.lower():
                        status_info["default_outgoing"] = "deny" if "deny" in line.lower() else "allow"
                    elif "routed" in line.lower():
                        status_info["default_routed"] = "deny" if "deny" in line.lower() else "allow"
            
            # Count total rules
            rule_count = stdout.count('ALLOW') + stdout.count('DENY') + stdout.count('REJECT')
            status_info["total_rules"] = rule_count
            
            return status_info
            
        except Exception as e:
            self.logger.error(f"Error getting UFW status: {e}")
            return {"error": str(e), "available": False}
    
    def cleanup(self) -> None:
        """Clean up UFW adapter and remove temporary rules."""
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
            self.logger.error(f"Error during UFW cleanup: {e}")