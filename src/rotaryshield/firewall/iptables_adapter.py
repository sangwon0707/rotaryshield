#!/usr/bin/env python3
"""
RotaryShield Iptables Adapter
Direct iptables implementation for advanced users and systems without UFW/firewalld.

Security Features:
- Direct iptables command validation and sanitization
- Chain management with isolation
- Rule ordering and conflict prevention
- Comprehensive error handling and logging
- Performance optimization for large rule sets
- IPv4 and IPv6 support
"""

import re
import shutil
from typing import List, Optional, Dict, Set, Tuple
import ipaddress

from .adapter import FirewallAdapter, FirewallError, FirewallOperationError, FirewallPermissionError


class IptablesAdapter(FirewallAdapter):
    """
    Direct iptables adapter implementation.
    
    This adapter provides direct integration with iptables for systems
    that don't use UFW or firewalld, or for advanced users who prefer
    direct iptables control.
    """
    
    def __init__(self):
        """Initialize iptables adapter."""
        super().__init__("iptables")
        
        # Iptables-specific configuration
        self._iptables_binary = "/sbin/iptables"
        self._ip6tables_binary = "/sbin/ip6tables"
        self._chain_name = "ROTARYSHIELD"
        self._rule_comment = "RotaryShield-managed"
        self._rule_cache: Dict[str, bool] = {}
        self._cache_timeout = 30  # seconds
        self._last_cache_update = 0
        
        # Rule templates
        self._ipv4_block_rule = [
            "-A", self._chain_name,
            "-s", "{ip}",
            "-j", "DROP",
            "-m", "comment", "--comment", self._rule_comment
        ]
        
        self._ipv6_block_rule = [
            "-A", self._chain_name,
            "-s", "{ip}",
            "-j", "DROP",
            "-m", "comment", "--comment", self._rule_comment
        ]
    
    def is_available(self) -> bool:
        """
        Check if iptables is available and functional.
        
        Returns:
            True if iptables is available, False otherwise
        """
        try:
            # Check if iptables binary exists
            if not shutil.which("iptables") and not shutil.which(self._iptables_binary):
                self.logger.debug("iptables binary not found")
                return False
            
            # Try to list iptables rules (basic functionality test)
            stdout, stderr, return_code = self._execute_command([
                "iptables", "-L", "-n"
            ])
            
            if return_code != 0:
                self.logger.debug(f"iptables list failed: {stderr}")
                return False
            
            # Check if we have iptables module support
            if "iptables" not in stdout.lower() and "chain" not in stdout.lower():
                self.logger.debug("iptables appears non-functional")
                return False
            
            self.logger.debug("iptables is available")
            return True
            
        except Exception as e:
            self.logger.debug(f"iptables availability check failed: {e}")
            return False
    
    def initialize(self) -> None:
        """
        Initialize iptables and create RotaryShield chain.
        
        Raises:
            FirewallError: If initialization fails
            FirewallPermissionError: If insufficient privileges
        """
        try:
            # Check if iptables is available
            if not self.is_available():
                raise FirewallError("iptables is not available on this system")
            
            # Test permissions
            stdout, stderr, return_code = self._execute_command([
                "iptables", "-L", "-n"
            ])
            
            if return_code != 0:
                if "permission denied" in stderr.lower() or "not permitted" in stderr.lower():
                    raise FirewallPermissionError(
                        "Insufficient privileges to manage iptables. Root privileges required."
                    )
                else:
                    raise FirewallOperationError(f"iptables test failed: {stderr}")
            
            # Create RotaryShield chain for IPv4
            self._create_chain("iptables", self._chain_name)
            
            # Create RotaryShield chain for IPv6 if available
            if self._is_ipv6_available():
                self._create_chain("ip6tables", self._chain_name)
            
            # Ensure our chain is referenced in INPUT chain
            self._setup_chain_reference("iptables")
            if self._is_ipv6_available():
                self._setup_chain_reference("ip6tables")
            
            # Initialize rule cache
            self._update_rule_cache()
            
            self.logger.info("iptables initialization successful")
            
        except (FirewallError, FirewallPermissionError):
            raise
        except Exception as e:
            raise FirewallError(f"iptables initialization failed: {e}")
    
    def _is_ipv6_available(self) -> bool:
        """Check if IPv6 and ip6tables are available."""
        try:
            if not shutil.which("ip6tables") and not shutil.which(self._ip6tables_binary):
                return False
            
            stdout, stderr, return_code = self._execute_command([
                "ip6tables", "-L", "-n"
            ])
            
            return return_code == 0
            
        except Exception:
            return False
    
    def _create_chain(self, iptables_cmd: str, chain_name: str) -> None:
        """Create iptables chain if it doesn't exist."""
        try:
            # Check if chain already exists
            stdout, stderr, return_code = self._execute_command([
                iptables_cmd, "-L", chain_name, "-n"
            ])
            
            if return_code == 0:
                self.logger.debug(f"{iptables_cmd} chain {chain_name} already exists")
                return
            
            # Create new chain
            stdout, stderr, return_code = self._execute_command([
                iptables_cmd, "-N", chain_name
            ])
            
            if return_code == 0:
                self.logger.info(f"Created {iptables_cmd} chain: {chain_name}")
            elif "already exists" in stderr.lower():
                self.logger.debug(f"{iptables_cmd} chain {chain_name} already exists")
            else:
                raise FirewallOperationError(f"Failed to create {iptables_cmd} chain: {stderr}")
                
        except Exception as e:
            self.logger.error(f"Error creating {iptables_cmd} chain {chain_name}: {e}")
            raise
    
    def _setup_chain_reference(self, iptables_cmd: str) -> None:
        """Ensure our chain is referenced in the INPUT chain."""
        try:
            # Check if reference already exists
            stdout, stderr, return_code = self._execute_command([
                iptables_cmd, "-L", "INPUT", "-n"
            ])
            
            if return_code == 0 and self._chain_name in stdout:
                self.logger.debug(f"{iptables_cmd} chain reference already exists")
                return
            
            # Add reference to our chain at the beginning of INPUT
            stdout, stderr, return_code = self._execute_command([
                iptables_cmd, "-I", "INPUT", "1", "-j", self._chain_name
            ])
            
            if return_code == 0:
                self.logger.info(f"Added {iptables_cmd} chain reference to INPUT")
            else:
                self.logger.error(f"Failed to add {iptables_cmd} chain reference: {stderr}")
                
        except Exception as e:
            self.logger.error(f"Error setting up {iptables_cmd} chain reference: {e}")
    
    def block_ip(self, ip_address: str, comment: Optional[str] = None) -> bool:
        """
        Block an IP address using iptables.
        
        Args:
            ip_address: IP address to block
            comment: Optional comment for the rule
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate IP address and determine version
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
            is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
            
            # Choose appropriate iptables binary and rule template
            if is_ipv6:
                if not self._is_ipv6_available():
                    raise FirewallError("IPv6 support not available")
                iptables_cmd = "ip6tables"
                rule_template = self._ipv6_block_rule.copy()
            else:
                iptables_cmd = "iptables"
                rule_template = self._ipv4_block_rule.copy()
            
            # Substitute IP address in rule template
            rule = [arg.format(ip=normalized_ip) if '{ip}' in arg else arg 
                   for arg in rule_template]
            
            # Execute iptables command
            stdout, stderr, return_code = self._execute_command([iptables_cmd] + rule)
            
            if return_code == 0:
                # Update cache
                self._rule_cache[normalized_ip] = True
                self.logger.debug(f"iptables rule added for IP: {normalized_ip}")
                return True
            else:
                # Check for duplicate rule error
                if "already exists" in stderr.lower() or "duplicate" in stderr.lower():
                    self.logger.debug(f"iptables rule already exists for IP: {normalized_ip}")
                    self._rule_cache[normalized_ip] = True
                    return True
                else:
                    self.logger.error(f"iptables block command failed: {stderr}")
                    return False
            
        except ipaddress.AddressValueError:
            raise FirewallError(f"Invalid IP address format: {ip_address}")
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address} with iptables: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address using iptables.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate IP address and determine version
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
            is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
            
            # Choose appropriate iptables binary
            iptables_cmd = "ip6tables" if is_ipv6 else "iptables"
            
            # Build delete command
            delete_rule = [
                iptables_cmd, "-D", self._chain_name,
                "-s", normalized_ip,
                "-j", "DROP",
                "-m", "comment", "--comment", self._rule_comment
            ]
            
            # Execute delete command
            stdout, stderr, return_code = self._execute_command(delete_rule)
            
            if return_code == 0:
                # Update cache
                self._rule_cache[normalized_ip] = False
                self.logger.debug(f"iptables rule removed for IP: {normalized_ip}")
                return True
            else:
                # Check if rule doesn't exist
                if ("no such rule" in stderr.lower() or 
                    "bad rule" in stderr.lower() or
                    "does not exist" in stderr.lower()):
                    self.logger.debug(f"iptables rule doesn't exist for IP: {normalized_ip}")
                    self._rule_cache[normalized_ip] = False
                    return True
                else:
                    self.logger.error(f"iptables unblock command failed: {stderr}")
                    return False
            
        except ipaddress.AddressValueError:
            raise FirewallError(f"Invalid IP address format: {ip_address}")
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address} with iptables: {e}")
            return False
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked by iptables.
        
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
        Get total number of iptables rules managed by RotaryShield.
        
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
        """Update the internal rule cache by parsing iptables rules."""
        try:
            new_cache = {}
            
            # Parse IPv4 rules
            self._parse_iptables_rules("iptables", new_cache)
            
            # Parse IPv6 rules if available
            if self._is_ipv6_available():
                self._parse_iptables_rules("ip6tables", new_cache)
            
            # Update cache and timestamp
            self._rule_cache = new_cache
            self._last_cache_update = self._get_current_time()
            
            self.logger.debug(f"Updated iptables rule cache with {len(new_cache)} rules")
            
        except Exception as e:
            self.logger.error(f"Error updating rule cache: {e}")
    
    def _parse_iptables_rules(self, iptables_cmd: str, cache: Dict[str, bool]) -> None:
        """Parse iptables rules for a specific command (iptables/ip6tables)."""
        try:
            # Get rules from our chain
            stdout, stderr, return_code = self._execute_command([
                iptables_cmd, "-L", self._chain_name, "-n", "-v"
            ])
            
            if return_code != 0:
                if "no chain" in stderr.lower():
                    # Chain doesn't exist yet, that's OK
                    return
                else:
                    self.logger.error(f"Failed to list {iptables_cmd} rules: {stderr}")
                    return
            
            # Parse output to find DROP rules with our comment
            for line in stdout.split('\n'):
                if 'DROP' in line and self._rule_comment in line:
                    # Extract source IP from the line
                    # Format is typically: pkts bytes target prot opt source destination
                    parts = line.split()
                    if len(parts) >= 6:
                        source = parts[4]  # source column
                        if source != "0.0.0.0/0" and source != "::/0":
                            # Remove subnet mask if present
                            ip_address = source.split('/')[0]
                            try:
                                # Validate and normalize IP
                                ip_obj = ipaddress.ip_address(ip_address)
                                normalized_ip = str(ip_obj)
                                cache[normalized_ip] = True
                            except ipaddress.AddressValueError:
                                continue
            
        except Exception as e:
            self.logger.error(f"Error parsing {iptables_cmd} rules: {e}")
    
    def _get_current_time(self) -> float:
        """Get current time (wrapper for testing)."""
        import time
        return time.time()
    
    def get_iptables_status(self) -> Dict[str, any]:
        """
        Get detailed iptables status information.
        
        Returns:
            Dictionary with iptables status details
        """
        try:
            status_info = {
                "available": True,
                "ipv4_available": True,
                "ipv6_available": self._is_ipv6_available(),
                "chain_exists": False,
                "total_rules": 0,
                "rotaryshield_rules": len(self.list_blocked_ips())
            }
            
            # Check if our chain exists
            stdout, stderr, return_code = self._execute_command([
                "iptables", "-L", self._chain_name, "-n"
            ])
            
            if return_code == 0:
                status_info["chain_exists"] = True
                # Count rules in our chain
                rule_count = stdout.count('DROP') + stdout.count('ACCEPT') + stdout.count('REJECT')
                status_info["total_rules"] = rule_count
            
            return status_info
            
        except Exception as e:
            self.logger.error(f"Error getting iptables status: {e}")
            return {"error": str(e), "available": False}
    
    def flush_chain(self) -> bool:
        """
        Flush all rules from RotaryShield chain.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            success = True
            
            # Flush IPv4 chain
            stdout, stderr, return_code = self._execute_command([
                "iptables", "-F", self._chain_name
            ])
            
            if return_code != 0 and "no chain" not in stderr.lower():
                self.logger.error(f"Failed to flush iptables chain: {stderr}")
                success = False
            
            # Flush IPv6 chain if available
            if self._is_ipv6_available():
                stdout, stderr, return_code = self._execute_command([
                    "ip6tables", "-F", self._chain_name
                ])
                
                if return_code != 0 and "no chain" not in stderr.lower():
                    self.logger.error(f"Failed to flush ip6tables chain: {stderr}")
                    success = False
            
            if success:
                # Clear cache
                self._rule_cache.clear()
                self.logger.info("iptables chains flushed successfully")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error flushing iptables chains: {e}")
            return False
    
    def cleanup(self) -> None:
        """Clean up iptables adapter and remove chains."""
        try:
            super().cleanup()
            
            # Optional: Remove all rules and chains
            # This is disabled by default to maintain security state
            # self.flush_chain()
            
            # Clear cache
            self._rule_cache.clear()
            
        except Exception as e:
            self.logger.error(f"Error during iptables cleanup: {e}")