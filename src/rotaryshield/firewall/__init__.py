#!/usr/bin/env python3
"""
RotaryShield Firewall Module
Multi-platform firewall integration with auto-detection and security hardening.
"""

from .adapter import FirewallAdapter, FirewallError, FirewallOperationError
from .manager import FirewallManager
from .ufw_adapter import UFWAdapter
from .firewalld_adapter import FirewalldAdapter
from .iptables_adapter import IptablesAdapter

__all__ = [
    'FirewallAdapter',
    'FirewallError',
    'FirewallOperationError',
    'FirewallManager',
    'UFWAdapter',
    'FirewalldAdapter',
    'IptablesAdapter'
]