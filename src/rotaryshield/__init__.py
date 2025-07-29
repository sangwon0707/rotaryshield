#!/usr/bin/env python3
"""
RotaryShield - 3-Layer Security System
A production-ready intrusion detection and prevention system.

Copyright (c) 2025 RotaryShield Project
Licensed under MIT License
"""

__version__ = "0.1.0"
__author__ = "RotaryShield Team"
__license__ = "MIT"
__description__ = "3-layer security system with detection, throttling, and blocking"

# Security configuration
REQUIRED_PYTHON_VERSION = (3, 8)
MAX_MEMORY_USAGE_MB = 50
MAX_CPU_USAGE_PERCENT = 2

# Validate Python version for security features
import sys
if sys.version_info < REQUIRED_PYTHON_VERSION:
    raise RuntimeError(f"RotaryShield requires Python {REQUIRED_PYTHON_VERSION[0]}.{REQUIRED_PYTHON_VERSION[1]}+ for security features")

# Import main components
from .security.engine import SecurityEngine
from .config import ConfigManager

__all__ = [
    'SecurityEngine',
    'ConfigManager',
    '__version__',
    '__author__',
    '__license__',
    '__description__'
]