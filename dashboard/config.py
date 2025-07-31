#!/usr/bin/env python3
"""
RotaryShield Dashboard Configuration
"""

from pathlib import Path

# Dashboard settings
DASHBOARD_HOST = '127.0.0.1'
DASHBOARD_PORT = 8080
DEBUG_MODE = False

# Database configuration
DASHBOARD_DB_PATH = Path(__file__).parent / "data" / "dashboard.db"

# Refresh intervals (seconds)
AUTO_REFRESH_INTERVAL = 10
STATS_UPDATE_INTERVAL = 30

# Display settings
MAX_RECENT_EVENTS = 50
MAX_TOP_ATTACKERS = 15
MAX_BLOCKED_IPS = 20

# Security settings
RATE_LIMIT_PER_MINUTE = 100
CSRF_PROTECTION = True

# Integration settings - where to read RotaryShield data from
ROTARYSHIELD_DB_PATH = Path(__file__).parent.parent / "rotaryshield_live.db"

# Dashboard metadata
DASHBOARD_TITLE = "RotaryShield Security Dashboard"
DASHBOARD_VERSION = "2.0.0"
ORGANIZATION_NAME = "RotaryShield Security"