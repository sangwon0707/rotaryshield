"""Console entry points. Legacy cli.py is retained as historical source."""
from .commands import (
    CLISecurityManager, CommandResult, RotaryShieldCLI,
    config_main, control_main, list_blocked_main, monitor_main,
    stats_main, status_main, unblock_main,
)
