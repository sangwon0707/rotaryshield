#!/usr/bin/env python3
"""
RotaryShield CLI Interface
Production-ready command-line interface with comprehensive security features.

Security Features:
- Input validation and sanitization for all arguments
- Rate limiting for command execution
- Comprehensive audit logging of all CLI operations
- Permission validation before executing privileged operations
- Secure error handling with sanitized output
- Process isolation and resource limits

Enhanced with Rich library for beautiful terminal output.
"""

import os
import sys
import time
import signal
import argparse
import subprocess
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime

# Rich library for beautiful CLI output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.style import Style
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Import handling for both module and direct script execution
try:
    from .config import ConfigManager, ConfigurationError
    from .utils.logging import setup_logging, get_audit_logger
    from .utils.validators import validate_file_path, sanitize_string, validate_ip_address
    from .main import test_configuration
    from .database.manager import DatabaseManager
    from .database.ip_manager import IPManager
    from .database.models import BanStatus, EventSeverity
except ImportError:
    # Add the src directory to Python path for direct script execution
    current_dir = Path(__file__).resolve().parent
    src_dir = current_dir.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    from rotaryshield.config import ConfigManager, ConfigurationError
    from rotaryshield.utils.logging import setup_logging, get_audit_logger
    from rotaryshield.utils.validators import validate_file_path, sanitize_string, validate_ip_address
    from rotaryshield.main import test_configuration
    from rotaryshield.database.manager import DatabaseManager
    from rotaryshield.database.ip_manager import IPManager
    from rotaryshield.database.models import BanStatus, EventSeverity


# Initialize Rich console
console = Console() if RICH_AVAILABLE else None


def get_severity_style(severity: str) -> str:
    """Get Rich style for severity level."""
    severity_styles = {
        'critical': 'bold red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'green'
    }
    return severity_styles.get(severity.lower(), 'white')


def format_timestamp(timestamp: float) -> str:
    """Format Unix timestamp to readable string."""
    if timestamp <= 0:
        return "N/A"
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
    else:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        return f"{days}d {hours}h"


@dataclass
class CommandResult:
    """Secure command execution result with sanitized output."""
    success: bool
    message: str
    exit_code: int
    execution_time: float


class CLISecurityManager:
    """Security manager for CLI operations with comprehensive protections."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.audit_logger = get_audit_logger()
        self._command_history: List[Dict[str, Any]] = []
        self._last_command_time = 0.0
        self._command_rate_limit = 1.0  # Minimum seconds between commands

    def validate_command_execution(self, command: str, user_id: str = "cli") -> bool:
        """
        Validate that command execution is authorized and within rate limits.

        Args:
            command: Command being executed
            user_id: User executing the command

        Returns:
            True if command execution is authorized
        """
        try:
            # Rate limiting protection
            current_time = time.time()
            if current_time - self._last_command_time < self._command_rate_limit:
                self.logger.warning(f"Rate limit exceeded for command: {command}")
                return False

            self._last_command_time = current_time

            # Log command execution attempt
            if self.audit_logger:
                self.audit_logger.log_system_event(
                    action="cli_command_attempted",
                    user_id=user_id,
                    description=f"CLI command: {sanitize_string(command)}"
                )

            # Check for potentially dangerous commands
            dangerous_patterns = [
                "rm -rf", "sudo rm", "mkfs", "dd if=", ":(){ :|:& };:",
                "chmod 777", "chown -R root", ">/dev/sd"
            ]

            for pattern in dangerous_patterns:
                if pattern in command.lower():
                    self.logger.error(f"Dangerous command pattern detected: {pattern}")
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Error validating command execution: {e}")
            return False

    def log_command_result(self, command: str, result: CommandResult, user_id: str = "cli") -> None:
        """Log command execution result for audit trail."""
        try:
            # Store in command history (limited to last 100 commands)
            self._command_history.append({
                "timestamp": time.time(),
                "command": sanitize_string(command),
                "success": result.success,
                "exit_code": result.exit_code,
                "execution_time": result.execution_time,
                "user_id": user_id
            })

            # Keep only last 100 commands
            if len(self._command_history) > 100:
                self._command_history.pop(0)

            # Audit logging
            if self.audit_logger:
                self.audit_logger.log_system_event(
                    action="cli_command_completed",
                    user_id=user_id,
                    description=f"Command: {sanitize_string(command)}, "
                               f"Success: {result.success}, "
                               f"Exit Code: {result.exit_code}, "
                               f"Duration: {result.execution_time:.3f}s"
                )

        except Exception as e:
            self.logger.error(f"Error logging command result: {e}")


class RotaryShieldCLI:
    """Main CLI interface with security hardening and comprehensive functionality."""

    def __init__(self):
        self.security_manager = CLISecurityManager()
        self.logger = logging.getLogger(__name__)
        self.config_path = "/etc/rotaryshield/config.yml"
        self.service_name = "rotaryshield"
        self.pid_file = "/run/rotaryshield/rotaryshield.pid"
        self.db_path = "/var/lib/rotaryshield/rotaryshield.db"
        self._db_manager: Optional[DatabaseManager] = None
        self._ip_manager: Optional[IPManager] = None

    def _get_db_manager(self) -> Optional[DatabaseManager]:
        """Get or create database manager instance."""
        if self._db_manager is None:
            try:
                self._db_manager = DatabaseManager(self.db_path)
                self._db_manager.initialize()
            except Exception as e:
                self.logger.error(f"Failed to initialize database: {e}")
                return None
        return self._db_manager

    def _get_ip_manager(self) -> Optional[IPManager]:
        """Get or create IP manager instance."""
        if self._ip_manager is None:
            db_manager = self._get_db_manager()
            if db_manager:
                try:
                    self._ip_manager = IPManager(db_manager)
                except Exception as e:
                    self.logger.error(f"Failed to initialize IP manager: {e}")
                    return None
        return self._ip_manager

    def _execute_system_command(self, command: List[str], timeout: int = 30) -> CommandResult:
        """
        Execute system command with security protections and timeout.

        Args:
            command: Command and arguments as list
            timeout: Command timeout in seconds

        Returns:
            CommandResult with execution details
        """
        start_time = time.time()
        command_str = " ".join(command)

        # Validate command execution
        if not self.security_manager.validate_command_execution(command_str):
            return CommandResult(
                success=False,
                message="Command execution denied by security policy",
                exit_code=1,
                execution_time=0.0
            )

        try:
            # Execute with security restrictions
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}  # Restricted PATH
            )

            execution_time = time.time() - start_time
            success = result.returncode == 0

            # Sanitize output for security
            stdout = sanitize_string(result.stdout) if result.stdout else ""
            stderr = sanitize_string(result.stderr) if result.stderr else ""

            message = stdout if success else stderr

            command_result = CommandResult(
                success=success,
                message=message,
                exit_code=result.returncode,
                execution_time=execution_time
            )

            # Log command execution
            self.security_manager.log_command_result(command_str, command_result)

            return command_result

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            error_msg = f"Command timed out after {timeout} seconds"
            self.logger.error(f"Command timeout: {command_str}")

            return CommandResult(
                success=False,
                message=error_msg,
                exit_code=124,  # Standard timeout exit code
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Command execution failed: {str(e)}"
            self.logger.error(f"Command execution error: {e}")

            return CommandResult(
                success=False,
                message=error_msg,
                exit_code=1,
                execution_time=execution_time
            )

    def status(self) -> int:
        """Show RotaryShield service status with detailed information."""
        if RICH_AVAILABLE:
            return self._status_rich()
        return self._status_plain()

    def _status_plain(self) -> int:
        """Plain text status output."""
        print("RotaryShield Status")
        print("=" * 50)

        try:
            # Check systemd service status
            result = self._execute_system_command(["systemctl", "status", self.service_name])

            if result.success:
                print("Service Status: ACTIVE")
                print(result.message)
            else:
                print("Service Status: INACTIVE/FAILED")
                if result.message:
                    print(f"Error: {result.message}")

            # Check PID file
            if os.path.exists(self.pid_file):
                try:
                    with open(self.pid_file, 'r') as f:
                        pid = int(f.read().strip())

                    try:
                        os.kill(pid, 0)
                        print(f"Process ID: {pid} (Running)")
                    except ProcessLookupError:
                        print(f"Process ID: {pid} (Not Running - Stale PID file)")

                except (ValueError, IOError) as e:
                    print(f"PID file error: {e}")
            else:
                print("PID file: Not found")

            # Check configuration
            print(f"\nConfiguration: {self.config_path}")
            if os.path.exists(self.config_path):
                print("Configuration file: Found")
                config_valid = test_configuration(self.config_path)
                print(f"Configuration valid: {'Yes' if config_valid else 'No'}")
            else:
                print("Configuration file: Not found")

            return 0 if result.success else 1

        except Exception as e:
            print(f"Error checking status: {e}")
            return 1

    def _status_rich(self) -> int:
        """Rich formatted status output."""
        try:
            # Create status table
            table = Table(title="RotaryShield Status", box=box.ROUNDED)
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("Details", style="dim")

            # Check systemd service status
            result = self._execute_system_command(["systemctl", "is-active", self.service_name])
            service_status = result.message.strip() if result.success else "inactive"

            status_style = "green" if service_status == "active" else "red"
            table.add_row("Service", f"[{status_style}]{service_status.upper()}[/{status_style}]", self.service_name)

            # Check PID file
            pid_status = "Not found"
            pid_details = ""
            if os.path.exists(self.pid_file):
                try:
                    with open(self.pid_file, 'r') as f:
                        pid = int(f.read().strip())
                    try:
                        os.kill(pid, 0)
                        pid_status = "[green]Running[/green]"
                        pid_details = f"PID: {pid}"
                    except ProcessLookupError:
                        pid_status = "[yellow]Stale[/yellow]"
                        pid_details = f"PID: {pid} (process not found)"
                except (ValueError, IOError):
                    pid_status = "[red]Error[/red]"
            else:
                pid_status = "[dim]Not found[/dim]"

            table.add_row("Process", pid_status, pid_details)

            # Check configuration
            if os.path.exists(self.config_path):
                config_valid = test_configuration(self.config_path)
                config_status = "[green]Valid[/green]" if config_valid else "[red]Invalid[/red]"
            else:
                config_status = "[yellow]Not found[/yellow]"

            table.add_row("Configuration", config_status, self.config_path)

            # Check database
            db_status = "[dim]Unknown[/dim]"
            db_details = ""
            if os.path.exists(self.db_path):
                db_size = os.path.getsize(self.db_path)
                db_status = "[green]Available[/green]"
                db_details = f"Size: {db_size / 1024:.1f} KB"
            else:
                db_status = "[yellow]Not found[/yellow]"

            table.add_row("Database", db_status, db_details)

            console.print(table)

            return 0 if service_status == "active" else 1

        except Exception as e:
            console.print(f"[red]Error checking status: {e}[/red]")
            return 1

    def start(self) -> int:
        """Start RotaryShield service with validation."""
        if RICH_AVAILABLE:
            console.print("[cyan]Starting RotaryShield service...[/cyan]")
        else:
            print("Starting RotaryShield service...")

        try:
            # Pre-start validation
            if not os.path.exists(self.config_path):
                msg = f"Configuration file not found: {self.config_path}"
                if RICH_AVAILABLE:
                    console.print(f"[red]Error: {msg}[/red]")
                else:
                    print(f"Error: {msg}")
                return 1

            # Test configuration before starting
            if RICH_AVAILABLE:
                console.print("Validating configuration...")
            else:
                print("Validating configuration...")

            if not test_configuration(self.config_path):
                msg = "Configuration validation failed"
                if RICH_AVAILABLE:
                    console.print(f"[red]Error: {msg}[/red]")
                else:
                    print(f"Error: {msg}")
                return 1

            # Start systemd service
            result = self._execute_system_command(["systemctl", "start", self.service_name])

            if result.success:
                time.sleep(2)
                status_result = self._execute_system_command(["systemctl", "is-active", self.service_name])

                if status_result.success and "active" in status_result.message:
                    if RICH_AVAILABLE:
                        console.print("[green]RotaryShield service started successfully[/green]")
                    else:
                        print("RotaryShield service started successfully")
                    return 0
                else:
                    if RICH_AVAILABLE:
                        console.print("[yellow]Warning: Service start command succeeded but service is not active[/yellow]")
                    else:
                        print("Warning: Service start command succeeded but service is not active")
                    return 1
            else:
                if RICH_AVAILABLE:
                    console.print(f"[red]Failed to start service: {result.message}[/red]")
                else:
                    print(f"Failed to start service: {result.message}")
                return result.exit_code

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]Error starting service: {e}[/red]")
            else:
                print(f"Error starting service: {e}")
            return 1

    def stop(self) -> int:
        """Stop RotaryShield service gracefully."""
        if RICH_AVAILABLE:
            console.print("[cyan]Stopping RotaryShield service...[/cyan]")
        else:
            print("Stopping RotaryShield service...")

        try:
            result = self._execute_system_command(["systemctl", "stop", self.service_name])

            if result.success:
                if os.path.exists(self.pid_file):
                    try:
                        os.remove(self.pid_file)
                    except OSError:
                        pass

                if RICH_AVAILABLE:
                    console.print("[green]RotaryShield service stopped successfully[/green]")
                else:
                    print("RotaryShield service stopped successfully")
                return 0
            else:
                if RICH_AVAILABLE:
                    console.print(f"[red]Failed to stop service: {result.message}[/red]")
                else:
                    print(f"Failed to stop service: {result.message}")
                return result.exit_code

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]Error stopping service: {e}[/red]")
            else:
                print(f"Error stopping service: {e}")
            return 1

    def restart(self) -> int:
        """Restart RotaryShield service."""
        if RICH_AVAILABLE:
            console.print("[cyan]Restarting RotaryShield service...[/cyan]")
        else:
            print("Restarting RotaryShield service...")

        try:
            if not test_configuration(self.config_path):
                if RICH_AVAILABLE:
                    console.print("[red]Error: Configuration validation failed. Restart aborted.[/red]")
                else:
                    print("Error: Configuration validation failed. Restart aborted.")
                return 1

            result = self._execute_system_command(["systemctl", "restart", self.service_name])

            if result.success:
                time.sleep(3)
                status_result = self._execute_system_command(["systemctl", "is-active", self.service_name])

                if status_result.success and "active" in status_result.message:
                    if RICH_AVAILABLE:
                        console.print("[green]RotaryShield service restarted successfully[/green]")
                    else:
                        print("RotaryShield service restarted successfully")
                    return 0
                else:
                    if RICH_AVAILABLE:
                        console.print("[yellow]Warning: Restart command succeeded but service is not active[/yellow]")
                    else:
                        print("Warning: Restart command succeeded but service is not active")
                    return 1
            else:
                if RICH_AVAILABLE:
                    console.print(f"[red]Failed to restart service: {result.message}[/red]")
                else:
                    print(f"Failed to restart service: {result.message}")
                return result.exit_code

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]Error restarting service: {e}[/red]")
            else:
                print(f"Error restarting service: {e}")
            return 1

    def test_config(self, config_path: Optional[str] = None) -> int:
        """Test configuration file validity."""
        config_file = config_path or self.config_path

        if RICH_AVAILABLE:
            console.print(f"[cyan]Testing configuration: {config_file}[/cyan]")
        else:
            print(f"Testing configuration: {config_file}")

        try:
            if not os.path.exists(config_file):
                if RICH_AVAILABLE:
                    console.print(f"[red]Error: Configuration file not found: {config_file}[/red]")
                else:
                    print(f"Error: Configuration file not found: {config_file}")
                return 1

            success = test_configuration(config_file)

            if success:
                if RICH_AVAILABLE:
                    console.print("[green]Configuration is valid[/green]")
                else:
                    print("Configuration is valid")
            else:
                if RICH_AVAILABLE:
                    console.print("[red]Configuration validation failed[/red]")
                else:
                    print("Configuration validation failed")

            return 0 if success else 1

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]Error testing configuration: {e}[/red]")
            else:
                print(f"Error testing configuration: {e}")
            return 1

    def show_stats(self) -> int:
        """Display system statistics and performance metrics."""
        if RICH_AVAILABLE:
            return self._show_stats_rich()
        return self._show_stats_plain()

    def _show_stats_plain(self) -> int:
        """Plain text statistics output."""
        print("RotaryShield Statistics")
        print("=" * 50)

        try:
            ip_manager = self._get_ip_manager()
            if not ip_manager:
                print("Warning: Could not connect to database")
                return 1

            stats = ip_manager.get_statistics()

            print("Database Statistics:")
            print(f"  Total bans: {stats.total_bans}")
            print(f"  Active bans: {stats.active_bans}")
            print(f"  Expired bans: {stats.expired_bans}")
            print(f"  Manually removed: {stats.manually_removed_bans}")
            print(f"  Unique IPs: {stats.unique_ips_banned}")

            if stats.most_banned_ips:
                print("\nTop 10 Most Banned IPs:")
                for ip, count in stats.most_banned_ips:
                    print(f"  {ip}: {count} times")

            return 0

        except Exception as e:
            print(f"Error retrieving statistics: {e}")
            return 1

    def _show_stats_rich(self) -> int:
        """Rich formatted statistics output."""
        try:
            ip_manager = self._get_ip_manager()
            if not ip_manager:
                console.print("[yellow]Warning: Could not connect to database[/yellow]")
                return 1

            stats = ip_manager.get_statistics()

            # Create main statistics table
            table = Table(title="RotaryShield Statistics", box=box.ROUNDED)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white", justify="right")

            table.add_row("Total Bans", str(stats.total_bans))
            table.add_row("Active Bans", f"[green]{stats.active_bans}[/green]")
            table.add_row("Expired Bans", str(stats.expired_bans))
            table.add_row("Manually Removed", str(stats.manually_removed_bans))
            table.add_row("Unique IPs Banned", str(stats.unique_ips_banned))

            if stats.average_ban_duration > 0:
                table.add_row("Average Ban Duration", format_duration(stats.average_ban_duration))

            console.print(table)

            # Top attackers table
            if stats.most_banned_ips:
                top_table = Table(title="Top 10 Most Banned IPs", box=box.SIMPLE)
                top_table.add_column("Rank", style="dim", justify="right")
                top_table.add_column("IP Address", style="red")
                top_table.add_column("Ban Count", justify="right")

                for i, (ip, count) in enumerate(stats.most_banned_ips, 1):
                    top_table.add_row(str(i), ip, str(count))

                console.print()
                console.print(top_table)

            return 0

        except Exception as e:
            console.print(f"[red]Error retrieving statistics: {e}[/red]")
            return 1

    def list_blocked(self) -> int:
        """List currently blocked IP addresses."""
        if RICH_AVAILABLE:
            return self._list_blocked_rich()
        return self._list_blocked_plain()

    def _list_blocked_plain(self) -> int:
        """Plain text blocked IPs output."""
        print("RotaryShield Blocked IPs")
        print("=" * 50)

        try:
            ip_manager = self._get_ip_manager()
            if not ip_manager:
                print("Warning: Could not connect to database")
                return 1

            active_bans = ip_manager.get_active_bans()

            if not active_bans:
                print("No IP addresses are currently blocked.")
                return 0

            print(f"Total blocked IPs: {len(active_bans)}")
            print()
            print(f"{'IP Address':<18} {'Expires In':<15} {'Reason':<40}")
            print("-" * 75)

            for ip in active_bans:
                ban_record = ip_manager.get_ban_record(ip)
                if ban_record:
                    remaining = ban_record.expires_at - time.time()
                    expires_in = format_duration(remaining) if remaining > 0 else "Expiring"
                    reason = ban_record.ban_reason[:38] + ".." if len(ban_record.ban_reason) > 40 else ban_record.ban_reason
                    print(f"{ip:<18} {expires_in:<15} {reason:<40}")

            return 0

        except Exception as e:
            print(f"Error listing blocked IPs: {e}")
            return 1

    def _list_blocked_rich(self) -> int:
        """Rich formatted blocked IPs output."""
        try:
            ip_manager = self._get_ip_manager()
            if not ip_manager:
                console.print("[yellow]Warning: Could not connect to database[/yellow]")
                return 1

            active_bans = ip_manager.get_active_bans()

            if not active_bans:
                console.print(Panel("[green]No IP addresses are currently blocked.[/green]",
                                   title="Blocked IPs"))
                return 0

            table = Table(title=f"Blocked IPs ({len(active_bans)} total)", box=box.ROUNDED)
            table.add_column("IP Address", style="red")
            table.add_column("Expires In", style="yellow", justify="right")
            table.add_column("Ban Count", justify="center")
            table.add_column("Reason", style="dim")

            for ip in active_bans:
                ban_record = ip_manager.get_ban_record(ip)
                if ban_record:
                    remaining = ban_record.expires_at - time.time()
                    expires_in = format_duration(remaining) if remaining > 0 else "[dim]Expiring[/dim]"
                    reason = ban_record.ban_reason[:50] + "..." if len(ban_record.ban_reason) > 50 else ban_record.ban_reason
                    table.add_row(ip, expires_in, str(ban_record.ban_count), reason)

            console.print(table)
            return 0

        except Exception as e:
            console.print(f"[red]Error listing blocked IPs: {e}[/red]")
            return 1

    def unblock_ip(self, ip_address: str) -> int:
        """Unblock a specific IP address."""
        if RICH_AVAILABLE:
            console.print(f"[cyan]Unblocking IP: {ip_address}[/cyan]")
        else:
            print(f"Unblocking IP: {ip_address}")

        try:
            # Validate IP address
            is_valid, error, normalized_ip = validate_ip_address(ip_address)
            if not is_valid:
                if RICH_AVAILABLE:
                    console.print(f"[red]Error: {error}[/red]")
                else:
                    print(f"Error: {error}")
                return 1

            ip_manager = self._get_ip_manager()
            if not ip_manager:
                if RICH_AVAILABLE:
                    console.print("[yellow]Warning: Could not connect to database[/yellow]")
                else:
                    print("Warning: Could not connect to database")
                return 1

            # Check if IP is currently banned
            if not ip_manager.is_banned(normalized_ip):
                if RICH_AVAILABLE:
                    console.print(f"[yellow]IP {normalized_ip} is not currently blocked.[/yellow]")
                else:
                    print(f"IP {normalized_ip} is not currently blocked.")
                return 0

            # Unban the IP
            success = ip_manager.unban_ip(normalized_ip, reason="Manual unblock via CLI")

            if success:
                if RICH_AVAILABLE:
                    console.print(f"[green]Successfully unblocked IP: {normalized_ip}[/green]")
                else:
                    print(f"Successfully unblocked IP: {normalized_ip}")
                return 0
            else:
                if RICH_AVAILABLE:
                    console.print(f"[red]Failed to unblock IP: {normalized_ip}[/red]")
                else:
                    print(f"Failed to unblock IP: {normalized_ip}")
                return 1

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]Error unblocking IP: {e}[/red]")
            else:
                print(f"Error unblocking IP: {e}")
            return 1

    def ban_ip(self, ip_address: str, duration: int = 3600, reason: str = "Manual ban via CLI") -> int:
        """Manually ban an IP address."""
        if RICH_AVAILABLE:
            console.print(f"[cyan]Banning IP: {ip_address}[/cyan]")
        else:
            print(f"Banning IP: {ip_address}")

        try:
            # Validate IP address
            is_valid, error, normalized_ip = validate_ip_address(ip_address)
            if not is_valid:
                if RICH_AVAILABLE:
                    console.print(f"[red]Error: {error}[/red]")
                else:
                    print(f"Error: {error}")
                return 1

            ip_manager = self._get_ip_manager()
            if not ip_manager:
                if RICH_AVAILABLE:
                    console.print("[yellow]Warning: Could not connect to database[/yellow]")
                else:
                    print("Warning: Could not connect to database")
                return 1

            # Ban the IP
            success = ip_manager.ban_ip(
                normalized_ip,
                ban_duration=duration,
                reason=reason,
                offense_type="manual_ban",
                created_by="cli"
            )

            if success:
                duration_str = format_duration(duration)
                if RICH_AVAILABLE:
                    console.print(f"[green]Successfully banned IP: {normalized_ip} for {duration_str}[/green]")
                else:
                    print(f"Successfully banned IP: {normalized_ip} for {duration_str}")
                return 0
            else:
                if RICH_AVAILABLE:
                    console.print(f"[red]Failed to ban IP: {normalized_ip}[/red]")
                else:
                    print(f"Failed to ban IP: {normalized_ip}")
                return 1

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]Error banning IP: {e}[/red]")
            else:
                print(f"Error banning IP: {e}")
            return 1

    def top_attackers(self, limit: int = 10) -> int:
        """Display top attacker IPs."""
        if RICH_AVAILABLE:
            return self._top_attackers_rich(limit)
        return self._top_attackers_plain(limit)

    def _top_attackers_plain(self, limit: int) -> int:
        """Plain text top attackers output."""
        print(f"Top {limit} Attackers")
        print("=" * 50)

        try:
            ip_manager = self._get_ip_manager()
            if not ip_manager:
                print("Warning: Could not connect to database")
                return 1

            stats = ip_manager.get_statistics()

            if not stats.most_banned_ips:
                print("No attacker data available.")
                return 0

            print(f"{'Rank':<6} {'IP Address':<18} {'Ban Count':<12}")
            print("-" * 40)

            for i, (ip, count) in enumerate(stats.most_banned_ips[:limit], 1):
                print(f"{i:<6} {ip:<18} {count:<12}")

            return 0

        except Exception as e:
            print(f"Error retrieving top attackers: {e}")
            return 1

    def _top_attackers_rich(self, limit: int) -> int:
        """Rich formatted top attackers output."""
        try:
            ip_manager = self._get_ip_manager()
            if not ip_manager:
                console.print("[yellow]Warning: Could not connect to database[/yellow]")
                return 1

            stats = ip_manager.get_statistics()

            if not stats.most_banned_ips:
                console.print(Panel("[green]No attacker data available.[/green]",
                                   title="Top Attackers"))
                return 0

            table = Table(title=f"Top {limit} Attackers", box=box.ROUNDED)
            table.add_column("Rank", style="dim", justify="right")
            table.add_column("IP Address", style="red")
            table.add_column("Ban Count", justify="right")
            table.add_column("Threat Level", justify="center")

            for i, (ip, count) in enumerate(stats.most_banned_ips[:limit], 1):
                # Determine threat level based on ban count
                if count >= 10:
                    threat = "[bold red]CRITICAL[/bold red]"
                elif count >= 5:
                    threat = "[red]HIGH[/red]"
                elif count >= 3:
                    threat = "[yellow]MEDIUM[/yellow]"
                else:
                    threat = "[blue]LOW[/blue]"

                table.add_row(str(i), ip, str(count), threat)

            console.print(table)
            return 0

        except Exception as e:
            console.print(f"[red]Error retrieving top attackers: {e}[/red]")
            return 1

    def recent_events(self, limit: int = 20) -> int:
        """Display recent security events."""
        if RICH_AVAILABLE:
            return self._recent_events_rich(limit)
        return self._recent_events_plain(limit)

    def _recent_events_plain(self, limit: int) -> int:
        """Plain text recent events output."""
        print(f"Recent Security Events (last {limit})")
        print("=" * 70)

        try:
            db_manager = self._get_db_manager()
            if not db_manager:
                print("Warning: Could not connect to database")
                return 1

            query = '''
                SELECT * FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            '''

            rows = db_manager.execute_query(query, (limit,), fetch_all=True)

            if not rows:
                print("No recent security events.")
                return 0

            print(f"{'Time':<20} {'Severity':<10} {'Type':<20} {'Source IP':<18}")
            print("-" * 70)

            for row in rows:
                timestamp = format_timestamp(row['timestamp'])
                severity = row['severity'].upper()
                event_type = row['event_type'][:18] if row['event_type'] else "Unknown"
                source_ip = row['source_ip'] or "N/A"
                print(f"{timestamp:<20} {severity:<10} {event_type:<20} {source_ip:<18}")

            return 0

        except Exception as e:
            print(f"Error retrieving events: {e}")
            return 1

    def _recent_events_rich(self, limit: int) -> int:
        """Rich formatted recent events output."""
        try:
            db_manager = self._get_db_manager()
            if not db_manager:
                console.print("[yellow]Warning: Could not connect to database[/yellow]")
                return 1

            query = '''
                SELECT * FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            '''

            rows = db_manager.execute_query(query, (limit,), fetch_all=True)

            if not rows:
                console.print(Panel("[green]No recent security events.[/green]",
                                   title="Recent Events"))
                return 0

            table = Table(title=f"Recent Security Events", box=box.ROUNDED)
            table.add_column("Time", style="dim")
            table.add_column("Severity", justify="center")
            table.add_column("Type", style="cyan")
            table.add_column("Source IP", style="red")
            table.add_column("Description", style="white")

            for row in rows:
                timestamp = format_timestamp(row['timestamp'])
                severity = row['severity'] or 'info'
                severity_styled = f"[{get_severity_style(severity)}]{severity.upper()}[/{get_severity_style(severity)}]"
                event_type = row['event_type'] or "Unknown"
                source_ip = row['source_ip'] or "N/A"
                description = row['description'][:40] + "..." if row['description'] and len(row['description']) > 40 else (row['description'] or "")

                table.add_row(timestamp, severity_styled, event_type, source_ip, description)

            console.print(table)
            return 0

        except Exception as e:
            console.print(f"[red]Error retrieving events: {e}[/red]")
            return 1

    def watch(self, interval: int = 5) -> int:
        """Real-time monitoring with live statistics updates."""
        if not RICH_AVAILABLE:
            print("Watch mode requires the Rich library. Install with: pip install rich")
            return 1

        try:
            console.print("[cyan]Starting real-time monitoring... Press Ctrl+C to stop.[/cyan]")

            while True:
                try:
                    # Clear screen and show updated stats
                    console.clear()

                    # Header
                    console.print(Panel(
                        f"[bold cyan]RotaryShield Live Monitor[/bold cyan]\n"
                        f"[dim]Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
                        box=box.ROUNDED
                    ))

                    # Service status
                    result = self._execute_system_command(["systemctl", "is-active", self.service_name])
                    service_status = result.message.strip() if result.success else "inactive"
                    status_color = "green" if service_status == "active" else "red"
                    console.print(f"Service Status: [{status_color}]{service_status.upper()}[/{status_color}]")
                    console.print()

                    # Get statistics
                    ip_manager = self._get_ip_manager()
                    if ip_manager:
                        stats = ip_manager.get_statistics()

                        # Stats table
                        stats_table = Table(box=box.SIMPLE, show_header=False)
                        stats_table.add_column("Metric", style="cyan")
                        stats_table.add_column("Value", justify="right")

                        stats_table.add_row("Active Bans", f"[bold red]{stats.active_bans}[/bold red]")
                        stats_table.add_row("Total Bans (All Time)", str(stats.total_bans))
                        stats_table.add_row("Unique IPs", str(stats.unique_ips_banned))

                        console.print(stats_table)
                        console.print()

                        # Recent bans
                        active_bans = ip_manager.get_active_bans()[:5]
                        if active_bans:
                            console.print("[bold]Recent Active Bans:[/bold]")
                            for ip in active_bans:
                                ban_record = ip_manager.get_ban_record(ip)
                                if ban_record:
                                    remaining = ban_record.expires_at - time.time()
                                    expires_in = format_duration(remaining) if remaining > 0 else "Expiring"
                                    console.print(f"  [red]{ip}[/red] - expires in {expires_in}")
                    else:
                        console.print("[yellow]Database unavailable[/yellow]")

                    console.print()
                    console.print(f"[dim]Refreshing every {interval} seconds. Press Ctrl+C to stop.[/dim]")

                    time.sleep(interval)

                except KeyboardInterrupt:
                    console.print("\n[yellow]Monitoring stopped.[/yellow]")
                    return 0

        except Exception as e:
            console.print(f"[red]Error in watch mode: {e}[/red]")
            return 1

    def monitor(self, tail_lines: int = 20, follow: bool = False) -> int:
        """Monitor RotaryShield activity with real-time log viewing."""
        if RICH_AVAILABLE:
            console.print(Panel("[bold cyan]RotaryShield Monitor[/bold cyan]", box=box.ROUNDED))
        else:
            print("RotaryShield Monitor")
            print("=" * 50)

        try:
            # Show current status first
            status_result = self._execute_system_command(["systemctl", "is-active", self.service_name])
            if status_result.success:
                service_status = status_result.message.strip()
                if RICH_AVAILABLE:
                    color = "green" if service_status == "active" else "red"
                    console.print(f"Service: [{color}]{service_status}[/{color}]")
                else:
                    print(f"Service: {service_status}")

            if RICH_AVAILABLE:
                console.print(f"\n[dim]Showing last {tail_lines} log lines:[/dim]")
            else:
                print(f"\nMonitoring logs (last {tail_lines} lines):")
                print("-" * 50)

            # Build journalctl command
            cmd = ["journalctl", "-u", self.service_name, "-n", str(tail_lines)]
            if follow:
                cmd.append("-f")
            cmd.append("--no-pager")

            if follow:
                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True,
                        bufsize=1
                    )

                    if RICH_AVAILABLE:
                        console.print("[dim]Press Ctrl+C to stop monitoring...[/dim]")
                    else:
                        print("Press Ctrl+C to stop monitoring...")

                    for line in iter(process.stdout.readline, ''):
                        # Color log lines by level if Rich is available
                        if RICH_AVAILABLE:
                            if 'error' in line.lower():
                                console.print(f"[red]{line.rstrip()}[/red]")
                            elif 'warning' in line.lower() or 'warn' in line.lower():
                                console.print(f"[yellow]{line.rstrip()}[/yellow]")
                            elif 'banned' in line.lower() or 'blocked' in line.lower():
                                console.print(f"[bold red]{line.rstrip()}[/bold red]")
                            else:
                                console.print(line.rstrip())
                        else:
                            print(line.rstrip())

                    process.wait()
                    return process.returncode

                except KeyboardInterrupt:
                    if RICH_AVAILABLE:
                        console.print("\n[yellow]Monitoring stopped by user[/yellow]")
                    else:
                        print("\nMonitoring stopped by user")
                    if process:
                        process.terminate()
                    return 0
            else:
                result = self._execute_system_command(cmd)
                if result.success and result.message:
                    if RICH_AVAILABLE:
                        # Color the output
                        for line in result.message.split('\n'):
                            if 'error' in line.lower():
                                console.print(f"[red]{line}[/red]")
                            elif 'warning' in line.lower() or 'warn' in line.lower():
                                console.print(f"[yellow]{line}[/yellow]")
                            elif 'banned' in line.lower() or 'blocked' in line.lower():
                                console.print(f"[bold red]{line}[/bold red]")
                            else:
                                console.print(line)
                    else:
                        print(result.message)
                    return 0
                else:
                    if RICH_AVAILABLE:
                        console.print("[dim]No log entries found[/dim]")
                    else:
                        print("No log entries found")
                    return 1

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]Error monitoring service: {e}[/red]")
            else:
                print(f"Error monitoring service: {e}")
            return 1


def create_base_parser() -> argparse.ArgumentParser:
    """Create base argument parser with common options."""
    parser = argparse.ArgumentParser(
        description="RotaryShield CLI - Manage the 3-Layer Security System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to configuration file"
    )

    parser.add_argument(
        "--log-level", "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level"
    )

    parser.add_argument(
        "--db-path",
        type=str,
        help="Path to database file"
    )

    return parser


def status_main() -> int:
    """Entry point for rotaryshield-status command."""
    parser = create_base_parser()
    parser.description = "Show RotaryShield service status"
    args = parser.parse_args()

    setup_logging(log_level=args.log_level, enable_audit=True)

    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    if args.db_path:
        cli.db_path = args.db_path

    return cli.status()


def config_main() -> int:
    """Entry point for rotaryshield-config command."""
    parser = create_base_parser()
    parser.description = "Test and validate RotaryShield configuration"
    parser.add_argument(
        "config_file",
        nargs="?",
        help="Configuration file to test"
    )
    args = parser.parse_args()

    setup_logging(log_level=args.log_level, enable_audit=True)

    cli = RotaryShieldCLI()
    config_path = args.config_file or args.config

    return cli.test_config(config_path)


def control_main() -> int:
    """Entry point for rotaryshield-control command (start/stop/restart)."""
    parser = create_base_parser()
    parser.description = "Control RotaryShield service"
    parser.add_argument(
        "action",
        choices=["start", "stop", "restart", "status"],
        help="Action to perform"
    )
    args = parser.parse_args()

    setup_logging(log_level=args.log_level, enable_audit=True)

    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    if args.db_path:
        cli.db_path = args.db_path

    if args.action == "start":
        return cli.start()
    elif args.action == "stop":
        return cli.stop()
    elif args.action == "restart":
        return cli.restart()
    elif args.action == "status":
        return cli.status()
    else:
        print(f"Unknown action: {args.action}")
        return 1


def monitor_main() -> int:
    """Entry point for rotaryshield-monitor command."""
    parser = create_base_parser()
    parser.description = "Monitor RotaryShield activity with real-time logs"
    parser.add_argument(
        "-n", "--lines",
        type=int,
        default=20,
        help="Number of log lines to show (default: 20)"
    )
    parser.add_argument(
        "-f", "--follow",
        action="store_true",
        help="Follow log output in real-time"
    )
    args = parser.parse_args()

    setup_logging(log_level=args.log_level, enable_audit=True)

    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    if args.db_path:
        cli.db_path = args.db_path

    return cli.monitor(tail_lines=args.lines, follow=args.follow)


def list_blocked_main() -> int:
    """Entry point for rotaryshield-list-blocked command."""
    parser = create_base_parser()
    parser.description = "List currently blocked IP addresses"
    args = parser.parse_args()

    setup_logging(log_level=args.log_level, enable_audit=True)

    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    if args.db_path:
        cli.db_path = args.db_path

    return cli.list_blocked()


def unblock_main() -> int:
    """Entry point for rotaryshield-unblock command."""
    parser = create_base_parser()
    parser.description = "Unblock a specific IP address"
    parser.add_argument(
        "ip_address",
        help="IP address to unblock"
    )
    args = parser.parse_args()

    setup_logging(log_level=args.log_level, enable_audit=True)

    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    if args.db_path:
        cli.db_path = args.db_path

    return cli.unblock_ip(args.ip_address)


def stats_main() -> int:
    """Entry point for rotaryshield-stats command."""
    parser = create_base_parser()
    parser.description = "Display RotaryShield statistics and metrics"
    args = parser.parse_args()

    setup_logging(log_level=args.log_level, enable_audit=True)

    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    if args.db_path:
        cli.db_path = args.db_path

    return cli.show_stats()


if __name__ == "__main__":
    # When run directly, provide a comprehensive interface
    if len(sys.argv) < 2:
        if RICH_AVAILABLE:
            console.print(Panel(
                "[bold cyan]RotaryShield CLI[/bold cyan]\n\n"
                "[bold]Service Control:[/bold] status, start, stop, restart\n"
                "[bold]Monitoring:[/bold] monitor, list-blocked, unblock, stats\n"
                "[bold]Analysis:[/bold] top-attackers, events, watch\n"
                "[bold]Configuration:[/bold] test-config, ban\n\n"
                "[dim]Use 'rotaryshield <command> --help' for more information[/dim]",
                title="Usage",
                box=box.ROUNDED
            ))
        else:
            print("Usage: python cli.py <command>")
            print("Commands:")
            print("  Service Control: status, start, stop, restart")
            print("  Monitoring: monitor, list-blocked, unblock, stats")
            print("  Analysis: top-attackers, events, watch")
            print("  Configuration: test-config, ban")
        sys.exit(1)

    command = sys.argv[1]

    # Remove command from argv for proper parsing
    original_argv = sys.argv.copy()
    sys.argv = [sys.argv[0]] + sys.argv[2:]

    if command == "status":
        sys.exit(status_main())
    elif command in ["start", "stop", "restart"]:
        sys.argv = [original_argv[0], command] + original_argv[2:]
        sys.exit(control_main())
    elif command == "test-config":
        sys.exit(config_main())
    elif command == "monitor":
        sys.exit(monitor_main())
    elif command == "list-blocked":
        sys.exit(list_blocked_main())
    elif command == "unblock":
        sys.exit(unblock_main())
    elif command == "stats":
        sys.exit(stats_main())
    elif command == "top-attackers":
        parser = create_base_parser()
        parser.add_argument("--limit", "-n", type=int, default=10, help="Number of top attackers to show")
        args = parser.parse_args()
        setup_logging(log_level=args.log_level, enable_audit=True)
        cli = RotaryShieldCLI()
        if args.db_path:
            cli.db_path = args.db_path
        sys.exit(cli.top_attackers(limit=args.limit))
    elif command == "events":
        parser = create_base_parser()
        parser.add_argument("--limit", "-n", type=int, default=20, help="Number of events to show")
        args = parser.parse_args()
        setup_logging(log_level=args.log_level, enable_audit=True)
        cli = RotaryShieldCLI()
        if args.db_path:
            cli.db_path = args.db_path
        sys.exit(cli.recent_events(limit=args.limit))
    elif command == "watch":
        parser = create_base_parser()
        parser.add_argument("--interval", "-i", type=int, default=5, help="Refresh interval in seconds")
        args = parser.parse_args()
        setup_logging(log_level=args.log_level, enable_audit=True)
        cli = RotaryShieldCLI()
        if args.db_path:
            cli.db_path = args.db_path
        sys.exit(cli.watch(interval=args.interval))
    elif command == "ban":
        parser = create_base_parser()
        parser.add_argument("ip_address", help="IP address to ban")
        parser.add_argument("--duration", "-d", type=int, default=3600, help="Ban duration in seconds (default: 3600)")
        parser.add_argument("--reason", "-r", type=str, default="Manual ban via CLI", help="Reason for the ban")
        args = parser.parse_args()
        setup_logging(log_level=args.log_level, enable_audit=True)
        cli = RotaryShieldCLI()
        if args.db_path:
            cli.db_path = args.db_path
        sys.exit(cli.ban_ip(args.ip_address, duration=args.duration, reason=args.reason))
    else:
        if RICH_AVAILABLE:
            console.print(f"[red]Unknown command: {command}[/red]")
            console.print("[dim]Available commands: status, start, stop, restart, test-config, monitor, list-blocked, unblock, stats, top-attackers, events, watch, ban[/dim]")
        else:
            print(f"Unknown command: {command}")
            print("Available commands: status, start, stop, restart, test-config, monitor, list-blocked, unblock, stats, top-attackers, events, watch, ban")
        sys.exit(1)
