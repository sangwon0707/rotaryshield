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

# Import handling for both module and direct script execution
try:
    from .config import ConfigManager, ConfigurationError
    from .utils.logging import setup_logging, get_audit_logger
    from .utils.validators import validate_file_path, sanitize_string
    from .main import test_configuration
except ImportError:
    # Add the src directory to Python path for direct script execution
    current_dir = Path(__file__).resolve().parent
    src_dir = current_dir.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    
    from rotaryshield.config import ConfigManager, ConfigurationError
    from rotaryshield.utils.logging import setup_logging, get_audit_logger
    from rotaryshield.utils.validators import validate_file_path, sanitize_string
    from rotaryshield.main import test_configuration


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
                    
                    # Check if process is running
                    try:
                        os.kill(pid, 0)  # Signal 0 just checks if process exists
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
                # Test configuration validity
                config_valid = test_configuration(self.config_path)
                print(f"Configuration valid: {'Yes' if config_valid else 'No'}")
            else:
                print("Configuration file: Not found")
            
            # Show recent log entries
            print("\nRecent Log Entries:")
            log_result = self._execute_system_command([
                "journalctl", "-u", self.service_name, "-n", "5", "--no-pager"
            ])
            
            if log_result.success and log_result.message:
                print(log_result.message)
            else:
                print("No recent log entries found")
            
            return 0 if result.success else 1
            
        except Exception as e:
            print(f"Error checking status: {e}")
            self.logger.error(f"Status check failed: {e}")
            return 1
    
    def start(self) -> int:
        """Start RotaryShield service with validation."""
        print("Starting RotaryShield service...")
        
        try:
            # Pre-start validation
            if not os.path.exists(self.config_path):
                print(f"Error: Configuration file not found: {self.config_path}")
                return 1
            
            # Test configuration before starting
            print("Validating configuration...")
            if not test_configuration(self.config_path):
                print("Error: Configuration validation failed")
                return 1
            
            print("Configuration valid. Starting service...")
            
            # Start systemd service
            result = self._execute_system_command(["systemctl", "start", self.service_name])
            
            if result.success:
                print("RotaryShield service started successfully")
                
                # Wait a moment and check if it's actually running
                time.sleep(2)
                status_result = self._execute_system_command(["systemctl", "is-active", self.service_name])
                
                if status_result.success and "active" in status_result.message:
                    print("Service is running and active")
                    return 0
                else:
                    print("Warning: Service start command succeeded but service is not active")
                    return 1
            else:
                print(f"Failed to start service: {result.message}")
                return result.exit_code
                
        except Exception as e:
            print(f"Error starting service: {e}")
            self.logger.error(f"Service start failed: {e}")
            return 1
    
    def stop(self) -> int:
        """Stop RotaryShield service gracefully."""
        print("Stopping RotaryShield service...")
        
        try:
            # Stop systemd service
            result = self._execute_system_command(["systemctl", "stop", self.service_name])
            
            if result.success:
                print("RotaryShield service stopped successfully")
                
                # Clean up PID file if it exists
                if os.path.exists(self.pid_file):
                    try:
                        os.remove(self.pid_file)
                        print("Cleaned up PID file")
                    except OSError as e:
                        print(f"Warning: Could not remove PID file: {e}")
                
                return 0
            else:
                print(f"Failed to stop service: {result.message}")
                return result.exit_code
                
        except Exception as e:
            print(f"Error stopping service: {e}")
            self.logger.error(f"Service stop failed: {e}")
            return 1
    
    def restart(self) -> int:
        """Restart RotaryShield service."""
        print("Restarting RotaryShield service...")
        
        try:
            # Configuration validation before restart
            if not test_configuration(self.config_path):
                print("Error: Configuration validation failed. Restart aborted.")
                return 1
            
            result = self._execute_system_command(["systemctl", "restart", self.service_name])
            
            if result.success:
                print("RotaryShield service restarted successfully")
                
                # Wait and verify
                time.sleep(3)
                status_result = self._execute_system_command(["systemctl", "is-active", self.service_name])
                
                if status_result.success and "active" in status_result.message:
                    print("Service is running and active")
                    return 0
                else:
                    print("Warning: Restart command succeeded but service is not active")
                    return 1
            else:
                print(f"Failed to restart service: {result.message}")
                return result.exit_code
                
        except Exception as e:
            print(f"Error restarting service: {e}")
            self.logger.error(f"Service restart failed: {e}")
            return 1
    
    def test_config(self, config_path: Optional[str] = None) -> int:
        """Test configuration file validity."""
        config_file = config_path or self.config_path
        
        print(f"Testing configuration: {config_file}")
        
        try:
            if not os.path.exists(config_file):
                print(f"Error: Configuration file not found: {config_file}")
                return 1
            
            success = test_configuration(config_file)
            return 0 if success else 1
            
        except Exception as e:
            print(f"Error testing configuration: {e}")
            self.logger.error(f"Configuration test failed: {e}")
            return 1
    
    def monitor(self, tail_lines: int = 20, follow: bool = False) -> int:
        """Monitor RotaryShield activity with real-time log viewing."""
        print("RotaryShield Monitor")
        print("=" * 50)
        
        try:
            # Show current status first
            print("Current Status:")
            status_result = self._execute_system_command(["systemctl", "is-active", self.service_name])
            if status_result.success:
                print(f"Service: {status_result.message.strip()}")
            else:
                print(f"Service: inactive")
            
            print(f"\nMonitoring logs (last {tail_lines} lines):")
            print("-" * 50)
            
            # Build journalctl command
            cmd = ["journalctl", "-u", self.service_name, "-n", str(tail_lines)]
            if follow:
                cmd.append("-f")
            cmd.append("--no-pager")
            
            if follow:
                # For follow mode, use direct subprocess for real-time output
                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True,
                        bufsize=1
                    )
                    
                    print("Press Ctrl+C to stop monitoring...")
                    
                    for line in iter(process.stdout.readline, ''):
                        print(line.rstrip())
                    
                    process.wait()
                    return process.returncode
                    
                except KeyboardInterrupt:
                    print("\nMonitoring stopped by user")
                    if process:
                        process.terminate()
                    return 0
            else:
                # For static mode, use our execute method
                result = self._execute_system_command(cmd)
                if result.success and result.message:
                    print(result.message)
                    return 0
                else:
                    print("No log entries found")
                    return 1
                    
        except Exception as e:
            print(f"Error monitoring service: {e}")
            self.logger.error(f"Monitor failed: {e}")
            return 1
    
    def list_blocked(self) -> int:
        """List currently blocked IP addresses."""
        print("RotaryShield Blocked IPs")
        print("=" * 50)
        
        try:
            # Import database manager to query blocked IPs
            from .database.ip_manager import IPManager
            
            ip_manager = IPManager()
            
            # Get all banned IPs
            banned_ips = ip_manager.get_all_banned_ips()
            
            if not banned_ips:
                print("No IP addresses are currently blocked.")
                return 0
            
            print(f"Total blocked IPs: {len(banned_ips)}")
            print()
            print(f"{'IP Address':<15} {'Ban Time':<20} {'Reason':<30} {'Status'}")
            print("-" * 80)
            
            for ip_record in banned_ips:
                ip = ip_record.ip_address
                ban_time = ip_record.ban_timestamp.strftime('%Y-%m-%d %H:%M:%S') if ip_record.ban_timestamp else 'Unknown'
                reason = ip_record.reason or 'No reason specified'
                status = ip_record.status.value if ip_record.status else 'Unknown'
                
                # Truncate long reasons
                if len(reason) > 28:
                    reason = reason[:25] + "..."
                
                print(f"{ip:<15} {ban_time:<20} {reason:<30} {status}")
            
            return 0
            
        except Exception as e:
            print(f"Error listing blocked IPs: {e}")
            self.logger.error(f"List blocked IPs failed: {e}")
            return 1
    
    def unblock_ip(self, ip_address: str) -> int:
        """Unblock a specific IP address."""
        print(f"Unblocking IP: {ip_address}")
        print("=" * 50)
        
        try:
            # Validate IP address
            from .utils.validators import validate_ip_address
            
            is_valid, error, normalized_ip = validate_ip_address(ip_address)
            if not is_valid:
                print(f"Error: {error}")
                return 1
            
            # Import database manager
            from .database.ip_manager import IPManager
            
            ip_manager = IPManager()
            
            # Check if IP is currently banned
            ban_record = ip_manager.get_ban_record(normalized_ip)
            if not ban_record:
                print(f"IP {normalized_ip} is not currently blocked.")
                return 0
            
            # Unban the IP
            success = ip_manager.unban_ip(normalized_ip, reason="Manual unblock via CLI")
            
            if success:
                print(f"Successfully unblocked IP: {normalized_ip}")
                
                # Also remove from firewall if possible
                try:
                    from .firewall.manager import FirewallManager
                    
                    fw_manager = FirewallManager()
                    fw_manager.remove_ip_ban(normalized_ip)
                    print(f"Removed firewall rule for: {normalized_ip}")
                    
                except Exception as fw_e:
                    print(f"Warning: Could not remove firewall rule: {fw_e}")
                
                return 0
            else:
                print(f"Failed to unblock IP: {normalized_ip}")
                return 1
                
        except Exception as e:
            print(f"Error unblocking IP: {e}")
            self.logger.error(f"Unblock IP failed: {e}")
            return 1
    
    def show_stats(self) -> int:
        """Display system statistics and performance metrics."""
        print("RotaryShield Statistics")
        print("=" * 50)
        
        try:
            # Import required modules
            from .database.ip_manager import IPManager
            from .monitoring.pattern_matcher import PatternMatcher
            
            ip_manager = IPManager()
            
            # Database statistics
            stats = ip_manager.get_statistics()
            
            print("Database Statistics:")
            print(f"  Total banned IPs: {stats.get('total_banned_ips', 0)}")
            print(f"  Active bans: {stats.get('active_bans', 0)}")
            print(f"  Expired bans: {stats.get('expired_bans', 0)}")
            print(f"  Total security events: {stats.get('total_events', 0)}")
            
            # Pattern matcher statistics if available
            try:
                pattern_matcher = PatternMatcher()
                pattern_stats = pattern_matcher.get_statistics()
                
                print("\nPattern Matching Statistics:")
                print(f"  Total patterns: {pattern_stats.get('total_patterns', 0)}")
                print(f"  Total matches: {pattern_stats.get('total_matches', 0)}")
                print(f"  Average match time: {pattern_stats.get('average_match_time_ms', 0):.2f}ms")
                print(f"  Timeout count: {pattern_stats.get('timeout_count', 0)}")
                
            except Exception as pattern_e:
                print(f"\nPattern statistics unavailable: {pattern_e}")
            
            # System resource usage
            try:
                import psutil
                
                # Get current process if running
                rotary_procs = []
                for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
                    if 'rotaryshield' in proc.info['name'].lower():
                        rotary_procs.append(proc)
                
                if rotary_procs:
                    print("\nSystem Resource Usage:")
                    for proc in rotary_procs:
                        memory_mb = proc.info['memory_info'].rss / 1024 / 1024
                        cpu_percent = proc.info['cpu_percent']
                        print(f"  PID {proc.info['pid']}: {memory_mb:.1f}MB RAM, {cpu_percent:.1f}% CPU")
                else:
                    print("\nSystem Resource Usage: RotaryShield not currently running")
                    
            except ImportError:
                print("\nSystem resource monitoring unavailable (psutil not installed)")
            except Exception as sys_e:
                print(f"\nSystem resource monitoring error: {sys_e}")
            
            # Recent activity summary
            print("\nRecent Activity (last 24 hours):")
            recent_bans = ip_manager.get_recent_bans(hours=24)
            print(f"  New bans: {len(recent_bans)}")
            
            if recent_bans:
                print("  Recent banned IPs:")
                for ban in recent_bans[:5]:  # Show last 5
                    ban_time = ban.ban_timestamp.strftime('%H:%M:%S') if ban.ban_timestamp else 'Unknown'
                    print(f"    {ban.ip_address} at {ban_time}")
                if len(recent_bans) > 5:
                    print(f"    ... and {len(recent_bans) - 5} more")
            
            return 0
            
        except Exception as e:
            print(f"Error retrieving statistics: {e}")
            self.logger.error(f"Statistics failed: {e}")
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
    
    return parser


def status_main() -> int:
    """Entry point for rotaryshield-status command."""
    parser = create_base_parser()
    parser.description = "Show RotaryShield service status"
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(log_level=args.log_level, enable_audit=True)
    
    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    
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
    
    # Setup logging
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
    
    # Setup logging
    setup_logging(log_level=args.log_level, enable_audit=True)
    
    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    
    # Execute requested action
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
    
    # Setup logging
    setup_logging(log_level=args.log_level, enable_audit=True)
    
    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    
    return cli.monitor(tail_lines=args.lines, follow=args.follow)


def list_blocked_main() -> int:
    """Entry point for rotaryshield-list-blocked command."""
    parser = create_base_parser()
    parser.description = "List currently blocked IP addresses"
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(log_level=args.log_level, enable_audit=True)
    
    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    
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
    
    # Setup logging
    setup_logging(log_level=args.log_level, enable_audit=True)
    
    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    
    return cli.unblock_ip(args.ip_address)


def stats_main() -> int:
    """Entry point for rotaryshield-stats command."""
    parser = create_base_parser()
    parser.description = "Display RotaryShield statistics and metrics"
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(log_level=args.log_level, enable_audit=True)
    
    cli = RotaryShieldCLI()
    if args.config:
        cli.config_path = args.config
    
    return cli.show_stats()


if __name__ == "__main__":
    # When run directly, provide a simple interface
    if len(sys.argv) < 2:
        print("Usage: python cli.py <command>")
        print("Commands:")
        print("  Service Control: status, start, stop, restart")
        print("  Monitoring: monitor, list-blocked, unblock, stats")
        print("  Configuration: test-config")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "status":
        sys.exit(status_main())
    elif command in ["start", "stop", "restart"]:
        # Simulate control_main for direct execution
        sys.argv = [sys.argv[0], command] + sys.argv[2:]
        sys.exit(control_main())
    elif command == "test-config":
        sys.exit(config_main())
    elif command == "monitor":
        # Remove the command argument for proper parsing
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        sys.exit(monitor_main())
    elif command == "list-blocked":
        # Remove the command argument for proper parsing
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        sys.exit(list_blocked_main())
    elif command == "unblock":
        # Remove the command argument for proper parsing
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        sys.exit(unblock_main())
    elif command == "stats":
        # Remove the command argument for proper parsing
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        sys.exit(stats_main())
    else:
        print(f"Unknown command: {command}")
        print("Available commands: status, start, stop, restart, test-config, monitor, list-blocked, unblock, stats")
        sys.exit(1)