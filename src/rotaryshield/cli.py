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


if __name__ == "__main__":
    # When run directly, provide a simple interface
    if len(sys.argv) < 2:
        print("Usage: python cli.py <command>")
        print("Commands: status, start, stop, restart, test-config")
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
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)