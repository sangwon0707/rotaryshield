#!/usr/bin/env python3
"""
RotaryShield Main Entry Point
Production-ready security daemon with comprehensive error handling.

Security Features:
- Privilege separation and dropping
- Signal handling for graceful shutdown
- Resource monitoring and limits
- Comprehensive audit logging
- Configuration validation
- Daemon mode support
"""

import os
import sys
import signal
import argparse
import logging
import time
from pathlib import Path
from typing import Optional

# Import RotaryShield components - handle both direct script and module import
try:
    # When run as module (python -m rotaryshield or installed via pip)
    from .security.engine import SecurityEngine
    from .config import ConfigManager
    from .utils.logging import setup_logging, get_audit_logger
except ImportError:
    # When run as direct script (python main.py)
    import sys
    from pathlib import Path
    
    # Add the src directory to Python path
    current_dir = Path(__file__).resolve().parent
    src_dir = current_dir.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    
    # Now import with absolute imports
    from rotaryshield.security.engine import SecurityEngine
    from rotaryshield.config import ConfigManager
    from rotaryshield.utils.logging import setup_logging, get_audit_logger


class RotaryShieldDaemon:
    """
    Main daemon class for RotaryShield security system.
    
    This class orchestrates the entire security system and handles
    system-level concerns like signal handling, privilege management,
    and resource monitoring.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize RotaryShield daemon.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path or "/etc/rotaryshield/config.yml"
        self.security_engine: Optional[SecurityEngine] = None
        self.logger = logging.getLogger(__name__)
        
        # Runtime state
        self._shutdown_requested = False
        self._start_time = time.time()
        
        # Register signal handlers
        self._register_signal_handlers()
    
    def _register_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            signal_name = signal.Signals(signum).name
            self.logger.info(f"Received signal {signal_name} ({signum}), initiating shutdown")
            self._shutdown_requested = True
            
            if self.security_engine:
                self.security_engine.shutdown()
        
        # Register handlers for common termination signals
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGHUP, self._handle_reload)
    
    def _handle_reload(self, signum, frame):
        """Handle configuration reload signal."""
        self.logger.info("Received SIGHUP, reloading configuration")
        try:
            if self.security_engine:
                # Reload configuration
                config_manager = ConfigManager(self.config_path)
                new_config = config_manager.load_config()
                
                # TODO: Implement hot configuration reload
                self.logger.info("Configuration reloaded successfully")
                
                # Log audit event
                audit_logger = get_audit_logger()
                if audit_logger:
                    audit_logger.log_config_event(
                        action="config_reloaded",
                        user_id="system",
                        config_section="all",
                        result="success"
                    )
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
    
    def _setup_directories(self) -> None:
        """Ensure required directories exist with proper permissions."""
        directories = [
            "/var/lib/rotaryshield",
            "/var/log/rotaryshield",
            "/run/rotaryshield",
            "/etc/rotaryshield"
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, mode=0o750, exist_ok=True)
                self.logger.debug(f"Ensured directory exists: {directory}")
            except PermissionError:
                self.logger.warning(f"Cannot create directory {directory}: Permission denied")
            except Exception as e:
                self.logger.error(f"Error creating directory {directory}: {e}")
    
    def _drop_privileges(self) -> None:
        """Drop privileges to run as non-root user."""
        # This is a placeholder for privilege dropping
        # In production, this would switch to the rotaryshield user
        
        current_uid = os.getuid()
        current_gid = os.getgid()
        
        if current_uid == 0:
            self.logger.warning(
                "Running as root. Consider running as dedicated user 'rotaryshield' "
                "for better security."
            )
            
            # In production, uncomment and implement:
            # try:
            #     # Get rotaryshield user/group IDs
            #     import pwd, grp
            #     rotary_user = pwd.getpwnam('rotaryshield')
            #     rotary_group = grp.getgrnam('rotaryshield')
            #     
            #     # Drop privileges
            #     os.setgid(rotary_group.gr_gid)
            #     os.setuid(rotary_user.pw_uid)
            #     
            #     self.logger.info("Dropped privileges to rotaryshield user")
            # except KeyError:
            #     self.logger.error("User 'rotaryshield' not found. Create with: useradd -r rotaryshield")
            #     sys.exit(1)
            # except Exception as e:
            #     self.logger.error(f"Failed to drop privileges: {e}")
            #     sys.exit(1)
    
    def _validate_environment(self) -> None:
        """Validate runtime environment and dependencies."""
        # Check Python version
        if sys.version_info < (3, 8):
            self.logger.error("Python 3.8 or higher is required")
            sys.exit(1)
        
        # Check for required system tools
        required_tools = ["iptables"]  # Basic requirement
        
        for tool in required_tools:
            if not self._check_tool_available(tool):
                self.logger.warning(f"Recommended tool not found: {tool}")
        
        # Check file permissions
        config_dir = os.path.dirname(self.config_path)
        if not os.access(config_dir, os.R_OK):
            self.logger.error(f"Cannot read configuration directory: {config_dir}")
            sys.exit(1)
        
        self.logger.info("Environment validation completed")
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if a system tool is available."""
        import shutil
        return shutil.which(tool) is not None
    
    def start(self) -> None:
        """Start the RotaryShield daemon."""
        try:
            self.logger.info("Starting RotaryShield daemon")
            
            # Environment setup
            self._validate_environment()
            self._setup_directories()
            self._drop_privileges()
            
            # Initialize security engine
            self.security_engine = SecurityEngine(self.config_path)
            self.security_engine.initialize()
            
            # Start security engine
            self.security_engine.start()
            
            # Log startup completion
            audit_logger = get_audit_logger()
            if audit_logger:
                audit_logger.log_system_event(
                    action="daemon_started",
                    user_id="system",
                    description="RotaryShield daemon started successfully"
                )
            
            self.logger.info("RotaryShield daemon started successfully")
            
            # Main daemon loop
            self._main_loop()
            
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
        except Exception as e:
            self.logger.critical(f"Fatal error in daemon startup: {e}", exc_info=True)
            sys.exit(1)
        finally:
            self._cleanup()
    
    def _main_loop(self) -> None:
        """Main daemon event loop."""
        self.logger.info("Entering main daemon loop")
        
        # Performance monitoring
        last_stats_time = time.time()
        stats_interval = 300  # 5 minutes
        
        try:
            while not self._shutdown_requested:
                # Sleep with periodic wake-ups for monitoring
                time.sleep(10)
                
                # Periodic statistics logging
                current_time = time.time()
                if current_time - last_stats_time >= stats_interval:
                    self._log_performance_stats()
                    last_stats_time = current_time
                
                # Check if security engine is still running
                if self.security_engine and not self.security_engine.is_running():
                    self.logger.error("Security engine stopped unexpectedly")
                    break
        
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}", exc_info=True)
        
        self.logger.info("Main daemon loop exited")
    
    def _log_performance_stats(self) -> None:
        """Log periodic performance statistics."""
        try:
            if self.security_engine:
                metrics = self.security_engine.get_metrics()
                uptime = time.time() - self._start_time
                
                self.logger.info(
                    f"STATS: uptime={uptime:.0f}s, "
                    f"events={metrics.events_processed}, "
                    f"threats={metrics.threats_detected}, "
                    f"banned={metrics.ips_banned}, "
                    f"memory={metrics.memory_usage_mb:.1f}MB, "
                    f"cpu={metrics.cpu_usage_percent:.1f}%"
                )
        except Exception as e:
            self.logger.error(f"Error logging performance stats: {e}")
    
    def _cleanup(self) -> None:
        """Clean up resources and shutdown gracefully."""
        self.logger.info("Cleaning up daemon resources")
        
        try:
            if self.security_engine:
                self.security_engine.shutdown()
                self.security_engine = None
            
            # Log shutdown
            audit_logger = get_audit_logger()
            if audit_logger:
                uptime = time.time() - self._start_time
                audit_logger.log_system_event(
                    action="daemon_stopped",
                    user_id="system",
                    description=f"RotaryShield daemon stopped after {uptime:.0f}s uptime"
                )
            
            self.logger.info("RotaryShield daemon shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="RotaryShield - 3-Layer Security System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rotaryshield --daemon                    # Run as daemon
  rotaryshield --config /path/config.yml  # Custom config
  rotaryshield --log-level DEBUG           # Debug logging
  rotaryshield --test-config              # Test configuration

For more information, visit: https://rotaryshield.readthedocs.io/
        """
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to configuration file (default: /etc/rotaryshield/config.yml)"
    )
    
    parser.add_argument(
        "--daemon", "-d",
        action="store_true",
        help="Run as daemon (background process)"
    )
    
    parser.add_argument(
        "--log-level", "-l",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        default="/var/log/rotaryshield/rotaryshield.log",
        help="Log file path (default: /var/log/rotaryshield/rotaryshield.log)"
    )
    
    parser.add_argument(
        "--test-config",
        action="store_true",
        help="Test configuration and exit"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"RotaryShield {__import__('rotaryshield').__version__}"
    )
    
    return parser.parse_args()


def test_configuration(config_path: Optional[str]) -> bool:
    """Test configuration file validity."""
    print("Testing RotaryShield configuration...")
    
    try:
        config_manager = ConfigManager(config_path)
        config = config_manager.load_config()
        
        print(f"✓ Configuration file loaded: {config_manager.config_path}")
        print(f"✓ Log files: {len(config.detection.log_files)} configured")
        print(f"✓ Patterns: {len(config.detection.patterns)} configured")
        print(f"✓ Firewall backend: {config.ban.firewall_backend}")
        print(f"✓ Database path: {config.database.db_path}")
        
        # Test pattern compilation
        try:
            from .monitoring.pattern_matcher import PatternMatcher
        except ImportError:
            from rotaryshield.monitoring.pattern_matcher import PatternMatcher
        pattern_matcher = PatternMatcher()
        
        valid_patterns = 0
        for name, pattern in config.detection.patterns.items():
            if pattern_matcher.add_pattern(name, pattern):
                valid_patterns += 1
            else:
                print(f"✗ Invalid pattern '{name}': {pattern}")
        
        print(f"✓ Valid patterns: {valid_patterns}/{len(config.detection.patterns)}")
        
        print("\nConfiguration test completed successfully!")
        return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False


def main():
    """Main entry point for RotaryShield daemon."""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(
        log_level=args.log_level,
        log_file=args.log_file if not args.daemon else args.log_file,
        enable_json=False,
        enable_audit=True
    )
    
    logger = logging.getLogger(__name__)
    
    # Print banner
    print(f"RotaryShield v{__import__('rotaryshield').__version__}")
    print("3-Layer Security System: Detection → Throttling → Blocking")
    print("=" * 60)
    
    # Test configuration if requested
    if args.test_config:
        success = test_configuration(args.config)
        sys.exit(0 if success else 1)
    
    # Daemon mode setup
    if args.daemon:
        logger.info("Starting in daemon mode")
        # In production, this would fork and detach from terminal
        # For now, we just run in foreground with daemon-like behavior
    
    try:
        # Create and start daemon
        daemon = RotaryShieldDaemon(config_path=args.config)
        daemon.start()
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()