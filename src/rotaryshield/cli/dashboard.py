#!/usr/bin/env python3
"""
RotaryShield Dashboard CLI Command

Command-line interface for launching the real-time web dashboard.
Enterprise-grade security monitoring interface.

Usage: rotaryshield-dashboard [options]
"""

import sys
import os
import argparse
import time
import subprocess
import signal
from pathlib import Path
from typing import Optional

# Add the parent directory to the path for imports
sys.path.append(str(Path(__file__).parent.parent))

from utils.validators import validate_ip_address, validate_port
from utils.logging import SecurityLogger
from dashboard.server import DashboardServer


class DashboardCLI:
    """CLI interface for the RotaryShield Dashboard."""
    
    def __init__(self):
        self.logger = SecurityLogger("dashboard-cli")
        self.server = None
        self.running = False
    
    def show_banner_with_info(self):
        """Display RotaryShield banner with version info - Modern design colors"""
        # Modern color palette (Tailwind/Material Design inspired)
        SLATE_BLUE = '\033[38;5;67m'      # Slate Blue #5B7B9A
        ELECTRIC_BLUE = '\033[38;5;39m'   # Electric Blue #00AAFF
        EMERALD = '\033[38;5;42m'         # Emerald #10B981
        AMBER = '\033[38;5;214m'          # Amber #F59E0B
        VIOLET = '\033[38;5;141m'         # Violet #8B5CF6
        ROSE = '\033[38;5;205m'           # Rose #F43F5E
        GRAY_100 = '\033[38;5;254m'       # Light Gray
        GRAY_400 = '\033[38;5;245m'       # Medium Gray
        BOLD = '\033[1m'
        RESET = '\033[0m'
        
        print(f"""
{BOLD}{SLATE_BLUE}┌─────────────────────────────────────────────────────────────┐{RESET}
{BOLD}{SLATE_BLUE}│                                                             │{RESET}
{BOLD}{ELECTRIC_BLUE}│  ██████╗  ██████╗ ████████╗ █████╗ ██████╗ ██╗   ██╗      │{RESET}
{BOLD}{ELECTRIC_BLUE}│  ██╔══██╗██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗╚██╗ ██╔╝      │{RESET}
{BOLD}{EMERALD}│  ██████╔╝██║   ██║   ██║   ███████║██████╔╝ ╚████╔╝       │{RESET}
{BOLD}{EMERALD}│  ██╔══██╗██║   ██║   ██║   ██╔══██║██╔══██╗  ╚██╔╝        │{RESET}
{BOLD}{VIOLET}│  ██║  ██║╚██████╔╝   ██║   ██║  ██║██║  ██║   ██║         │{RESET}
{BOLD}{VIOLET}│  ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝         │{RESET}
{BOLD}{SLATE_BLUE}│                                                             │{RESET}
{BOLD}{EMERALD}│  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗                │{RESET}
{BOLD}{EMERALD}│  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗               │{RESET}
{BOLD}{ELECTRIC_BLUE}│  ███████╗███████║██║█████╗  ██║     ██║  ██║               │{RESET}
{BOLD}{ELECTRIC_BLUE}│  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║               │{RESET}
{BOLD}{VIOLET}│  ███████║██║  ██║██║███████╗███████╗██████╔╝               │{RESET}
{BOLD}{VIOLET}│  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝                │{RESET}
{BOLD}{SLATE_BLUE}│                                                             │{RESET}
{BOLD}{EMERALD}│  🛡️  3-Layer Security Protection System  🛡️               │{RESET}
{BOLD}{GRAY_100}│      Phase 2 Complete | Dashboard v2.0.0                   │{RESET}
{BOLD}{AMBER}│      Engineered with ❤️  by Sangwon & Claude Code           │{RESET}
{BOLD}{SLATE_BLUE}│                                                             │{RESET}
{BOLD}{SLATE_BLUE}└─────────────────────────────────────────────────────────────┘{RESET}
""")
    
    def run(self, args):
        """Run the dashboard CLI command."""
        try:
            # Display banner first
            self.show_banner_with_info()
            
            # Validate arguments
            if not self._validate_args(args):
                return 1
            
            # Check if already running
            if self._check_already_running(args.port):
                print(f"❌ Dashboard already running on port {args.port}")
                return 1
            
            # Initialize server
            self.server = DashboardServer(
                config_path=args.config,
                host=args.host,
                port=args.port
            )
            
            # Setup signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Start dashboard
            print(f"🚀 Starting RotaryShield Dashboard...")
            print(f"📊 Dashboard URL: http://{args.host}:{args.port}")
            print(f"🔒 Config: {args.config or 'default'}")
            print(f"🐛 Debug mode: {'enabled' if args.debug else 'disabled'}")
            print()
            
            if not args.background:
                print("Press Ctrl+C to stop the dashboard")
                print("=" * 50)
            
            self.running = True
            
            if args.background:
                return self._run_background()
            else:
                return self._run_foreground(args.debug)
                
        except KeyboardInterrupt:
            print("\n🛑 Dashboard shutdown requested")
            return self._cleanup()
        except Exception as e:
            self.logger.error(f"Dashboard CLI error: {e}")
            print(f"❌ Error starting dashboard: {e}")
            return 1
    
    def _validate_args(self, args) -> bool:
        """Validate command line arguments."""
        try:
            # Validate host
            if args.host != '127.0.0.1' and args.host != 'localhost':
                is_valid, error_or_ip, ip_obj = validate_ip_address(args.host)
                if not is_valid:
                    print(f"❌ Invalid host address: {args.host} - {error_or_ip}")
                    return False
            
            # Validate port
            is_valid, error, port_num = validate_port(args.port)
            if not is_valid:
                print(f"❌ Invalid port number: {args.port} - {error}")
                return False
            
            # Check port range
            if args.port < 1024 and os.geteuid() != 0:
                print(f"❌ Port {args.port} requires root privileges")
                return False
            
            # Validate config file if specified
            if args.config and not Path(args.config).exists():
                print(f"❌ Configuration file not found: {args.config}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Argument validation error: {e}")
            print(f"❌ Argument validation failed: {e}")
            return False
    
    def _check_already_running(self, port: int) -> bool:
        """Check if dashboard is already running on the specified port."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _run_foreground(self, debug: bool = False) -> int:
        """Run dashboard in foreground mode."""
        try:
            self.server.run(debug=debug)
            return 0
        except Exception as e:
            self.logger.error(f"Dashboard server error: {e}")
            print(f"❌ Dashboard server error: {e}")
            return 1
    
    def _run_background(self) -> int:
        """Run dashboard in background mode."""
        try:
            # Fork process for background execution
            pid = os.fork()
            
            if pid > 0:
                # Parent process
                print(f"✅ Dashboard started in background (PID: {pid})")
                
                # Save PID for later management
                pid_file = Path("/var/run/rotaryshield-dashboard.pid")
                try:
                    with open(pid_file, 'w') as f:
                        f.write(str(pid))
                except PermissionError:
                    # Fallback to user directory
                    pid_file = Path.home() / ".rotaryshield" / "dashboard.pid"
                    pid_file.parent.mkdir(exist_ok=True)
                    with open(pid_file, 'w') as f:
                        f.write(str(pid))
                
                print(f"📝 PID file: {pid_file}")
                return 0
            else:
                # Child process - run the server
                os.setsid()  # Create new session
                self.server.run(debug=False)
                return 0
                
        except OSError as e:
            print(f"❌ Failed to fork background process: {e}")
            return 1
        except Exception as e:
            self.logger.error(f"Background mode error: {e}")
            print(f"❌ Background mode error: {e}")
            return 1
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\n🛑 Received signal {signum}, shutting down...")
        self.running = False
        self._cleanup()
        sys.exit(0)
    
    def _cleanup(self) -> int:
        """Cleanup resources and shutdown gracefully."""
        try:
            if self.server:
                print("🧹 Cleaning up dashboard resources...")
                # The Flask server will handle its own cleanup
            
            print("✅ Dashboard shutdown complete")
            return 0
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")
            print(f"⚠️  Cleanup error: {e}")
            return 1


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for dashboard CLI."""
    parser = argparse.ArgumentParser(
        description='RotaryShield Real-time Security Dashboard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  rotaryshield-dashboard                    # Start on localhost:8080
  rotaryshield-dashboard --port 8443       # Use different port
  rotaryshield-dashboard --host 0.0.0.0    # Bind to all interfaces
  rotaryshield-dashboard --background      # Run in background
  rotaryshield-dashboard --debug           # Enable debug mode

Security Note:
  The dashboard provides real-time access to security data.
  Use appropriate firewall rules and authentication when exposing
  to networks beyond localhost.
        '''
    )
    
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port to bind to (default: 8080)'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--background',
        action='store_true',
        help='Run in background mode'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='RotaryShield Dashboard 2.0.0 (Phase 2 Complete)'
    )
    
    return parser


def main():
    """Main entry point for dashboard CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Create and run CLI
    cli = DashboardCLI()
    return cli.run(args)


if __name__ == '__main__':
    sys.exit(main())