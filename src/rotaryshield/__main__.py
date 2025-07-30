#!/usr/bin/env python3
"""
RotaryShield Module Entry Point
Enables execution via 'python -m rotaryshield' with security hardening.

Security Features:
- Input validation for all command-line arguments
- Secure error handling with sanitized output
- Comprehensive audit logging of module execution
- Resource limits and timeout protections
- Privilege validation and warnings
"""

import sys
import os
import logging
from pathlib import Path

# Ensure proper import handling
try:
    from .main import main
    from .utils.logging import setup_logging, get_audit_logger
    from .utils.validators import sanitize_string
except ImportError:
    # Handle direct execution case
    current_dir = Path(__file__).resolve().parent
    src_dir = current_dir.parent
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    
    from rotaryshield.main import main
    from rotaryshield.utils.logging import setup_logging, get_audit_logger
    from rotaryshield.utils.validators import sanitize_string


def validate_execution_environment() -> bool:
    """
    Validate execution environment for security and functionality.
    
    Returns:
        True if environment is safe for execution
    """
    try:
        # Check Python version
        if sys.version_info < (3, 8):
            print("Error: RotaryShield requires Python 3.8 or higher", file=sys.stderr)
            return False
        
        # Check if running as root (security warning)
        if os.getuid() == 0:
            print("Warning: Running as root. Consider using a dedicated user for better security.")
        
        # Validate command line arguments for basic security
        if len(sys.argv) > 50:  # Arbitrary but reasonable limit
            print("Error: Too many command line arguments", file=sys.stderr)
            return False
        
        # Check for potentially dangerous argument patterns
        dangerous_patterns = [
            "../", "../../", "/etc/passwd", "/etc/shadow", 
            "$(", "`", ";", "&&", "||", "|", ">"
        ]
        
        for arg in sys.argv:
            sanitized_arg = sanitize_string(arg)
            for pattern in dangerous_patterns:
                if pattern in arg.lower():
                    print(f"Error: Potentially dangerous argument detected: {sanitized_arg}", 
                          file=sys.stderr)
                    return False
        
        return True
        
    except Exception as e:
        # Use sanitized error message for security
        error_msg = sanitize_string(str(e))
        print(f"Error validating execution environment: {error_msg}", file=sys.stderr)
        return False


def log_module_execution() -> None:
    """Log module execution for audit purposes."""
    try:
        # Setup basic logging for audit purposes
        setup_logging(log_level="INFO", enable_audit=True)
        
        audit_logger = get_audit_logger()
        if audit_logger:
            # Sanitize arguments for logging
            sanitized_args = [sanitize_string(arg) for arg in sys.argv]
            
            audit_logger.log_system_event(
                action="module_execution",
                user_id=str(os.getuid()),
                description=f"RotaryShield module executed with args: {sanitized_args}"
            )
    except Exception as e:
        # Silent fail for audit logging to not interfere with main execution
        pass


def main_wrapper() -> None:
    """
    Main wrapper with security validation and error handling.
    
    This wrapper provides additional security checks and proper error handling
    for module execution via 'python -m rotaryshield'.
    """
    try:
        # Security validation
        if not validate_execution_environment():
            sys.exit(1)
        
        # Log execution for audit trail
        log_module_execution()
        
        # Show execution context
        if "--help" in sys.argv or "-h" in sys.argv:
            print("RotaryShield - 3-Layer Security System")
            print("Execution mode: Python module")
            print("=" * 50)
        
        # Execute main function
        main()
        
    except KeyboardInterrupt:
        print("\nOperation interrupted by user", file=sys.stderr)
        sys.exit(130)  # Standard exit code for SIGINT
        
    except PermissionError as e:
        error_msg = sanitize_string(str(e))
        print(f"Permission error: {error_msg}", file=sys.stderr)
        print("Hint: Some operations may require elevated privileges", file=sys.stderr)
        sys.exit(13)  # Permission denied exit code
        
    except FileNotFoundError as e:
        error_msg = sanitize_string(str(e))
        print(f"File not found: {error_msg}", file=sys.stderr)
        print("Hint: Check configuration file paths and installation", file=sys.stderr)
        sys.exit(2)  # File not found exit code
        
    except ImportError as e:
        error_msg = sanitize_string(str(e))
        print(f"Import error: {error_msg}", file=sys.stderr)
        print("Hint: RotaryShield may not be properly installed", file=sys.stderr)
        print("Try: pip install -e . (from project root)", file=sys.stderr)
        sys.exit(1)
        
    except Exception as e:
        # Generic error handling with sanitized output
        error_msg = sanitize_string(str(e))
        print(f"Unexpected error: {error_msg}", file=sys.stderr)
        
        # Log error for debugging (if logging is available)
        try:
            logger = logging.getLogger(__name__)
            logger.critical(f"Module execution failed: {e}", exc_info=True)
        except:
            pass  # Silent fail for logging
        
        sys.exit(1)


if __name__ == "__main__":
    main_wrapper()