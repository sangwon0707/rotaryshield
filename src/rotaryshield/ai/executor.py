"""
Command Executor
Executes parsed AI commands against RotaryShield
"""

from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass

from .parser import ParsedCommand


@dataclass
class ExecutionResult:
    """Result of command execution."""
    success: bool
    message: str
    data: Optional[Any] = None


class CommandExecutor:
    """
    Executes parsed commands using provided handlers.
    """

    def __init__(self):
        self._handlers: Dict[str, Callable] = {}
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default command handlers (stubs)."""
        self._handlers = {
            "ban": self._handle_ban,
            "unban": self._handle_unban,
            "list_blocked": self._handle_list_blocked,
            "events": self._handle_events,
            "stats": self._handle_stats,
            "status": self._handle_status,
            "refresh": self._handle_refresh,
            "unban_all": self._handle_unban_all,
            "help": self._handle_help,
            "error": self._handle_error,
        }

    def register_handler(self, action: str, handler: Callable):
        """Register a custom handler for an action."""
        self._handlers[action] = handler

    def execute(self, command: ParsedCommand) -> ExecutionResult:
        """
        Execute a parsed command.

        Args:
            command: ParsedCommand from AIParser

        Returns:
            ExecutionResult with success status and message
        """
        handler = self._handlers.get(command.action)

        if not handler:
            return ExecutionResult(
                success=False,
                message=f"Unknown action: {command.action}"
            )

        try:
            return handler(command.params)
        except Exception as e:
            return ExecutionResult(
                success=False,
                message=f"Execution error: {e}"
            )

    # Default handlers (to be overridden by TUI/CLI)
    def _handle_ban(self, params: Dict) -> ExecutionResult:
        ip = params.get("ip")
        duration = params.get("duration", 3600)
        return ExecutionResult(
            success=True,
            message=f"🚫 Ban {ip} for {duration}s",
            data={"ip": ip, "duration": duration}
        )

    def _handle_unban(self, params: Dict) -> ExecutionResult:
        ip = params.get("ip")
        return ExecutionResult(
            success=True,
            message=f"✅ Unban {ip}",
            data={"ip": ip}
        )

    def _handle_list_blocked(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            message="📋 Blocked IPs list",
            data={"action": "list_blocked"}
        )

    def _handle_events(self, params: Dict) -> ExecutionResult:
        limit = params.get("limit", 10)
        return ExecutionResult(
            success=True,
            message=f"📝 Show {limit} events",
            data={"limit": limit}
        )

    def _handle_stats(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            message="📊 Show statistics",
            data={"action": "stats"}
        )

    def _handle_status(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            message="ℹ️ Show status",
            data={"action": "status"}
        )

    def _handle_refresh(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            message="🔄 Refresh",
            data={"action": "refresh"}
        )

    def _handle_unban_all(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            message="⚠️ Unban all IPs",
            data={"action": "unban_all"}
        )

    def _handle_help(self, params: Dict) -> ExecutionResult:
        help_text = """
🤖 AI Commands:
  "192.168.1.1 차단해" - Ban IP
  "192.168.1.1 풀어" - Unban IP
  "차단 목록" - List blocked IPs
  "이벤트 20개" - Show recent events
  "통계" - Show statistics
  "새로고침" - Refresh data
  "전부 해제" - Unban all

⌨️ Keyboard:
  Ctrl+B - Ban IP (from input)
  Ctrl+U - Unban IP (from input)
  Ctrl+R - Refresh
  Ctrl+Q - Quit
"""
        return ExecutionResult(
            success=True,
            message=help_text,
            data={"action": "help"}
        )

    def _handle_error(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(
            success=False,
            message="❌ Could not understand command. Type '도움' for help."
        )
