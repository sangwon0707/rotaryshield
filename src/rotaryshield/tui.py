#!/usr/bin/env python3
"""
RotaryShield TUI (Terminal User Interface)
Retro-style security monitoring dashboard with AI-powered commands.
"""

import sys
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Input, Footer
from textual.binding import Binding
from textual.reactive import reactive
from textual.timer import Timer
from rich.text import Text

# Import RotaryShield components
try:
    from .database.manager import DatabaseManager
    from .database.ip_manager import IPManager
    from .ai.parser import AIParser
    from .ai.ollama import OllamaConfig
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from rotaryshield.database.manager import DatabaseManager
    from rotaryshield.database.ip_manager import IPManager
    from rotaryshield.ai.parser import AIParser
    from rotaryshield.ai.ollama import OllamaConfig


VERSION = "0.2.0"

# ASCII Logo
LOGO = """[bold cyan]  _____       _
 |  __ \\     | |
 | |__) |___ | |_ __ _ _ __ _   _
 |  _  // _ \\| __/ _` | '__| | | |
 | | \\ \\ (_) | || (_| | |  | |_| |
 |_|  \\_\\___/ \\__\\__,_|_|   \\__, |
  _____ _     _      _     _ __/ |
 / ____| |   (_)    | |   | |___/
| (___ | |__  _  ___| | __| |
 \\___ \\| '_ \\| |/ _ \\ |/ _` |
 ____) | | | | |  __/ | (_| |
|_____/|_| |_|_|\\___|_|\\__,_|[/bold cyan]"""


class HeaderPanel(Static):
    """Main header with ASCII logo and system stats."""

    status = reactive("CONNECTING")
    uptime_days = reactive(0)
    total_banned = reactive(0)
    threat_level = reactive(0)
    active_bans = reactive(0)
    ai_status = reactive("OFF")

    def render(self) -> Text:
        status_color = "green" if self.status == "ONLINE" else "yellow"
        ai_color = "green" if self.ai_status == "ON" else "dim"

        # Threat level bar
        threat_filled = min(self.threat_level, 10)
        threat_bar = "■" * threat_filled + "□" * (10 - threat_filled)
        if self.threat_level <= 3:
            threat_text = "LOW"
            threat_color = "green"
        elif self.threat_level <= 6:
            threat_text = "MEDIUM"
            threat_color = "yellow"
        else:
            threat_text = "HIGH"
            threat_color = "red"

        right_panel = f"""
[bold white][ SYSTEM STATUS ][/bold white]  [{status_color}]● {self.status}[/{status_color}]  [dim](Ver {VERSION})[/dim]
[bold white][ THREAT LEVEL  ][/bold white]  [{threat_color}]{threat_bar}[/{threat_color}] [bold {threat_color}]({threat_text})[/bold {threat_color}]
[bold white][ TOTAL BANNED  ][/bold white]  [cyan]{self.total_banned:,}[/cyan] IPs
[bold white][ ACTIVE BANS   ][/bold white]  [red]{self.active_bans}[/red] IPs
[bold white][ AI ASSISTANT  ][/bold white]  [{ai_color}]● {self.ai_status}[/{ai_color}]

[dim]< ROTARY SHIELD >[/dim]
[dim italic]"AI-Powered Defense System"[/dim italic]"""

        # Combine logo and right panel side by side
        logo_lines = LOGO.split('\n')
        right_lines = right_panel.strip().split('\n')

        combined = []
        max_lines = max(len(logo_lines), len(right_lines))

        for i in range(max_lines):
            logo_part = logo_lines[i] if i < len(logo_lines) else ""
            right_part = right_lines[i] if i < len(right_lines) else ""
            combined.append(f"{logo_part:<45} {right_part}")

        return Text.from_markup("\n".join(combined))


class NetworkGraph(Static):
    """Simple network activity visualization."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data_points = [0] * 24

    def update_data(self, events_count: int):
        self.data_points.pop(0)
        self.data_points.append(min(events_count * 10, 100))
        self.refresh()

    def render(self) -> Text:
        lines = ["[bold yellow][ 📊 NETWORK ACTIVITY ][/bold yellow]", ""]

        max_val = max(self.data_points) if max(self.data_points) > 0 else 100

        for level in [100, 50, 0]:
            row = f" {level:>3}+ │"
            for val in self.data_points[-20:]:
                normalized = (val / max_val * 100) if max_val > 0 else 0
                if normalized >= level:
                    row += "█"
                elif normalized >= level - 25:
                    row += "▄"
                else:
                    row += " "
            lines.append(f"[green]{row}[/green]")

        lines.append("      └" + "─" * 20)
        lines.append("       [dim]" + "".join(f"{h:02d}" if i % 5 == 0 else "  " for i, h in enumerate(range(0, 24, 1)))[:20] + "[/dim]")

        return Text.from_markup("\n".join(lines))


class ThreatsList(Static):
    """Active threats panel."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.threats = []

    def update_threats(self, threats: list):
        self.threats = threats[:6]
        self.refresh()

    def render(self) -> Text:
        lines = ["[bold red][ 🚩 ACTIVE THREATS ][/bold red]", ""]

        if not self.threats:
            lines.append(" [green]No active threats[/green]")
        else:
            for i, threat in enumerate(self.threats, 1):
                if isinstance(threat, str):
                    ip = threat
                    severity = "Med"
                    action = "BAN"
                else:
                    ip = threat.get('ip', '?.?.?.?')
                    severity = threat.get('severity', 'Med')[:4]
                    action = "BAN" if threat.get('banned') else "LOG"

                sev_color = "red" if severity in ("High", "Crit") else "yellow" if severity == "Med" else "green"
                action_color = "red" if action == "BAN" else "cyan"

                lines.append(f" [white]{i}.[/white] [bold]{ip:<15}[/bold] [{sev_color}]({severity:<4})[/{sev_color}] [{action_color}][{action}][/{action_color}]")

        return Text.from_markup("\n".join(lines))


class LogsTable(Static):
    """Live security logs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logs = []

    def update_logs(self, logs: list):
        self.logs = logs[:20]  # Max 20 for display
        self.refresh()

    def render(self) -> Text:
        lines = [
            "[bold magenta][ 📝 LIVE SECURITY LOGS ][/bold magenta]",
            "[bold white] TIME     TYPE       SOURCE IP        ACTION    REASON              STATUS[/bold white]",
            "[dim]─" * 78 + "[/dim]"
        ]

        if not self.logs:
            lines.append(" [dim]Waiting for events...[/dim]")
        else:
            for log in self.logs:
                ts = log.get('timestamp', '')
                if isinstance(ts, (int, float)):
                    ts = datetime.fromtimestamp(ts).strftime('%H:%M:%S')
                elif isinstance(ts, str) and len(ts) > 8:
                    ts = ts[11:19] if ' ' in ts else ts[:8]
                else:
                    ts = "--:--:--"

                event_type = log.get('event_type', 'Unknown')[:10]
                source_ip = log.get('source_ip', 'N/A')[:15]
                severity = log.get('severity', 'info')

                if severity in ('critical', 'high'):
                    action = "BANNED"
                    action_color = "red"
                    status = "[red][BLOCKED][/red]"
                elif severity == 'medium':
                    action = "LOGGED"
                    action_color = "yellow"
                    status = "[yellow][WARNING][/yellow]"
                else:
                    action = "ALLOWED"
                    action_color = "green"
                    status = "[green][SUCCESS][/green]"

                reason = event_type[:18]

                lines.append(
                    f" [dim]{ts}[/dim]  [cyan]{event_type:<10}[/cyan] [white]{source_ip:<16}[/white] "
                    f"[{action_color}]{action:<8}[/{action_color}]  {reason:<18} {status}"
                )

        lines.append("[dim]─" * 78 + "[/dim]")
        return Text.from_markup("\n".join(lines))


class RotaryShieldTUI(App):
    """RotaryShield TUI - AI-Powered Security Monitor."""

    TITLE = "RotaryShield"

    CSS = """
    Screen {
        background: #0a0a0a;
        layout: vertical;
    }

    #header-panel {
        height: auto;
        padding: 1 2;
        background: #0a0a0a;
        border: solid #333;
    }

    #middle-row {
        height: 10;
        layout: horizontal;
        padding: 0 1;
    }

    #network-graph {
        width: 1fr;
        padding: 0 1;
        border: solid #333;
        background: #0d1117;
    }

    #threats-panel {
        width: 40;
        padding: 0 1;
        border: solid #333;
        background: #0d1117;
        margin-left: 1;
    }

    #logs-panel {
        height: 1fr;
        padding: 0 1;
        margin: 1;
        border: solid #333;
        background: #0d1117;
    }

    #input-row {
        height: 3;
        layout: horizontal;
        padding: 0 2;
        background: #161b22;
    }

    #input-label {
        width: auto;
        padding: 1 0;
    }

    #ai-input {
        width: 1fr;
        margin: 0 1;
    }

    #shortcuts {
        width: auto;
        padding: 1 0;
    }

    Footer {
        display: none;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("ctrl+c", "quit", "Quit", show=False),
        Binding("ctrl+r", "refresh", "Refresh", show=False),
        Binding("ctrl+b", "ban_ip", "Ban IP", show=False),
        Binding("ctrl+u", "unban_ip", "Unban", show=False),
        Binding("ctrl+l", "clear_input", "Clear", show=False),
        Binding("escape", "focus_input", show=False),
    ]

    def __init__(
        self,
        db_path: str = "/var/lib/rotaryshield/rotaryshield.db",
        ollama_host: str = "localhost",
        ollama_port: int = 11434,
    ):
        super().__init__()
        self.db_path = db_path
        self._db_manager: Optional[DatabaseManager] = None
        self._ip_manager: Optional[IPManager] = None
        self._start_time = time.time()
        self._refresh_timer: Optional[Timer] = None
        self._event_limit = 8  # Default event limit

        # AI Parser
        ollama_config = OllamaConfig(
            host=ollama_host,
            port=ollama_port,
            model="gemma3:1b",
            timeout=30
        )
        self._ai_parser = AIParser(ollama_config)

    def _get_db_manager(self) -> Optional[DatabaseManager]:
        if self._db_manager is None:
            try:
                self._db_manager = DatabaseManager(self.db_path)
                self._db_manager.initialize()
            except Exception:
                return None
        return self._db_manager

    def _get_ip_manager(self) -> Optional[IPManager]:
        if self._ip_manager is None:
            db_manager = self._get_db_manager()
            if db_manager:
                try:
                    self._ip_manager = IPManager(db_manager)
                except Exception:
                    return None
        return self._ip_manager

    def compose(self) -> ComposeResult:
        yield HeaderPanel(id="header-panel")

        with Horizontal(id="middle-row"):
            yield NetworkGraph(id="network-graph")
            yield ThreatsList(id="threats-panel")

        yield LogsTable(id="logs-panel")

        with Horizontal(id="input-row"):
            yield Static("[bold cyan]🤖 >[/bold cyan]", id="input-label")
            yield Input(placeholder="Type command or ask in natural language... (e.g., '192.168.1.1 차단해')", id="ai-input")
            yield Static(
                "[dim]Ctrl+B[/dim] Ban  "
                "[dim]Ctrl+U[/dim] Unban  "
                "[dim]Ctrl+R[/dim] Refresh  "
                "[dim]Ctrl+Q[/dim] Quit",
                id="shortcuts"
            )

    def on_mount(self) -> None:
        self.refresh_data()
        self._refresh_timer = self.set_interval(2.0, self.refresh_data)
        self.query_one("#ai-input", Input).focus()

        # Check AI availability
        header = self.query_one("#header-panel", HeaderPanel)
        if self._ai_parser.is_available():
            header.ai_status = "ON"
        else:
            header.ai_status = "OFF"

    def refresh_data(self) -> None:
        try:
            ip_manager = self._get_ip_manager()
            db_manager = self._get_db_manager()

            header = self.query_one("#header-panel", HeaderPanel)
            header.status = "ONLINE"
            header.uptime_days = int(time.time() - self._start_time)

            if ip_manager:
                stats = ip_manager.get_statistics()
                header.total_banned = stats.total_bans
                header.active_bans = stats.active_bans
                header.threat_level = min(stats.active_bans, 10)

                threats_panel = self.query_one("#threats-panel", ThreatsList)
                blocked = ip_manager.get_active_bans()[:6]
                threats_panel.update_threats(blocked)

            if db_manager:
                try:
                    query = f'''
                        SELECT timestamp, event_type, source_ip, severity
                        FROM security_events
                        ORDER BY timestamp DESC
                        LIMIT {self._event_limit}
                    '''
                    rows = db_manager.execute_query(query, fetch_all=True)
                    logs = [dict(row) for row in rows] if rows else []

                    logs_panel = self.query_one("#logs-panel", LogsTable)
                    logs_panel.update_logs(logs)

                    graph = self.query_one("#network-graph", NetworkGraph)
                    graph.update_data(len(logs))
                except Exception:
                    pass

        except Exception:
            pass

    def _execute_ai_command(self, user_input: str) -> None:
        """Parse and execute AI command."""
        # Parse the input
        parsed = self._ai_parser.parse(user_input)

        if parsed.error:
            self.notify(f"❌ {parsed.error}", severity="error")
            return

        ip_manager = self._get_ip_manager()

        # Execute based on action
        if parsed.action == "ban":
            ip = parsed.params.get("ip")
            duration = parsed.params.get("duration", 3600)
            if ip and ip_manager:
                try:
                    success = ip_manager.ban_ip(ip, ban_duration=duration, reason="AI command")
                    if success:
                        self.notify(f"🚫 Banned: {ip} ({duration}s)", severity="warning")
                        self.refresh_data()
                    else:
                        self.notify(f"Failed to ban {ip}", severity="error")
                except Exception as e:
                    self.notify(f"Error: {e}", severity="error")
            else:
                self.notify("No IP specified", severity="warning")

        elif parsed.action == "unban":
            ip = parsed.params.get("ip")
            if ip and ip_manager:
                try:
                    success = ip_manager.unban_ip(ip, reason="AI command")
                    if success:
                        self.notify(f"✅ Unbanned: {ip}", severity="information")
                        self.refresh_data()
                    else:
                        self.notify(f"Failed to unban {ip}", severity="error")
                except Exception as e:
                    self.notify(f"Error: {e}", severity="error")
            else:
                self.notify("No IP specified", severity="warning")

        elif parsed.action == "list_blocked":
            if ip_manager:
                blocked = ip_manager.get_active_bans()
                if blocked:
                    ips = ", ".join(str(b) if isinstance(b, str) else b.get('ip', '?') for b in blocked[:5])
                    self.notify(f"📋 Blocked: {ips}{'...' if len(blocked) > 5 else ''}", timeout=5)
                else:
                    self.notify("📋 No IPs blocked", timeout=3)

        elif parsed.action == "events":
            limit = parsed.params.get("limit", 10)
            self._event_limit = min(limit, 20)  # Max 20 for display
            self.refresh_data()
            self.notify(f"📝 Showing {self._event_limit} events", timeout=2)

        elif parsed.action == "stats":
            if ip_manager:
                stats = ip_manager.get_statistics()
                self.notify(
                    f"📊 Active: {stats.active_bans} | Total: {stats.total_bans}",
                    timeout=3
                )

        elif parsed.action == "status":
            self.notify("ℹ️ System ONLINE", timeout=2)

        elif parsed.action == "refresh":
            self.refresh_data()
            self.notify("🔄 Refreshed", timeout=1)

        elif parsed.action == "unban_all":
            self.notify("⚠️ Unban all not implemented (safety)", severity="warning")

        elif parsed.action == "help":
            self.notify(
                "💡 Commands: '차단해', '풀어', '목록', '통계', '새로고침'",
                timeout=5
            )

        else:
            self.notify(f"Unknown action: {parsed.action}", severity="warning")

        # Clear input
        self.query_one("#ai-input", Input).value = ""

    def action_refresh(self) -> None:
        self.refresh_data()
        self.notify("🔄 Refreshed", timeout=1)

    def action_ban_ip(self) -> None:
        input_widget = self.query_one("#ai-input", Input)
        ip = input_widget.value.strip()

        # Extract IP if mixed with text
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', ip)
        if ip_match:
            ip = ip_match.group(1)

        if not ip:
            self.notify("Enter IP address first", severity="warning")
            return

        ip_manager = self._get_ip_manager()
        if ip_manager:
            try:
                success = ip_manager.ban_ip(ip, ban_duration=3600, reason="TUI manual ban")
                if success:
                    self.notify(f"🚫 BANNED: {ip}", severity="warning")
                    input_widget.value = ""
                    self.refresh_data()
                else:
                    self.notify("Ban failed", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

    def action_unban_ip(self) -> None:
        input_widget = self.query_one("#ai-input", Input)
        ip = input_widget.value.strip()

        # Extract IP if mixed with text
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', ip)
        if ip_match:
            ip = ip_match.group(1)

        if not ip:
            self.notify("Enter IP address first", severity="warning")
            return

        ip_manager = self._get_ip_manager()
        if ip_manager:
            try:
                success = ip_manager.unban_ip(ip, reason="TUI manual unban")
                if success:
                    self.notify(f"✅ UNBANNED: {ip}", severity="information")
                    input_widget.value = ""
                    self.refresh_data()
                else:
                    self.notify("Unban failed", severity="error")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

    def action_clear_input(self) -> None:
        self.query_one("#ai-input", Input).value = ""

    def action_focus_input(self) -> None:
        self.query_one("#ai-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key - use AI parsing."""
        user_input = event.value.strip()
        if user_input:
            self._execute_ai_command(user_input)


def main():
    """Entry point for TUI."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="RotaryShield TUI")
    parser.add_argument(
        "--db-path",
        default="/var/lib/rotaryshield/rotaryshield.db",
        help="Path to database file"
    )
    parser.add_argument(
        "--ollama-host",
        default=os.environ.get("OLLAMA_HOST", "localhost").split(":")[0],
        help="Ollama server host"
    )
    parser.add_argument(
        "--ollama-port",
        type=int,
        default=11434,
        help="Ollama server port"
    )
    args = parser.parse_args()

    app = RotaryShieldTUI(
        db_path=args.db_path,
        ollama_host=args.ollama_host,
        ollama_port=args.ollama_port
    )
    app.run()


if __name__ == "__main__":
    main()
