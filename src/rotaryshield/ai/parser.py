"""
AI Parser
Converts natural language to structured commands using LLM
"""

import json
import re
from typing import Optional, Dict, Any
from dataclasses import dataclass

from .ollama import OllamaClient, OllamaConfig


SYSTEM_PROMPT = """You are a security command parser for RotaryShield.
Convert user's natural language to JSON command.

Available actions:
- ban: {"action": "ban", "ip": "<IP>", "duration": <seconds>}
- unban: {"action": "unban", "ip": "<IP>"}
- list_blocked: {"action": "list_blocked"}
- events: {"action": "events", "limit": <number>}
- stats: {"action": "stats"}
- status: {"action": "status"}
- refresh: {"action": "refresh"}
- help: {"action": "help"}
- unban_all: {"action": "unban_all"}

Rules:
- Default ban duration is 3600 seconds (1 hour)
- Default events limit is 10
- Extract IP addresses from user input
- Respond ONLY with valid JSON, no explanation

Examples:
User: "192.168.1.1 차단해"
{"action": "ban", "ip": "192.168.1.1", "duration": 3600}

User: "block 10.0.0.5 for 2 hours"
{"action": "ban", "ip": "10.0.0.5", "duration": 7200}

User: "차단 목록 보여줘"
{"action": "list_blocked"}

User: "최근 이벤트 20개"
{"action": "events", "limit": 20}

User: "통계"
{"action": "stats"}

User: "45.33.22.11 풀어줘"
{"action": "unban", "ip": "45.33.22.11"}

User: "전부 해제"
{"action": "unban_all"}

User: "새로고침"
{"action": "refresh"}"""


@dataclass
class ParsedCommand:
    """Parsed command result."""
    action: str
    params: Dict[str, Any]
    raw_input: str
    confidence: float = 1.0
    error: Optional[str] = None


class AIParser:
    """
    Natural language to command parser using local LLM.
    """

    def __init__(self, ollama_config: Optional[OllamaConfig] = None):
        self.client = OllamaClient(ollama_config)
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if AI parsing is available."""
        if self._available is None:
            self._available = self.client.is_available()
        return self._available

    def parse(self, user_input: str) -> ParsedCommand:
        """
        Parse natural language input to structured command.

        Args:
            user_input: Natural language command from user

        Returns:
            ParsedCommand with action and parameters
        """
        user_input = user_input.strip()

        if not user_input:
            return ParsedCommand(
                action="error",
                params={},
                raw_input=user_input,
                error="Empty input"
            )

        # Try rule-based parsing first (faster, no AI needed)
        rule_result = self._rule_based_parse(user_input)
        if rule_result:
            return rule_result

        # Fall back to AI parsing
        if not self.is_available():
            return ParsedCommand(
                action="error",
                params={},
                raw_input=user_input,
                error="AI not available. Use direct commands."
            )

        return self._ai_parse(user_input)

    def _rule_based_parse(self, user_input: str) -> Optional[ParsedCommand]:
        """
        Simple rule-based parsing for common commands.
        Faster than AI and works offline.
        """
        text = user_input.lower().strip()

        # Extract IP address if present
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', user_input)
        ip = ip_match.group(1) if ip_match else None

        # Ban commands
        if ip and any(kw in text for kw in ['차단', '막아', '밴', 'ban', 'block']):
            duration = 3600  # default 1 hour
            # Check for duration keywords
            if '2시간' in text or '2 hour' in text:
                duration = 7200
            elif '24시간' in text or '하루' in text or '1 day' in text:
                duration = 86400
            return ParsedCommand(
                action="ban",
                params={"ip": ip, "duration": duration},
                raw_input=user_input
            )

        # Unban commands
        if ip and any(kw in text for kw in ['풀어', '해제', 'unban', 'unblock', 'release']):
            return ParsedCommand(
                action="unban",
                params={"ip": ip},
                raw_input=user_input
            )

        # List blocked
        if any(kw in text for kw in ['차단 목록', '블록 목록', 'blocked', 'list block', '막힌']):
            return ParsedCommand(
                action="list_blocked",
                params={},
                raw_input=user_input
            )

        # Events
        if any(kw in text for kw in ['이벤트', 'event', '로그', 'log', '공격']):
            limit = 10
            num_match = re.search(r'(\d+)', text)
            if num_match:
                limit = min(int(num_match.group(1)), 100)
            return ParsedCommand(
                action="events",
                params={"limit": limit},
                raw_input=user_input
            )

        # Stats
        if any(kw in text for kw in ['통계', 'stat', '현황']):
            return ParsedCommand(
                action="stats",
                params={},
                raw_input=user_input
            )

        # Status
        if any(kw in text for kw in ['상태', 'status']):
            return ParsedCommand(
                action="status",
                params={},
                raw_input=user_input
            )

        # Refresh
        if any(kw in text for kw in ['새로고침', 'refresh', '갱신', 'reload']):
            return ParsedCommand(
                action="refresh",
                params={},
                raw_input=user_input
            )

        # Unban all
        if any(kw in text for kw in ['전부 해제', '모두 풀어', 'unban all', 'clear all']):
            return ParsedCommand(
                action="unban_all",
                params={},
                raw_input=user_input
            )

        # Help
        if any(kw in text for kw in ['도움', 'help', '명령어', 'command']):
            return ParsedCommand(
                action="help",
                params={},
                raw_input=user_input
            )

        # No rule matched, need AI
        return None

    def _ai_parse(self, user_input: str) -> ParsedCommand:
        """Parse using AI (Ollama)."""
        try:
            response = self.client.generate(
                prompt=f"User: \"{user_input}\"",
                system=SYSTEM_PROMPT
            )

            # Extract JSON from response
            json_match = re.search(r'\{[^}]+\}', response)
            if not json_match:
                return ParsedCommand(
                    action="error",
                    params={},
                    raw_input=user_input,
                    confidence=0.0,
                    error=f"Could not parse: {response[:100]}"
                )

            parsed = json.loads(json_match.group())
            action = parsed.get("action", "error")

            return ParsedCommand(
                action=action,
                params={k: v for k, v in parsed.items() if k != "action"},
                raw_input=user_input,
                confidence=0.9
            )

        except json.JSONDecodeError as e:
            return ParsedCommand(
                action="error",
                params={},
                raw_input=user_input,
                error=f"JSON parse error: {e}"
            )
        except Exception as e:
            return ParsedCommand(
                action="error",
                params={},
                raw_input=user_input,
                error=f"AI error: {e}"
            )
