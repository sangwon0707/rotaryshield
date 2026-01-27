"""
Ollama API Client
Lightweight wrapper for local LLM inference
"""

import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class OllamaConfig:
    """Ollama connection configuration."""
    host: str = "localhost"
    port: int = 11434
    model: str = "gemma3:1b"
    timeout: int = 30


class OllamaClient:
    """
    Simple Ollama API client using only stdlib (no external dependencies).
    """

    def __init__(self, config: Optional[OllamaConfig] = None):
        self.config = config or OllamaConfig()
        self.base_url = f"http://{self.config.host}:{self.config.port}"

    def _request(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make HTTP request to Ollama API."""
        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/json"}

        json_data = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=json_data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to connect to Ollama: {e}")
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Ollama API error: {e.code} {e.reason}")

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """
        Generate text completion.

        Args:
            prompt: User prompt
            system: System prompt (optional)

        Returns:
            Generated text response
        """
        data = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
        }

        if system:
            data["system"] = system

        # Set generation parameters for faster response
        data["options"] = {
            "temperature": 0.1,  # Low temperature for consistent parsing
            "num_predict": 256,  # Limit response length
            "top_p": 0.9,
        }

        response = self._request("/api/generate", data)
        return response.get("response", "")

    def chat(self, messages: list, system: Optional[str] = None) -> str:
        """
        Chat completion API.

        Args:
            messages: List of {"role": "user/assistant", "content": "..."}
            system: System prompt (optional)

        Returns:
            Assistant's response
        """
        data = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
        }

        if system:
            data["messages"] = [{"role": "system", "content": system}] + messages

        data["options"] = {
            "temperature": 0.1,
            "num_predict": 256,
        }

        response = self._request("/api/chat", data)
        return response.get("message", {}).get("content", "")

    def is_available(self) -> bool:
        """Check if Ollama server is available."""
        try:
            url = f"{self.base_url}/api/tags"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except Exception:
            return False

    def list_models(self) -> list:
        """List available models."""
        try:
            url = f"{self.base_url}/api/tags"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []
