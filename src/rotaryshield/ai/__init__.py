"""
RotaryShield AI Module
Natural language command parsing using local LLM (Ollama)
"""

from .ollama import OllamaClient
from .parser import AIParser
from .executor import CommandExecutor

__all__ = ["OllamaClient", "AIParser", "CommandExecutor"]
