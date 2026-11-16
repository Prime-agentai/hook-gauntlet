"""hook-gauntlet: test Claude Code hooks against real history, mutated attacks and their previous version."""

from __future__ import annotations

__version__ = "0.1.0"

from .model import Hook, HookResult, Outcome, ToolCall, Verdict

__all__ = ["Hook", "HookResult", "Outcome", "ToolCall", "Verdict", "__version__"]
