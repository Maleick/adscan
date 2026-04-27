"""Shared type aliases for ADScan."""

from __future__ import annotations

from collections.abc import Callable
import subprocess


# Generic command executor that accepts a command string and timeout,
# returning a CompletedProcess (used by enumeration services).
CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str]]

# Flexible command executor that accepts variadic arguments and may return None
# (used by file analysis, spidering, and credsweeper services).
FlexibleCommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]

# Legacy alias for FlexibleCommandExecutor (kept for backward compatibility).
RunCommand = FlexibleCommandExecutor


__all__ = [
    "CommandExecutor",
    "FlexibleCommandExecutor",
    "RunCommand",
]
