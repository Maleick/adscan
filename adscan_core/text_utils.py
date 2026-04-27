"""Utility helpers for working with textual output."""

from __future__ import annotations

import re

from adscan_core.sensitive import strip_sensitive_markers

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]")


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape sequences from the provided text string."""
    if not text:
        return text
    return _ANSI_ESCAPE_RE.sub("", text)


def strip_control_characters(text: str) -> str:
    """Remove non-printable ASCII control characters from text.

    This preserves common whitespace such as newlines and tabs, but removes
    characters that can make "empty" output appear non-empty (e.g. null bytes).
    """
    if not text:
        return text
    return _CONTROL_CHARS_RE.sub("", text)


def normalize_cli_output(text: str) -> str:
    """Normalize CLI output for content checks and parsing."""
    return strip_control_characters(strip_ansi_codes(text or ""))


_NTLM_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_NTLM_PAIR_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")


def looks_like_ntlm_hash(value: str | None) -> bool:
    """Return True when value resembles an NTLM hash or LM:NT pair.

    Supports:
    - NT hash: 32 hex characters
    - LM:NT format: 32:32 hex characters
    """
    if not value:
        return False
    candidate = str(value).strip()
    if _NTLM_HASH_RE.match(candidate):
        return True
    return bool(_NTLM_PAIR_RE.match(candidate))


def normalize_account_name(value: str | None) -> str:
    """Normalize a domain account label to a SAM-like lowercase identifier.

    Strips domain prefix (DOMAIN\\user → user) and UPN suffix (user@domain → user).
    Also removes any sensitive markers before processing.
    """
    name = strip_sensitive_markers(str(value or "")).strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()
