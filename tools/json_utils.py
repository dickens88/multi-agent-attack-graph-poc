"""Robust JSON extraction from LLM responses.

Handles common LLM output patterns:
- Pure JSON
- JSON wrapped in ```json ... ``` fences (with optional preamble text)
- JSON with trailing text
- Unescaped backslashes (e.g. \\FS01\\C$ where \\C is invalid)
- Minor structural errors like missing colon between key and value
"""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)


def _fix_invalid_escapes(text: str) -> str:
    r"""Fix unescaped backslashes that are not valid JSON escape sequences.

    In JSON, only these escapes are valid: \" \\ \/ \b \f \n \r \t \uXXXX
    Any other \X (e.g. \C, \F, \S) is invalid and must become \\X.
    """
    return re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)


def _try_parse(text: str) -> dict | None:
    """Attempt json.loads, return None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def extract_json(text: str) -> dict:
    """Extract the first valid JSON object from *text*.

    Strategy:
    1. Direct ``json.loads`` on the stripped text.
    2. Strip markdown fences (``` or ```json) and retry.
    3. Brace-match the first ``{ ... }`` block and parse.
    4. After each step above fails, retry with invalid-escape fixing.

    Returns the parsed dict, or raises ``ValueError`` if nothing works.
    """
    text = text.strip()

    # ── Attempt 1: Direct parse ──────────────────────────────────────────
    result = _try_parse(text)
    if result is not None:
        return result

    # ── Attempt 2: Strip markdown fences ─────────────────────────────────
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if fenced:
        inner = fenced.group(1).strip()
        result = _try_parse(inner)
        if result is not None:
            return result
        # Try with escape fixing
        result = _try_parse(_fix_invalid_escapes(inner))
        if result is not None:
            return result

    # ── Attempt 3: Brace-match the first { ... } block ──────────────────
    candidate = _extract_brace_block(text)
    if candidate:
        result = _try_parse(candidate)
        if result is not None:
            return result
        # Try with escape fixing
        result = _try_parse(_fix_invalid_escapes(candidate))
        if result is not None:
            return result

    # ── Attempt 4: Full escape fix then retry all strategies ─────────────
    fixed = _fix_invalid_escapes(text)
    result = _try_parse(fixed)
    if result is not None:
        return result

    fenced2 = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", fixed, re.DOTALL)
    if fenced2:
        result = _try_parse(fenced2.group(1).strip())
        if result is not None:
            return result

    candidate2 = _extract_brace_block(fixed)
    if candidate2:
        result = _try_parse(candidate2)
        if result is not None:
            return result

    raise ValueError(f"Could not extract JSON from LLM response: {text[:300]}")


def _extract_brace_block(text: str) -> str | None:
    """Find the first top-level { ... } block using brace depth counting."""
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        ch = text[i]

        if escape_next:
            escape_next = False
            continue

        if ch == "\\":
            escape_next = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start: i + 1]

    return None
