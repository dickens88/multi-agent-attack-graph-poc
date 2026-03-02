"""Robust JSON extraction from LLM responses.

Handles common LLM output patterns:
- Pure JSON
- JSON wrapped in ```json ... ``` fences (with optional preamble text)
- JSON with trailing text
- Multiple markdown fences
- Unescaped backslashes (e.g. \\FS01\\C$ where \\C is invalid)
- Minor structural errors like missing colon between key and value
"""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

DEFAULT_REQUIRED_FIELDS: dict[str, set[str]] = {
    "analyzer": {"analysis", "new_evidence", "gaps"},
    "planner": {"thought", "actions", "confidence"},
    "coordinator": {"investigation_type", "investigation_goal", "key_entities"},
}


def _fix_missing_colon(text: str) -> str:
    """Fix missing colon between key and value in JSON-like text.
    
    Example: "custom_cypher "value"" -> "custom_cypher": "value"
    """
    return re.sub(r'(\w+)\s+(")', r'\1": "', text)


def _fix_missing_comma(text: str) -> str:
    """Fix missing comma between JSON elements.
    
    Examples:
      "key": "value" "next_key": -> "key": "value", "next_key":
      "value"} "next": -> "value", "next":
    """
    text = re.sub(r'(")\s+("[\w_]+":)', r'\1,\2', text)
    text = re.sub(r'(})\s+(")', r'\1,\2', text)
    return text


def _fix_invalid_escapes(text: str) -> str:
    r"""Fix unescaped backslashes that are not valid JSON escape sequences.

    In JSON, only these escapes are valid: \" \\ \/ \b \f \n \r \t \uXXXX
    Any other \X (e.g. \C, \F, \S) is invalid and must become \\X.
    """
    return re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)


def _strip_markdown_fences(text: str) -> str:
    """Remove all markdown code fences from text."""
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*', '', text)
    return text.strip()


def _try_parse(text: str) -> dict | None:
    """Attempt json.loads, return None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _validate_fields(data: dict, required_fields: set[str]) -> bool:
    """Check if all required fields are present in the parsed JSON."""
    if not isinstance(data, dict):
        return False
    return required_fields.issubset(data.keys())


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


def _try_parse_with_fixes(text: str) -> dict | None:
    """Try parsing with multiple fix strategies."""
    strategies = [
        ("raw", lambda t: t),
        ("missing_colon", _fix_missing_colon),
        ("missing_comma", _fix_missing_comma),
        ("invalid_escapes", _fix_invalid_escapes),
        ("both_fixes", lambda t: _fix_missing_colon(_fix_invalid_escapes(t))),
        ("colon_and_comma", lambda t: _fix_missing_colon(_fix_missing_comma(t))),
    ]
    
    for name, fix_fn in strategies:
        fixed = fix_fn(text)
        result = _try_parse(fixed)
        if result is not None:
            logger.debug(f"Successfully parsed with strategy: {name}")
            return result
    
    return None


def extract_json(
    text: str,
    required_fields: set[str] | None = None,
    allow_partial: bool = True,
) -> dict:
    """Extract the first valid JSON object from *text*.

    Args:
        text: The raw text containing JSON
        required_fields: Set of field names that must be present in the result.
                       If None, accepts any valid JSON.
        allow_partial: If True, attempts to fix common JSON errors.
                      If False, only accepts perfectly valid JSON.

    Strategy:
        1. Direct parse of stripped text
        2. Strip markdown fences and retry
        3. Extract first { ... } block using brace matching
        4. Try multiple fix strategies (missing colon, invalid escapes)
        5. Try all combinations

    Returns:
        The parsed dict with required fields validated

    Raises:
        ValueError: If no valid JSON could be extracted
    """
    text = text.strip()
    logger.debug(f"extract_json called with text length: {len(text)}")

    # ── Strategy 1: Direct parse ──────────────────────────────────────────
    result = _try_parse(text)
    if result:
        if _validate_fields(result, required_fields or set()):
            logger.debug("Strategy 1: Direct parse succeeded with validation")
            return result
        # Try fixes on the parsed result
        fixed_result = _try_parse_with_fixes(text)
        if fixed_result and _validate_fields(fixed_result, required_fields or set()):
            logger.debug("Strategy 1b: Direct parse + fixes succeeded")
            return fixed_result

    # ── Strategy 2: Strip markdown fences ─────────────────────────────────
    cleaned = _strip_markdown_fences(text)
    result = _try_parse(cleaned)
    if result:
        if _validate_fields(result, required_fields or set()):
            logger.debug("Strategy 2: Strip markdown fences succeeded")
            return result
        fixed_result = _try_parse_with_fixes(cleaned)
        if fixed_result and _validate_fields(fixed_result, required_fields or set()):
            logger.debug("Strategy 2b: Strip markdown + fixes succeeded")
            return fixed_result
    
    # Try fixes on original text (most common case)
    result = _try_parse_with_fixes(text)
    if result and _validate_fields(result, required_fields or set()):
        logger.debug("Strategy X: Fixes on original text succeeded")
        return result
    
    # Try fixes on cleaned text
    result = _try_parse_with_fixes(cleaned)
    if result and _validate_fields(result, required_fields or set()):
        logger.debug("Strategy X: Fixes on cleaned text succeeded")
        return result

    # ── Strategy 3: Extract using brace matching ──────────────────────────
    candidate = _extract_brace_block(text)
    if candidate:
        result = _try_parse(candidate)
        if result and _validate_fields(result, required_fields or set()):
            logger.debug("Strategy 3: Brace matching succeeded")
            return result
        
        result = _try_parse_with_fixes(candidate)
        if result and _validate_fields(result, required_fields or set()):
            logger.debug("Strategy 3b: Brace matching + fixes succeeded")
            return result

    # ── Strategy 4: Extract from cleaned text ─────────────────────────────
    # Remove common preamble text before JSON
    lines = text.split('\n')
    json_start = -1
    for i, line in enumerate(lines):
        if '{' in line and '"' in line:
            json_start = i
            break
    
    if json_start > 0:
        candidate = '\n'.join(lines[json_start:])
        result = _try_parse_with_fixes(candidate)
        if result and _validate_fields(result, required_fields or set()):
            logger.debug("Strategy 4: Remove preamble succeeded")
            return result

    # ── Strategy 5: Try multiple extractions ─────────────────────────────
    # Try finding any { ... } block in the text
    all_blocks = re.findall(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text)
    for block in all_blocks:
        result = _try_parse_with_fixes(block)
        if result and _validate_fields(result, required_fields or set()):
            logger.debug("Strategy 5: Multiple block extraction succeeded")
            return result

    # ── Strategy 6: Allow partial match if requested ──────────────────────
    if allow_partial and required_fields:
        # Try to find any valid JSON and fill missing fields with defaults
        for candidate in [text, cleaned]:
            result = _try_parse_with_fixes(candidate)
            if result and isinstance(result, dict):
                # Check which required fields are present
                missing = required_fields - set(result.keys())
                if len(missing) < len(required_fields):
                    # Fill missing fields with defaults
                    for field in missing:
                        if field == "confidence":
                            result[field] = 0.0
                        elif field in ("analysis", "thought", "gaps"):
                            result[field] = ""
                        elif field in ("new_evidence", "actions"):
                            result[field] = []
                    logger.debug(f"Strategy 6: Partial match succeeded with fields: {result.keys()}")
                    return result

    # Log failure details for debugging
    preview = text[:500].replace('\n', ' ')
    logger.warning(f"Failed to extract JSON. Preview: {preview}...")

    raise ValueError(f"Could not extract JSON from LLM response: {text[:300]}")


def extract_analyzer_json(text: str) -> dict:
    """Extract JSON specifically for Analyzer agent."""
    return extract_json(
        text,
        required_fields=DEFAULT_REQUIRED_FIELDS["analyzer"],
    )


def extract_planner_json(text: str) -> dict:
    """Extract JSON specifically for Planner agent."""
    return extract_json(
        text,
        required_fields=DEFAULT_REQUIRED_FIELDS["planner"],
    )


def extract_coordinator_json(text: str) -> dict:
    """Extract JSON specifically for Coordinator agent."""
    return extract_json(
        text,
        required_fields=DEFAULT_REQUIRED_FIELDS["coordinator"],
    )
