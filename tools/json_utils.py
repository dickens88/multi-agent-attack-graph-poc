"""Lightweight JSON parsing helpers for LLM responses."""

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


def _strip_markdown_fences(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"```json\s*([\s\S]*?)\s*```", text, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\s*([\s\S]*?)\s*```", text)
    return m.group(1).strip() if m else text.strip()


def _extract_first_object_block(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
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
                return text[start : i + 1]
    return None


def extract_json(text: str, required_fields: set[str] | None = None, allow_partial: bool = True) -> dict:
    raw = (text or "").strip()
    cleaned = _strip_markdown_fences(raw)
    block_raw = _extract_first_object_block(raw)
    block_clean = _extract_first_object_block(cleaned) if cleaned else None

    candidates = [raw, cleaned, block_raw, block_clean]
    seen = set()

    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)

        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue

        if not isinstance(parsed, dict):
            continue

        if not required_fields or required_fields.issubset(parsed.keys()):
            return parsed

        if allow_partial and required_fields:
            result = dict(parsed)
            for field in required_fields - set(result.keys()):
                if field == "confidence":
                    result[field] = 0.0
                elif field in {"new_evidence", "actions", "key_entities"}:
                    result[field] = []
                else:
                    result[field] = ""
            return result

    preview = raw[:300].replace("\n", " ")
    logger.warning("Failed to extract JSON object. preview=%s", preview)
    raise ValueError(f"Could not extract JSON object from response: {preview}")


def parse_json_list(text: str, *, default: list | None = None) -> list:
    raw = (text or "").strip()
    for candidate in (raw, _strip_markdown_fences(raw)):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]

    try:
        return [extract_json(raw)]
    except ValueError:
        return default or []
