"""Lightweight JSON parsing helpers for LLM responses."""

import json
import re

from logging_config import get_logger

logger = get_logger(__name__)

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


def _escape_invalid_backslashes(text: str) -> str:
    if not text:
        return text
    return re.sub(r"\\(?![\\\"/bfnrtu])", r"\\\\", text)


def _fix_missing_colon_after_key(text: str) -> str:
    if not text:
        return text
    text = re.sub(r'("(?:\\.|[^"\\])+")\s+(?=")', r'\1: ', text)
    text = re.sub(r'("(?:\\.|[^"\\])+")\s+(?=[\[{0-9\-])', r'\1: ', text)
    return text


def extract_json(text: str, required_fields: set[str] | None = None, allow_partial: bool = True) -> dict:
    raw = (text or "").strip()
    cleaned = _strip_markdown_fences(raw)
    block_raw = _extract_first_object_block(raw)
    block_clean = _extract_first_object_block(cleaned) if cleaned else None

    candidates = [raw, cleaned, block_raw, block_clean]
    candidates += [_escape_invalid_backslashes(c) for c in candidates if c]
    candidates += [_fix_missing_colon_after_key(c) for c in candidates if c]
    seen = set()
    parse_errors: list[str] = []

    for idx, candidate in enumerate(candidates):
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)

        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            parse_errors.append(f"candidate[{idx}] parse failed: {e}")
            continue

        if not isinstance(parsed, dict):
            parse_errors.append(f"candidate[{idx}] parsed type is {type(parsed).__name__}, not dict")
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

        missing = required_fields - set(parsed.keys()) if required_fields else set()
        if missing:
            parse_errors.append(f"candidate[{idx}] missing required fields: {sorted(missing)}")

    has_opening_brace = "{" in raw
    has_full_object = _extract_first_object_block(raw) is not None
    diagnostics = (
        f"raw_length={len(raw)}, has_opening_brace={has_opening_brace}, "
        f"has_full_object={has_full_object}, errors={parse_errors}"
    )

    logger.warning("Failed to extract JSON object. diagnostics=%s raw=%s", diagnostics, raw)
    raise ValueError(f"Could not extract JSON object from response. {diagnostics}\nRaw response:\n{raw}")


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
