"""LLM factory — centralized LLM construction with deep thinking support."""

from __future__ import annotations

import time
import logging

from langchain_openai import ChatOpenAI
from config import settings

logger = logging.getLogger(__name__)


class _TimedChatOpenAI(ChatOpenAI):
    """Thin subclass that logs invoke() elapsed time."""

    def invoke(self, *args, **kwargs):
        t0 = time.time()
        result = super().invoke(*args, **kwargs)
        elapsed = time.time() - t0
        tokens = getattr(result, "usage_metadata", None)
        tok_str = ""
        if tokens:
            tok_str = f" | tokens in={tokens.get('input_tokens','-')} out={tokens.get('output_tokens','-')}"
        logger.info("LLM responded in %.2fs%s", elapsed, tok_str)
        return result


def get_llm(deep_thinking: bool = False, temperature: float = 0.1) -> ChatOpenAI:
    """Create a ChatOpenAI instance with optional deep thinking control.

    Args:
        deep_thinking: If True, sends thinking={"type":"enabled", "budget_tokens": 10000}
                       to the API via model_kwargs. If False, uses standard mode.
        temperature: LLM temperature (default 0.1).
    """
    kwargs = {}

    # Only add the thinking parameter when explicitly enabled
    kwargs["extra_body"] = {
        "thinking": {
            "type": "enabled" if deep_thinking else "disabled"
        }
    }

    return _TimedChatOpenAI(
        model=settings.OPENAI_MODEL,
        base_url=settings.OPENAI_API_BASE,
        api_key=settings.OPENAI_API_KEY,
        temperature=temperature,
        **kwargs,
    )
