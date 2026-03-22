"""LangChain async callbacks and helpers for investigation debug logging."""

from __future__ import annotations

import logging
import os
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.messages import BaseMessage
from langchain_core.outputs import LLMResult

log = logging.getLogger("lab.agent.callbacks")

_DEFAULT_TRUNC = 400
_FULL_CONTENT = os.getenv("LOG_FULL_CONTENT", "").lower() in ("1", "true", "yes")


def truncate_text(text: str, limit: int | None = None) -> str:
    """Truncate for logs unless LOG_FULL_CONTENT is set."""
    lim = limit if limit is not None else _DEFAULT_TRUNC
    if _FULL_CONTENT:
        return text
    if len(text) <= lim:
        return text
    return f"{text[:lim]}... [{len(text)} chars total]"


def _serialized_name(serialized: dict[str, Any] | None) -> str:
    if not serialized:
        return "unknown"
    name = serialized.get("name")
    if name:
        return str(name)
    cid = serialized.get("id")
    if isinstance(cid, list) and cid:
        return str(cid[-1])
    return str(cid or "unknown")


def _messages_preview(messages: list[list[BaseMessage]]) -> str:
    parts: list[str] = []
    for group in messages:
        for m in group:
            role = getattr(m, "type", None) or m.__class__.__name__
            content = m.content
            if isinstance(content, str):
                text = truncate_text(content, 300)
            else:
                text = truncate_text(repr(content), 300)
            parts.append(f"{role}:{text}")
    return " | ".join(parts)[:2000]


class InvestigationDebugHandler(AsyncCallbackHandler):
    """Logs LLM, tool, and chain events for the investigation agent graph."""

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[BaseMessage]],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        model = _serialized_name(serialized)
        md = metadata or {}
        log.info(
            "llm_start model=%s run_id=%s parent_run_id=%s",
            model,
            run_id,
            parent_run_id,
        )
        log.debug(
            "llm_start tags=%s metadata_keys=%s preview=%s",
            tags,
            list(md.keys())[:20],
            _messages_preview(messages),
        )

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        model = _serialized_name(serialized)
        log.info("llm_start (completion) model=%s run_id=%s", model, run_id)
        if prompts:
            log.debug("llm_start prompt_preview=%s", truncate_text(prompts[0]))

    async def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        llm_output = response.llm_output or {}
        usage = llm_output.get("token_usage") or llm_output.get("usage")
        gens = response.generations
        n_gen = sum(len(g) for g in gens) if gens else 0
        log.info(
            "llm_end run_id=%s generations=%s usage=%s",
            run_id,
            n_gen,
            usage,
        )

    async def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        log.error("llm_error run_id=%s: %s", run_id, error, exc_info=True)

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = _serialized_name(serialized)
        log.info("tool_start name=%s run_id=%s", tool_name, run_id)
        log.debug("tool_start input=%s", truncate_text(input_str))

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        out = output if isinstance(output, str) else repr(output)
        log.info("tool_end run_id=%s output_len=%s", run_id, len(out))
        log.debug("tool_end output=%s", truncate_text(out))

    async def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        log.error("tool_error run_id=%s: %s", run_id, error, exc_info=True)

    async def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        name = _serialized_name(serialized)
        md = metadata or {}
        log.debug(
            "chain_start name=%s run_id=%s parent_run_id=%s meta=%s",
            name,
            run_id,
            parent_run_id,
            {k: md[k] for k in list(md)[:8]},
        )


def get_investigation_callbacks() -> list[InvestigationDebugHandler]:
    """Handlers to pass in RunnableConfig['callbacks'] for invoke/astream."""
    return [InvestigationDebugHandler()]
