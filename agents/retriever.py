"""Retriever Agent — translates Planner instructions into Cypher and executes.

Supports parallel execution with real-time streaming of individual query results
via the event bus.
"""

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from logging_config import get_logger
import event_bus
from config import settings
from llm_factory import get_llm
from state.investigation_state import InvestigationState
from tools.cypher_templates import TEMPLATES
from tools.json_utils import extract_json, parse_json_list
from tools.neo4j_tools import neo4j_client

logger = get_logger(__name__)

# Prompt used only when the Planner requests a "custom" Cypher query
CYPHER_GEN_PROMPT = """\
You are a Cypher query generator for Neo4j. Generate a READ-ONLY Cypher query.

## Rules
- ONLY use MATCH, OPTIONAL MATCH, WHERE, WITH, RETURN, ORDER BY, LIMIT, UNWIND, COLLECT, COUNT.
- NEVER use CREATE, DELETE, SET, REMOVE, MERGE, DROP, or CALL {{}}.
- Use parameter binding ($param) instead of string interpolation.
- Limit results to 50 rows max.

## Graph Schema
{schema}

## User Request
{request}

Respond with ONLY a JSON object:
```json
{{"cypher": "<the Cypher query>", "params": {{"<name>": "<value>", ...}}}}
```
"""

# Thread pool for parallel query execution
_query_pool = ThreadPoolExecutor(max_workers=settings.QUERY_PARALLEL_WORKERS)
_TEMPLATE_MAP = {t["name"]: t["cypher"] for t in TEMPLATES}


class _SharedIdSet:
    def __init__(self) -> None:
        self._ids: set[str] = set()
        self._lock = threading.Lock()

    def update(self, ids: set[str]) -> None:
        with self._lock:
            self._ids.update(ids)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self._ids)


def _emit(progress_cb, event_type: str, payload: dict) -> None:
    if progress_cb:
        progress_cb(event_type, payload)


def _resolve_template(action: dict) -> tuple[str, dict]:
    template_name = action.get("template_name", "")
    params = action.get("params", {})

    cypher = _TEMPLATE_MAP.get(template_name)
    if cypher is None:
        raise KeyError(f"Template '{template_name}' not found")
    return cypher, params


def _generate_custom_cypher(action: dict, schema: str, deep_thinking: bool = False) -> tuple[str, dict]:
    llm = get_llm(deep_thinking=deep_thinking, temperature=settings.TEMPERATURE)

    description = action.get("description", "")
    custom_cypher = action.get("custom_cypher", "")
    request = f"{description}\n\nSuggested Cypher (may need fixes): {custom_cypher}" if custom_cypher else description

    messages = [
        SystemMessage(content=CYPHER_GEN_PROMPT.format(schema=schema, request=request)),
        HumanMessage(content="Generate the Cypher query."),
    ]
    response = llm.invoke(messages)

    result = extract_json(
        response.content,
        required_fields={"cypher", "params"},
        allow_partial=True,
    )
    return result.get("cypher", ""), result.get("params", {})


def _format_results_preview(results: list[dict]) -> str:
    lines: list[str] = []
    for i, rec in enumerate(results[:10], 1):
        parts = []
        for k, v in rec.items():
            if isinstance(v, dict):
                labels = v.get("_labels", [])
                name = v.get("name") or v.get("id") or v.get("value", "")
                label = labels[0] if labels else "Node"
                parts.append(f"{label}:`{name}`")
            elif k not in ("_labels", "_type"):
                sv = str(v)
                parts.append(f"{k}=`{sv[:60] + '…' if len(sv) > 60 else sv}`")
        lines.append(f"{i}. {' | '.join(parts)}")
    return "\n".join(lines)


def _maybe_update_graph(results: list[dict], progress_cb, shared_node_ids: _SharedIdSet | None) -> None:
    try:
        from tools.graph_utils import extract_graph_entities, extract_node_ids

        new_ids = extract_node_ids(results)
        if not new_ids:
            return

        if shared_node_ids is not None:
            shared_node_ids.update(new_ids)
            query_ids = shared_node_ids.snapshot()
        else:
            query_ids = list(new_ids)

        subgraph_results = neo4j_client.execute_cypher(
            "MATCH (a)-[r]->(b) "
            "WHERE a.id IN $ids OR b.id IN $ids "
            "RETURN a, type(r) AS rel_type, b "
            "LIMIT 200",
            {"ids": query_ids},
        )

        graph_data = extract_graph_entities(subgraph_results)
        if graph_data["nodes"] or graph_data["edges"]:
            _emit(progress_cb, "graph_update", graph_data)
            logger.info("Graph update: %d nodes, %d edges", len(graph_data["nodes"]), len(graph_data["edges"]))
    except Exception as e:
        logger.warning("Per-query graph update failed: %s", e)


def _execute_single_action(
    action: dict,
    schema: str,
    iteration: int,
    deep_thinking: bool = False,
    progress_cb=None,
    shared_node_ids: _SharedIdSet | None = None,
) -> tuple[dict | None, dict | None]:
    template_name = action.get("template_name", "DONE")
    description = action.get("description", "")

    if template_name == "DONE":
        return None, None

    try:
        cypher, params = (
            _generate_custom_cypher(action, schema, deep_thinking)
            if template_name == "custom"
            else _resolve_template(action)
        )
    except Exception as e:
        logger.error("Failed to resolve Cypher for '%s': %s", description, e)
        message = {
            "agent": "Retriever",
            "action": "Error",
            "content": f"Failed to resolve query: {e}",
            "iteration": iteration,
        }
        _emit(progress_cb, "agent_message", message)
        return {
            "cypher": f"ERROR: {e}",
            "params": {},
            "results": [],
            "description": description,
        }, message

    try:
        results = neo4j_client.execute_cypher(cypher, params)
    except Exception as e:
        logger.error("Cypher execution failed for '%s': %s", description, e)
        results = [{"error": str(e)}]

    results_preview = results[:30]
    logger.info("Retriever executed: %s → %d results", description, len(results))

    params_display = "NA"
    if isinstance(params, dict) and params:
        try:
            params_display = json.dumps(params, ensure_ascii=False, default=str)
        except Exception:
            params_display = str(params)

    preview_text = _format_results_preview(results_preview)
    if len(results) > 10:
        preview_text = f"{preview_text}\n... 共 {len(results)} 条记录" if preview_text else f"... 共 {len(results)} 条记录"

    message = {
        "agent": "Retriever",
        "action": "Query Executed",
        "content": (
            f"**Query**: `{cypher}`\n\n"
            f"**Params**: `{params_display}`\n\n"
            f"**Results** ({len(results)} records):\n{preview_text}"
        ),
        "iteration": iteration,
    }

    _emit(progress_cb, "agent_message", message)
    _maybe_update_graph(results, progress_cb, shared_node_ids)

    return {
        "cypher": cypher,
        "params": params,
        "results": results_preview,
        "description": description,
    }, message


def _get_schema(state: InvestigationState) -> str:
    schema = state.get("graph_schema", "")
    if schema:
        return schema
    try:
        return neo4j_client.get_schema()
    except Exception as e:
        return f"(Schema unavailable: {e})"


def retriever_node(state: InvestigationState) -> dict:
    """LangGraph node: Retriever — executes queries in parallel with real-time streaming."""
    actions = parse_json_list(state.get("query_instructions", "[]"), default=[])
    real_actions = [a for a in actions if a.get("template_name") != "DONE"]

    if not real_actions:
        return {
            "agent_messages": [
                {
                    "agent": "Retriever",
                    "action": "Skipped",
                    "content": "Investigation complete — no query to execute.",
                    "iteration": state.get("iteration_count", 0),
                }
            ]
        }

    schema = _get_schema(state)
    iteration = state.get("iteration_count", 0)
    deep_thinking = state.get("deep_thinking", False)
    progress_cb = event_bus.get_callback()

    all_query_records: list[dict[str, Any]] = []
    all_messages: list[dict[str, Any]] = []

    if len(real_actions) == 1:
        qr, msg = _execute_single_action(real_actions[0], schema, iteration, deep_thinking, progress_cb)
        if qr:
            all_query_records.append(qr)
        if msg:
            all_messages.append(msg)
    else:
        logger.info("Executing %d queries in parallel", len(real_actions))
        banner = {
            "agent": "Retriever",
            "action": f"Parallel Execution ⚡ {len(real_actions)} queries",
            "content": "\n".join(f"- **Q{i}**: {a.get('description', '?')}" for i, a in enumerate(real_actions, 1)),
            "iteration": iteration,
        }
        all_messages.append(banner)
        _emit(progress_cb, "agent_message", banner)

        shared_ids = _SharedIdSet()
        futures = {
            _query_pool.submit(
                _execute_single_action,
                action,
                schema,
                iteration,
                deep_thinking,
                progress_cb,
                shared_ids,
            ): action
            for action in real_actions
        }

        for future in as_completed(futures):
            try:
                qr, msg = future.result()
                if qr:
                    all_query_records.append(qr)
                if msg:
                    all_messages.append(msg)
            except Exception as e:
                logger.error("Parallel query failed: %s", e)
                err_msg = {
                    "agent": "Retriever",
                    "action": "Error",
                    "content": f"Parallel query failed: {e}",
                    "iteration": iteration,
                }
                all_messages.append(err_msg)
                _emit(progress_cb, "agent_message", err_msg)

    return {
        "graph_schema": schema,
        "queries_executed": all_query_records,
        "agent_messages": all_messages,
    }
