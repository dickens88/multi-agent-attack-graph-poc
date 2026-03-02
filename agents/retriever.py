"""Retriever Agent — translates Planner instructions into Cypher and executes.

Supports parallel execution with real-time streaming of individual query results
via the event bus.
"""

from __future__ import annotations
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_core.messages import SystemMessage, HumanMessage

from state.investigation_state import InvestigationState
from llm_factory import get_llm
from tools.neo4j_tools import neo4j_client
from tools.cypher_templates import TEMPLATES
import event_bus

logger = logging.getLogger(__name__)

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
_query_pool = ThreadPoolExecutor(max_workers=3)


def _resolve_template(action: dict) -> tuple[str, dict]:
    """Look up a Cypher template and fill in params."""
    template_name = action.get("template_name", "")
    params = action.get("params", {})

    for t in TEMPLATES:
        if t["name"] == template_name:
            return t["cypher"], params

    raise KeyError(f"Template '{template_name}' not found")


def _generate_custom_cypher(action: dict, schema: str, deep_thinking: bool = False) -> tuple[str, dict]:
    """Use the LLM to generate a custom Cypher query."""
    llm = get_llm(deep_thinking=deep_thinking, temperature=0)

    description = action.get("description", "")
    custom_cypher = action.get("custom_cypher", "")

    request = f"{description}\n\nSuggested Cypher (may need fixes): {custom_cypher}" if custom_cypher else description

    messages = [
        SystemMessage(content=CYPHER_GEN_PROMPT.format(schema=schema, request=request)),
        HumanMessage(content="Generate the Cypher query."),
    ]

    response = llm.invoke(messages)
    raw = response.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    result = json.loads(raw)
    return result["cypher"], result.get("params", {})


def _execute_single_action(
    action: dict,
    schema: str,
    iteration: int,
    deep_thinking: bool = False,
    progress_cb=None,
    shared_node_ids=None,
) -> tuple[dict, dict]:
    """Execute a single query action. Returns (query_record, agent_message).

    If progress_cb is provided, immediately streams the result to the frontend.
    If shared_node_ids is provided, accumulates discovered IDs for subgraph queries.
    """
    template_name = action.get("template_name", "DONE")
    description = action.get("description", "")

    if template_name == "DONE":
        return None, None

    # Resolve Cypher
    try:
        if template_name == "custom":
            cypher, params = _generate_custom_cypher(action, schema, deep_thinking)
        else:
            cypher, params = _resolve_template(action)
    except Exception as e:
        logger.error("Failed to resolve Cypher for '%s': %s", description, e)
        query_record = {
            "cypher": f"ERROR: {e}",
            "params": {},
            "results": [],
            "description": description,
        }
        message = {
            "agent": "Retriever",
            "action": "Error",
            "content": f"Failed to resolve query: {e}",
            "iteration": iteration,
        }
        # Stream immediately
        if progress_cb:
            progress_cb("agent_message", message)
        return query_record, message

    # Execute
    try:
        results = neo4j_client.execute_cypher(cypher, params)
    except Exception as e:
        logger.error("Cypher execution failed for '%s': %s", description, e)
        results = [{"error": str(e)}]

    logger.info("Retriever executed: %s → %d results", description, len(results))
    results_preview = results[:30]

    query_record = {
        "cypher": cypher,
        "params": params,
        "results": results_preview,
        "description": description,
    }
    # Format results for display (show actual data, not just count)
    results_display = ""
    display_records = results_preview[:10]
    for i, rec in enumerate(display_records, 1):
        parts = []
        for k, v in rec.items():
            if isinstance(v, dict):
                # Node: show label + name/id
                labels = v.get("_labels", [])
                name = v.get("name") or v.get("id") or v.get("value", "")
                lbl = labels[0] if labels else "Node"
                parts.append(f"{lbl}:`{name}`")
            elif k not in ("_labels", "_type"):
                sv = str(v)
                if len(sv) > 60:
                    sv = sv[:60] + "…"
                parts.append(f"{k}=`{sv}`")
        results_display += f"\n{i}. {' | '.join(parts)}"
    if len(results) > 10:
        results_display += f"\n... 共 {len(results)} 条记录"

    params_display = "NA"
    if isinstance(params, dict) and params:
        try:
            params_display = json.dumps(params, ensure_ascii=False, default=str)
        except Exception:
            params_display = str(params)

    message = {
        "agent": "Retriever",
        "action": "Query Executed",
        "content": (
            f"**Query**: `{cypher}`\n\n"
            f"**Params**: `{params_display}`\n\n"
            f"**Results** ({len(results)} records):{results_display}"
        ),
        "iteration": iteration,
    }

    # Stream this result immediately to the frontend
    if progress_cb:
        progress_cb("agent_message", message)

    # ── Immediate subgraph query for this query's results ──
    try:
        from tools.graph_utils import extract_node_ids, extract_graph_entities

        new_ids = extract_node_ids(results)
        logger.info("Retriever extracted IDs: %s", new_ids)
        
        if new_ids:
            if shared_node_ids is not None:
                shared_node_ids.update(new_ids)
                query_ids = list(shared_node_ids)
            else:
                query_ids = list(new_ids)

            subgraph_results = neo4j_client.execute_cypher(
                "MATCH (a)-[r]->(b) "
                "WHERE a.id IN $ids OR b.id IN $ids "
                "RETURN a, type(r) AS rel_type, b "
                "LIMIT 200",
                {"ids": query_ids},
            )
            logger.info("Subgraph query returned: %d records", len(subgraph_results))
            graph_data = extract_graph_entities(subgraph_results)
            logger.info("Graph data extracted: %d nodes, %d edges", len(graph_data["nodes"]), len(graph_data["edges"]))
            if graph_data["nodes"] or graph_data["edges"]:
                if progress_cb:
                    progress_cb("graph_update", graph_data)
                logger.info(
                    "Graph update: %d nodes, %d edges",
                    len(graph_data["nodes"]), len(graph_data["edges"]),
                )
    except Exception as e:
        logger.warning("Per-query graph update failed: %s", e)

    return query_record, message


def retriever_node(state: InvestigationState) -> dict:
    """LangGraph node: Retriever — executes queries in parallel with real-time streaming."""

    raw_instructions = state.get("query_instructions", "[]")

    # Parse actions list (backward compatible with single action)
    try:
        actions = json.loads(raw_instructions)
    except json.JSONDecodeError:
        actions = []

    if isinstance(actions, dict):
        actions = [actions]

    # Filter out DONE actions
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

    # Fetch schema
    schema = state.get("graph_schema", "")
    if not schema:
        try:
            schema = neo4j_client.get_schema()
        except Exception as e:
            schema = f"(Schema unavailable: {e})"

    iteration = state.get("iteration_count", 0)
    deep_thinking = state.get("deep_thinking", False)
    all_query_records = []
    all_messages = []

    # Get the progress callback from the parent thread for streaming
    progress_cb = event_bus.get_callback()

    if len(real_actions) == 1:
        # Single query — no thread pool overhead
        qr, msg = _execute_single_action(
            real_actions[0], schema, iteration, deep_thinking, progress_cb,
        )
        if qr:
            all_query_records.append(qr)
        if msg:
            all_messages.append(msg)
    else:
        # Parallel execution — shared set for incremental graph updates
        import threading as _th
        shared_ids: set[str] = set()
        shared_ids_lock = _th.Lock()

        class _ThreadSafeSet:
            def update(self, ids):
                with shared_ids_lock:
                    shared_ids.update(ids)
            def __iter__(self):
                with shared_ids_lock:
                    return iter(list(shared_ids))
            def __len__(self):
                return len(shared_ids)

        safe_ids = _ThreadSafeSet()

        logger.info("Executing %d queries in parallel", len(real_actions))

        # Send parallel execution banner immediately
        banner = {
            "agent": "Retriever",
            "action": f"Parallel Execution ⚡ {len(real_actions)} queries",
            "content": "\n".join(
                f"- **Q{i}**: {a.get('description', '?')}"
                for i, a in enumerate(real_actions, 1)
            ),
            "iteration": iteration,
        }
        all_messages.append(banner)
        if progress_cb:
            progress_cb("agent_message", banner)

        futures = {}
        for action in real_actions:
            future = _query_pool.submit(
                _execute_single_action,
                action, schema, iteration, deep_thinking, progress_cb, safe_ids,
            )
            futures[future] = action

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
                if progress_cb:
                    progress_cb("agent_message", err_msg)
    return {
        "graph_schema": schema,
        "queries_executed": all_query_records,
        "agent_messages": all_messages,
    }
