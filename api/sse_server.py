import json

from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from common.logging_utils import get_logger, setup_logging

setup_logging()

from common.orchestrator import orchestrator

app = FastAPI()
logger = get_logger("lab.sse")


def _parse_subagent_context(ns: tuple, metadata: dict, fallback_counter: int) -> tuple[bool, str | None, str]:
    """
    Infer whether current chunk belongs to a subagent and return
    (is_subagent, call_id, agent_name).
    """
    agent_name = metadata.get("lc_agent_name", "unknown-agent")

    for item in ns:
        if not isinstance(item, str):
            continue
        if item.startswith("tools:"):
            parts = item.split(":")
            if len(parts) >= 2 and parts[1]:
                return True, parts[1], agent_name

    # Fallback for runtimes where namespace shape changed but agent metadata is present.
    if agent_name and agent_name not in {"attack-graph-orchestrator", "unknown-agent"}:
        synthetic_call_id = f"auto_{agent_name}_{fallback_counter}"
        return True, synthetic_call_id, agent_name

    return False, None, agent_name


# ── Node display config（与旧版 graph_utils.py 保持一致）──────────────────
_NODE_COLORS = {
    "Host": "#00e5ff",
    "User": "#b388ff",
    "IOC": "#ff1744",
    "Alert": "#ffab00",
    "Process": "#39ff14",
    "Network_Connection": "#448aff",
    "File": "#78909c",
    "Email": "#ff6e40",
    "MITRE_Technique": "#ea80fc",
    "Vulnerability": "#ffd740",
    # 兼容当前版本已有的类型
    "IP": "#378ADD",
    "Attacker": "#E24B4A",
}

_NODE_ICONS = {
    "Host": "🖥",
    "User": "👤",
    "IOC": "⚠",
    "Alert": "🔔",
    "Process": "⚙",
    "Network_Connection": "🌐",
    "File": "📄",
    "Email": "✉",
    "MITRE_Technique": "🎯",
    "Vulnerability": "🛡",
    "IP": "🔵",
    "Attacker": "💀",
}


def _pick_node_id(obj: dict) -> str | None:
    """Derive a stable identifier from a node dict."""
    return obj.get("id") or obj.get("ip") or obj.get("name") or obj.get("value") or obj.get("src_ip")


def _pick_node_label(obj: dict) -> str:
    """Pick a human-readable label."""
    return obj.get("name") or obj.get("id") or obj.get("ip") or obj.get("value") or "?"


def _build_node(obj: dict) -> dict | None:
    """Convert a serialized Neo4j node dict (with _labels) into a graph node."""
    labels = obj.get("_labels", [])
    nid = _pick_node_id(obj)
    if not nid:
        return None
    node_type = labels[0] if labels else "Unknown"
    properties = {k: v for k, v in obj.items() if not k.startswith("_")}
    return {
        "id": str(nid),
        "label": _pick_node_label(obj),
        "type": node_type,
        "color": _NODE_COLORS.get(node_type, "#90a4ae"),
        "icon": _NODE_ICONS.get(node_type, "●"),
        "properties": properties,
    }


def _scan_rows_for_nodes_and_edges(rows: list[dict]) -> tuple[dict[str, dict], list[dict]]:
    """
    Scan result rows, extract all nodes (with _labels) and edges (with _type).
    Returns (nodes_map {id: node}, edges list).

    This mirrors the logic in the old graph_utils.extract_graph_entities().
    """
    nodes_map: dict[str, dict] = {}
    edges_set: set[tuple] = set()
    edges: list[dict] = []

    for row in rows:
        row_nodes: list[dict] = []
        rel_type: str | None = None
        rel_start: str | None = None
        rel_end: str | None = None

        for key, val in row.items():
            if not isinstance(val, dict):
                if key in ("rel_type", "action", "relationship", "type") and isinstance(val, str):
                    rel_type = val
                continue

            if "_labels" in val:
                node = _build_node(val)
                if node:
                    if node["id"] not in nodes_map:
                        nodes_map[node["id"]] = node
                    row_nodes.append(node)

            elif "_type" in val:
                rel_type = val["_type"]
                rel_start = str(val.get("_start", "")) or None
                rel_end = str(val.get("_end", "")) or None

            elif "nodes" in val and "relationships" in val:
                for n_obj in val.get("nodes", []):
                    if isinstance(n_obj, dict) and "_labels" in n_obj:
                        node = _build_node(n_obj)
                        if node and node["id"] not in nodes_map:
                            nodes_map[node["id"]] = node
                            row_nodes.append(node)
                for r_obj in val.get("relationships", []):
                    if isinstance(r_obj, dict) and "_type" in r_obj:
                        rt = r_obj["_type"]
                        rs = str(r_obj.get("_start", "")) or None
                        re_ = str(r_obj.get("_end", "")) or None
                        if rs and re_:
                            key_ = (rs, re_, rt)
                            if key_ not in edges_set:
                                edges_set.add(key_)
                                edges.append({"source": rs, "target": re_, "label": rt})

            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and "_labels" in item:
                        node = _build_node(item)
                        if node and node["id"] not in nodes_map:
                            nodes_map[node["id"]] = node

        if rel_start and rel_end and rel_type:
            key_ = (rel_start, rel_end, rel_type)
            if key_ not in edges_set:
                edges_set.add(key_)
                edges.append({"source": rel_start, "target": rel_end, "label": rel_type})

        elif len(row_nodes) >= 2 and rel_type:
            src, tgt = row_nodes[0], row_nodes[1]
            key_ = (src["id"], tgt["id"], rel_type)
            if key_ not in edges_set:
                edges_set.add(key_)
                edges.append({"source": src["id"], "target": tgt["id"], "label": rel_type})

        elif len(row_nodes) == 2 and not rel_type:
            src, tgt = row_nodes[0], row_nodes[1]
            key_ = (src["id"], tgt["id"], "RELATED")
            if key_ not in edges_set:
                edges_set.add(key_)
                edges.append({"source": src["id"], "target": tgt["id"], "label": "RELATED"})

    return nodes_map, edges


def extract_graph_data(tool_name: str, tool_result: str) -> dict | None:
    """
    Extract graph-renderable nodes/edges from tool results.

    Strategy:
    1. Parse the tool result and extract all nodes (preserving full properties + labels).
    2. For any nodes found, run a subgraph query to fetch all relationships
       connecting them (and their immediate neighbors) — this prevents isolated nodes.
    3. Merge everything and return.
    """
    graph_tools = {
        "get_node_by_id",
        "run_cypher_query",
        "get_node_neighbors",
        "trace_attack_path",
    }
    if tool_name not in graph_tools:
        return None

    try:
        data = json.loads(tool_result)
    except Exception:
        return None

    nodes_map: dict[str, dict] = {}
    edges_set: set[tuple] = set()
    edges: list[dict] = []
    highlight: list[str] = []

    if tool_name == "get_node_by_id" and data.get("found"):
        node_obj = data["node"]
        node_type = data.get("node_type", "Unknown")
        # 用 id 或 ip 作为图节点的唯一标识
        nid = (node_obj.get("id") or node_obj.get("ip")
               or node_obj.get("name") or node_obj.get("username"))
        if nid:
            node = _build_node(node_obj) if "_labels" in node_obj else {
                "id": str(nid),
                "label": (node_obj.get("name") or node_obj.get("username")
                          or node_obj.get("id") or str(nid)),
                "type": node_type,
                "color": _NODE_COLORS.get(node_type, "#90a4ae"),
                "icon": _NODE_ICONS.get(node_type, "●"),
                "properties": {k: v for k, v in node_obj.items() if not k.startswith("_")},
            }
            nodes_map[node["id"]] = node
            highlight = [node["id"]]

            # 同时把 get_node_by_id 返回的 neighbors 直接用于图谱
            for nb in data.get("neighbors", []):
                nid2 = nb.get("neighbor_id")
                ntype2 = nb.get("neighbor_type", "Unknown")
                nb_props = nb.get("neighbor_props") or {}
                if nid2:
                    if nid2 not in nodes_map:
                        nodes_map[nid2] = {
                            "id": str(nid2),
                            "label": (nb_props.get("name") or nb_props.get("username")
                                      or nb_props.get("id") or str(nid2)),
                            "type": ntype2,
                            "color": _NODE_COLORS.get(ntype2, "#90a4ae"),
                            "icon": _NODE_ICONS.get(ntype2, "●"),
                            "properties": {k: v for k, v in nb_props.items()
                                           if not k.startswith("_")},
                        }
                    rt = nb.get("rel_type", "")
                    direction = nb.get("rel_direction", "out")
                    src_id = str(node["id"]) if direction == "out" else str(nid2)
                    tgt_id = str(nid2) if direction == "out" else str(node["id"])
                    key_ = (src_id, tgt_id, rt)
                    if key_ not in edges_set:
                        edges_set.add(key_)
                        edges.append({"source": src_id, "target": tgt_id, "label": rt})

    elif tool_name == "run_cypher_query" and data.get("status") == "success":
        nm, el = _scan_rows_for_nodes_and_edges(data.get("rows", []))
        nodes_map.update(nm)
        for e in el:
            key_ = (e["source"], e["target"], e["label"])
            if key_ not in edges_set:
                edges_set.add(key_)
                edges.append(e)

    elif tool_name == "get_node_neighbors":
        center = data.get("node_id")
        for row in data.get("neighbors", []):
            n_obj = row.get("n")
            m_obj = row.get("m")
            rel_type = row.get("rel_type") or ""
            if isinstance(n_obj, dict) and "_labels" in n_obj:
                bn = _build_node(n_obj)
                if bn:
                    nodes_map[bn["id"]] = bn
                    if center and (bn["id"] == str(center) or bn["id"] == center):
                        highlight = [bn["id"]]
            if isinstance(m_obj, dict) and "_labels" in m_obj:
                bm = _build_node(m_obj)
                if bm:
                    nodes_map[bm["id"]] = bm
            n_id = None
            m_id = None
            if isinstance(n_obj, dict) and "_labels" in n_obj:
                nn = _build_node(n_obj)
                if nn:
                    n_id = nn["id"]
            if isinstance(m_obj, dict) and "_labels" in m_obj:
                mm = _build_node(m_obj)
                if mm:
                    m_id = mm["id"]
            if n_id and m_id:
                key_ = (n_id, m_id, rel_type)
                if key_ not in edges_set:
                    edges_set.add(key_)
                    edges.append({"source": n_id, "target": m_id, "label": rel_type})

    elif tool_name == "trace_attack_path":
        for path in data.get("paths", []):
            path_nodes = path.get("path_nodes") or []
            path_rels = path.get("path_rels") or []
            chain_ids: list[str] = []
            for pn in path_nodes:
                if not isinstance(pn, dict):
                    continue
                props = pn.get("props")
                node = None
                if isinstance(props, dict) and "_labels" in props:
                    node = _build_node(props)
                if node:
                    nodes_map[node["id"]] = node
                    chain_ids.append(node["id"])
                else:
                    pid = pn.get("id")
                    if pid:
                        ptype = pn.get("type", "Unknown")
                        plabel = _pick_node_label(props) if isinstance(props, dict) else str(pid)
                        nodes_map[str(pid)] = {
                            "id": str(pid),
                            "label": plabel,
                            "type": ptype,
                            "color": _NODE_COLORS.get(ptype, "#90a4ae"),
                            "icon": _NODE_ICONS.get(ptype, "●"),
                            "properties": (
                                {k: v for k, v in props.items() if not k.startswith("_")}
                                if isinstance(props, dict) else {}
                            ),
                        }
                        chain_ids.append(str(pid))
            for i in range(len(chain_ids) - 1):
                rt = "RELATED"
                if i < len(path_rels) and isinstance(path_rels[i], dict):
                    rt = path_rels[i].get("type") or rt
                a, b = chain_ids[i], chain_ids[i + 1]
                key_ = (a, b, rt)
                if key_ not in edges_set:
                    edges_set.add(key_)
                    edges.append({"source": a, "target": b, "label": rt})

    if not nodes_map and not edges:
        return None

    return {
        "nodes": list(nodes_map.values()),
        "edges": edges,
        "highlight": highlight,
    }


def _sse(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _extract_todos_payload(raw: str):
    """Best-effort parser for write_todos tool output.

    Handles strict JSON, markdown-wrapped JSON and python-like repr text.
    Returns list[dict] or None.
    """
    text = raw.strip()
    if not text:
        return None

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict) and isinstance(parsed.get("todos"), list):
            return parsed.get("todos")
    except Exception:
        pass

    start = min([i for i in [text.find("["), text.find("{")] if i != -1], default=-1)
    end = max(text.rfind("]"), text.rfind("}"))
    if start == -1 or end == -1 or end <= start:
        return None

    snippet = text[start : end + 1]
    try:
        parsed = json.loads(snippet)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict) and isinstance(parsed.get("todos"), list):
            return parsed.get("todos")
    except Exception:
        pass

    # final fallback for python repr (single quotes / True / False)
    try:
        import ast

        parsed = ast.literal_eval(snippet)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict) and isinstance(parsed.get("todos"), list):
            return parsed.get("todos")
    except Exception:
        return None

    return None


async def stream_investigation(user_query: str, thread_id: str):
    logger.info(f"investigation_start thread_id={thread_id} query_len={len(user_query)} query_preview={(user_query[:200] + '…') if len(user_query) > 200 else user_query}")
    config = {
        "configurable": {"thread_id": thread_id},
    }

    active_subagents: dict[str, str] = {}
    pending_tool_calls: dict[str, dict] = {}
    logged_tool_chunk_ids: set[str] = set()
    synthetic_counter = 0

    async for chunk in orchestrator.astream(
        {"messages": [{"role": "user", "content": user_query}]},
        config=config,
        stream_mode="messages",
        subgraphs=True,
        version="v2",
    ):
        if chunk["type"] != "messages":
            continue

        token, metadata = chunk["data"]
        ns = chunk.get("ns", ())
        is_subagent, call_id, inferred_agent_name = _parse_subagent_context(ns, metadata, synthetic_counter)
        if is_subagent and call_id and call_id.startswith("auto_"):
            synthetic_counter += 1

        if is_subagent and call_id and call_id not in active_subagents:
            agent_name = metadata.get("lc_agent_name") or getattr(token, "name", None) or inferred_agent_name
            active_subagents[call_id] = agent_name

            # 从 pending_tool_calls 里取 task() 的 description
            task_description = ""
            if call_id in pending_tool_calls:
                raw = pending_tool_calls[call_id].get("args_buf", "")
                if raw:
                    try:
                        task_args = json.loads(raw)
                        task_description = task_args.get("description", "")
                    except Exception:
                        pass

            logger.info(f"subagent_start call_id={call_id} agent_name={agent_name} description_len={len(task_description)}")
            yield _sse(
                "subagent_start",
                {
                    "type": "subagent_start",
                    "agent_name": agent_name,
                    "call_id": call_id,
                    "task_description": task_description,
                },
            )

        if hasattr(token, "tool_call_chunks") and token.tool_call_chunks:
            for tc in token.tool_call_chunks:
                tc_id = tc.get("id") or tc.get("index", "")
                tc_key = str(tc_id)
                name = tc.get("name", "")
                args_chunk = tc.get("args", "")

                if name:
                    pending_tool_calls[tc_id] = {"name": name, "args_buf": ""}
                    if tc_key not in logged_tool_chunk_ids:
                        logged_tool_chunk_ids.add(tc_key)
                        scope = "subagent" if is_subagent else "orchestrator"

                if args_chunk and tc_id in pending_tool_calls:
                    pending_tool_calls[tc_id]["args_buf"] += args_chunk

                if tc_id in pending_tool_calls and pending_tool_calls[tc_id]["name"]:
                    raw_args = pending_tool_calls[tc_id]["args_buf"]
                    parsed_args = {"_raw": raw_args} if raw_args else {}
                    if raw_args:
                        try:
                            parsed_args = json.loads(raw_args)
                        except Exception:
                            parsed_args = {"_raw": raw_args}

                    event_type = "subagent_tool_call" if is_subagent else "orchestrator_tool_call"
                    payload = {
                        "type": event_type,
                        "tool": pending_tool_calls[tc_id]["name"],
                        "args": parsed_args,
                    }
                    if is_subagent:
                        payload["call_id"] = call_id
                        payload["agent_name"] = active_subagents.get(call_id, inferred_agent_name)

                    if isinstance(parsed_args, dict) and "reason" in parsed_args:
                        reason_text = parsed_args.pop("reason", "")
                        if reason_text:
                            payload["reasoning"] = str(reason_text)

                    yield _sse(event_type, payload)

        elif token.type == "tool":
            tool_name = token.name or ""
            # Fallback: resolve tool name from pending_tool_calls when
            # the ToolMessage lacks a `name` attribute (e.g. write_todos
            # returns a Command with a manually-created ToolMessage).
            if not tool_name:
                tc_id = getattr(token, "tool_call_id", None)
                if tc_id and tc_id in pending_tool_calls:
                    tool_name = pending_tool_calls[tc_id].get("name", "")
            result_str = str(token.content)
            graph_data = extract_graph_data(tool_name, result_str)
            scope = "subagent" if is_subagent else "orchestrator"
            logger.info(f"tool_result scope={scope} tool={tool_name} result_len={len(result_str)} has_graph={graph_data is not None} call_id={call_id}")

            event_type = "subagent_tool_result" if is_subagent else "orchestrator_tool_result"
            payload = {
                "type": event_type,
                "tool": tool_name,
                "result": result_str,
                "graph_data": graph_data,
            }
            if is_subagent:
                payload["call_id"] = call_id
                payload["agent_name"] = active_subagents.get(call_id, inferred_agent_name)

            todos_list = None
            if tool_name == "write_todos":
                todos_list = _extract_todos_payload(result_str)
                if todos_list:
                    payload["todos"] = todos_list

            yield _sse(event_type, payload)

            if graph_data:
                logger.info(f"[graph_update_emit] source={'subagent' if is_subagent else 'orchestrator'} tool={tool_name} call_id={call_id} nodes={len(graph_data.get('nodes', []))} edges={len(graph_data.get('edges', []))}")
                yield _sse("graph_update", {"type": "graph_update", **graph_data})

            if tool_name == "write_todos" and todos_list:
                source_agent = (
                    active_subagents.get(call_id, "orchestrator")
                    if is_subagent
                    else "orchestrator"
                )
                yield _sse(
                    "todos_update_realtime",
                    {
                        "type": "todos_update_realtime",
                        "source": source_agent,
                        "call_id": call_id if is_subagent else None,
                        "todos": todos_list,
                    },
                )

        if token.type == "ai" and token.content:
            event_type = "subagent_token" if is_subagent else "orchestrator_token"
            payload = {"type": event_type, "content": token.content}
            if is_subagent:
                payload["call_id"] = call_id
                payload["agent_name"] = active_subagents.get(call_id, inferred_agent_name)
            yield _sse(event_type, payload)

        if token.type == "tool":
            finished_call_id = getattr(token, "tool_call_id", None)
            if finished_call_id and finished_call_id in active_subagents:
                agent_name = active_subagents[finished_call_id]
                final_result = str(token.content)

                logger.info(f"subagent_complete call_id={finished_call_id} agent_name={agent_name} result_len={len(final_result)}")
                yield _sse(
                    "subagent_complete",
                    {
                        "type": "subagent_complete",
                        "call_id": finished_call_id,
                        "agent_name": agent_name,
                        "result": final_result,
                    },
                )
                del active_subagents[finished_call_id]

                # report-agent 完成后立即结束流程，跳过后续阶段
                if agent_name == "report-agent":
                    logger.info(f"investigation_done_early reason=report-agent_finished thread_id={thread_id}")
                    yield _sse("done", {"type": "done"})
                    return

    logger.info(f"investigation_stream_complete thread_id={thread_id}")
    yield _sse("done", {"type": "done"})


@app.get("/api/investigate")
async def investigate(query: str, thread_id: str = "default"):
    return StreamingResponse(
        stream_investigation(query, thread_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
