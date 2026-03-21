import json
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from orchestrator import orchestrator

app = FastAPI()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"


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


def extract_graph_data(tool_name: str, tool_result: str) -> dict | None:
    """Extract graph-renderable nodes/edges from selected tool results."""
    graph_tools = {
        "get_node_by_ip",
        "run_cypher_query",
        "get_node_neighbors",
        "trace_attack_path",
        "find_attacker_origin",
    }
    if tool_name not in graph_tools:
        return None

    try:
        data = json.loads(tool_result)
    except Exception:
        return None

    nodes, edges, highlight = [], [], []

    if tool_name == "get_node_by_ip" and data.get("found"):
        node = data["node"]
        nodes.append(
            {
                "id": node.get("ip"),
                "label": node.get("hostname") or node.get("ip"),
                "type": "IP",
                "risk_score": node.get("risk_score", 0),
                "properties": node,
            }
        )
        highlight = [node.get("ip")]

    elif tool_name == "get_node_neighbors":
        src_ip = data.get("ip")
        if src_ip:
            nodes.append({"id": src_ip, "label": src_ip, "type": "IP"})
        for neighbor in data.get("neighbors", []):
            nip = neighbor.get("neighbor_ip")
            if nip:
                nodes.append(
                    {
                        "id": nip,
                        "label": neighbor.get("neighbor_hostname") or nip,
                        "type": "IP",
                        "risk_score": neighbor.get("risk_score", 0),
                    }
                )
                edges.append(
                    {
                        "source": src_ip,
                        "target": nip,
                        "label": neighbor.get("rel_type", ""),
                        "timestamp": neighbor.get("timestamp"),
                    }
                )

    elif tool_name == "trace_attack_path":
        seen_nodes = set()
        for path in data.get("paths", []):
            chain = path.get("ip_chain", [])
            rel_types = path.get("rel_types", [])
            timestamps = path.get("timestamps", [])
            for i, ip in enumerate(chain):
                if ip and ip not in seen_nodes:
                    nodes.append({"id": ip, "label": ip, "type": "IP"})
                    seen_nodes.add(ip)
                if i > 0 and chain[i - 1] and ip:
                    edges.append(
                        {
                            "source": chain[i - 1],
                            "target": ip,
                            "label": rel_types[i - 1] if i - 1 < len(rel_types) else "",
                            "timestamp": timestamps[i - 1] if i - 1 < len(timestamps) else None,
                        }
                    )

    elif tool_name == "find_attacker_origin" and data.get("found"):
        attacker = data["attacker"]
        nodes.append(
            {
                "id": f"attacker:{attacker.get('attacker_id')}",
                "label": attacker.get("group") or attacker.get("attacker_id"),
                "type": "Attacker",
                "properties": attacker,
            }
        )
        highlight = [f"attacker:{attacker.get('attacker_id')}"]

    if not nodes and not edges:
        return None

    return {"nodes": nodes, "edges": edges, "highlight": highlight}


def _sse(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _extract_json_payload(raw_text: str) -> dict | None:
    text = raw_text.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Try extracting from markdown fenced block.
    if "```" in text:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                parsed = json.loads(text[start : end + 1])
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return None
    return None


def _persist_tracer_findings(result_str: str) -> tuple[str, str | None]:
    payload = _extract_json_payload(result_str)
    if not payload:
        return result_str, None

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    source_ip = str(payload.get("source_ip") or "unknown").replace("/", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"trace_{source_ip}_{ts}.json"
    file_path = ARTIFACTS_DIR / file_name
    payload["findings_file"] = f"/artifacts/{file_name}"
    file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(payload, ensure_ascii=False, indent=2), str(file_path)


def _persist_report_markdown(result_str: str) -> tuple[str, str | None]:
    text = result_str.strip()
    if not text:
        return result_str, None
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = ARTIFACTS_DIR / f"{ts}_investigation_report.md"
    file_path.write_text(text, encoding="utf-8")
    decorated = f"{text}\n\n\n---\nreport_file: artifacts/{file_path.name}"
    return decorated, str(file_path)


async def stream_investigation(user_query: str, thread_id: str):
    config = {"configurable": {"thread_id": thread_id}}

    active_subagents: dict[str, str] = {}
    pending_tool_calls: dict[str, dict] = {}
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
            yield _sse(
                "subagent_start",
                {
                    "type": "subagent_start",
                    "agent_name": agent_name,
                    "call_id": call_id,
                    "task_description": "",
                },
            )

        if hasattr(token, "tool_call_chunks") and token.tool_call_chunks:
            for tc in token.tool_call_chunks:
                tc_id = tc.get("id") or tc.get("index", "")
                name = tc.get("name", "")
                args_chunk = tc.get("args", "")

                if name:
                    pending_tool_calls[tc_id] = {"name": name, "args_buf": ""}

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
                    yield _sse(event_type, payload)

        elif token.type == "tool":
            tool_name = token.name or ""
            result_str = str(token.content)
            graph_data = extract_graph_data(tool_name, result_str)

            event_type = "subagent_tool_result" if is_subagent else "orchestrator_tool_result"
            payload = {
                "type": event_type,
                "tool": tool_name,
                "result": result_str[:500],
                "graph_data": graph_data,
            }
            if is_subagent:
                payload["call_id"] = call_id
            yield _sse(event_type, payload)

            if graph_data:
                yield _sse("graph_update", {"type": "graph_update", **graph_data})

        if token.type == "ai" and token.content:
            event_type = "subagent_token" if is_subagent else "orchestrator_token"
            payload = {"type": event_type, "content": token.content}
            if is_subagent:
                payload["call_id"] = call_id
                payload["agent_name"] = active_subagents.get(call_id, inferred_agent_name)
            yield _sse(event_type, payload)

        if not is_subagent and token.type == "tool":
            finished_call_id = getattr(token, "tool_call_id", None)
            if finished_call_id and finished_call_id in active_subagents:
                agent_name = active_subagents[finished_call_id]
                final_result = str(token.content)[:4000]
                persisted_file: str | None = None
                if agent_name == "tracer-agent":
                    final_result, persisted_file = _persist_tracer_findings(final_result)
                elif agent_name == "report-agent":
                    final_result, persisted_file = _persist_report_markdown(final_result)

                yield _sse(
                    "subagent_complete",
                    {
                        "type": "subagent_complete",
                        "call_id": finished_call_id,
                        "agent_name": agent_name,
                        "result": final_result,
                        "persisted_file": persisted_file,
                    },
                )
                del active_subagents[finished_call_id]

    async for chunk in orchestrator.astream(
        None,
        config=config,
        stream_mode="updates",
        subgraphs=False,
        version="v2",
    ):
        if chunk["type"] == "updates":
            for _, data in chunk["data"].items():
                todos = data.get("todos")
                if todos:
                    yield _sse("todos_update", {"type": "todos_update", "todos": todos})

    yield _sse("done", {"type": "done"})


@app.get("/api/investigate")
async def investigate(query: str, thread_id: str = "default"):
    return StreamingResponse(
        stream_investigation(query, thread_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
