import json
import logging
import os
import time
from typing import Optional

from dotenv import load_dotenv
from neo4j import GraphDatabase

from logging_config import get_logger

load_dotenv()

log = get_logger("lab.tools.graph")

_driver = None


def get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            os.environ["NEO4J_URI"],
            auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"])
        )
    return _driver


def _serialize_value(val):
    """Recursively serialize Neo4j driver objects to plain Python types."""
    if hasattr(val, "labels") and hasattr(val, "items"):  # Node
        d = {k: _serialize_value(v) for k, v in dict(val.items()).items()}
        d["_labels"] = list(val.labels)
        return d
    if hasattr(val, "type") and hasattr(val, "items") and not isinstance(val, dict):  # Relationship
        d = {k: _serialize_value(v) for k, v in dict(val.items()).items()}
        d["_type"] = val.type
        try:
            d["_start"] = (val.start_node.get("id") or val.start_node.get("ip")
                           or str(val.start_node.id))
            d["_end"] = (val.end_node.get("id") or val.end_node.get("ip")
                         or str(val.end_node.id))
        except Exception:
            pass
        return d
    if hasattr(val, "nodes") and hasattr(val, "relationships"):  # Path
        return {
            "nodes": [_serialize_value(n) for n in val.nodes],
            "relationships": [_serialize_value(r) for r in val.relationships],
        }
    if isinstance(val, list):
        return [_serialize_value(v) for v in val]
    if isinstance(val, dict):
        return {k: _serialize_value(v) for k, v in val.items()}
    try:
        json.dumps(val)
        return val
    except (TypeError, ValueError):
        return str(val)


def _run(query: str, params: dict) -> list[dict]:
    """Execute a query and return fully serialized rows."""
    log.debug(
        "cypher_execute preview=%s param_keys=%s",
        query[:500] + ("…" if len(query) > 500 else ""),
        list(params.keys()),
    )
    t0 = time.perf_counter()
    with get_driver().session() as session:
        result = session.run(query, params)
        rows = [
            {key: _serialize_value(record[key]) for key in record.keys()}
            for record in result
        ]
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    log.info("cypher_done rows=%s elapsed_ms=%.2f", len(rows), elapsed_ms)
    return rows


# ── Public tools ────────────────────────────────────────────────────────────

def get_node_by_id(node_id: str, reason: str = "", label: str = "") -> str:
    """Look up any graph entity by its id and return its full properties plus
    all directly connected neighbors and relationships.

    This is the primary lookup tool. Use it for any entity type:
    Host (id = hostname e.g. 'DC01'), User (id = username e.g. 'u_jchen'),
    Process (e.g. 'proc_payload_01'), Alert, IOC, File, Email,
    Network_Connection, MITRE_Technique, Vulnerability.

    For Host nodes you may also pass an IP address — the query will match on
    both the id and ip properties.

    Args:
        node_id: The entity's id value, name, username, or IP address.
        reason:  Required. Explain in Chinese WHY you are calling this tool:
                 what clue led you here, what node type you expect, and what
                 you hope to learn from the result.
                 Example: "DC01触发了RDP暴力破解告警，查询其邻居以确认
                 是否有账号被成功利用，重点关注关联的User和Alert节点。"
        label:   Optional node label to narrow the search (e.g. 'Host', 'User').
                 Leave empty to search across all labels.

    Returns JSON: {found, node_type, node, neighbors: [{id, type, label, rel_type, rel_props}]}
    """
    label_clause = f":{label}" if label else ""

    # Try id first, then ip, then name/username as fallback
    query = f"""
    MATCH (n{label_clause})
    WHERE n.id = $val OR n.ip = $val OR n.name = $val OR n.username = $val
    WITH n LIMIT 1
    OPTIONAL MATCH (n)-[r]-(m)
    RETURN n, labels(n) AS lbls,
           collect({{
               neighbor_id:   coalesce(m.id, m.ip, m.name, m.value, ''),
               neighbor_type: labels(m)[0],
               neighbor_props: m,
               rel_type:      type(r),
               rel_direction: CASE WHEN startNode(r) = n THEN 'out' ELSE 'in' END,
               rel_props:     r
           }}) AS neighbors
    """
    rows = _run(query, {"val": node_id})

    if not rows or rows[0].get("n") is None:
        return json.dumps({"found": False, "node_id": node_id})

    row = rows[0]
    node_obj = row["n"]
    lbls = row.get("lbls") or []
    node_type = lbls[0] if lbls else "Unknown"

    # Clean up neighbor list: remove nulls from OPTIONAL MATCH with no match
    neighbors = [
        nb for nb in (row.get("neighbors") or [])
        if nb.get("neighbor_id") or nb.get("rel_type")
    ]

    return json.dumps({
        "found": True,
        "node_type": node_type,
        "node": node_obj,
        "neighbors": neighbors,
    })


def get_node_neighbors(node_id: str, reason: str = "", depth: int = 1, limit: int = 50) -> str:
    """Get all entities connected to a node within the given hop depth.

    Matches by id, ip, name, or username — no need to know the node label.
    Returns full node objects for all neighbors so the graph panel can render them.

    Args:
        node_id: The entity's id, ip, name, or username.
        reason:  Required. Explain in Chinese why you are expanding this node:
                 what you already know about it and what relationships you
                 expect to find.
        depth:   How many hops to expand (1–3 recommended, max 5).
        limit:   Max neighbors to return (default 50).

    Returns JSON: {node_id, depth, neighbors: [{n, rel_type, m}]}
    """
    query = f"""
    MATCH (n)
    WHERE n.id = $val OR n.ip = $val OR n.name = $val OR n.username = $val
    WITH n LIMIT 1
    MATCH (n)-[r*1..{depth}]-(m)
    RETURN n, type(r[-1]) AS rel_type, r[-1] AS rel, m
    LIMIT {limit}
    """
    rows = _run(query, {"val": node_id})
    return json.dumps({"node_id": node_id, "depth": depth, "neighbors": rows})


def trace_attack_path(node_id: str, reason: str = "", max_hops: int = 6) -> str:
    """Trace attack propagation and lateral movement paths from a starting entity.

    Follows CONNECTED_TO, SPAWNED, EXECUTED, INITIATED, ESTABLISHED, TRIGGERED,
    MATCHES_IOC, HAS_VULNERABILITY, DELIVERS_TO, RUNS_ON relationships.
    Works with any entity type — Host, User, Process, Network_Connection, etc.

    Args:
        node_id:   The starting entity's id, ip, name, or username.
        reason:    Required. Explain in Chinese what attack pattern you are
                   tracing, why this node is the starting point, and what
                   path you expect to find.
        max_hops:  Maximum relationship hops to traverse (default 6).

    Returns JSON: {node_id, paths_found, paths: [{nodes, relationships, length}]}
    """
    query = f"""
    MATCH (src)
    WHERE src.id = $val OR src.ip = $val OR src.name = $val OR src.username = $val
    WITH src LIMIT 1
    MATCH path = (src)-[*1..{max_hops}]-(target)
    WHERE target <> src
    RETURN
        [n IN nodes(path) | {{
            id:    coalesce(n.id, n.ip, n.name, ''),
            type:  labels(n)[0],
            props: n
        }}] AS path_nodes,
        [r IN relationships(path) | {{
            type:  type(r),
            props: r
        }}] AS path_rels,
        length(path) AS hops
    ORDER BY hops ASC
    LIMIT 20
    """
    rows = _run(query, {"val": node_id})
    return json.dumps({
        "node_id": node_id,
        "max_hops": max_hops,
        "paths_found": len(rows),
        "paths": rows,
    })


def run_cypher_query(query: str, reason: str = "", params: Optional[dict] = None) -> str:
    """Execute a read-only Cypher query and return fully serialized results.

    Node objects in the result include _labels and all properties.
    Relationship objects include _type, _start, _end and all properties.
    Use this for any query that cannot be expressed with the other tools.

    Args:
        query:   The Cypher query string.
        reason:  Required. Explain in Chinese what information you need,
                 why the other tools are insufficient, and what result
                 you expect from this query.
        params:  Optional parameter dict for the query.

    Rules: only MATCH/RETURN queries; always include LIMIT; max 100 rows.

    Returns JSON: {status, rows, count} or {status, error, query}
    """
    if params is None:
        params = {}
    try:
        rows = _run(query, params)
        return json.dumps({"status": "success", "rows": rows, "count": len(rows)})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "query": query})


def get_live_schema() -> str:
    """Query Neo4j for the current graph schema.

    Returns a human-readable string covering all node labels with their
    properties, all relationship types with their properties, and the
    relationship patterns showing which node types connect to which.
    This is the authoritative schema source — always prefer it over any
    static schema file.
    """
    try:
        with get_driver().session() as session:
            node_rows = session.run(
                "CALL db.schema.nodeTypeProperties() "
                "YIELD nodeType, propertyName, propertyTypes "
                "RETURN nodeType, collect({name: propertyName, types: propertyTypes}) AS properties"
            ).data()

            rel_rows = session.run(
                "CALL db.schema.relTypeProperties() "
                "YIELD relType, propertyName, propertyTypes "
                "RETURN relType, collect({name: propertyName, types: propertyTypes}) AS properties"
            ).data()

            try:
                pattern_data = session.run(
                    "CALL db.schema.visualization() YIELD nodes, relationships "
                    "RETURN nodes, relationships"
                ).data()
                patterns = pattern_data[0]["relationships"] if pattern_data else []
            except Exception:
                patterns = []

        lines = ["=== Live Graph Schema (from Neo4j) ===", "", "-- Node Labels & Properties --"]
        for row in node_rows:
            props = ", ".join(
                f"{p['name']}({'|'.join(p['types'])})"
                for p in row["properties"] if p.get("name")
            )
            label = row["nodeType"].strip(":` ")
            lines.append(f"  {label}:  id(string, unique key)  {props}")

        lines += ["", "-- Relationship Types & Properties --"]
        for row in rel_rows:
            props = ", ".join(
                f"{p['name']}({'|'.join(p['types'])})"
                for p in row["properties"] if p.get("name")
            )
            rel = row["relType"].strip(":` ")
            lines.append(f"  {rel}:  {props}" if props else f"  {rel}")

        if patterns:
            lines += ["", "-- Relationship Patterns --"]
            for p in patterns:
                try:
                    start = p.get("startNodeLabels", ["?"])[0]
                    end = p.get("endNodeLabels", ["?"])[0]
                    rel_type = p.get("relationshipType", "?")
                    lines.append(f"  ({start})-[:{rel_type}]->({end})")
                except Exception:
                    continue

        return "\n".join(lines)

    except Exception as e:
        return f"(Schema query failed: {e})"
