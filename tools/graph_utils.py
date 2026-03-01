"""Graph entity extraction utilities.

Scans Neo4j query result dicts and extracts graph nodes & edges
for the attack graph visualization.
"""

from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Node-type display config ────────────────────────────────────────────────

NODE_COLORS = {
    "Host":               "#00e5ff",
    "User":               "#b388ff",
    "IOC":                "#ff1744",
    "Alert":              "#ffab00",
    "Process":            "#39ff14",
    "Network_Connection": "#448aff",
    "File":               "#78909c",
    "Email":              "#ff6e40",
    "MITRE_Technique":    "#ea80fc",
    "Vulnerability":      "#ffd740",
}

NODE_ICONS = {
    "Host":               "🖥",
    "User":               "👤",
    "IOC":                "⚠",
    "Alert":              "🔔",
    "Process":            "⚙",
    "Network_Connection": "🌐",
    "File":               "📄",
    "Email":              "✉",
    "MITRE_Technique":    "🎯",
    "Vulnerability":      "🛡",
}


def _node_id(obj: dict) -> str | None:
    """Derive a stable identifier for a node dict."""
    return obj.get("id") or obj.get("name") or obj.get("value") or obj.get("ip")


def _node_label(obj: dict) -> str:
    """Pick a human-readable label for the node."""
    return (
        obj.get("name")
        or obj.get("id")
        or obj.get("value")
        or obj.get("ip")
        or "?"
    )


def _extract_node(obj: dict) -> dict | None:
    """Convert a Neo4j-style dict (with _labels) into a graph node."""
    labels = obj.get("_labels", [])
    if not labels:
        return None
    nid = _node_id(obj)
    if not nid:
        return None
    node_type = labels[0]
    return {
        "id": nid,
        "label": _node_label(obj),
        "type": node_type,
        "color": NODE_COLORS.get(node_type, "#90a4ae"),
        "icon": NODE_ICONS.get(node_type, "●"),
        "properties": {
            k: v for k, v in obj.items()
            if k not in ("_labels",) and not k.startswith("_")
        },
    }


def extract_node_ids(results: list[dict]) -> set[str]:
    """Scan result rows and return a set of all node IDs found."""
    ids: set[str] = set()
    for row in results:
        for val in row.values():
            if isinstance(val, dict) and "_labels" in val:
                nid = _node_id(val)
                if nid:
                    ids.add(nid)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and "_labels" in item:
                        nid = _node_id(item)
                        if nid:
                            ids.add(nid)
    return ids


def extract_graph_entities(results: list[dict]) -> dict:
    """Extract unique nodes and edges from a list of Neo4j result rows.

    Each row is a dict where values may be:
    - Node dicts: have '_labels' key
    - Scalars: strings, ints, etc.

    Edges are inferred from rows that have exactly two node-like objects
    and a 'rel_type' / '_type' key.

    Returns: {"nodes": [...], "edges": [...]}
    """
    nodes_map: dict[str, dict] = {}
    edges_set: set[tuple] = set()
    edges: list[dict] = []

    for row in results:
        # Collect all nodes in this row
        row_nodes: list[dict] = []
        rel_type = None

        for key, val in row.items():
            if not isinstance(val, dict):
                # Check for relationship type as a plain string
                if key in ("rel_type", "action", "relationship") and isinstance(val, str):
                    rel_type = val
                continue

            # Check if it's a node (has _labels)
            if "_labels" in val:
                node = _extract_node(val)
                if node and node["id"] not in nodes_map:
                    nodes_map[node["id"]] = node

                if node:
                    row_nodes.append(node)

            # Check if it's a relationship (has _type)
            elif "_type" in val:
                rel_type = val["_type"]

            # Could be a collected list — skip
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and "_labels" in item:
                        n = _extract_node(item)
                        if n and n["id"] not in nodes_map:
                            nodes_map[n["id"]] = n

        # Infer edge if we have two nodes and a relationship type
        if len(row_nodes) >= 2 and rel_type:
            src = row_nodes[0]
            tgt = row_nodes[1]
            edge_key = (src["id"], tgt["id"], rel_type)
            if edge_key not in edges_set:
                edges_set.add(edge_key)
                edges.append({
                    "source": src["id"],
                    "target": tgt["id"],
                    "type": rel_type,
                })
        elif len(row_nodes) == 2 and not rel_type:
            # Two nodes, no explicit rel — create a generic edge
            src = row_nodes[0]
            tgt = row_nodes[1]
            edge_key = (src["id"], tgt["id"], "RELATED")
            if edge_key not in edges_set:
                edges_set.add(edge_key)
                edges.append({
                    "source": src["id"],
                    "target": tgt["id"],
                    "type": "RELATED",
                })

    return {
        "nodes": list(nodes_map.values()),
        "edges": edges,
    }
