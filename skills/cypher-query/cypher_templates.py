"""Pre-defined Cypher query templates for common security investigation patterns.

These templates are parameterized and safe-by-construction.  The Retriever
agent picks the best template when possible and falls back to LLM-generated
Cypher only for ad-hoc requests.
"""

from __future__ import annotations

# Each template is a dict with:
#   name        – human-readable identifier
#   description – when to use this template
#   cypher      – parameterized Cypher string ($param style)
#   params      – list of parameter names the caller must fill

TEMPLATES: list[dict] = [
    # ── Find Host by IP ─────────────────────────────────────────────────────
    {
        "name": "find_host_by_ip",
        "description": "Find a host by its IP address and return it along with all directly connected entities.",
        "cypher": (
            "MATCH (h:Host {ip: $ip})-[r]-(m) "
            "RETURN h, type(r) AS rel_type, labels(m) AS target_labels, m "
            "LIMIT 50"
        ),
        "params": ["ip"],
    },
    # ── Neighborhood Exploration ────────────────────────────────────────────
    {
        "name": "get_node_neighbors",
        "description": "Retrieve all direct neighbors of a given node by its id, regardless of relationship type.",
        "cypher": (
            "MATCH (n {id: $node_id})-[r]-(m) "
            "RETURN n, type(r) AS rel_type, r, m "
            "LIMIT 50"
        ),
        "params": ["node_id"],
    },
    # ── Alert / Event Queries ───────────────────────────────────────────────
    {
        "name": "alerts_for_host_ip",
        "description": "Get all alerts/events triggered by a host with a given IP address.",
        "cypher": (
            "MATCH (h:Host {ip: $ip})-[:TRIGGERED]->(a:Alert) "
            "RETURN h, a ORDER BY a.timestamp DESC LIMIT 50"
        ),
        "params": ["ip"],
    },
    {
        "name": "alerts_for_entity",
        "description": "Get all alerts/events connected to a specific entity by its id.",
        "cypher": (
            "MATCH (entity {id: $entity_id})-[r]-(a:Alert) "
            "RETURN a ORDER BY a.timestamp DESC LIMIT 50"
        ),
        "params": ["entity_id"],
    },

    # ── Host Process Activity ───────────────────────────────────────────────
    {
        "name": "processes_on_host",
        "description": "Get all processes running on a host identified by IP address, with their spawn chain.",
        "cypher": (
            "MATCH (p:Process)-[:RUNS_ON]->(h:Host {ip: $ip}) "
            "OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
            "RETURN p, parent, h "
            "ORDER BY p.timestamp LIMIT 50"
        ),
        "params": ["ip"],
    },
    # ── Path & Traversal ────────────────────────────────────────────────────
    {
        "name": "shortest_path",
        "description": "Find the shortest path between two entities by their ids.",
        "cypher": (
            "MATCH (a {id: $source_id}), (b {id: $target_id}), "
            "p = shortestPath((a)-[*..10]-(b)) "
            "RETURN p"
        ),
        "params": ["source_id", "target_id"],
    },
    {
        "name": "attack_chain",
        "description": "Trace a process spawn chain from a starting process following the SPAWNED relationships.",
        "cypher": (
            "MATCH path = (start:Process {id: $start_id})-[:SPAWNED*1..8]->(descendant) "
            "RETURN path "
            "ORDER BY length(path) "
            "LIMIT 20"
        ),
        "params": ["start_id"],
    },
    # ── Lateral Movement ────────────────────────────────────────────────────
    {
        "name": "lateral_movement",
        "description": "Find hosts that a compromised host connected to (lateral movement detection). Use the host id.",
        "cypher": (
            "MATCH (src:Host {id: $host_id})-[:CONNECTED_TO]->(dst:Host) "
            "RETURN src, dst "
            "LIMIT 50"
        ),
        "params": ["host_id"],
    },
    {
        "name": "lateral_movement_by_ip",
        "description": "Find hosts that a compromised host connected to by IP address.",
        "cypher": (
            "MATCH (src:Host {ip: $ip})-[:CONNECTED_TO]->(dst:Host) "
            "RETURN src.name AS source, src.ip AS source_ip, dst.name AS target, dst.ip AS target_ip "
            "LIMIT 50"
        ),
        "params": ["ip"],
    },
    # ── Network Connections ─────────────────────────────────────────────────
    {
        "name": "network_connections_for_host",
        "description": "Get all network connections initiated by a host (by IP), including external IPs contacted.",
        "cypher": (
            "MATCH (h:Host {ip: $ip})-[:INITIATED]->(nc:Network_Connection) "
            "OPTIONAL MATCH (nc)-[:CONNECTS_TO]->(ioc:IOC) "
            "RETURN nc, ioc "
            "ORDER BY nc.timestamp LIMIT 50"
        ),
        "params": ["ip"],
    },
    # ── IOC Correlation ─────────────────────────────────────────────────────
    {
        "name": "ioc_connections",
        "description": "Find all entities connected to a specific IOC by its value (IP address, hash, domain).",
        "cypher": (
            "MATCH (ioc:IOC {value: $ioc_value})-[r]-(entity) "
            "RETURN ioc, type(r) AS rel_type, entity "
            "LIMIT 50"
        ),
        "params": ["ioc_value"],
    },
    {
        "name": "iocs_for_host",
        "description": "Find all Indicators of Compromise (IOCs) directly or indirectly connected to a specific host by its IP. Up to 2 hops.",
        "cypher": (
            "MATCH (h:Host {ip: $ip})-[*1..2]-(ioc:IOC) "
            "RETURN DISTINCT h, ioc "
            "LIMIT 50"
        ),
        "params": ["ip"],
    },
    # ── Process Tree ────────────────────────────────────────────────────────
    {
        "name": "process_tree",
        "description": "Retrieve the full process tree (parent/child chain) for a given process by id.",
        "cypher": (
            "MATCH path=(root)-[:SPAWNED*]->(target:Process {id: $process_id}) "
            "RETURN path "
            "LIMIT 10"
        ),
        "params": ["process_id"],
    },
    # ── User Activity ───────────────────────────────────────────────────────
    {
        "name": "user_activity",
        "description": "Get all activity (logons, process execution) by a user identified by their id.",
        "cypher": (
            "MATCH (u:User {id: $user_id})-[r]->(target) "
            "RETURN u, type(r) AS action, target "
            "ORDER BY r.timestamp DESC LIMIT 50"
        ),
        "params": ["user_id"],
    },
    # ── Full Attack Path from Host IP ───────────────────────────────────────
    {
        "name": "full_host_investigation",
        "description": "Get a comprehensive view of a host: alerts, processes, network connections, and lateral movement. Use this as a first step.",
        "cypher": (
            "MATCH (h:Host {ip: $ip}) "
            "OPTIONAL MATCH (h)-[:TRIGGERED]->(a:Alert) "
            "OPTIONAL MATCH (p:Process)-[:RUNS_ON]->(h) "
            "OPTIONAL MATCH (h)-[:INITIATED]->(nc:Network_Connection) "
            "OPTIONAL MATCH (h)-[:CONNECTED_TO]->(dst:Host) "
            "RETURN h, collect(DISTINCT a) AS alerts, "
            "collect(DISTINCT p) AS processes, "
            "collect(DISTINCT nc) AS connections, "
            "collect(DISTINCT dst) AS lateral_targets "
            "LIMIT 1"
        ),
        "params": ["ip"],
    },
]


def get_template_descriptions() -> str:
    """Return a formatted string of all available templates for the LLM."""
    lines = []
    for i, t in enumerate(TEMPLATES, 1):
        params = ', '.join(t['params']) if t['params'] else '(none)'
        lines.append(f"{i}. **{t['name']}** — {t['description']}")
        lines.append(f"   Params: {params}")
    return "\n".join(lines)
