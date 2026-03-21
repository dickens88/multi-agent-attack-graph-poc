import os
import json
from typing import Optional
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

_driver = None


def get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            os.environ["NEO4J_URI"],
            auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"])
        )
    return _driver


def get_node_by_ip(ip: str) -> str:
    """Look up a single IP node and return its properties.

    Use for: simple IP existence checks, single-node attribute lookups.
    Do NOT use for: multi-hop traversal, path tracing, or relationship queries.

    Returns JSON string with node properties, or a not-found message.
    """
    query = "MATCH (n:IP {ip: $ip}) RETURN n LIMIT 1"
    with get_driver().session() as session:
        result = session.run(query, {"ip": ip})
        records = [dict(r["n"]) for r in result]
        if not records:
            return json.dumps({"found": False, "ip": ip})
        return json.dumps({"found": True, "node": records[0]})


def run_cypher_query(query: str, params: Optional[dict] = None) -> str:
    """Execute a Cypher query against the attack graph database.

    Use for: any direct Cypher execution after query has been composed.
    The query must be a valid Cypher string — use nlp_to_cypher() first if
    starting from natural language.

    Returns JSON string with result rows, or error details on failure.
    Max 100 rows returned by default (add LIMIT in query to override).
    """
    if params is None:
        params = {}
    try:
        with get_driver().session() as session:
            result = session.run(query, params)
            rows = [dict(r) for r in result]
            return json.dumps({"status": "success", "rows": rows, "count": len(rows)})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "query": query})


def get_node_neighbors(ip: str, depth: int = 1, limit: int = 50) -> str:
    """Get neighboring nodes of an IP up to specified depth.

    Use for: understanding direct connections, initial recon before deep tracing.
    Do NOT use for: full attack chain reconstruction (use trace_attack_path instead).

    Args:
        ip: The IP address of the source node.
        depth: How many hops to expand (1-3 recommended).
        limit: Max neighbors to return.

    Returns JSON with neighbors and relationship types.
    """
    query = f"""
    MATCH (n:IP {{ip: $ip}})-[r*1..{depth}]-(neighbor)
    RETURN
        type(r[-1]) as rel_type,
        neighbor.ip as neighbor_ip,
        neighbor.hostname as neighbor_hostname,
        neighbor.risk_score as risk_score,
        r[-1].timestamp as timestamp
    LIMIT {limit}
    """
    with get_driver().session() as session:
        result = session.run(query, {"ip": ip})
        rows = [dict(r) for r in result]
        return json.dumps({"ip": ip, "depth": depth, "neighbors": rows})


def trace_attack_path(source_ip: str, max_hops: int = 5) -> str:
    """Trace complete attack propagation paths from a source IP.

    Use for: deep investigation tasks requiring full attack chain reconstruction.
    ONLY invoke this for investigation queries — not for simple lookups.
    Expensive operation: traverses up to max_hops relationship levels.

    Returns JSON with all discovered attack paths, hop counts, and node chains.
    """
    query = f"""
    MATCH path = (src:IP {{ip: $ip}})-[:ATTACKED|EXPLOITED|LATERAL_MOVE*1..{max_hops}]->(target)
    RETURN
        [n in nodes(path) | n.ip] as ip_chain,
        length(path) as hops,
        [r in relationships(path) | type(r)] as rel_types,
        [r in relationships(path) | r.timestamp] as timestamps
    ORDER BY hops DESC
    LIMIT 20
    """
    with get_driver().session() as session:
        result = session.run(query, {"ip": source_ip})
        paths = [dict(r) for r in result]
        return json.dumps({
            "source_ip": source_ip,
            "max_hops": max_hops,
            "paths_found": len(paths),
            "paths": paths
        })


def find_attacker_origin(ip: str) -> str:
    """Search for an Attacker node connected to this IP via ORIGIN_OF relationship.

    Use for: confirming whether an attack origin has been found in the graph.
    Returns attacker details if found, or null if no attacker node linked.
    """
    query = """
    MATCH (a:Attacker)-[:ORIGIN_OF]->(n:IP {ip: $ip})
    RETURN a.id as attacker_id, a.group as group, a.ttps as ttps
    LIMIT 1
    """
    with get_driver().session() as session:
        result = session.run(query, {"ip": ip})
        records = [dict(r) for r in result]
        if not records:
            return json.dumps({"found": False, "ip": ip})
        return json.dumps({"found": True, "attacker": records[0]})
