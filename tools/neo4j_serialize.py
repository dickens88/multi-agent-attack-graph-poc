import json


def serialize_neo4j_value(val):
    """Recursively serialize Neo4j driver objects to plain Python types."""
    if hasattr(val, "labels") and hasattr(val, "items"):  # Node
        d = {k: serialize_neo4j_value(v) for k, v in dict(val.items()).items()}
        d["_labels"] = list(val.labels)
        return d
    if hasattr(val, "type") and hasattr(val, "items") and not isinstance(val, dict):  # Relationship
        d = {k: serialize_neo4j_value(v) for k, v in dict(val.items()).items()}
        d["_type"] = val.type
        try:
            d["_start"] = val.start_node.get("id") or val.start_node.get("ip") or str(val.start_node.id)
            d["_end"] = val.end_node.get("id") or val.end_node.get("ip") or str(val.end_node.id)
        except Exception:
            pass
        return d
    if hasattr(val, "nodes") and hasattr(val, "relationships"):  # Path
        return {
            "nodes": [serialize_neo4j_value(n) for n in val.nodes],
            "relationships": [serialize_neo4j_value(r) for r in val.relationships],
        }
    if isinstance(val, list):
        return [serialize_neo4j_value(v) for v in val]
    if isinstance(val, dict):
        return {k: serialize_neo4j_value(v) for k, v in val.items()}
    try:
        json.dumps(val)
        return val
    except (TypeError, ValueError):
        return str(val)
