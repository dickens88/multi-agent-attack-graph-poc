import os

from dotenv import load_dotenv

from common.llm_factory import build_chat_model
from common.logging_utils import get_logger

load_dotenv()

log = get_logger("lab.tools.analysis")


def nlp_to_cypher(natural_language_query: str, schema_hint: str = "") -> str:
    """Convert a natural language question into a Cypher query string.

    Use for: translating user questions into graph queries before execution.
    Always call this before run_cypher_query() when starting from natural language.
    Returns ONLY the Cypher query string — not the results.

    Args:
        natural_language_query: The user's question in plain language.
        schema_hint: Optional extra schema context to improve translation.
    """
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm = build_chat_model(model_name=model_name, temperature=0)

    schema = schema_hint or """
    Nodes: (IP {ip, hostname, risk_score, first_seen}),
           (Host {name, os, role}),
           (Vulnerability {cve_id, severity, cvss}),
           (Attacker {id, group, ttps})
    Relationships:
           (Attacker)-[:ORIGIN_OF]->(IP),
           (IP)-[:ATTACKED {timestamp, method}]->(IP),
           (IP)-[:EXPLOITED {cve, timestamp}]->(Vulnerability),
           (IP)-[:LATERAL_MOVE {method, timestamp}]->(Host)
    """

    prompt = f"""Convert this question to a Neo4j Cypher query for an attack graph.

Schema:
{schema}

Rules:
- Always add LIMIT (max 100)
- Use correct label and relationship names from schema only
- Return only the Cypher query, no markdown, no explanation

Question: {natural_language_query}"""

    log.info(f"tool_start tool=nlp_to_cypher question_len={len(natural_language_query or '')} schema_hint_len={len(schema_hint or '')}")

    import time

    t0 = time.perf_counter()
    out = llm.invoke(prompt).content.strip()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    log.info(f"tool_end tool=nlp_to_cypher status=success elapsed_ms={elapsed_ms:.2f} cypher_len={len(out)}")
    return out


def evaluate_termination(
    iteration: int,
    nodes_this_iteration: list,
    nodes_previous_iteration: list,
    attacker_found: bool,
    paths: list,
) -> dict:
    """Programmatic pre-check for termination conditions.

    Use BEFORE loading the termination_rules.md skill — this provides
    a fast structural check. The skill provides semantic evaluation.

    Returns dict with should_stop (bool) and reason (str).
    """
    _ = paths

    max_iterations_raw = os.getenv("MAX_ITERATIONS", "8")
    try:
        max_iterations = int(max_iterations_raw)
    except ValueError:
        max_iterations = 8

    if iteration >= max_iterations:
        return {"should_stop": True, "reason": "STOP-3", "confidence": "depends"}

    if attacker_found:
        return {"should_stop": True, "reason": "STOP-1", "confidence": "high"}

    new_nodes = set(str(n) for n in nodes_this_iteration) - set(str(n) for n in nodes_previous_iteration)
    if iteration > 0 and len(new_nodes) == 0:
        return {"should_stop": True, "reason": "STOP-2", "confidence": "medium"}

    return {"should_stop": False, "reason": "new_nodes_found", "confidence": None}


