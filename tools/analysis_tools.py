import json
import os
from pathlib import Path

from dotenv import load_dotenv

from agent_logging import truncate_text
from llm_factory import build_chat_model
from logging_config import get_logger

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

    log.info("nlp_to_cypher model=%s", model_name)
    log.debug("nlp_to_cypher question=%s", truncate_text(natural_language_query, 600))
    out = llm.invoke(prompt).content.strip()
    log.debug("nlp_to_cypher cypher=%s", truncate_text(out, 800))
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


def write_text_file(path: str, content: str) -> str:
    """Write UTF-8 text to a file and create parent directories automatically.

    Use for: persisting tracer findings and final markdown reports to disk.
    Path can be absolute or relative to current working directory.

    Returns JSON string with success flag and absolute file path.
    """
    try:
        file_path = Path(path).expanduser()
        if not file_path.is_absolute():
            file_path = Path.cwd() / file_path

        file_path.parent.mkdir(parents=True, exist_ok=True)
        nbytes = len(content.encode("utf-8"))
        file_path.write_text(content, encoding="utf-8")
        log.info("write_text_file path=%s bytes=%s", file_path.resolve(), nbytes)

        return json.dumps(
            {
                "status": "success",
                "path": str(file_path.resolve()),
                "bytes": nbytes,
            },
            ensure_ascii=False,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "path": path}, ensure_ascii=False)


def read_text_file(path: str) -> str:
    """Read UTF-8 text from a file.

    Use for: loading persisted investigation findings and previously generated reports.

    Returns JSON string with file content and metadata.
    """
    try:
        file_path = Path(path).expanduser()
        if not file_path.is_absolute():
            file_path = Path.cwd() / file_path

        if not file_path.exists():
            return json.dumps({"status": "error", "error": "file_not_found", "path": str(file_path)}, ensure_ascii=False)

        content = file_path.read_text(encoding="utf-8")
        log.info(
            "read_text_file path=%s chars=%s",
            file_path.resolve(),
            len(content),
        )
        return json.dumps(
            {
                "status": "success",
                "path": str(file_path.resolve()),
                "content": content,
                "chars": len(content),
            },
            ensure_ascii=False,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "path": path}, ensure_ascii=False)
