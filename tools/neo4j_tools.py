"""Neo4j interaction tools — execute Cypher, get schema, validate queries."""

from __future__ import annotations
import re
import time
import logging
from typing import Any

from neo4j import GraphDatabase
from config import settings

logger = logging.getLogger(__name__)

# ── Dangerous Cypher keywords that must NEVER appear in generated queries ──
_WRITE_KEYWORDS = re.compile(
    r"\b(CREATE|DELETE|DETACH|SET|REMOVE|MERGE|DROP|CALL\s*\{)\b",
    re.IGNORECASE,
)


class Neo4jClient:
    """Thin wrapper around the Neo4j Python driver with safety guardrails."""

    def __init__(self):
        self._driver = None

    # ── Connection ──────────────────────────────────────────────────────────

    def connect(self):
        """Lazily connect to Neo4j."""
        if self._driver is None:
            self._driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            logger.info("Connected to Neo4j at %s", settings.NEO4J_URI)

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    # ── Schema Discovery ────────────────────────────────────────────────────

    def get_schema(self) -> str:
        """Return a human-readable description of the graph schema.

        This feeds into the LLM prompt so it knows what nodes / rels / props
        are available when generating Cypher.
        """
        self.connect()
        with self._driver.session() as session:
            # Node labels + properties
            node_info = session.run(
                "CALL db.schema.nodeTypeProperties() "
                "YIELD nodeType, propertyName, propertyTypes "
                "RETURN nodeType, collect({name: propertyName, types: propertyTypes}) AS properties"
            ).data()

            # Relationship types + properties
            rel_info = session.run(
                "CALL db.schema.relTypeProperties() "
                "YIELD relType, propertyName, propertyTypes "
                "RETURN relType, collect({name: propertyName, types: propertyTypes}) AS properties"
            ).data()

        lines: list[str] = ["=== Graph Database Schema ===", "", "-- Node Labels --"]
        for row in node_info:
            props = ", ".join(
                f"{p['name']}({'/'.join(p['types'])})" for p in row["properties"] if p["name"]
            )
            lines.append(f"  {row['nodeType']}: [{props}]")

        lines += ["", "-- Relationship Types --"]
        for row in rel_info:
            props = ", ".join(
                f"{p['name']}({'/'.join(p['types'])})" for p in row["properties"] if p["name"]
            )
            lines.append(f"  {row['relType']}: [{props}]")

        return "\n".join(lines)

    # ── Cypher Validation ───────────────────────────────────────────────────

    @staticmethod
    def validate_cypher(query: str) -> tuple[bool, str]:
        """Validate that a Cypher query is read-only and safe to execute.

        Returns (is_valid, reason).
        """
        match = _WRITE_KEYWORDS.search(query)
        if match:
            return False, f"Write keyword detected: {match.group()}"
        return True, "OK"

    # ── Query Execution ─────────────────────────────────────────────────────

    def execute_cypher(
        self, query: str, params: dict[str, Any] | None = None
    ) -> list[dict]:
        """Execute a READ-ONLY Cypher query with parameter binding.

        Raises ValueError when validation fails.
        """
        is_valid, reason = self.validate_cypher(query)
        if not is_valid:
            raise ValueError(f"Cypher validation failed: {reason}")

        self.connect()
        t0 = time.time()
        with self._driver.session() as session:
            result = session.run(query, parameters=params or {})
            records = []
            for record in result:
                row = {}
                for key in record.keys():
                    val = record[key]
                    # Convert Neo4j Node / Relationship objects to plain dicts
                    if hasattr(val, "items"):  # Node
                        row[key] = dict(val.items())
                        row[key]["_labels"] = list(val.labels) if hasattr(val, "labels") else []
                    elif hasattr(val, "type"):  # Relationship
                        row[key] = {
                            "_type": val.type,
                            **dict(val.items()),
                        }
                    else:
                        row[key] = val
                records.append(row)
        elapsed = time.time() - t0
        logger.info("Cypher executed in %.3fs → %d records | %s", elapsed, len(records), query[:120])
        return records


# ── Singleton ────────────────────────────────────────────────────────────────
neo4j_client = Neo4jClient()
