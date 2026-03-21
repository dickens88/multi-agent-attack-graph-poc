---
name: cypher-query-templates
description: Use this skill whenever you need to write or validate a Cypher query 
  against the attack graph. Provides verified query patterns for IP lookup, path 
  tracing, neighbor expansion, attacker attribution, and vulnerability correlation.
  Always consult before writing any Cypher query from scratch.
allowed-tools: read_file, run_cypher_query
---

# Cypher Query Templates

## Overview

This skill provides battle-tested Cypher templates for the attack graph database.
Always use these as the starting point — they encode correct node labels,
relationship types, index hints, and safe LIMIT clauses.

## When to use

- Before writing any new Cypher query
- When a previous query returned empty results (verify schema first)
- When unsure about relationship direction or property names

## Graph Schema Reference

**Node labels and key properties:**
- `(IP {ip: string, hostname: string, risk_score: float, first_seen: datetime})`
- `(Host {name: string, os: string, role: string})`
- `(Vulnerability {cve_id: string, severity: string, cvss: float})`
- `(Attacker {id: string, group: string, ttps: list})`

**Relationship types and directions:**
- `(Attacker)-[:ORIGIN_OF]->(IP)`
- `(IP)-[:ATTACKED {timestamp, method}]->(IP)`
- `(IP)-[:EXPLOITED {cve, timestamp}]->(Vulnerability)`
- `(IP)-[:LATERAL_MOVE {method, timestamp}]->(Host)`

## Instructions

### Step 1: Read the templates file
Use read_file to load: `skills/cypher-query/cypher_templates.py`

### Step 2: Select the matching template category

| Prefix | Use case |
|--------|----------|
| `LOOKUP_*` | Single node queries |
| `PATH_*` | Attack path traversal |
| `NEIGHBOR_*` | Neighbor expansion |
| `ATTR_*` | Attacker attribution |
| `VULN_*` | Vulnerability correlation |

### Step 3: Adapt and execute

Replace `<<PARAM>>` placeholders, then call `run_cypher_query()`.
If result is empty, re-check schema above before modifying the query.
