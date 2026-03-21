---
name: graph-schema-reference
description: Quick reference for the attack graph Neo4j schema. Load this skill 
  when unsure about node labels, relationship types, property names, or index 
  availability. Use before writing any Cypher query if schema details are uncertain.
allowed-tools: read_file
---

# Attack Graph Schema Reference

## Node Labels

| Label | Key Properties | Indexed |
|-------|---------------|---------|
| `IP` | `ip` (string), `hostname`, `risk_score` (float 0-1), `first_seen` (datetime) | `ip` |
| `Host` | `name` (string), `os`, `role` | `name` |
| `Vulnerability` | `cve_id` (string), `severity` (LOW/MEDIUM/HIGH/CRITICAL), `cvss` (float) | `cve_id` |
| `Attacker` | `id` (string), `group`, `ttps` (list of strings) | `id` |

## Relationship Types

| Relationship | Direction | Key Properties |
|-------------|-----------|---------------|
| `ATTACKED` | `(IP)->(IP)` | `timestamp` (datetime), `method` (string) |
| `EXPLOITED` | `(IP)->(Vulnerability)` | `timestamp`, `cve` (string) |
| `LATERAL_MOVE` | `(IP)->(Host)` | `timestamp`, `method` |
| `ORIGIN_OF` | `(Attacker)->(IP)` | — |

## Common Mistakes to Avoid

- `ATTACKED` is directional: attacker → victim (not bidirectional)
- `ORIGIN_OF` goes FROM Attacker TO IP (not the other way)
- `risk_score` is 0.0–1.0 float, not integer percentage
- Always add `LIMIT` to prevent full graph scans
- Use `datetime()` for timestamp comparisons, not string comparison

## Available Indexes

- `:IP(ip)` — use for single IP lookups
- `:Attacker(id)` — use for attacker lookups
- `:Vulnerability(cve_id)` — use for CVE lookups
