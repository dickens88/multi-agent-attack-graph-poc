"""Analyzer Agent — examines query results, extracts findings, decides if more data is needed.

Handles batch results from parallel query execution.
"""

import json

from langchain_core.messages import SystemMessage, HumanMessage

from logging_config import get_logger

from state.investigation_state import InvestigationState
from llm_factory import get_llm
from tools.json_utils import extract_json, DEFAULT_REQUIRED_FIELDS
from config import settings

logger = get_logger(__name__)

SYSTEM_PROMPT = """\
You are the **Analyzer** of a security incident investigation system.

Your job is to analyze the LATEST batch of query results in the context of the overall investigation.

## Investigation Context
- **Goal**: {investigation_goal}
- **Type**: {investigation_type}

## Latest Queries (this iteration)
{queries_section}

## Previous Evidence
{previous_evidence}

## Instructions
1. Analyze ALL new results together: what patterns, anomalies, or relationships do you see?
2. Cross-correlate findings across the different queries — look for connections between results.
3. Extract key findings as structured evidence items.
4. Assess how these findings contribute to answering the investigation goal.

## Output Format (strict JSON - MANDATORY)
CRITICAL: Your response must be VALID JSON that can be parsed by json.loads().
- Start your response with opening brace and end with closing brace
- Do NOT wrap in markdown code fences (no triple backticks)
- Do NOT include any text before or after the JSON
- All string values must be properly quoted
- Do NOT use single quotes
- Ensure all brackets and braces are matched

Required schema:
```json
{{
  "analysis": "<your analysis narrative>",
  "new_evidence": [
    {{
      "finding": "<concise finding>",
      "confidence": 0.0-1.0,
      "entities_involved": ["entity_id1", ...]
    }}
  ],
  "gaps": "<what information is still missing>"
}}
```
"""


def analyzer_node(state: InvestigationState) -> dict:
    """LangGraph node: Analyzer."""
    llm = get_llm(
        deep_thinking=state.get("deep_thinking", False),
        temperature=settings.TEMPERATURE,
    )

    all_queries = state.get("queries_executed", [])
    iteration = state.get("iteration_count", 0)

    prev_evidence = state.get("evidence_collected", [])
    prev_query_descriptions = {e.get("source_query", "") for e in prev_evidence}

    # Find queries not yet analyzed
    new_queries = []
    for q in all_queries:
        desc = q.get("description", "")
        if desc not in prev_query_descriptions:
            new_queries.append(q)

    if not new_queries:
        new_queries = all_queries[-1:] if all_queries else []

    # Build queries section for prompt
    queries_parts = []
    for i, q in enumerate(new_queries, 1):
        results = q.get("results", [])[:15]
        results_str = json.dumps(results, ensure_ascii=False, default=str)
        if len(results) > 15:
            results_str += "\n... (truncated)"
        queries_parts.append(
            f"### Query {i}: {q.get('description', 'N/A')}\n"
            f"**Results**: {results_str}"
        )
    queries_section = "\n\n".join(queries_parts) if queries_parts else "(no new queries)"

    prev_summary = "\n".join(
        f"- [{e.get('confidence', '?')}] {e['finding']}" for e in prev_evidence
    ) or "(none)"

    prompt = SYSTEM_PROMPT.format(
        investigation_goal=state.get("investigation_goal", ""),
        investigation_type=state.get("investigation_type", ""),
        queries_section=queries_section,
        previous_evidence=prev_summary,
    )

    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content="Analyze all the results and provide your findings."),
    ]

    response = llm.invoke(messages)
    raw = response.content.strip()

    try:
        result = extract_json(raw, required_fields=DEFAULT_REQUIRED_FIELDS["analyzer"])
    except ValueError as e:
        logger.warning("Analyzer produced invalid JSON. Raw: %s", raw)
        result = {
            "analysis": raw,
            "new_evidence": [],
            "gaps": "Parse error — could not extract structured findings.",
        }

    new_evidence_raw = result.get("new_evidence", [])
    new_evidence = []
    source_queries = ", ".join(q.get("description", "") for q in new_queries)
    for e in new_evidence_raw:
        new_evidence.append({
            "source_query": source_queries,
            "finding": e.get("finding", ""),
            "confidence": e.get("confidence", 0.5),
            "entities_involved": e.get("entities_involved", []),
        })

    analysis = result.get("analysis", "")
    gaps = result.get("gaps", "")

    logger.info(
        "Analyzer found %d new evidence items from %d queries",
        len(new_evidence), len(new_queries),
    )

    queries_label = f" ({len(new_queries)} queries)" if len(new_queries) > 1 else ""

    return {
        "evidence_collected": new_evidence,
        "analysis_gaps": gaps,
        "agent_messages": [
            {
                "agent": "Analyzer",
                "action": f"Analysis Complete{queries_label}",
                "content": (
                    f"**Analysis**: {analysis}\n\n"
                    f"**New Findings**: {len(new_evidence)} item(s)\n\n"
                    f"**Gaps**: {gaps}"
                ),
                "iteration": iteration,
            }
        ],
    }
