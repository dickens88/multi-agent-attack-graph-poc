"""Planner Agent — the ReAct brain that decides what to investigate next.

Supports generating 1-3 parallel query actions per iteration for efficiency.
"""

from __future__ import annotations
import json
import logging

from langchain_core.messages import SystemMessage, HumanMessage

from state.investigation_state import InvestigationState
from llm_factory import get_llm
from config import settings
from tools.cypher_templates import get_template_descriptions
from tools.json_utils import extract_json

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the **Planner** of a security incident investigation system.

You operate in a ReAct (Reasoning + Acting) loop. Each iteration you:
1. **Observe**: Review all evidence collected so far.
2. **Think**: Reason about what is known, what is unknown, and what to investigate next.
3. **Act**: Produce **one or more** query instructions for the Retriever agent.

## IMPORTANT: Parallel Queries
You can and SHOULD generate **multiple independent queries** (up to 3) per iteration
when the queries don't depend on each other's results. This dramatically improves
investigation speed.

Examples of parallelizable queries:
- "Get alerts for host X" + "Find lateral movement from host X" + "Check user activity for user Y"
- "Find IOC connections" + "Get process tree on host"

Examples of NON-parallelizable queries (must be sequential):
- "Find host IP" → then use that IP to query alerts (second depends on first)

## Context
- **Investigation Goal**: {investigation_goal}
- **Investigation Type**: {investigation_type}
- **Key Entities**: {key_entities}
- **Current Iteration**: {iteration} / {max_iterations}

## Available Cypher Templates
{templates}

## Evidence Collected So Far
{evidence_summary}

## Previous Queries
{previous_queries}

## Identified Gaps (from Analyzer)
{analysis_gaps}

## Graph Schema
{graph_schema}

## Output Format (strict JSON)

```json
{{
  "thought": "<your reasoning about what we know and what we need to find out next>",
  "actions": [
    {{
      "template_name": "<name of a template from above, or 'custom' for free-form Cypher>",
      "params": {{"<param_name>": "<value>", ...}},
      "custom_cypher": "<only if template_name is 'custom': the read-only Cypher query>",
      "description": "<one line describing what this query is looking for>"
    }}
  ],
  "confidence": <0.0 to 1.0 — how confident you are that existing evidence is sufficient to answer the user's question>
}}
```

Rules:
- The "actions" array must contain 1 to 3 query instructions.
- Use multiple actions when the queries are independent and can run in parallel.
- If confidence >= 0.85 or there is nothing more useful to query, set actions to a single entry with template_name "DONE".
- Always respond with ONLY the JSON object, no markdown fences.
"""


def _summarize_evidence(evidence: list[dict]) -> str:
    if not evidence:
        return "(no evidence yet)"
    lines = []
    for i, e in enumerate(evidence, 1):
        lines.append(f"{i}. [{e.get('confidence', '?')}] {e['finding']}")
    return "\n".join(lines)


def _summarize_queries(queries: list[dict]) -> str:
    if not queries:
        return "(no queries executed yet)"
    lines = []
    for i, q in enumerate(queries, 1):
        n = len(q.get("results", []))
        lines.append(f"{i}. {q['description']} → {n} results")
    return "\n".join(lines)


def planner_node(state: InvestigationState) -> dict:
    """LangGraph node: Planner."""
    llm = get_llm(
        deep_thinking=state.get("deep_thinking", False),
        temperature=0.1,
    )

    iteration = state.get("iteration_count", 0) + 1
    prompt = SYSTEM_PROMPT.format(
        investigation_goal=state.get("investigation_goal", ""),
        investigation_type=state.get("investigation_type", ""),
        key_entities=json.dumps(state.get("key_entities", []), ensure_ascii=False),
        iteration=iteration,
        max_iterations=state.get("max_iterations", settings.MAX_ITERATIONS),
        templates=get_template_descriptions(),
        evidence_summary=_summarize_evidence(state.get("evidence_collected", [])),
        previous_queries=_summarize_queries(state.get("queries_executed", [])),
        analysis_gaps=state.get("analysis_gaps", "(none yet)"),
        graph_schema=state.get("graph_schema", "(schema not yet loaded)"),
    )

    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content="Based on the above context, decide the next investigation step(s). Generate parallel queries when possible."),
    ]

    response = llm.invoke(messages)
    raw = response.content.strip()

    logger.info("Planner raw LLM response (first 500 chars): %s", raw[:500])

    try:
        result = extract_json(raw)
    except ValueError as e:
        logger.error(
            "Planner JSON parse FAILED. Error: %s\n"
            "=== FULL RAW RESPONSE START ===\n%s\n"
            "=== FULL RAW RESPONSE END ===",
            e, raw,
        )
        result = {
            "thought": "Unable to parse plan; concluding investigation.",
            "actions": [{"template_name": "DONE", "params": {}, "description": "Done"}],
            "confidence": 1.0,
        }

    thought = result.get("thought", "")
    confidence = result.get("confidence", 0.0)

    # Support both old "action" (single) and new "actions" (list) format
    actions = result.get("actions", [])
    if not actions:
        single_action = result.get("action", {})
        if single_action:
            actions = [single_action]
        else:
            actions = [{"template_name": "DONE", "params": {}, "description": "Done"}]

    is_done = all(a.get("template_name") == "DONE" for a in actions)
    if is_done and actions:
        logger.info("Planner explicitly concluded investigation with DONE.")

    logger.info(
        "Planner iteration %d | confidence=%.2f | done=%s | parallel_queries=%d",
        iteration, confidence, is_done, len(actions),
    )

    # Build action descriptions for UI
    action_lines = []
    for i, a in enumerate(actions, 1):
        desc = a.get("description", "N/A")
        tmpl = a.get("template_name", "?")
        if len(actions) > 1:
            action_lines.append(f"{i}. [{tmpl}] {desc}")
        else:
            action_lines.append(f"{desc}")
    actions_display = "\n".join(action_lines)

    parallel_tag = f" ⚡ {len(actions)} parallel queries" if len(actions) > 1 else ""

    return {
        "current_plan": thought,
        "query_instructions": json.dumps(actions, ensure_ascii=False),
        "iteration_count": iteration,
        "should_continue": not is_done,
        "agent_messages": [
            {
                "agent": "Planner",
                "action": f"Reasoning{parallel_tag}",
                "content": (
                    f"**Thought**: {thought}\n\n"
                    f"**Next Action{'s' if len(actions) > 1 else ''}**: {actions_display}\n\n"
                    f"**Confidence**: {confidence:.0%}"
                ),
                "iteration": iteration,
            }
        ],
    }
