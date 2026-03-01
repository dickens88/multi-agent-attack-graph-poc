"""Reporter Agent — synthesizes all evidence into a final investigation report."""

from __future__ import annotations
import json
import logging

from langchain_core.messages import SystemMessage, HumanMessage

from state.investigation_state import InvestigationState
from llm_factory import get_llm

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the **Reporter** of a security incident investigation system.

Your job is to produce a comprehensive, well-structured investigation report
based on all evidence collected during the investigation.

## Investigation Context
- **Original Question**: {user_question}
- **Investigation Type**: {investigation_type}
- **Investigation Goal**: {investigation_goal}
- **Key Entities**: {key_entities}

## All Evidence Collected
{all_evidence}

## Queries Executed
{all_queries}

## Report Requirements
Produce a report in **Markdown** format with the following sections:

1. **Executive Summary** — 2-3 sentence TL;DR of the investigation outcome.
2. **Investigation Timeline** — chronological sequence of events (if temporal data available).
3. **Key Findings** — numbered list of critical discoveries, each with confidence level.
4. **Attack Path / Relationship Map** — describe the attack chain or entity relationships found.
5. **Impact Assessment** — scope of affected systems, users, data.
6. **IOC List** — any Indicators of Compromise discovered (IPs, hashes, domains, etc.).
7. **Recommendations** — actionable remediation steps.
8. **Evidence Appendix** — summary of all queries run and their results.

Write the full report in Markdown. Be precise, cite specific entities by ID.
Use Chinese (简体中文) for the report content.
"""


def reporter_node(state: InvestigationState) -> dict:
    """LangGraph node: Reporter."""
    llm = get_llm(
        deep_thinking=state.get("deep_thinking", False),
        temperature=0.2,
    )

    evidence = state.get("evidence_collected", [])
    evidence_str = "\n".join(
        f"{i}. [{e.get('confidence', '?'):.0%}] {e['finding']} "
        f"(entities: {', '.join(e.get('entities_involved', []))})"
        for i, e in enumerate(evidence, 1)
    ) or "(no evidence collected)"

    queries = state.get("queries_executed", [])
    queries_str = "\n".join(
        f"{i}. {q['description']} | Cypher: `{q['cypher']}` | {len(q.get('results', []))} results"
        for i, q in enumerate(queries, 1)
    ) or "(no queries)"

    prompt = SYSTEM_PROMPT.format(
        user_question=state.get("user_question", ""),
        investigation_type=state.get("investigation_type", ""),
        investigation_goal=state.get("investigation_goal", ""),
        key_entities=json.dumps(state.get("key_entities", []), ensure_ascii=False),
        all_evidence=evidence_str,
        all_queries=queries_str,
    )

    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content="Generate the final investigation report."),
    ]

    response = llm.invoke(messages)
    report = response.content.strip()

    logger.info("Reporter generated report (%d chars)", len(report))

    return {
        "final_report": report,
        "agent_messages": [
            {
                "agent": "Reporter",
                "action": "Report Generated",
                "content": report,
                "iteration": state.get("iteration_count", 0),
            }
        ],
    }
