"""Coordinator Agent — classifies user intent and extracts key entities."""

from __future__ import annotations
import json
import logging

from langchain_core.messages import SystemMessage, HumanMessage

from state.investigation_state import InvestigationState
from llm_factory import get_llm

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the **Coordinator** of a security incident investigation system.

Your job is to:
1. Classify the investigation type based on the user's question.
2. Extract key entities (IPs, hostnames, usernames, hashes, etc.).
3. Define a clear investigation goal.

## Investigation Types
- attack_path: Trace an attack chain or investigate a compromised host
- ioc_correlation: Find connections to an Indicator of Compromise (IP, hash, domain)
- lateral_movement: Detect lateral movement patterns
- user_activity: Investigate suspicious user behaviour
- impact_assessment: Assess the scope and impact of an incident
- general_investigation: General security query

## Output Format (strict JSON)
```json
{{
  "investigation_type": "<one of the types above>",
  "investigation_goal": "<specific, actionable investigation goal>",
  "key_entities": [
    {{"type": "<Host|IP|User|Process|IOC|Alert>", "id": "<identifier>", "properties": {{}}}}
  ]
}}
```
Always respond with ONLY the JSON object, no markdown fences.
"""


def coordinator_node(state: InvestigationState) -> dict:
    """LangGraph node: Coordinator."""
    llm = get_llm(
        deep_thinking=state.get("deep_thinking", False),
        temperature=0,
    )

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"User question: {state['user_question']}"),
    ]

    response = llm.invoke(messages)
    raw = response.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Coordinator produced invalid JSON. Raw: %s", raw)
        result = {
            "investigation_type": "general_investigation",
            "investigation_goal": state["user_question"],
            "key_entities": [],
        }

    logger.info("Coordinator result: %s", result)

    return {
        "investigation_type": result.get("investigation_type", "general_investigation"),
        "investigation_goal": result.get("investigation_goal", ""),
        "key_entities": result.get("key_entities", []),
        "agent_messages": [
            {
                "agent": "Coordinator",
                "action": "Intent Classification",
                "content": (
                    f"**Investigation Type**: {result.get('investigation_type', '')}\n\n"
                    f"**Goal**: {result.get('investigation_goal', '')}\n\n"
                    f"**Key Entities**: {json.dumps(result.get('key_entities', []), ensure_ascii=False)}"
                ),
                "iteration": 0,
            }
        ],
    }
