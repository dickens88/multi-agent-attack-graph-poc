"""Investigation State — shared across all agents in the LangGraph."""

from __future__ import annotations
from typing import TypedDict, Annotated
import operator


def _merge_lists(left: list, right: list) -> list:
    """Reducer that appends new items to the existing list."""
    return left + right


class QueryRecord(TypedDict):
    """A single Cypher query execution record."""
    cypher: str
    params: dict
    results: list[dict]
    description: str  # what this query was looking for


class Evidence(TypedDict):
    """A piece of evidence discovered during investigation."""
    source_query: str
    finding: str
    confidence: float  # 0.0 - 1.0
    entities_involved: list[str]


class AgentMessage(TypedDict):
    """A message emitted by an agent, used for UI display."""
    agent: str           # agent name
    action: str          # what the agent is doing
    content: str         # detailed output
    iteration: int       # which ReAct iteration


class InvestigationState(TypedDict):
    """The shared state flowing through the LangGraph."""

    # ── User Input ──
    user_question: str

    # ── Coordinator Output ──
    investigation_type: str          # e.g. "attack_path", "impact_assessment", "ioc_correlation"
    investigation_goal: str          # structured goal description
    key_entities: list[dict]         # [{type, id, properties}]

    # ── Graph DB Schema ──
    graph_schema: str                # serialized schema info

    # ── Investigation Process ──
    current_plan: str                # Planner's current reasoning + plan
    query_instructions: str          # Planner -> Retriever: what to query next
    queries_executed: Annotated[list[QueryRecord], _merge_lists]
    evidence_collected: Annotated[list[Evidence], _merge_lists]

    # ── Control Flow ──
    iteration_count: int
    max_iterations: int
    should_continue: bool
    analysis_gaps: str                 # Analyzer's identified information gaps

    # ── LLM Settings ──
    deep_thinking: bool  # Whether to enable deep thinking mode

    # ── Agent Messages (for UI) ──
    agent_messages: Annotated[list[AgentMessage], _merge_lists]

    # ── Final Output ──
    final_report: str
