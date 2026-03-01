"""LangGraph Investigation Graph — wires all agents into a stateful workflow."""

from __future__ import annotations
import logging

from langgraph.graph import StateGraph, END

from state.investigation_state import InvestigationState
from agents.coordinator import coordinator_node
from agents.planner import planner_node
from agents.retriever import retriever_node
from agents.analyzer import analyzer_node
from agents.reporter import reporter_node

logger = logging.getLogger(__name__)


def _should_continue(state: InvestigationState) -> str:
    """Conditional edge after Analyzer: loop back to Planner or go to Reporter."""
    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", 10)
    should_continue = state.get("should_continue", False)

    if not should_continue:
        logger.info("Investigation complete (confidence threshold met).")
        return "reporter"

    if iteration >= max_iter:
        logger.info("Max iterations (%d) reached — forcing report.", max_iter)
        return "reporter"

    return "planner"


def _after_planner(state: InvestigationState) -> str:
    """Conditional edge after Planner: if DONE, skip Retriever and go to Reporter."""
    if not state.get("should_continue", False):
        return "reporter"
    return "retriever"


def build_investigation_graph() -> StateGraph:
    """Construct and compile the LangGraph investigation workflow.

    Flow:
        Coordinator → Planner ──→ Retriever → Analyzer ──→ Planner (loop)
                            └→ Reporter (DONE)           └→ Reporter (DONE)
    """
    graph = StateGraph(InvestigationState)

    # ── Add nodes ───────────────────────────────────────────────────────────
    graph.add_node("coordinator", coordinator_node)
    graph.add_node("planner", planner_node)
    graph.add_node("retriever", retriever_node)
    graph.add_node("analyzer", analyzer_node)
    graph.add_node("reporter", reporter_node)

    # ── Define edges ────────────────────────────────────────────────────────
    graph.set_entry_point("coordinator")
    graph.add_edge("coordinator", "planner")

    # Planner → Retriever or Reporter
    graph.add_conditional_edges(
        "planner",
        _after_planner,
        {"retriever": "retriever", "reporter": "reporter"},
    )

    graph.add_edge("retriever", "analyzer")

    # Analyzer → Planner (loop) or Reporter
    graph.add_conditional_edges(
        "analyzer",
        _should_continue,
        {"planner": "planner", "reporter": "reporter"},
    )

    graph.add_edge("reporter", END)

    return graph.compile()


# Pre-compiled graph instance
investigation_graph = build_investigation_graph()
