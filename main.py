"""CLI entry point for the Security Investigation Multi-Agent System."""

import json
import sys

from logging_config import get_logger, setup_logging

from graph.investigation_graph import investigation_graph
from state.investigation_state import InvestigationState
from config import settings

setup_logging()
logger = get_logger(__name__)


def run_investigation(question: str) -> str:
    """Run an investigation and print each agent's output. Returns final report."""
    initial_state: InvestigationState = {
        "user_question": question,
        "investigation_type": "",
        "investigation_goal": "",
        "key_entities": [],
        "graph_schema": "",
        "current_plan": "",
        "query_instructions": "",
        "queries_executed": [],
        "evidence_collected": [],
        "iteration_count": 0,
        "max_iterations": settings.MAX_ITERATIONS,
        "should_continue": True,
        "agent_messages": [],
        "final_report": "",
    }

    print(f"\n{'═' * 60}")
    print(f"  SECURITY INVESTIGATION")
    print(f"  Question: {question}")
    print(f"{'═' * 60}\n")

    for state_snapshot in investigation_graph.stream(
        initial_state,
        config={"recursion_limit": 50},
    ):
        for node_name, partial_state in state_snapshot.items():
            messages = partial_state.get("agent_messages", [])
            for msg in messages:
                agent = msg.get("agent", "?")
                action = msg.get("action", "")
                content = msg.get("content", "")
                iteration = msg.get("iteration", 0)

                print(f"┌─ [{agent}] {action} (iteration {iteration})")
                for line in content.split("\n"):
                    print(f"│  {line}")
                print(f"└{'─' * 58}")
                print()

            report = partial_state.get("final_report", "")
            if report:
                print(f"\n{'═' * 60}")
                print("  FINAL REPORT")
                print(f"{'═' * 60}\n")
                print(report)

    return ""


def main():
    if len(sys.argv) > 1:
        question = " ".join(sys.argv[1:])
    else:
        print("Security Investigation Multi-Agent System")
        print("─" * 40)
        question = input("Enter your investigation question: ").strip()
        if not question:
            print("No question provided. Exiting.")
            sys.exit(1)

    run_investigation(question)


if __name__ == "__main__":
    main()
