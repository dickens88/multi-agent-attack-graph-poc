"""FastAPI server — exposes investigation API with SSE streaming."""

from __future__ import annotations
import asyncio
import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from graph.investigation_graph import investigation_graph
from state.investigation_state import InvestigationState
from config import settings
import event_bus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Security Investigation Multi-Agent System")

# Serve static frontend
STATIC_DIR = Path(__file__).parent / "frontend"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Thread pool for running synchronous LangGraph
_executor = ThreadPoolExecutor(max_workers=4)


def _run_graph_sync(initial_state: dict, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    """Run the LangGraph synchronously in a thread, pushing events to a queue.

    Also registers an event_bus callback so agents can push progress
    events (e.g. individual query results) as they happen.
    """

    # Register event bus callback for this thread
    def on_progress(event_type: str, payload: dict):
        # Track message to avoid duplicate from LangGraph state loop
        if event_type == "agent_message":
            msg_key = f"{payload.get('agent')}:{payload.get('action')}:{hash(payload.get('content', ''))}"
            streamed_messages.add(msg_key)
        loop.call_soon_threadsafe(queue.put_nowait, (event_type, payload))

    event_bus.register_callback(on_progress)

    # Track which messages we already streamed via event_bus (by content hash)
    streamed_messages = set()

    try:
        for state_snapshot in investigation_graph.stream(
            initial_state,
            config={"recursion_limit": 50},
        ):
            for node_name, partial_state in state_snapshot.items():
                messages = partial_state.get("agent_messages", [])
                for msg in messages:
                    # Create a simple identity key to avoid duplicate sends
                    msg_key = f"{msg.get('agent')}:{msg.get('action')}:{hash(msg.get('content', ''))}"
                    if msg_key in streamed_messages:
                        continue  # Already streamed via event_bus
                    streamed_messages.add(msg_key)
                    loop.call_soon_threadsafe(queue.put_nowait, ("agent_message", msg))

                report = partial_state.get("final_report", "")
                if report:
                    loop.call_soon_threadsafe(
                        queue.put_nowait, ("report", {"report": report})
                    )
    except Exception as e:
        logger.exception("Investigation error in thread")
        loop.call_soon_threadsafe(queue.put_nowait, ("error", {"error": str(e)}))
    finally:
        event_bus.unregister_callback()
        loop.call_soon_threadsafe(queue.put_nowait, ("done", {}))


# ── SSE Streaming Investigation ─────────────────────────────────────────────

@app.get("/api/investigate")
async def investigate(request: Request):
    """Start an investigation and stream agent messages via SSE.

    Uses GET + query param so the frontend can use native EventSource.
    Supports: ?question=...&deep_thinking=true
    """
    question = request.query_params.get("question", "").strip()
    if not question:
        return JSONResponse({"error": "question is required"}, status_code=400)

    deep_thinking = request.query_params.get("deep_thinking", "false").lower() == "true"

    investigation_id = str(uuid.uuid4())[:8]
    logger.info(
        "Starting investigation %s (deep_thinking=%s): %s",
        investigation_id, deep_thinking, question,
    )

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
        "deep_thinking": deep_thinking,
        "agent_messages": [],
        "final_report": "",
    }

    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    # Kick off the graph in a background thread
    loop.run_in_executor(_executor, _run_graph_sync, initial_state, queue, loop)

    async def event_generator():
        # Send start event
        yield {
            "event": "start",
            "data": json.dumps({
                "investigation_id": investigation_id,
                "question": question,
                "deep_thinking": deep_thinking,
            }, ensure_ascii=False),
        }

        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                logger.info("Client disconnected, stopping SSE stream.")
                break

            try:
                event_type, payload = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                # Send a heartbeat comment to keep connection alive
                yield {"comment": "heartbeat"}
                continue

            if event_type == "done":
                yield {"event": "done", "data": "{}"}
                break

            yield {
                "event": event_type,
                "data": json.dumps(payload, ensure_ascii=False, default=str),
            }

    return EventSourceResponse(event_generator())


# ── Serve Frontend ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Frontend not found</h1>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8899, reload=True, log_level="debug")
