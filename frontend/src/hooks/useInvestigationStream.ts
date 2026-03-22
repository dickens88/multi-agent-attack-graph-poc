import { useState, useCallback, useRef } from "react";
import type {
  InvestigationState,
  TimelineEntry,
  GraphData,
  Todo,
} from "../types/stream-events";

export const AGENT_DISPLAY_NAMES: Record<string, string> = {
  "nl2cypher-agent": "NL → Cypher",
  "graph-query-agent": "图查询执行",
  "tracer-agent": "攻击溯源",
  "report-agent": "报告生成",
  "unknown-agent": "子 Agent",
};

export const AGENT_COLORS: Record<string, string> = {
  "nl2cypher-agent": "#7c3aed",
  "graph-query-agent": "#0369a1",
  "tracer-agent": "#b45309",
  "report-agent": "#065f46",
  "unknown-agent": "#374151",
};

const initialState = (): InvestigationState => ({
  status: "idle",
  timeline: [],
  orchestrator_todos: [],
  agent_todos: {},
  graph: { nodes: [], edges: [], highlight: [] },
});

let _entryIdCounter = 0;
const nextId = () => `e${++_entryIdCounter}`;

function normalizeTodos(raw: unknown): Todo[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((item, i) => {
    const r = (item ?? {}) as Record<string, unknown>;
    const status =
      r.status === "in_progress" || r.status === "completed"
        ? r.status
        : "pending";
    return {
      id: r.id ?? `t${i}`,
      text: String(r.text ?? r.content ?? `任务 ${i + 1}`).trim(),
      status: status as Todo["status"],
    };
  });
}

/**
 * Convert Python repr text (single quotes, True/False/None) to valid JSON.
 * Only applied to the detected JSON-like substring, not arbitrary prose.
 */
function fixPythonRepr(s: string): string {
  return s
    .replace(/'/g, '"')
    .replace(/\bTrue\b/g, "true")
    .replace(/\bFalse\b/g, "false")
    .replace(/\bNone\b/g, "null");
}

function tryParseTodos(text: string): Todo[] | null {
  try {
    const p = JSON.parse(text);
    if (Array.isArray(p)) return normalizeTodos(p);
    if (p && typeof p === "object") {
      if (Array.isArray((p as Record<string, unknown>).todos)) {
        return normalizeTodos((p as Record<string, unknown>).todos);
      }
    }
  } catch {
    // ignore
  }
  return null;
}

function parseTodosFromResult(result: string): Todo[] | null {
  const text = result.trim();

  // 1. Try direct JSON parse
  const direct = tryParseTodos(text);
  if (direct) return direct;

  // 2. Extract JSON-like substring
  const start = text.search(/[\[{]/);
  if (start === -1) return null;
  const slice = text.slice(start);
  const end = Math.max(slice.lastIndexOf("]"), slice.lastIndexOf("}"));
  if (end === -1) return null;
  const snippet = slice.slice(0, end + 1);

  // 3. Try parsing the extracted substring as JSON
  const fromSnippet = tryParseTodos(snippet);
  if (fromSnippet) return fromSnippet;

  // 4. Fallback: convert Python repr format to JSON and retry
  const fixed = fixPythonRepr(snippet);
  const fromFixed = tryParseTodos(fixed);
  if (fromFixed) return fromFixed;

  return null;
}

function mergeGraphData(current: GraphData, incoming: GraphData): GraphData {
  const nodeIds = new Set(current.nodes.map((n) => n.id));
  const newNodes = incoming.nodes.filter((n) => !nodeIds.has(n.id));

  const edgeKey = (e: { source: string; target: string; label: string }) =>
    `${e.source}→${e.target}:${e.label}`;
  const edgeKeys = new Set(current.edges.map(edgeKey));
  const newEdges = incoming.edges.filter((e) => !edgeKeys.has(edgeKey(e)));

  return {
    nodes: [...current.nodes, ...newNodes],
    edges: [...current.edges, ...newEdges],
    highlight: incoming.highlight ?? current.highlight,
  };
}

function applyEvent(
  state: InvestigationState,
  eventType: string,
  payload: Record<string, unknown>
): InvestigationState {
  const now = Date.now();

  switch (eventType) {
    case "orchestrator_token": {
      const last = state.timeline.at(-1);
      if (last?.kind === "orchestrator_thinking") {
        const updated = state.timeline.map((e, i) =>
          i === state.timeline.length - 1
            ? {
                ...e,
                content:
                  e.kind === "orchestrator_thinking"
                    ? e.content + String(payload.content ?? "")
                    : e.content,
              }
            : e
        );
        return { ...state, timeline: updated };
      }
      return {
        ...state,
        timeline: [
          ...state.timeline,
          {
            kind: "orchestrator_thinking",
            id: nextId(),
            content: String(payload.content ?? ""),
            ts: now,
          },
        ],
      };
    }

    case "orchestrator_tool_call": {
      const reasoning = payload.reasoning ? String(payload.reasoning) : "";
      const newEntries: TimelineEntry[] = [];
      newEntries.push({
        kind: "orchestrator_tool",
        id: nextId(),
        tool: String(payload.tool ?? ""),
        args: (payload.args as Record<string, unknown>) ?? {},
        reasoning,
        status: "calling",
        ts: now,
      });
      return { ...state, timeline: [...state.timeline, ...newEntries] };
    }

    case "orchestrator_tool_result": {
      const toolName = String(payload.tool ?? "");
      const resultText = String(payload.result ?? "");
      const todos = toolName === "write_todos" ? parseTodosFromResult(resultText) : null;

      let matched = false;
      const updated = [...state.timeline]
        .reverse()
        .map((e) => {
          if (
            !matched &&
            e.kind === "orchestrator_tool" &&
            e.tool === toolName &&
            e.status === "calling"
          ) {
            matched = true;
            return {
              ...e,
              result: resultText,
              graph_data: (payload.graph_data as GraphData) ?? null,
              status: "done" as const,
            };
          }
          return e;
        })
        .reverse();

      let next: InvestigationState = { ...state, timeline: updated };
      if (todos) next = { ...next, orchestrator_todos: todos };
      if (payload.graph_data) {
        next = {
          ...next,
          graph: mergeGraphData(next.graph, payload.graph_data as GraphData),
        };
      }
      return next;
    }

    case "todos_update":
      return { ...state, orchestrator_todos: normalizeTodos(payload.todos) };

    case "todos_update_realtime": {
      const source = String(payload.source ?? "orchestrator");
      const callId = (payload.call_id as string | null) ?? null;
      const todos = normalizeTodos(payload.todos);
      if (!callId) return { ...state, orchestrator_todos: todos };
      return {
        ...state,
        agent_todos: {
          ...state.agent_todos,
          [callId]: { source, call_id: callId, todos },
        },
      };
    }

    case "subagent_start": {
      const callId = String(payload.call_id ?? "");
      const agentName = String(payload.agent_name ?? "unknown-agent");
      const entry: TimelineEntry = {
        kind: "subagent_lifecycle",
        id: nextId(),
        call_id: callId,
        agent_name: agentName,
        status: "start",
        task_description: String(payload.task_description ?? ""),
        ts: now,
      };
      return { ...state, timeline: [...state.timeline, entry] };
    }

    case "subagent_token": {
      const callId = String(payload.call_id ?? "");
      const content = String(payload.content ?? "");
      const agentName = String(payload.agent_name ?? "unknown-agent");

      const last = [...state.timeline]
        .reverse()
        .find((e) => e.kind === "subagent_thinking" && e.call_id === callId);

      if (last) {
        const updated = state.timeline.map((e) =>
          e.id === last.id && e.kind === "subagent_thinking"
            ? { ...e, content: e.content + content }
            : e
        );
        return { ...state, timeline: updated };
      }

      return {
        ...state,
        timeline: [
          ...state.timeline,
          {
            kind: "subagent_thinking",
            id: nextId(),
            call_id: callId,
            agent_name: agentName,
            content,
            ts: now,
          },
        ],
      };
    }

    case "subagent_tool_call": {
      const callId = String(payload.call_id ?? "");
      const agentName = String(payload.agent_name ?? "unknown-agent");
      const reasoning = payload.reasoning ? String(payload.reasoning) : "";
      const newEntries: TimelineEntry[] = [];
      newEntries.push({
        kind: "subagent_tool",
        id: nextId(),
        call_id: callId,
        agent_name: agentName,
        tool: String(payload.tool ?? ""),
        args: (payload.args as Record<string, unknown>) ?? {},
        reasoning,
        status: "calling",
        ts: now,
      });
      return { ...state, timeline: [...state.timeline, ...newEntries] };
    }

    case "subagent_tool_result": {
      const callId = String(payload.call_id ?? "");
      const agentName = String(payload.agent_name ?? "unknown-agent");
      const toolName = String(payload.tool ?? "");
      const resultText = String(payload.result ?? "");
      const todos = toolName === "write_todos" ? parseTodosFromResult(resultText) : null;

      let matched = false;
      const updated = [...state.timeline]
        .reverse()
        .map((e) => {
          if (
            !matched &&
            e.kind === "subagent_tool" &&
            e.call_id === callId &&
            e.tool === toolName &&
            e.status === "calling"
          ) {
            matched = true;
            return {
              ...e,
              result: resultText,
              graph_data: (payload.graph_data as GraphData) ?? null,
              status: "done" as const,
            };
          }
          return e;
        })
        .reverse();

      let next: InvestigationState = { ...state, timeline: updated };
      if (todos) {
        next = {
          ...next,
          agent_todos: {
            ...next.agent_todos,
            [callId]: { source: agentName, call_id: callId, todos },
          },
        };
      }
      if (payload.graph_data) {
        next = {
          ...next,
          graph: mergeGraphData(next.graph, payload.graph_data as GraphData),
        };
      }
      return next;
    }

    case "subagent_complete": {
      const callId = String(payload.call_id ?? "");
      const agentName = String(payload.agent_name ?? "unknown-agent");
      const result = String(payload.result ?? "");
      const updated = state.timeline.map((e) =>
        e.kind === "subagent_lifecycle" && e.call_id === callId
          ? { ...e, status: "complete" as const }
          : e
      );
      return {
        ...state,
        timeline: [
          ...updated,
          {
            kind: "subagent_result",
            id: nextId(),
            call_id: callId,
            agent_name: agentName,
            result,
            ts: now,
          },
        ],
      };
    }

    case "graph_update": {
      const incoming = payload as unknown as GraphData;
      const merged = mergeGraphData(state.graph, incoming);
      console.debug("[graph_update_recv]", {
        incomingNodes: incoming.nodes?.length ?? 0,
        incomingEdges: incoming.edges?.length ?? 0,
        totalNodes: merged.nodes.length,
        totalEdges: merged.edges.length,
      });
      return {
        ...state,
        graph: merged,
      };
    }

    case "done":
      return { ...state, status: "done" };

    default:
      return state;
  }
}

export function useInvestigationStream() {
  const [state, setState] = useState<InvestigationState>(initialState());
  const abortRef = useRef<AbortController | null>(null);

  const submit = useCallback(async (query: string, threadId: string) => {
    abortRef.current?.abort();
    const abort = new AbortController();
    abortRef.current = abort;

    setState({ ...initialState(), status: "running" });

    const url = `/api/investigate?query=${encodeURIComponent(query)}&thread_id=${threadId}`;
    try {
      const response = await fetch(url, { signal: abort.signal });
      if (!response.body) {
        setState((s) => ({ ...s, status: "error" }));
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() ?? "";

        for (const part of parts) {
          if (!part.trim()) continue;
          const evMatch = part.match(/^event: (.+)$/m);
          const dataMatch = part.match(/^data: (.+)$/ms);
          if (!evMatch || !dataMatch) continue;

          try {
            const payload = JSON.parse(dataMatch[1]) as Record<string, unknown>;
            setState((prev) => applyEvent(prev, evMatch[1].trim(), payload));
          } catch {
            // ignore malformed chunk
          }
        }
      }
    } catch (err: unknown) {
      if ((err as Error)?.name !== "AbortError") {
        setState((s) => ({ ...s, status: "error" }));
      }
    }

    setState((s) => (s.status === "running" ? { ...s, status: "done" } : s));
  }, []);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState(initialState());
  }, []);

  return { state, submit, reset, AGENT_DISPLAY_NAMES, AGENT_COLORS };
}
