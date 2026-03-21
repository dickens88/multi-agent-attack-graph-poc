import { useState, useCallback, useRef } from "react";
import type {
  InvestigationState,
  SubAgentState,
  GraphData,
  Todo,
} from "../types/stream-events";

function summarizeArgs(args?: Record<string, unknown>): string {
  if (!args || Object.keys(args).length === 0) return "无参数";
  const serialized = JSON.stringify(args);
  return serialized.length > 90 ? `${serialized.slice(0, 90)}...` : serialized;
}

function summarizeResult(result?: string): string {
  if (!result) return "无返回";
  const normalized = result.replace(/\s+/g, " ").trim();
  return normalized.length > 100 ? `${normalized.slice(0, 100)}...` : normalized;
}

function inferResultStatus(result: string): "success" | "error" {
  const text = result.toLowerCase();
  if (text.includes("error") || text.includes("failed") || text.includes("exception")) return "error";
  return "success";
}

function normalizeTodos(rawTodos: unknown): Todo[] {
  if (!Array.isArray(rawTodos)) return [];
  return rawTodos.map((item, index) => {
    const record = (item ?? {}) as Record<string, unknown>;
    const rawStatus = (record.status as string) || "pending";
    const status: Todo["status"] =
      rawStatus === "in_progress" || rawStatus === "completed" ? rawStatus : "pending";
    const text = String(record.text ?? record.content ?? "").trim();
    return {
      id: (record.id as number | string | undefined) ?? `todo_${index}_${Date.now()}`,
      text: text || `未命名待办 ${index + 1}`,
      status,
    };
  });
}

function parseWriteTodosResult(resultText: string): Todo[] | null {
  const text = resultText.trim();
  if (!text) return null;

  const tryParse = (candidate: string): Todo[] | null => {
    try {
      const parsed = JSON.parse(candidate) as unknown;
      if (Array.isArray(parsed)) return normalizeTodos(parsed);
      if (parsed && typeof parsed === "object") {
        const record = parsed as Record<string, unknown>;
        if (Array.isArray(record.todos)) return normalizeTodos(record.todos);
      }
    } catch {
      return null;
    }
    return null;
  };

  const direct = tryParse(text);
  if (direct) return direct;

  // Fallback: extract first JSON array/object from mixed log text.
  const startIdx = text.search(/[\[{]/);
  if (startIdx === -1) return null;
  const sliced = text.slice(startIdx);
  const endArray = sliced.lastIndexOf("]");
  const endObject = sliced.lastIndexOf("}");
  const endIdx = Math.max(endArray, endObject);
  if (endIdx === -1) return null;
  return tryParse(sliced.slice(0, endIdx + 1));
}

export const AGENT_DISPLAY_NAMES: Record<string, string> = {
  "nl2cypher-agent": "NL → Cypher 转换",
  "graph-query-agent": "图查询执行",
  "tracer-agent": "攻击路径溯源",
  "report-agent": "报告生成",
  "unknown-agent": "子 Agent",
};

export const AGENT_ICONS: Record<string, string> = {
  "nl2cypher-agent": "🔤",
  "graph-query-agent": "🔍",
  "tracer-agent": "🕵️",
  "report-agent": "📄",
};

const initialState = (): InvestigationState => ({
  status: "idle",
  orchestrator_text: "",
  orchestrator_tool_calls: [],
  todos: [],
  subagents: {},
  subagent_order: [],
  graph: { nodes: [], edges: [], highlight: [] },
});

export function useInvestigationStream() {
  const [state, setState] = useState<InvestigationState>(initialState());
  const abortRef = useRef<AbortController | null>(null);

  const submit = useCallback(async (query: string, threadId: string) => {
    abortRef.current?.abort();
    const abort = new AbortController();
    abortRef.current = abort;

    setState(initialState());
    setState((s) => ({ ...s, status: "running" }));

    const url = `/api/investigate?query=${encodeURIComponent(query)}&thread_id=${threadId}`;
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

        const eventMatch = part.match(/^event: (.+)$/m);
        const dataMatch = part.match(/^data: (.+)$/ms);
        if (!eventMatch || !dataMatch) continue;

        const eventType = eventMatch[1].trim();
        let payload: Record<string, unknown>;
        try {
          payload = JSON.parse(dataMatch[1]);
        } catch {
          continue;
        }

        setState((prev) => applyEvent(prev, eventType, payload));
      }
    }

    setState((s) => ({ ...s, status: "done" }));
  }, []);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState(initialState());
  }, []);

  return { state, submit, reset, AGENT_DISPLAY_NAMES, AGENT_ICONS };
}

function applyEvent(
  state: InvestigationState,
  eventType: string,
  payload: Record<string, unknown>
): InvestigationState {
  switch (eventType) {
    case "orchestrator_token":
      return {
        ...state,
        orchestrator_text: state.orchestrator_text + (payload.content as string),
      };

    case "orchestrator_tool_call": {
      return {
        ...state,
        orchestrator_tool_calls: [
          ...state.orchestrator_tool_calls,
          {
            type: "call",
            tool: payload.tool as string,
            args: payload.args as Record<string, unknown>,
            timestamp: Date.now(),
            summary: summarizeArgs(payload.args as Record<string, unknown>),
            severity: "neutral",
            result_status: "pending",
            updated_at: Date.now(),
          },
        ],
      };
    }

    case "orchestrator_tool_result": {
      const resultText = payload.result as string;
      const resultStatus = inferResultStatus(resultText);
      const toolName = payload.tool as string;
      const parsedTodos = toolName === "write_todos" ? parseWriteTodosResult(resultText) : null;
      const nextState: InvestigationState = {
        ...state,
        orchestrator_tool_calls: [
          ...state.orchestrator_tool_calls,
          {
            type: "result",
            tool: payload.tool as string,
            result: resultText,
            graph_data: payload.graph_data as GraphData | null,
            timestamp: Date.now(),
            summary: summarizeResult(resultText),
            severity: resultStatus === "success" ? "success" : "error",
            result_status: resultStatus,
            updated_at: Date.now(),
          },
        ],
        ...(parsedTodos ? { todos: parsedTodos } : {}),
      };
      if (payload.graph_data) {
        return mergeGraphData(nextState, payload.graph_data as GraphData);
      }
      return nextState;
    }

    case "todos_update":
      return { ...state, todos: normalizeTodos(payload.todos) };

    case "subagent_start": {
      const call_id = payload.call_id as string;
      const agent_name = payload.agent_name as string;
      const newAgent: SubAgentState = {
        call_id,
        agent_name,
        task_description: (payload.task_description as string) || "",
        status: "running",
        token_buffer: "",
        tool_calls: [],
        started_at: Date.now(),
      };
      return {
        ...state,
        subagents: { ...state.subagents, [call_id]: newAgent },
        subagent_order: [...state.subagent_order, call_id],
      };
    }

    case "subagent_token": {
      const call_id = payload.call_id as string;
      const agent = state.subagents[call_id];
      const tokenText = payload.content as string;
      if (!agent) {
        const autoAgentName = (payload.agent_name as string) || "unknown-agent";
        return {
          ...state,
          subagents: {
            ...state.subagents,
            [call_id]: {
              call_id,
              agent_name: autoAgentName,
              task_description: "",
              status: "running",
              token_buffer: tokenText,
              tool_calls: [],
              started_at: Date.now(),
            },
          },
          subagent_order: state.subagent_order.includes(call_id)
            ? state.subagent_order
            : [...state.subagent_order, call_id],
        };
      }
      return {
        ...state,
        subagents: {
          ...state.subagents,
          [call_id]: {
            ...agent,
            token_buffer: agent.token_buffer + tokenText,
          },
        },
      };
    }

    case "subagent_tool_call": {
      const call_id = payload.call_id as string;
      const agent = state.subagents[call_id];
      if (!agent) return state;
      return {
        ...state,
        subagents: {
          ...state.subagents,
          [call_id]: {
            ...agent,
            tool_calls: [
              ...agent.tool_calls,
              {
                type: "call",
                tool: payload.tool as string,
                args: payload.args as Record<string, unknown>,
                timestamp: Date.now(),
                summary: summarizeArgs(payload.args as Record<string, unknown>),
                severity: "neutral",
                result_status: "pending",
                updated_at: Date.now(),
              },
            ],
          },
        },
      };
    }

    case "subagent_tool_result": {
      const call_id = payload.call_id as string;
      const agent = state.subagents[call_id];
      if (!agent) return state;
      const resultText = payload.result as string;
      const resultStatus = inferResultStatus(resultText);
      const toolName = payload.tool as string;
      const parsedTodos = toolName === "write_todos" ? parseWriteTodosResult(resultText) : null;
      const nextState: InvestigationState = {
        ...state,
        subagents: {
          ...state.subagents,
          [call_id]: {
            ...agent,
            tool_calls: [
              ...agent.tool_calls,
              {
                type: "result",
                tool: payload.tool as string,
                result: resultText,
                graph_data: payload.graph_data as GraphData | null,
                timestamp: Date.now(),
                summary: summarizeResult(resultText),
                severity: resultStatus === "success" ? "success" : "error",
                result_status: resultStatus,
                updated_at: Date.now(),
              },
            ],
          },
        },
        ...(parsedTodos ? { todos: parsedTodos } : {}),
      };
      if (payload.graph_data) {
        return mergeGraphData(nextState, payload.graph_data as GraphData);
      }
      return nextState;
    }

    case "subagent_complete": {
      const call_id = payload.call_id as string;
      const agent = state.subagents[call_id];
      if (!agent) {
        const autoAgentName = (payload.agent_name as string) || "unknown-agent";
        return {
          ...state,
          subagents: {
            ...state.subagents,
            [call_id]: {
              call_id,
              agent_name: autoAgentName,
              task_description: "",
              status: "complete",
              token_buffer: "",
              tool_calls: [],
              result: payload.result as string,
              started_at: Date.now(),
              completed_at: Date.now(),
            },
          },
          subagent_order: state.subagent_order.includes(call_id)
            ? state.subagent_order
            : [...state.subagent_order, call_id],
        };
      }
      return {
        ...state,
        subagents: {
          ...state.subagents,
          [call_id]: {
            ...agent,
            status: "complete",
            result: payload.result as string,
            completed_at: Date.now(),
          },
        },
      };
    }

    case "graph_update":
      return mergeGraphData(state, payload as unknown as GraphData);

    case "done":
      return { ...state, status: "done" };

    default:
      return state;
  }
}

function mergeGraphData(state: InvestigationState, incoming: GraphData): InvestigationState {
  const existingNodeIds = new Set(state.graph.nodes.map((n) => n.id));
  const newNodes = incoming.nodes.filter((n) => !existingNodeIds.has(n.id));

  const edgeKey = (e: { source: string; target: string; label: string }) =>
    `${e.source}→${e.target}:${e.label}`;
  const existingEdgeKeys = new Set(state.graph.edges.map(edgeKey));
  const newEdges = incoming.edges.filter((e) => !existingEdgeKeys.has(edgeKey(e)));

  return {
    ...state,
    graph: {
      nodes: [...state.graph.nodes, ...newNodes],
      edges: [...state.graph.edges, ...newEdges],
      highlight: incoming.highlight ?? state.graph.highlight,
    },
  };
}
