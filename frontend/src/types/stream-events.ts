export type StreamEventType =
  | "orchestrator_token"
  | "orchestrator_tool_call"
  | "orchestrator_tool_result"
  | "todos_update"
  | "todos_update_realtime"
  | "subagent_start"
  | "subagent_token"
  | "subagent_tool_call"
  | "subagent_tool_result"
  | "subagent_complete"
  | "graph_update"
  | "done";

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  color?: string;
  icon?: string;
  risk_score?: number;
  properties?: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
  timestamp?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlight?: string[];
}

export interface Todo {
  id: number | string;
  text: string;
  status: "pending" | "in_progress" | "completed";
}

export type TimelineEntry =
  | { kind: "orchestrator_thinking"; id: string; content: string; ts: number }
  | { kind: "orchestrator_tool"; id: string; tool: string; args: Record<string, unknown>; reasoning?: string; result?: string; graph_data?: GraphData | null; status: "calling" | "done" | "error"; ts: number }
  | { kind: "subagent_lifecycle"; id: string; call_id: string; agent_name: string; status: "start" | "running" | "complete" | "error"; task_description: string; ts: number }
  | { kind: "subagent_thinking"; id: string; call_id: string; agent_name: string; content: string; ts: number }
  | { kind: "subagent_tool"; id: string; call_id: string; agent_name: string; tool: string; args: Record<string, unknown>; reasoning?: string; result?: string; graph_data?: GraphData | null; status: "calling" | "done" | "error"; ts: number }
  | { kind: "subagent_result"; id: string; call_id: string; agent_name: string; result: string; ts: number };

export interface AgentTodos {
  source: string;
  call_id: string | null;
  todos: Todo[];
}

export interface InvestigationState {
  status: "idle" | "running" | "done" | "error";
  timeline: TimelineEntry[];
  orchestrator_todos: Todo[];
  agent_todos: Record<string, AgentTodos>;
  graph: GraphData;
}
