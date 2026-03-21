export type StreamEventType =
  | "orchestrator_token"
  | "orchestrator_tool_call"
  | "orchestrator_tool_result"
  | "todos_update"
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
  type: "IP" | "Host" | "Attacker" | "Vulnerability";
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

export interface ToolCallEvent {
  type: "call" | "result";
  tool: string;
  args?: Record<string, unknown>;
  result?: string;
  graph_data?: GraphData | null;
  timestamp: number;
  summary?: string;
  severity?: "neutral" | "success" | "warning" | "error";
  result_status?: "pending" | "success" | "error";
  updated_at?: number;
}

export interface SubAgentState {
  call_id: string;
  agent_name: string;
  task_description: string;
  status: "running" | "complete" | "error";
  token_buffer: string;
  tool_calls: ToolCallEvent[];
  result?: string;
  started_at: number;
  completed_at?: number;
}

export interface InvestigationState {
  status: "idle" | "running" | "done" | "error";
  orchestrator_text: string;
  orchestrator_tool_calls: ToolCallEvent[];
  todos: Todo[];
  subagents: Record<string, SubAgentState>;
  subagent_order: string[];
  graph: GraphData;
}
