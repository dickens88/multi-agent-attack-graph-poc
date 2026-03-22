import type { Todo, AgentTodos } from "../types/stream-events";
import { AGENT_DISPLAY_NAMES, AGENT_COLORS } from "../hooks/useInvestigationStream";

interface Props {
  orchestratorTodos: Todo[];
  agentTodos: Record<string, AgentTodos>;
  status: string;
}

function TodoList({ todos }: { todos: Todo[] }) {
  if (todos.length === 0) {
    return <div style={{ color: "var(--text-muted)", fontSize: 12, padding: "4px 0" }}>No active tasks.</div>;
  }

  return (
    <ul className="todo-list">
      {todos.map((todo) => {
        const isDone = todo.status === "completed";
        const progress = todo.status === "in_progress";
        const iconColor = isDone ? "var(--success)" : (progress ? "var(--accent-cyan)" : "var(--text-muted)");
        const iconStr = isDone ? "✓" : (progress ? "▶" : "○");
        
        return (
          <li key={String(todo.id)} className="todo-item" style={{ opacity: isDone ? 0.6 : 1 }}>
            <span className="todo-icon" style={{ color: iconColor }}>{iconStr}</span>
            <span className="todo-text" style={{ textDecoration: isDone ? "line-through" : "none", color: isDone ? "var(--text-muted)" : "var(--text-main)" }}>
              {todo.text}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

export function TodosPanel({ orchestratorTodos, agentTodos, status }: Props) {
  const agentList = Object.values(agentTodos);

  return (
    <div className="todos-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="panel-title-bar">
        <span>Task Queue</span>
        <span className="panel-title-meta">
          {status === "running" ? (
             <><span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--warning)', boxShadow: '0 0 6px var(--warning)' }} /> ACTIVE</>
          ) : status === "done" ? "STANDBY" : "IDLE"}
        </span>
      </div>

      <div className="todos-scroll">
        <div className="todos-section" style={{ borderLeft: '3px solid var(--accent-blue)' }}>
          <div className="todos-section-label" style={{ color: "var(--accent-blue)" }}>
            🧠 Orchestrator Master Plan
          </div>
          <TodoList todos={orchestratorTodos} />
        </div>

        {agentList.map((at) => {
          const color = AGENT_COLORS[at.source] ?? "var(--accent-cyan)";
          const displayName = AGENT_DISPLAY_NAMES[at.source] ?? at.source;
          return (
            <div key={at.call_id ?? at.source} className="todos-section" style={{ borderLeft: `3px solid ${color}` }}>
              <div className="todos-section-label" style={{ color }}>
                {displayName} Queue
              </div>
              <TodoList todos={at.todos} />
            </div>
          );
        })}

        {orchestratorTodos.length === 0 && agentList.length === 0 && (
          <div style={{ color: "var(--text-muted)", fontSize: 13, padding: "24px 0", textAlign: "center" }}>
            Operational protocol standby.
          </div>
        )}
      </div>
    </div>
  );
}
