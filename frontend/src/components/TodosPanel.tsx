import type { Todo, AgentTodos } from "../types/stream-events";
import {
  AGENT_DISPLAY_NAMES,
  AGENT_COLORS,
} from "../hooks/useInvestigationStream";

interface Props {
  orchestratorTodos: Todo[];
  agentTodos: Record<string, AgentTodos>;
  status: string;
}

const STATUS_ICON: Record<Todo["status"], string> = {
  pending: "○",
  in_progress: "◉",
  completed: "✓",
};

const STATUS_COLOR: Record<Todo["status"], string> = {
  pending: "var(--text-soft)",
  in_progress: "#38bdf8",
  completed: "var(--success)",
};

function TodoList({ todos }: { todos: Todo[] }) {
  if (todos.length === 0) {
    return (
      <div style={{ color: "var(--text-soft)", fontSize: 12, padding: "4px 0" }}>
        暂无任务
      </div>
    );
  }

  return (
    <ul className="todo-list">
      {todos.map((todo) => (
        <li key={String(todo.id)} className="todo-item">
          <span
            style={{
              color: STATUS_COLOR[todo.status],
              fontFamily: "monospace",
              fontSize: 13,
            }}
          >
            {STATUS_ICON[todo.status]}
          </span>
          <span
            style={{
              color:
                todo.status === "completed"
                  ? "var(--text-soft)"
                  : "var(--text-main)",
              textDecoration:
                todo.status === "completed" ? "line-through" : "none",
              fontSize: 13,
            }}
          >
            {todo.text}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function TodosPanel({ orchestratorTodos, agentTodos, status }: Props) {
  const agentList = Object.values(agentTodos);

  return (
    <div className="todos-panel">
      <div className="panel-title-bar">
        <span>任务列表</span>
        <span className="panel-title-meta">
          {status === "running" ? "执行中" : status === "done" ? "已完成" : "待执行"}
        </span>
      </div>

      <div className="todos-scroll">
        <div className="todos-section">
          <div className="todos-section-label" style={{ color: "#38bdf8" }}>
            🧠 Orchestrator
          </div>
          <TodoList todos={orchestratorTodos} />
        </div>

        {agentList.map((at) => {
          const color = AGENT_COLORS[at.source] ?? "#374151";
          const displayName = AGENT_DISPLAY_NAMES[at.source] ?? at.source;
          return (
            <div key={at.call_id ?? at.source} className="todos-section">
              <div className="todos-section-label" style={{ color }}>
                {displayName}
              </div>
              <TodoList todos={at.todos} />
            </div>
          );
        })}

        {orchestratorTodos.length === 0 && agentList.length === 0 && (
          <div
            style={{
              color: "var(--text-soft)",
              fontSize: 13,
              padding: "12px 0",
              textAlign: "center",
            }}
          >
            深度调查时任务列表将在此更新
          </div>
        )}
      </div>
    </div>
  );
}
