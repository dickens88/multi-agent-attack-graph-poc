import type { Todo } from "../types/stream-events";
import { StatusBadge } from "./UiPrimitives";

interface Props {
  todos: Todo[];
  status: "idle" | "running" | "done" | "error";
}

const TODO_LABEL = {
  pending: "待处理",
  in_progress: "执行中",
  completed: "已完成",
} as const;

const TODO_TONE = {
  pending: "neutral",
  in_progress: "running",
  completed: "success",
} as const;

export function TodosPanel({ todos, status }: Props) {
  return (
    <aside className="todos-side-panel">
      <div className="panel-title-bar">
        <span>Write Todos</span>
        <span className="panel-title-meta">
          {status === "running" ? "实时覆盖" : status === "done" ? "最后一版" : "等待中"}
        </span>
      </div>

      <div className="todos-scroll">
        {todos.length === 0 ? (
          <div className="panel-muted-card">暂无待办。收到新的 write_todos 后会整块替换当前列表。</div>
        ) : (
          <div className="space-y-2">
            {todos.map((todo) => (
              <div key={todo.id} className="todo-row">
                <StatusBadge label={TODO_LABEL[todo.status]} tone={TODO_TONE[todo.status]} />
                <span className={todo.status === "completed" ? "line-through opacity-70" : ""}>{todo.text}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}
