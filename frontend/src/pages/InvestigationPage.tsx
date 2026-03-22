import { useState, useEffect } from "react";
import { useInvestigationStream } from "../hooks/useInvestigationStream";
import { Timeline } from "../components/Timeline";
import { GraphPanel } from "../components/GraphPanel";
import { TodosPanel } from "../components/TodosPanel";

function InvestigationTimer({ status }: { status: string }) {
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    let interval: number;
    if (status === "running") {
      interval = window.setInterval(() => {
        setSeconds((s) => s + 1);
      }, 1000);
    } else if (status === "idle") {
      setSeconds(0);
    }
    return () => clearInterval(interval);
  }, [status]);

  if (status === "idle" && seconds === 0) return null;

  const m = Math.floor(seconds / 60).toString().padStart(2, "0");
  const s = (seconds % 60).toString().padStart(2, "0");
  return (
    <span style={{ marginLeft: 8, fontVariantNumeric: "tabular-nums", color: "var(--accent-cyan)" }}>
      {m}:{s}
    </span>
  );
}

export function InvestigationPage() {
  const [query, setQuery] = useState("");
  const { state, submit, stop, reset } = useInvestigationStream();

  const handleSubmit = () => {
    if (!query.trim() || state.status === "running") return;
    submit(query.trim(), `thread_${Date.now()}`);
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand">⚔ 攻击图谱溯源系统</div>
        <div className="query-bar">
          <input
            className="query-input"
            placeholder="输入查询，例如：溯源 192.168.1.105 的攻击来源并生成报告"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            disabled={state.status === "running"}
          />
          {state.status !== "running" ? (
            <button
              onClick={handleSubmit}
              disabled={!query.trim()}
              className="btn-primary"
            >
              开始调查
            </button>
          ) : (
            <button onClick={stop} className="btn-secondary">
              停止调查
            </button>
          )}
          {state.status !== "idle" && (
            <button onClick={reset} className="btn-secondary">
              清除
            </button>
          )}
        </div>
        <div className="topbar-spacer"></div>
      </header>

      <main className="two-col-grid">
        <section className="col-timeline">
          <div className="panel-title-bar">
            <span>调查时间线</span>
            <span className="panel-title-meta">
              {state.status === "running"
                ? "• 执行中"
                : state.status === "done"
                  ? "已完成"
                  : ""}
              <InvestigationTimer status={state.status} />
            </span>
          </div>
          <div className="panel-scroll">
            <Timeline entries={state.timeline} />
          </div>
        </section>

        <section className="col-graph">
          <div className="panel-title-bar">
            <span>攻击图谱</span>
            <span className="panel-title-meta">实时更新</span>
          </div>
          <div className="panel-graph">
            <GraphPanel graphData={state.graph} isUpdating={state.status === "running"} />
            <div className="graph-todos-overlay">
              <TodosPanel
                orchestratorTodos={state.orchestrator_todos}
                agentTodos={state.agent_todos}
                status={state.status}
              />
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
