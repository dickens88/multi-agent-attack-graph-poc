import { useState } from "react";
import { useInvestigationStream } from "../hooks/useInvestigationStream";
import { Timeline } from "../components/Timeline";
import { GraphPanel } from "../components/GraphPanel";
import { TodosPanel } from "../components/TodosPanel";

export function InvestigationPage() {
  const [query, setQuery] = useState("");
  const { state, submit, reset } = useInvestigationStream();

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
          <button
            onClick={handleSubmit}
            disabled={state.status === "running" || !query.trim()}
            className="btn-primary"
          >
            {state.status === "running" ? "调查中…" : "开始调查"}
          </button>
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
          </div>
        </section>
      </main>
    </div>
  );
}
