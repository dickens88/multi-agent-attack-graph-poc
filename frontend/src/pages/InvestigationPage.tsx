import { useState } from "react";
import { useInvestigationStream } from "../hooks/useInvestigationStream";
import { InvestigationPanel } from "../components/InvestigationPanel";
import { GraphPanel } from "../components/GraphPanel";
import { TodosPanel } from "../components/TodosPanel";

export function InvestigationPage() {
  const [query, setQuery] = useState("");
  const { state, submit, reset, AGENT_DISPLAY_NAMES, AGENT_ICONS } = useInvestigationStream();

  const handleSubmit = () => {
    if (!query.trim() || state.status === "running") return;
    const threadId = `thread_${Date.now()}`;
    submit(query.trim(), threadId);
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-title-group">
          <h1 className="topbar-title">调查过程</h1>
          <p className="topbar-subtitle">角色分层展示执行过程与图谱更新状态</p>
        </div>
        <div className="query-bar">
          <input
            className="query-input"
            placeholder="输入查询，例如：溯源 192.168.1.105 的攻击来源并生成报告"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            disabled={state.status === "running"}
          />
          <button onClick={handleSubmit} disabled={state.status === "running" || !query.trim()} className="btn-primary">
            {state.status === "running" ? "调查中..." : "开始调查"}
          </button>
          {state.status !== "idle" && (
            <button onClick={reset} className="btn-secondary">
              清除
            </button>
          )}
        </div>
      </header>

      <main className="workspace-grid">
        <section className="workspace-left">
          <div className="panel-title-bar">
            <span>调查时间线</span>
            <span className="panel-title-meta">
              {state.status === "running" ? "执行中" : state.status === "done" ? "已完成" : "待执行"}
            </span>
          </div>
          <div className="panel-scroll">
            <InvestigationPanel
              state={state}
              agentDisplayNames={AGENT_DISPLAY_NAMES}
              agentIcons={AGENT_ICONS}
            />
          </div>
        </section>

        <section className="workspace-right">
          <div className="workspace-right-grid">
            <div className="workspace-graph-col">
              <div className="panel-title-bar">
                <span>攻击图谱</span>
                <span className="panel-title-meta">实时可视化</span>
              </div>
              <div className="panel-graph">
                <GraphPanel graphData={state.graph} isUpdating={state.status === "running"} />
              </div>
            </div>

            <TodosPanel todos={state.todos} status={state.status} />
          </div>
        </section>
      </main>
    </div>
  );
}
