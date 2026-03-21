import { OrchestratorCard } from "./OrchestratorCard";
import { SubAgentCard } from "./SubAgentCard";
import type { InvestigationState, SubAgentState } from "../types/stream-events";

interface Props {
  state: InvestigationState;
  agentDisplayNames: Record<string, string>;
  agentIcons: Record<string, string>;
}

export function InvestigationPanel({ state, agentDisplayNames, agentIcons }: Props) {
  const hasOrchestrator = state.orchestrator_text || state.todos.length > 0 || state.status === "running";
  const orderedSubAgents = state.subagent_order
    .map((call_id) => state.subagents[call_id])
    .filter((agent): agent is SubAgentState => Boolean(agent));
  const reportAgents = orderedSubAgents.filter((agent) => agent.agent_name === "report-agent");
  const executionAgents = orderedSubAgents.filter((agent) => agent.agent_name !== "report-agent");
  const hasReportComplete = reportAgents.some((agent) => agent.status === "complete" && Boolean(agent.result));
  const hasReportRunning = reportAgents.some((agent) => agent.status === "running");

  return (
    <div className="flex flex-col px-4 py-4 gap-4">
      {state.status === "idle" && (
        <div className="panel-surface p-6 text-sm text-slate-300">
          输入查询后，左侧将按照策略层、执行层、结论层逐步展示调查过程。
        </div>
      )}

      <section className="space-y-2">
        <div className="panel-section-title">策略层</div>
        {hasOrchestrator ? (
          <OrchestratorCard
            text={state.orchestrator_text}
            toolCalls={state.orchestrator_tool_calls}
            status={state.status}
          />
        ) : (
          <div className="panel-muted-card">等待编排器输出策略和计划</div>
        )}
      </section>

      <section className="space-y-2">
        <div className="panel-section-title">执行层</div>
        {executionAgents.length > 0 ? (
          executionAgents.map((agent) => (
            <SubAgentCard
              key={agent.call_id}
              agent={agent}
              displayName={agentDisplayNames[agent.agent_name] ?? agent.agent_name}
              icon={agentIcons[agent.agent_name] ?? "🤖"}
            />
          ))
        ) : (
          <div className="panel-muted-card">等待子 Agent 执行调查任务</div>
        )}
      </section>

      <section className="space-y-2 pb-4">
        <div className="panel-section-title">结论层</div>
        {reportAgents.length > 0 ? (
          reportAgents.map((agent) => (
            <SubAgentCard
              key={agent.call_id}
              agent={agent}
              displayName={agentDisplayNames[agent.agent_name] ?? "调查结论"}
              icon={agentIcons[agent.agent_name] ?? "📄"}
            />
          ))
        ) : (
          <div className="panel-muted-card">默认会触发报告 Agent，完成后在这里展示最终结论。</div>
        )}
        {hasReportRunning && (
          <div className="panel-muted-card">报告 Agent 正在生成结论，请稍候。</div>
        )}
        {state.status === "done" && !hasReportComplete && (
          <div className="panel-muted-card">
            流程已结束，但未收到报告 Agent 的完成结果（可能是事件丢失或报告未触发）。
          </div>
        )}
      </section>
    </div>
  );
}
