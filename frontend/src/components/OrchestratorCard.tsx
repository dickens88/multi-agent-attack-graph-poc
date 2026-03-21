import type { ToolCallEvent } from "../types/stream-events";
import { CodeDisclosure, EventSummary, PanelHeader, StatusBadge } from "./UiPrimitives";

interface Props {
  text: string;
  toolCalls: ToolCallEvent[];
  status: "running" | "done" | "idle" | "error";
}

const STATUS_LABEL = { running: "Running", done: "Completed", idle: "Pending", error: "Error" } as const;
const STATUS_TONE = { running: "running", done: "success", idle: "neutral", error: "danger" } as const;

function summarizeToolResult(event: ToolCallEvent): string {
  if (!event.result) return "无结果";
  const normalized = event.result.trim().replace(/\s+/g, " ");
  return normalized.length > 88 ? `${normalized.slice(0, 88)}...` : normalized;
}

export function OrchestratorCard({ text, toolCalls, status }: Props) {
  const visibleToolCalls = toolCalls.filter((event) => event.tool !== "write_todos");

  return (
    <article className="panel-surface">
      <PanelHeader
        title="Orchestrator"
        subtitle="策略分解与任务编排"
        icon="🧠"
        rightSlot={<StatusBadge label={STATUS_LABEL[status]} tone={STATUS_TONE[status]} />}
      />

      {visibleToolCalls.length > 0 ? (
        <section className="card-section">
          <div className="card-section-title">工具执行</div>
          <div className="space-y-2">
            {visibleToolCalls.map((event, idx) => (
              <OrchestratorToolCallBlock key={idx} event={event} />
            ))}
          </div>
        </section>
      ) : null}

      {text ? (
        <section className="card-section">
          <div className="card-section-title">主 Agent 决策流</div>
          <div className="stream-text">
            {text}
            {status === "running" ? <span className="inline-block w-1.5 h-4 bg-cyan-300 ml-0.5 animate-pulse" /> : null}
          </div>
        </section>
      ) : (
        <section className="card-section">
          <EventSummary title="等待编排器输出" detail="收到 token 后会持续更新执行叙述。" />
        </section>
      )}
    </article>
  );
}

function OrchestratorToolCallBlock({ event }: { event: ToolCallEvent }) {
  const argsSummary =
    event.args && Object.keys(event.args).length > 0 ? JSON.stringify(event.args).slice(0, 120) : "无参数";

  if (event.type === "call") {
    return (
      <div className="space-y-1.5">
        <EventSummary title={`Call · ${event.tool}`} detail={argsSummary} tone="neutral" />
        {event.args ? <CodeDisclosure label="参数详情" value={JSON.stringify(event.args, null, 2)} /> : null}
      </div>
    );
  }

  const graphHint =
    event.graph_data && (event.graph_data.nodes.length > 0 || event.graph_data.edges.length > 0)
      ? `更新图谱 ${event.graph_data.nodes.length} 节点 / ${event.graph_data.edges.length} 边`
      : "未携带图谱增量";

  return (
    <div className="space-y-1.5">
      <EventSummary
        title={`Result · ${event.tool}`}
        detail={`${summarizeToolResult(event)} · ${graphHint}`}
        tone="result"
      />
      {event.result ? <CodeDisclosure label="结果详情" value={event.result} /> : null}
    </div>
  );
}
