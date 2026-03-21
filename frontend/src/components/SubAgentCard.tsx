import { useState } from "react";
import type { SubAgentState, ToolCallEvent } from "../types/stream-events";
import { CodeDisclosure, EventSummary, PanelHeader, StatusBadge } from "./UiPrimitives";

interface Props {
  agent: SubAgentState;
  displayName: string;
  icon: string;
}

const STATUS_TONE = { running: "running", complete: "success", error: "danger" } as const;
const STATUS_LABEL = { running: "Running", complete: "Completed", error: "Error" } as const;

export function SubAgentCard({ agent, displayName, icon }: Props) {
  const [expanded, setExpanded] = useState(agent.status === "running");

  const elapsed = agent.completed_at
    ? ((agent.completed_at - agent.started_at) / 1000).toFixed(1)
    : ((Date.now() - agent.started_at) / 1000).toFixed(1);

  return (
    <article className="panel-surface">
      <button onClick={() => setExpanded((v) => !v)} className="w-full text-left">
        <PanelHeader
          title={displayName}
          subtitle={agent.task_description || "执行任务"}
          icon={icon}
          rightSlot={
            <div className="flex items-center gap-2">
              <StatusBadge label={`${elapsed}s`} />
              <StatusBadge label={STATUS_LABEL[agent.status]} tone={STATUS_TONE[agent.status]} />
            </div>
          }
        />
      </button>

      {expanded ? (
        <section className="card-section">
          {agent.tool_calls.length > 0 ? (
            <div className="space-y-2">
              <div className="card-section-title">工具链路</div>
              {agent.tool_calls.map((tc, i) => (
                <ToolCallBlock key={i} event={tc} />
              ))}
            </div>
          ) : null}

          {agent.token_buffer || agent.result ? (
            <div className="space-y-1.5">
              {agent.token_buffer ? (
                <div>
                  <div className="card-section-title">执行过程</div>
                  <div className="stream-text">
                    {agent.token_buffer}
                    {agent.status === "running" ? (
                      <span className="inline-block w-1.5 h-4 bg-sky-300 ml-0.5 animate-pulse" />
                    ) : null}
                  </div>
                </div>
              ) : null}

              {agent.result ? (
                <div>
                  <div className="card-section-title">最终结果</div>
                  <div className="stream-text">{agent.result}</div>
                </div>
              ) : null}
            </div>
          ) : (
            <EventSummary title="等待输出" detail="当前 Agent 尚未返回文本结果。" />
          )}
        </section>
      ) : null}
    </article>
  );
}

function ToolCallBlock({ event }: { event: ToolCallEvent }) {
  const argsSummary =
    event.args && Object.keys(event.args).length > 0 ? JSON.stringify(event.args).slice(0, 100) : "无参数";

  if (event.type === "call") {
    return (
      <div className="space-y-1.5">
        <EventSummary title={`Call · ${event.tool}`} detail={argsSummary} />
        {event.args ? <CodeDisclosure label="参数详情" value={JSON.stringify(event.args, null, 2)} /> : null}
      </div>
    );
  }

  const graphSummary =
    event.graph_data && (event.graph_data.nodes.length > 0 || event.graph_data.edges.length > 0)
      ? `图谱+${event.graph_data.nodes.length}节点/${event.graph_data.edges.length}边`
      : "无图谱增量";

  return (
    <div className="space-y-1.5">
      <EventSummary title={`Result · ${event.tool}`} detail={graphSummary} tone="result" />
      {event.result ? <CodeDisclosure label="结果详情" value={event.result} /> : null}
    </div>
  );
}
