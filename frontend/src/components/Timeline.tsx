import { useState, type ReactNode } from "react";
import type { TimelineEntry, GraphData } from "../types/stream-events";
import {
  AGENT_DISPLAY_NAMES,
  AGENT_COLORS,
} from "../hooks/useInvestigationStream";

interface Props {
  entries: TimelineEntry[];
}

type ParsedPayload = Record<string, unknown> | unknown[] | null;

/** 返回结果区：整段当作文本，若能解析为 JSON 则格式化缩进，否则保持原文 */
function formatRawJsonText(raw: string): string {
  const text = raw.trim();
  if (!text) return "";
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return raw;
  }
}

const JSON_MAX_DEPTH = 10;
const JSON_ARRAY_PREVIEW = 12;
const JSON_STRING_MAX = 480;

function JsonScalar({ value }: { value: string | number | boolean | null }) {
  if (value === null) {
    return <span className="json-scalar json-scalar-null">null</span>;
  }
  if (typeof value === "boolean") {
    return <span className="json-scalar json-scalar-bool">{String(value)}</span>;
  }
  if (typeof value === "number") {
    return <span className="json-scalar json-scalar-num">{String(value)}</span>;
  }
  const s = value;
  const truncated = s.length > JSON_STRING_MAX;
  const shown = truncated ? `${s.slice(0, JSON_STRING_MAX)}…` : s;
  return (
    <span className="json-scalar json-scalar-str" title={truncated ? s : undefined}>
      {shown}
    </span>
  );
}

function JsonKeyLabel({ children }: { children: ReactNode }) {
  return <div className="json-k">{children}</div>;
}

function JsonObjectBlock({
  data,
  depth,
  title,
}: {
  data: Record<string, unknown>;
  depth: number;
  title?: string;
}) {
  const keys = Object.keys(data);
  if (keys.length === 0) {
    return <span className="json-scalar json-scalar-empty">{"{ }"}</span>;
  }

  return (
    <div className={`json-kv-block ${depth > 0 ? "json-kv-block-nested" : ""}`}>
      {title && <div className="json-card-head">{title}</div>}
      <div className="json-kv-list" role="list">
        {keys.map((k) => (
          <div key={k} className="json-kv-row" role="listitem">
            <JsonKeyLabel>{k}</JsonKeyLabel>
            <div className="json-v">
              <JsonValue value={data[k]} depth={depth + 1} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function JsonArrayBlock({ data, depth }: { data: unknown[]; depth: number }) {
  if (data.length === 0) {
    return <span className="json-scalar json-scalar-empty">[ ]</span>;
  }

  const slice = data.slice(0, JSON_ARRAY_PREVIEW);
  const rest = data.length - slice.length;

  return (
    <div className={`json-array-block ${depth > 0 ? "json-kv-block-nested" : ""}`}>
      <div className="json-array-list" role="list">
        {slice.map((item, idx) => (
          <div key={idx} className="json-array-item" role="listitem">
            <span className="json-array-idx" aria-hidden>
              {idx + 1}
            </span>
            <div className="json-array-value">
              <JsonValue value={item} depth={depth + 1} />
            </div>
          </div>
        ))}
      </div>
      {rest > 0 && (
        <div className="json-more">其余 {rest} 项已省略</div>
      )}
    </div>
  );
}

function JsonValue({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const d = depth ?? 0;
  if (d > JSON_MAX_DEPTH) {
    return <span className="json-scalar json-scalar-str">{JSON.stringify(value)}</span>;
  }

  if (value === null || value === undefined) {
    return <JsonScalar value={null} />;
  }
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return <JsonScalar value={value} />;
  }
  if (Array.isArray(value)) {
    return <JsonArrayBlock data={value} depth={d} />;
  }
  if (typeof value === "object") {
    return <JsonObjectBlock data={value as Record<string, unknown>} depth={d} />;
  }
  return <span className="json-scalar json-scalar-str">{String(value)}</span>;
}

function JsonView({ data }: { data: ParsedPayload }) {
  if (!data) return null;

  if (Array.isArray(data)) {
    return (
      <div className="json-card">
        <div className="json-card-head">
          <span className="json-card-title">列表</span>
          <span className="json-card-badge">{data.length} 项</span>
        </div>
        <JsonArrayBlock data={data} depth={0} />
      </div>
    );
  }

  return (
    <div className="json-card">
      <div className="json-card-head">
        <span className="json-card-title">字段</span>
        <span className="json-card-badge">{Object.keys(data).length} 键</span>
      </div>
      <JsonObjectBlock data={data} depth={0} />
    </div>
  );
}

export function Timeline({ entries }: Props) {
  if (entries.length === 0) {
    return (
      <div
        className="flex items-center justify-center h-full text-sm"
        style={{ color: "var(--text-soft)" }}
      >
        输入查询后，调查过程将在此按时间顺序显示
      </div>
    );
  }

  return (
    <div className="timeline-list">
      {entries.map((entry) => (
        <TimelineItem key={entry.id} entry={entry} />
      ))}
    </div>
  );
}

function TimelineItem({ entry }: { entry: TimelineEntry }) {
  switch (entry.kind) {
    case "orchestrator_thinking":
      return <OrchestratorThinking content={entry.content} />;

    case "orchestrator_tool":
      return (
        <ToolRow
          isOrchestrator
          tool={entry.tool}
          args={entry.args}
          result={entry.result}
          graphData={entry.graph_data}
          status={entry.status}
        />
      );

    case "subagent_lifecycle":
      return (
        <SubagentLifecycle
          agentName={entry.agent_name}
          status={entry.status}
          taskDesc={entry.task_description}
        />
      );

    case "subagent_thinking":
      return (
        <SubagentThinking agentName={entry.agent_name} content={entry.content} />
      );

    case "subagent_tool":
      return (
        <ToolRow
          agentName={entry.agent_name}
          tool={entry.tool}
          args={entry.args}
          result={entry.result}
          graphData={entry.graph_data}
          status={entry.status}
        />
      );

    case "subagent_result":
      return <SubagentResult agentName={entry.agent_name} result={entry.result} />;

    default:
      return null;
  }
}

function OrchestratorThinking({ content }: { content: string }) {
  return (
    <div className="timeline-row">
      <div className="timeline-dot dot-orchestrator" />
      <div className="timeline-bubble bubble-orchestrator">
        <div className="bubble-label">🧠 Orchestrator</div>
        <div className="bubble-text">
          {content}
          <span className="cursor-blink" />
        </div>
      </div>
    </div>
  );
}

function SubagentLifecycle({
  agentName,
  status,
  taskDesc,
}: {
  agentName: string;
  status: string;
  taskDesc: string;
}) {
  const color = AGENT_COLORS[agentName] ?? "#374151";
  const displayName = AGENT_DISPLAY_NAMES[agentName] ?? agentName;
  const icon = status === "start" ? "▶" : status === "complete" ? "✓" : "✗";
  const label = status === "start" ? "开始" : status === "complete" ? "完成" : "错误";

  return (
    <div className="timeline-row">
      <div className="timeline-dot" style={{ background: color, borderColor: color }} />
      <div className="lifecycle-badge" style={{ borderColor: `${color}80`, color }}>
        <span>
          {icon} {displayName} · {label}
        </span>
        {taskDesc && <span className="lifecycle-desc">{taskDesc}</span>}
      </div>
    </div>
  );
}

function SubagentThinking({
  agentName,
  content,
}: {
  agentName: string;
  content: string;
}) {
  const color = AGENT_COLORS[agentName] ?? "#374151";
  const displayName = AGENT_DISPLAY_NAMES[agentName] ?? agentName;

  return (
    <div className="timeline-row timeline-indented">
      <div className="timeline-dot" style={{ background: `${color}60`, borderColor: color }} />
      <div
        className="timeline-bubble"
        style={{ borderColor: `${color}50`, background: `${color}15` }}
      >
        <div className="bubble-label" style={{ color }}>
          {displayName} · 思考
        </div>
        <div className="bubble-text">
          {content}
          <span className="cursor-blink" />
        </div>
      </div>
    </div>
  );
}

const TOOL_ICONS: Record<string, string> = {
  get_node_by_ip: "🔵",
  get_node_with_context: "🔵",
  run_cypher_query: "📊",
  get_node_neighbors: "🕸️",
  trace_attack_path: "🗺️",
  find_attacker_origin: "🎯",
  nlp_to_cypher: "💬",
  evaluate_termination: "🛑",
  write_todos: "📋",
  task: "📤",
};

function ToolRow({
  tool,
  args,
  result,
  graphData,
  status,
  isOrchestrator,
  agentName,
}: {
  tool: string;
  args: Record<string, unknown>;
  result?: string;
  graphData?: GraphData | null;
  status: "calling" | "done" | "error";
  isOrchestrator?: boolean;
  agentName?: string;
}) {
  const [open, setOpen] = useState(false);
  const color = isOrchestrator
    ? "#0ea5e9"
    : AGENT_COLORS[agentName ?? ""] ?? "#374151";
  const argsStr = Object.keys(args).length > 0 ? JSON.stringify(args) : "";
  const hasGraphData =
    !!graphData && (graphData.nodes.length > 0 || graphData.edges.length > 0);

  return (
    <div className={`timeline-row ${isOrchestrator ? "" : "timeline-indented"}`}>
      <div className="timeline-dot dot-tool" />
      <div className="tool-row">
        <button className="tool-header" onClick={() => setOpen((v) => !v)}>
          <span className="tool-icon">{TOOL_ICONS[tool] ?? "🔧"}</span>
          <span className="tool-name" style={{ color }}>
            {tool}()
          </span>
          {argsStr && (
            <span className="tool-args">
              {argsStr.length > 60 ? `${argsStr.slice(0, 60)}…` : argsStr}
            </span>
          )}
          {status === "calling" && <span className="tool-status-calling">调用中…</span>}
          {status === "error" && <span className="tool-status-error">✗ 错误</span>}
          {status === "done" && hasGraphData && (
            <span className="tool-graph-badge">
              图谱 +{graphData.nodes.length}N/{graphData.edges.length}E
            </span>
          )}
          <span className="tool-expand">{open ? "▲" : "▼"}</span>
        </button>

        {open && (
          <div className="tool-detail">
            {argsStr && (
              <div className="tool-section">
                <div className="tool-section-label">参数</div>
                <JsonView data={args} />
              </div>
            )}
            {result && (
              <div className="tool-section">
                <div className="tool-section-label">
                  返回结果
                  {hasGraphData && <span className="tool-graph-badge">含图谱数据</span>}
                </div>
                <pre className="tool-pre tool-pre--raw-result">{formatRawJsonText(result)}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SubagentResult({
  agentName,
  result,
}: {
  agentName: string;
  result: string;
}) {
  const [open, setOpen] = useState(false);
  const color = AGENT_COLORS[agentName] ?? "#374151";
  const displayName = AGENT_DISPLAY_NAMES[agentName] ?? agentName;
  const preview = result.replace(/\s+/g, " ").trim().slice(0, 120);

  return (
    <div className="timeline-row">
      <div className="timeline-dot" style={{ background: color, borderColor: color }} />
      <div className="result-card" style={{ borderColor: `${color}60` }}>
        <button className="result-header" onClick={() => setOpen((v) => !v)}>
          <span style={{ color }}>◎ {displayName} · 输出</span>
          <span className="tool-expand">{open ? "▲" : "▼"}</span>
        </button>
        <div className="result-preview">
          {open ? (
            <pre className="tool-pre tool-pre--raw-result">{formatRawJsonText(result)}</pre>
          ) : (
            preview + (result.length > 120 ? "…" : "")
          )}
        </div>
      </div>
    </div>
  );
}
