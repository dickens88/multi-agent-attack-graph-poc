import { useState, type ReactNode } from "react";
import type { TimelineEntry, GraphData } from "../types/stream-events";
import { AGENT_DISPLAY_NAMES, AGENT_COLORS } from "../hooks/useInvestigationStream";

interface Props {
  entries: TimelineEntry[];
}

type ParsedPayload = Record<string, unknown> | unknown[] | null;

function formatRawJsonText(raw: string): string {
  const text = raw.trim();
  if (!text) return "";
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return raw;
  }
}

// ============================================================================
// INSPECTOR-STYLE JSON VIEWER
// ============================================================================

function JsonScalar({ value }: { value: string | number | boolean | null }) {
  if (value === null) {
    return <span className="json-null">null</span>;
  }
  if (typeof value === "boolean") {
    return <span className="json-boolean">{String(value)}</span>;
  }
  if (typeof value === "number") {
    return <span className="json-number">{String(value)}</span>;
  }
  return (
    <span className="json-string">
      "{value}"
    </span>
  );
}

function JsonBlock({ data }: { data: Record<string, unknown> }) {
  const keys = Object.keys(data);
  if (keys.length === 0) return <span className="json-null">{"{}"}</span>;

  return (
    <div className="json-block">
      {keys.map((k) => (
        <div key={k} className="json-row">
          <div className="json-key">{k}</div>
          <div>
            <JsonNode value={data[k]} />
          </div>
        </div>
      ))}
    </div>
  );
}

function JsonArray({ data }: { data: unknown[] }) {
  if (data.length === 0) return <span className="json-null">[]</span>;

  return (
    <div className="json-block">
      {data.map((item, i) => (
        <div key={i} className="json-row">
          <div className="json-key" style={{ color: "var(--text-muted)" }}>{i}</div>
          <div>
            <JsonNode value={item} />
          </div>
        </div>
      ))}
    </div>
  );
}

function JsonNode({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <JsonScalar value={null} />;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return <JsonScalar value={value} />;
  }
  if (Array.isArray(value)) return <JsonArray data={value} />;
  if (typeof value === "object") return <JsonBlock data={value as Record<string, unknown>} />;
  return <span className="json-string">{String(value)}</span>;
}

function InspectorJsonView({ data }: { data: ParsedPayload }) {
  if (!data) return null;
  return (
    <div className="json-viewer">
      {Array.isArray(data) ? <JsonArray data={data} /> : <JsonBlock data={data as Record<string, unknown>} />}
    </div>
  );
}

// ============================================================================
// TIMELINE COMPONENTS
// ============================================================================

export function Timeline({ entries }: Props) {
  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[13px] text-[#64748B]">
        Initializing operational trace... Awaiting queries.
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
      return <ToolRow isOrchestrator tool={entry.tool} args={entry.args} reasoning={entry.reasoning} result={entry.result} graphData={entry.graph_data} status={entry.status} />;
    case "subagent_lifecycle":
      return <SubagentLifecycle agentName={entry.agent_name} status={entry.status} taskDesc={entry.task_description} />;
    case "subagent_thinking":
      return <SubagentThinking agentName={entry.agent_name} content={entry.content} />;
    case "subagent_tool":
      return <ToolRow agentName={entry.agent_name} tool={entry.tool} args={entry.args} reasoning={entry.reasoning} result={entry.result} graphData={entry.graph_data} status={entry.status} />;
    case "subagent_result":
      return <SubagentResult agentName={entry.agent_name} result={entry.result} />;
    default:
      return null;
  }
}

// ----------------------------------------------------------------------------
// SPECIFIC ITEM BUILDERS
// ----------------------------------------------------------------------------

function OrchestratorThinking({ content }: { content: string }) {
  return (
    <div className="timeline-row">
      <div className="timeline-dot" style={{ borderColor: 'var(--accent-blue)', boxShadow: '0 0 10px rgba(59,130,246,0.4)' }} />
      <div className="agent-card">
        <div className="card-header">
          <div className="card-title-wrap">
            <span className="agent-badge" style={{ color: 'var(--accent-blue)', borderColor: 'rgba(59,130,246,0.4)', background: 'rgba(59,130,246,0.1)' }}>🧠 Orchestrator</span>
            <span className="card-meta">Reasoning</span>
          </div>
        </div>
        <div className="card-content">
          {content}
          <span className="cursor-blink" />
        </div>
      </div>
    </div>
  );
}

function SubagentLifecycle({ agentName, status, taskDesc }: { agentName: string; status: string; taskDesc: string }) {
  const color = AGENT_COLORS[agentName] ?? "#00E5FF";
  const displayName = AGENT_DISPLAY_NAMES[agentName] ?? agentName;
  
  const icon = status === "start" ? "▶" : status === "complete" ? "✓" : "✗";
  const label = status === "start" ? "INITIATED" : status === "complete" ? "COMPLETED" : "FAILED";
  
  return (
    <div className="timeline-row timeline-row-indented">
      <div className="timeline-dot" style={{ borderColor: color, background: color }} />
      <div className="status-badge" style={{ color, borderColor: `${color}40`, background: `${color}10`, width: 'max-content' }}>
        <span>{icon} {displayName} · {label}</span>
      </div>
      {taskDesc && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{taskDesc}</div>}
    </div>
  );
}

function SubagentThinking({ agentName, content }: { agentName: string; content: string }) {
  const color = AGENT_COLORS[agentName] ?? "#00E5FF";
  const displayName = AGENT_DISPLAY_NAMES[agentName] ?? agentName;

  return (
    <div className="timeline-row timeline-row-indented">
      <div className="timeline-dot" style={{ borderColor: color }} />
      <div className="agent-card" style={{ borderLeftColor: color, borderLeftWidth: 3 }}>
        <div className="card-header">
          <div className="card-title-wrap">
            <span className="agent-badge" style={{ color, borderColor: `${color}40`, background: `${color}10` }}>{displayName}</span>
            <span className="card-meta">Processing</span>
          </div>
        </div>
        <div className="card-content">
          {content}
          <span className="cursor-blink" />
        </div>
      </div>
    </div>
  );
}

const TOOL_ICONS: Record<string, string> = {
  get_node_by_id: "⚡", run_cypher_query: "📊", get_node_neighbors: "🕸️",
  trace_attack_path: "🗺️", get_live_schema: "📐", nlp_to_cypher: "💬", evaluate_termination: "🛑",
  write_todos: "📋", task: "📤",
};

function ToolRow({ tool, args, reasoning, result, graphData, status, isOrchestrator, agentName }: any) {
  const [open, setOpen] = useState(false);
  const color = isOrchestrator ? "var(--accent-blue)" : (AGENT_COLORS[agentName ?? ""] ?? "var(--accent-cyan)");
  const argsStr = Object.keys(args).length > 0 ? JSON.stringify(args) : "";
  const hasGraphData = !!graphData && (graphData.nodes.length > 0 || graphData.edges.length > 0);
  const reasoningText = typeof reasoning === "string" ? reasoning.trim() : "";

  return (
    <div className={`timeline-row ${isOrchestrator ? "" : "timeline-row-indented"}`}>
      <div className="timeline-dot" style={{ borderColor: 'var(--text-muted)', width: 6, height: 6, left: isOrchestrator ? -2 : 13, background: 'var(--text-muted)' }} />
      
      <button className="tool-expand-btn" onClick={() => setOpen(!open)}>
        <span>{TOOL_ICONS[tool] ?? "🔧"}</span>
        <span className="tool-name" style={{ color }}>{tool}</span>
        
        {status === "calling" && <span className="status-badge status-running">RUNNING</span>}
        {status === "error" && <span className="status-badge status-error">ERROR</span>}
        {status === "done" && hasGraphData && (
          <span className="status-badge" style={{ color: 'var(--accent-purple)', borderColor: 'rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.1)' }}>
            GRAPH +{graphData.nodes.length}N
          </span>
        )}
        <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)' }}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="tool-details">
          {reasoningText && (
            <div className="tool-reasoning">
              <div className="tool-reasoning-label">REASON</div>
              <div className="tool-reasoning-text">{reasoningText}</div>
            </div>
          )}
          {argsStr && (
            <div>
              <div className="detail-section-label">PAYLOAD_ARGS</div>
              <InspectorJsonView data={args} />
            </div>
          )}
          {result && (
            <div>
              <div className="detail-section-label">RETURN_DATA</div>
              {(() => {
                const text = result.trim();
                let parsed = null;
                try {
                  parsed = JSON.parse(text);
                } catch {
                  // ignore
                }
                return parsed && typeof parsed === "object" ? (
                  <InspectorJsonView data={parsed} />
                ) : (
                  <pre className="json-raw-pre">{formatRawJsonText(result)}</pre>
                );
              })()}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SubagentResult({ agentName, result }: { agentName: string; result: string }) {
  const [open, setOpen] = useState(false);
  const color = AGENT_COLORS[agentName] ?? "#00E5FF";
  const displayName = AGENT_DISPLAY_NAMES[agentName] ?? agentName;
  const preview = result.replace(/\s+/g, " ").trim().slice(0, 100);

  return (
    <div className="timeline-row">
      <div className="timeline-dot" style={{ borderColor: color, boxShadow: `0 0 10px ${color}60` }} />
      <div className="agent-card" style={{ borderTopWidth: 2, borderTopColor: color }}>
        <div className="card-header" style={{ marginBottom: 4, cursor: 'pointer' }} onClick={() => setOpen(!open)}>
          <div className="card-title-wrap">
            <span className="agent-badge" style={{ color, borderColor: `${color}40`, background: `${color}10` }}>{displayName}</span>
            <span className="card-meta">Final Yield</span>
          </div>
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{open ? "▲" : "▼"}</span>
        </div>
        <div className="card-content" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
          {open ? (
             <div style={{ marginTop: 8 }}>
             {(() => {
                const text = result.trim();
                let parsed = null;
                try {
                  parsed = JSON.parse(text);
                } catch {
                  // ignore
                }
                return parsed && typeof parsed === "object" ? (
                  <InspectorJsonView data={parsed} />
                ) : (
                  <pre className="json-raw-pre">{formatRawJsonText(result)}</pre>
                );
              })()}
             </div>
          ) : (
            <span>{preview}{result.length > 100 ? "..." : ""}</span>
          )}
        </div>
      </div>
    </div>
  );
}
