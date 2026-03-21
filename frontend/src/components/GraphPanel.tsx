import { useEffect, useMemo, useRef, useState } from "react";
import * as d3 from "d3";
import type { GraphData } from "../types/stream-events";

interface Props {
  graphData: GraphData;
  isUpdating: boolean;
}

type SimNode = d3.SimulationNodeDatum & {
  id: string;
  label: string;
  type: string;
  color?: string;
  icon?: string;
  risk_score?: number;
  properties?: Record<string, unknown>;
};

type SimLink = d3.SimulationLinkDatum<SimNode> & {
  source: string | SimNode;
  target: string | SimNode;
  label: string;
};

const NODE_STYLES: Record<string, { bg: string; border: string }> = {
  Host: { bg: "#00e5ff22", border: "#00e5ff" },
  User: { bg: "#b388ff22", border: "#b388ff" },
  IOC: { bg: "#ff174422", border: "#ff1744" },
  Alert: { bg: "#ffab0022", border: "#ffab00" },
  Process: { bg: "#39ff1422", border: "#39ff14" },
  Network_Connection: { bg: "#448aff22", border: "#448aff" },
  File: { bg: "#78909c22", border: "#78909c" },
  Email: { bg: "#ff6e4022", border: "#ff6e40" },
  MITRE_Technique: { bg: "#ea80fc22", border: "#ea80fc" },
  Vulnerability: { bg: "#ffd74022", border: "#ffd740" },
  IP: { bg: "#378ADD22", border: "#378ADD" },
  Attacker: { bg: "#E24B4A22", border: "#E24B4A" },
};

export function GraphPanel({ graphData, isUpdating }: Props) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [hovered, setHovered] = useState<SimNode | null>(null);

  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, SimNode>();
    graphData.nodes.forEach((n) => {
      if (!n?.id) return;
      nodeMap.set(String(n.id), {
        id: String(n.id),
        label: n.label || String(n.id),
        type: n.type || "IP",
        color: n.color,
        icon: n.icon,
        risk_score: n.risk_score,
        properties: n.properties,
      });
    });

    const linkMap = new Map<string, SimLink>();
    let skippedMissingNodeEdges = 0;
    graphData.edges.forEach((e) => {
      const s = String(e.source || "");
      const t = String(e.target || "");
      if (!s || !t || !nodeMap.has(s) || !nodeMap.has(t)) {
        skippedMissingNodeEdges += 1;
        return;
      }
      const key = `${s}->${t}:${e.label || ""}`;
      if (!linkMap.has(key)) {
        linkMap.set(key, { source: s, target: t, label: e.label || "" });
      }
    });

    console.debug("[graph_panel_normalize]", {
      inputNodes: graphData.nodes.length,
      inputEdges: graphData.edges.length,
      normalizedNodes: nodeMap.size,
      normalizedEdges: linkMap.size,
      skippedMissingNodeEdges,
    });

    return { nodes: Array.from(nodeMap.values()), edges: Array.from(linkMap.values()) };
  }, [graphData]);

  useEffect(() => {
    const svgEl = svgRef.current;
    const wrapEl = wrapRef.current;
    if (!svgEl || !wrapEl) return;

    const width = wrapEl.clientWidth || 600;
    const height = wrapEl.clientHeight || 500;

    const svg = d3.select(svgEl);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    if (!nodes.length) return;

    const root = svg.append("g");

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.4, 2.5])
      .on("zoom", (event) => root.attr("transform", event.transform.toString()));
    svg.call(zoom);

    const links = root
      .append("g")
      .selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke", "rgba(148,163,184,0.42)")
      .attr("stroke-width", 1.4);

    const labels = root
      .append("g")
      .selectAll("text")
      .data(edges)
      .join("text")
      .text((d) => d.label || "")
      .attr("font-size", 9)
      .attr("fill", "#94a3b8")
      .attr("pointer-events", "none");

    const nodeGroup = root
      .append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .style("cursor", "pointer");

    nodeGroup
      .append("circle")
      .attr("r", (d) => 11 + (d.risk_score ?? 0.25) * 10)
      .attr("fill", (d) => {
        if (d.color) {
          return `${d.color}33`;
        }
        return NODE_STYLES[d.type]?.bg ?? "#2d2d2d";
      })
      .attr("stroke", (d) => d.color ?? NODE_STYLES[d.type]?.border ?? "#666")
      .attr("stroke-width", 2);

    nodeGroup
      .append("text")
      .text((d) => d.label)
      .attr("font-size", 10)
      .attr("fill", "#e2e8f0")
      .attr("text-anchor", "middle")
      .attr("dy", 24)
      .attr("pointer-events", "none");

    nodeGroup
      .on("mouseenter", (_, d) => setHovered(d))
      .on("mouseleave", () => setHovered(null));

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3.forceLink<SimNode, SimLink>(edges).id((d) => d.id).distance(110).strength(0.75)
      )
      .force("charge", d3.forceManyBody().strength(-350))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide<SimNode>().radius((d) => 16 + (d.risk_score ?? 0.25) * 10));

    const drag = d3
      .drag<SVGGElement, SimNode>()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.2).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    nodeGroup.call(drag);

    simulation.on("tick", () => {
      links
        .attr("x1", (d) => (d.source as SimNode).x ?? 0)
        .attr("y1", (d) => (d.source as SimNode).y ?? 0)
        .attr("x2", (d) => (d.target as SimNode).x ?? 0)
        .attr("y2", (d) => (d.target as SimNode).y ?? 0);

      labels
        .attr("x", (d) => (((d.source as SimNode).x ?? 0) + ((d.target as SimNode).x ?? 0)) / 2)
        .attr("y", (d) => (((d.source as SimNode).y ?? 0) + ((d.target as SimNode).y ?? 0)) / 2 - 4);

      nodeGroup.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

    return () => {
      simulation.stop();
      setHovered(null);
    };
  }, [nodes, edges]);

  return (
    <div className="graph-panel-wrap" ref={wrapRef}>
      <div className="graph-overlay-top">
        <span className="graph-stat">
          {nodes.length} 节点 · {edges.length} 边
        </span>
        {isUpdating && <span className="graph-updating-badge">图谱更新中</span>}
      </div>

      {hovered && (
        <div className="graph-node-detail">
          <div className="graph-node-detail-title">{hovered.label}</div>
          <div className="graph-node-detail-type">{hovered.type}</div>
          <div className="graph-node-detail-row">
            <span className="graph-node-detail-key">ID</span>
            <span className="graph-node-detail-val">{hovered.id}</span>
          </div>
          {hovered.risk_score !== undefined && (
            <div className="graph-node-detail-row">
              <span className="graph-node-detail-key">risk_score</span>
              <span className="graph-node-detail-val">{String(hovered.risk_score)}</span>
            </div>
          )}
          {hovered.properties &&
            Object.entries(hovered.properties)
              .filter(([k]) => !["id", "ip", "label", "hostname", "risk_score", "type"].includes(k))
              .slice(0, 5)
              .map(([k, v]) => (
                <div key={k} className="graph-node-detail-row">
                  <span className="graph-node-detail-key">{k}</span>
                  <span className="graph-node-detail-val">{String(v ?? "")}</span>
                </div>
              ))}
        </div>
      )}

      <div className="graph-legend">
        {Object.entries(NODE_STYLES).map(([type, style]) => (
          <div key={type} className="graph-legend-item">
            <span className="graph-legend-dot" style={{ background: style.bg, borderColor: style.border }} />
            {type}
          </div>
        ))}
      </div>

      {nodes.length === 0 && <div className="graph-empty">暂无图数据，等待工具结果</div>}
      <svg ref={svgRef} className="graph-canvas" />
    </div>
  );
}
