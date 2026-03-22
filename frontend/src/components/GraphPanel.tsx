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

// Cyber-Forensic Tech Palette for Nodes
const NODE_STYLES: Record<string, { bg: string; border: string }> = {
  Host: { bg: "#00E5FF11", border: "#00E5FF" }, // Cyan
  User: { bg: "#8B5CF611", border: "#8B5CF6" }, // Purple
  IOC: { bg: "#F43F5E11", border: "#F43F5E" }, // Rose
  Alert: { bg: "#F59E0B11", border: "#F59E0B" }, // Amber
  Process: { bg: "#10B98111", border: "#10B981" }, // Emerald 
  Network_Connection: { bg: "#3B82F611", border: "#3B82F6" }, // Blue
  File: { bg: "#94A3B811", border: "#94A3B8" }, // Slate
  Email: { bg: "#F9731611", border: "#F97316" }, // Orange
  MITRE_Technique: { bg: "#D946EF11", border: "#D946EF" }, // Fuchsia
  Vulnerability: { bg: "#EAB30811", border: "#EAB308" }, // Yellow
  IP: { bg: "#0EA5E911", border: "#0EA5E9" }, // Sky
  Attacker: { bg: "#EF444411", border: "#EF4444" }, // Red
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
    graphData.edges.forEach((e) => {
      const s = String(e.source || "");
      const t = String(e.target || "");
      if (!s || !t || !nodeMap.has(s) || !nodeMap.has(t)) return;
      const key = `${s}->${t}:${e.label || ""}`;
      if (!linkMap.has(key)) {
        linkMap.set(key, { source: s, target: t, label: e.label || "" });
      }
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

    // Add Definitions for glows
    const defs = svg.append("defs");
    const filter = defs.append("filter").attr("id", "glow").attr("x", "-50%").attr("y", "-50%").attr("width", "200%").attr("height", "200%");
    filter.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    if (!nodes.length) return;

    const root = svg.append("g");

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 3])
      .on("zoom", (event) => root.attr("transform", event.transform.toString()));
    svg.call(zoom);

    // Links (thinner, more electric line)
    const links = root.append("g")
      .selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke", "rgba(148, 163, 184, 0.3)")
      .attr("stroke-width", 1.2);

    const labels = root.append("g")
      .selectAll("text")
      .data(edges)
      .join("text")
      .text((d) => d.label || "")
      .attr("font-size", 9)
      .attr("font-family", "'JetBrains Mono', monospace")
      .attr("fill", "rgba(148, 163, 184, 0.7)")
      .attr("pointer-events", "none");

    // Nodes
    const nodeGroup = root.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .style("cursor", "pointer")
      .style("transition", "transform 0.1s ease");

    nodeGroup.append("circle")
      .attr("r", (d) => 10 + (d.risk_score ?? 0) * 12)
      .attr("fill", (d) => {
        if (d.color) return `${d.color}11`;
        return NODE_STYLES[d.type]?.bg ?? "#1E293B";
      })
      .attr("stroke", (d) => d.color ?? NODE_STYLES[d.type]?.border ?? "#64748B")
      .attr("stroke-width", 2)
      .style("filter", (d) => (d.risk_score && d.risk_score > 0.5) ? "url(#glow)" : "none");

    const textNodes = nodeGroup.append("text")
      .text((d) => d.label)
      .attr("font-size", 10)
      .attr("font-family", "'Inter', sans-serif")
      .attr("font-weight", "500")
      .attr("fill", "#F8FAFC")
      .attr("text-anchor", "middle")
      .attr("dy", 26)
      .attr("pointer-events", "none");
    
    // Slight shadow to text for readability against grid
    textNodes.style("text-shadow", "0px 2px 4px rgba(0,0,0,0.8)");

    nodeGroup
      .on("mouseenter", (event, d) => {
        d3.select(event.currentTarget).select("circle").attr("r", 14 + (d.risk_score ?? 0)*12).style("filter", "url(#glow)");
        setHovered(d);
      })
      .on("mouseleave", (event, d) => {
        d3.select(event.currentTarget).select("circle").attr("r", 10 + (d.risk_score ?? 0)*12).style("filter", (d: any) => (d.risk_score && d.risk_score > 0.5) ? "url(#glow)" : "none");
        setHovered(null);
      });

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink<SimNode, SimLink>(edges).id((d) => d.id).distance(120).strength(0.6))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide<SimNode>().radius((d) => 24 + (d.risk_score ?? 0)*12));

    const drag = d3.drag<SVGGElement, SimNode>()
      .on("start", (event, d) => { if (!event.active) simulation.alphaTarget(0.2).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; });

    nodeGroup.call(drag);

    simulation.on("tick", () => {
      links.attr("x1", (d) => (d.source as SimNode).x ?? 0).attr("y1", (d) => (d.source as SimNode).y ?? 0)
        .attr("x2", (d) => (d.target as SimNode).x ?? 0).attr("y2", (d) => (d.target as SimNode).y ?? 0);
      labels.attr("x", (d) => (((d.source as SimNode).x ?? 0) + ((d.target as SimNode).x ?? 0)) / 2)
        .attr("y", (d) => (((d.source as SimNode).y ?? 0) + ((d.target as SimNode).y ?? 0)) / 2 - 4);
      nodeGroup.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

    return () => { simulation.stop(); setHovered(null); };
  }, [nodes, edges]);

  return (
    <div className="graph-panel-wrap" ref={wrapRef}>
      <div className="graph-overlay-top">
        <span className="graph-stat">NODES: {nodes.length} | EDGES: {edges.length}</span>
        {isUpdating && <span className="graph-updating-badge">SYNCING GRAPH...</span>}
      </div>

      {hovered && (
        <div className="graph-node-detail">
          <div className="graph-node-detail-title">{hovered.label}</div>
          <div className="graph-node-detail-type" style={{ color: NODE_STYLES[hovered.type]?.border ?? "inherit" }}>
            {hovered.type}
          </div>
          <div className="graph-node-kv"><span className="graph-node-k">ID</span><span className="graph-node-v">{hovered.id}</span></div>
          {hovered.risk_score !== undefined && (
            <div className="graph-node-kv"><span className="graph-node-k">RISK</span><span className="graph-node-v" style={{ color: hovered.risk_score > 0.5 ? 'var(--danger)' : 'var(--text-main)' }}>{String(hovered.risk_score)}</span></div>
          )}
          {hovered.properties && Object.entries(hovered.properties)
            .filter(([k]) => !["id", "ip", "label", "hostname", "risk_score", "type"].includes(k))
            .slice(0, 5)
            .map(([k, v]) => (
              <div key={k} className="graph-node-kv">
                <span className="graph-node-k">{k}</span>
                <span className="graph-node-v">{String(v ?? "")}</span>
              </div>
            ))}
        </div>
      )}

      <div className="graph-legend">
        {Object.entries(NODE_STYLES).map(([type, style]) => (
          <div key={type} className="graph-legend-item">
            <span className="graph-legend-dot" style={{ background: style.border, boxShadow: `0 0 8px ${style.border}` }} />
            {type}
          </div>
        ))}
      </div>

      {nodes.length === 0 && <div className="graph-empty">AWAITING TOPOLOGY DATA...</div>}
      <svg ref={svgRef} className="graph-canvas" />
    </div>
  );
}
