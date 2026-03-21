import { useEffect, useMemo, useRef, useState } from "react";
import type { GraphData } from "../types/stream-events";
import cytoscape from "cytoscape";

const NODE_STYLES: Record<string, { bg: string; border: string }> = {
  IP: { bg: "#1e3a5f", border: "#378ADD" },
  Attacker: { bg: "#5f1e1e", border: "#E24B4A" },
  Host: { bg: "#1e4a2f", border: "#639922" },
  Vulnerability: { bg: "#4a3a1e", border: "#BA7517" },
};

interface Props {
  graphData: GraphData;
  isUpdating: boolean;
}

export function GraphPanel({ graphData, isUpdating }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const prevCountsRef = useRef({ nodes: 0, edges: 0 });
  const [selectedInfo, setSelectedInfo] = useState<string>("未选中节点");
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);

  const graphMode = useMemo(() => {
    if (graphData.nodes.length === 0) return "empty";
    if (graphData.nodes.length === 1 && graphData.edges.length === 0) return "single";
    return "multi";
  }, [graphData.edges.length, graphData.nodes.length]);

  useEffect(() => {
    if (!containerRef.current) return;
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (ele) => NODE_STYLES[ele.data("nodeType")]?.bg ?? "#333",
            "border-color": (ele) => NODE_STYLES[ele.data("nodeType")]?.border ?? "#666",
            "border-width": 1.5,
            label: "data(label)",
            color: "#e0e0e0",
            "font-size": 10,
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: (ele) => {
              const risk = ele.data("risk_score") ?? 0.3;
              return 20 + risk * 20;
            },
            height: (ele) => {
              const risk = ele.data("risk_score") ?? 0.3;
              return 20 + risk * 20;
            },
          },
        },
        {
          selector: "node.highlighted",
          style: {
            "border-width": 3,
            "border-color": "#EF9F27",
            "background-color": "#4a3000",
          },
        },
        {
          selector: "node[nodeType='Attacker']",
          style: {
            shape: "diamond",
            "border-width": 2,
          },
        },
        {
          selector: "edge",
          style: {
            "line-color": "#444",
            "target-arrow-color": "#666",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 9,
            color: "#888",
            "text-rotation": "autorotate",
            width: 1.5,
          },
        },
        {
          selector: "edge.new",
          style: { "line-color": "#378ADD", "target-arrow-color": "#378ADD" },
        },
      ],
      layout: { name: "cose", animate: true, animationDuration: 400 },
    });

    cyRef.current.on("tap", "node", (e) => {
      const node = e.target;
      const label = node.data("label");
      const type = node.data("nodeType");
      setSelectedInfo(`${label} · ${type}`);
    });

    cyRef.current.on("tap", "edge", (e) => {
      const edge = e.target;
      setSelectedInfo(`${edge.data("source")} -> ${edge.data("target")} · ${edge.data("label")}`);
    });

    cyRef.current.on("tap", (e) => {
      if (e.target === cyRef.current) {
        setSelectedInfo("未选中节点");
      }
    });

    return () => cyRef.current?.destroy();
  }, []);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Rebuild graph each update so that duplicated logical ids can still render
    // as separate visible nodes in edge-less datasets.
    cy.elements().remove();

    const nodeCountByBaseId = new Map<string, number>();
    const renderIdsByBaseId = new Map<string, string[]>();

    graphData.nodes.forEach((node, index) => {
      const seen = nodeCountByBaseId.get(node.id) ?? 0;
      const renderId = seen === 0 ? node.id : `${node.id}__dup_${seen}`;
      nodeCountByBaseId.set(node.id, seen + 1);

      const idList = renderIdsByBaseId.get(node.id) ?? [];
      idList.push(renderId);
      renderIdsByBaseId.set(node.id, idList);

      cy.add({
        group: "nodes",
        data: {
          ...node.properties,
          id: renderId,
          baseId: node.id,
          label: node.label || `${node.id} #${index + 1}`,
          nodeType: node.type,
          risk_score: node.risk_score,
        },
      });
    });

    graphData.edges.forEach((edge, edgeIndex) => {
      const sourceRenderId = renderIdsByBaseId.get(edge.source)?.[0] ?? edge.source;
      const targetRenderId = renderIdsByBaseId.get(edge.target)?.[0] ?? edge.target;
      const edgeId = `${sourceRenderId}→${targetRenderId}:${edge.label}:${edgeIndex}`;
      cy.add({
        group: "edges",
        data: {
          id: edgeId,
          source: sourceRenderId,
          target: targetRenderId,
          label: edge.label,
        },
        classes: "new",
      });
    });

    graphData.highlight?.forEach((id) => {
      const renderIds = renderIdsByBaseId.get(id) ?? [id];
      renderIds.forEach((renderId) => cy.getElementById(renderId).addClass("highlighted"));
    });

    const previous = prevCountsRef.current;
    const hasDelta = graphData.nodes.length !== previous.nodes || graphData.edges.length !== previous.edges;
    prevCountsRef.current = { nodes: graphData.nodes.length, edges: graphData.edges.length };

    if (graphData.nodes.length > 0 || graphData.edges.length > 0) {
      if (hasDelta) {
        cy.layout({ name: "cose", animate: true, animationDuration: 280, fit: false }).run();
      }
      cy.fit(undefined, 48);
      setLastUpdatedAt(Date.now());
    }
  }, [graphData]);

  return (
    <div className="relative h-full">
      <div className="absolute top-3 left-3 right-3 z-10 flex items-center justify-between text-xs">
        <div className="rounded-md border border-slate-700/70 bg-slate-950/85 px-2.5 py-1 text-slate-200">
          {graphData.nodes.length} 节点 · {graphData.edges.length} 边
        </div>
        <div className="rounded-md border border-slate-700/70 bg-slate-950/85 px-2.5 py-1 text-slate-300">
          {lastUpdatedAt ? `最近更新 ${new Date(lastUpdatedAt).toLocaleTimeString()}` : "等待图数据"}
        </div>
      </div>

      {isUpdating ? (
        <div className="absolute top-14 right-3 z-10 rounded-md border border-sky-600/60 bg-sky-950/80 px-2 py-1 text-xs text-sky-300">
          图谱更新中
        </div>
      ) : null}

      <div className="absolute bottom-3 left-3 z-10 rounded-md border border-slate-700/70 bg-slate-950/85 px-2.5 py-1 text-xs text-slate-300">
        当前对象：{selectedInfo}
      </div>

      <div className="absolute bottom-3 right-3 z-10 flex flex-col gap-1 rounded-md border border-slate-700/70 bg-slate-950/85 p-2 text-[10px] text-gray-400">
        {Object.entries(NODE_STYLES).map(([type, style]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-sm inline-block border"
              style={{ background: style.bg, borderColor: style.border }}
            />
            {type}
          </div>
        ))}
      </div>

      {graphMode === "empty" ? (
        <div className="absolute inset-0 z-10 flex items-center justify-center pointer-events-none">
          <div className="rounded-lg border border-slate-700 bg-slate-900/90 px-4 py-3 text-sm text-slate-300">
            暂无图数据，等待工具结果写入图谱。
          </div>
        </div>
      ) : null}

      {graphMode === "single" ? (
        <div className="absolute inset-x-0 top-20 z-10 flex justify-center pointer-events-none">
          <div className="rounded-lg border border-amber-600/60 bg-amber-950/85 px-4 py-2 text-xs text-amber-200">
            当前仅收到单节点数据。若后端尚未返回关系边，图谱会暂时只显示一个点。
          </div>
        </div>
      ) : null}

      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
}
