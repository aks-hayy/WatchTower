import { createFileRoute } from "@tanstack/react-router";
import {
  fetchEvidenceGraphNeighborhood,
  fetchEvidenceGraphStatus,
  fetchTopology,
  materializeEvidenceGraph,
} from "@/lib/api.functions";
import { useEffect, useState } from "react";
import type { EvidenceGraphStatus, TopologyEdge, TopologyNode } from "@/types/watchtower";
import { useSensorScope } from "@/components/useSensorScope";

export const Route = createFileRoute("/topology")({
  head: () => ({ meta: [{ title: "Topology - Watchtower" }] }),
  loader: async () => {
    const [topology, graph] = await Promise.all([
      fetchTopology({ data: {} }),
      fetchEvidenceGraphStatus(),
    ]);
    return { ...(topology as { nodes: TopologyNode[]; edges: TopologyEdge[] }), graph };
  },
  component: TopologyPage,
});

function getColor(risk: number) {
  if (risk >= 80) return "#ef4444";
  if (risk >= 50) return "#f97316";
  if (risk >= 20) return "#f0b429";
  return "#38bdf8";
}

function TopologyPage() {
  const {
    nodes: initialNodes,
    edges: initialEdges,
    graph: initialGraph,
  } = Route.useLoaderData() as {
    nodes: TopologyNode[];
    edges: TopologyEdge[];
    graph: EvidenceGraphStatus;
  };
  const [topology, setTopology] = useState({ nodes: initialNodes, edges: initialEdges });
  const { nodes, edges } = topology;
  const { selectedNodeId } = useSensorScope();
  const [selected, setSelected] = useState<string | null>(null);
  const [graph, setGraph] = useState(initialGraph);
  const [graphDetail, setGraphDetail] = useState<{
    nodes: Record<string, unknown>[];
    edges: Record<string, unknown>[];
  } | null>(null);
  const [graphNotice, setGraphNotice] = useState("");
  const [materializing, setMaterializing] = useState(false);

  useEffect(() => {
    fetchTopology({ data: { node: selectedNodeId } })
      .then(setTopology)
      .catch((error) =>
        setGraphNotice(error instanceof Error ? error.message : "Topology query failed"),
      );
    setSelected(null);
  }, [selectedNodeId]);

  const degree = new Map<string, number>();
  edges.forEach((edge) => {
    degree.set(edge.data.source, (degree.get(edge.data.source) || 0) + 1);
    degree.set(edge.data.target, (degree.get(edge.data.target) || 0) + 1);
  });
  const visibleNodes = [...nodes]
    .sort(
      (left, right) =>
        right.data.risk - left.data.risk ||
        (degree.get(right.data.id) || 0) - (degree.get(left.data.id) || 0) ||
        left.data.id.localeCompare(right.data.id),
    )
    .slice(0, 48);
  const visibleIds = new Set(visibleNodes.map((node) => node.data.id));
  const visibleEdges = edges
    .filter((edge) => visibleIds.has(edge.data.source) && visibleIds.has(edge.data.target))
    .slice(0, 180);
  const positions = visibleNodes.map((_, index) => {
    const angle = index * 2.399963 - Math.PI / 2;
    const radius = 80 + Math.sqrt((index + 1) / Math.max(1, visibleNodes.length)) * 240;
    return {
      x: Number((500 + Math.cos(angle) * radius).toFixed(3)),
      y: Number((340 + Math.sin(angle) * radius).toFixed(3)),
    };
  });
  const nodeMap = new Map<string, number>(visibleNodes.map((node, index) => [node.data.id, index]));
  const selectedNode = selected ? visibleNodes.find((node) => node.data.id === selected) : null;

  useEffect(() => {
    if (!selected || !graph.available) {
      setGraphDetail(null);
      return;
    }
    fetchEvidenceGraphNeighborhood({
      data: { ip: selected, node: selectedNodeId, depth: 2, limit: 40 },
    })
      .then((value) => setGraphDetail({ nodes: value.nodes, edges: value.edges }))
      .catch((error) =>
        setGraphNotice(error instanceof Error ? error.message : "Evidence graph query failed"),
      );
  }, [selected, selectedNodeId, graph.available]);

  const materialize = async () => {
    setMaterializing(true);
    setGraphNotice("");
    try {
      const result = await materializeEvidenceGraph({ data: { limit: 500 } });
      setGraph(result);
      setGraphNotice(
        result.available
          ? `${result.materialized} pending graph event(s) materialized`
          : String(result.reason || "Evidence graph is unavailable"),
      );
    } catch (error) {
      setGraphNotice(error instanceof Error ? error.message : "Graph materialization failed");
    } finally {
      setMaterializing(false);
    }
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex flex-wrap items-center gap-4 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">TOP</span>
          <span className="text-foreground">/ Signal Graph</span>
          <span className="text-muted-foreground">
            {nodes.length} nodes / {edges.length} edges
          </span>
          <span className={`text-[10px] ${graph.available ? "text-ok" : "text-muted-foreground"}`}>
            graph {graph.available ? graph.freshness : "sqlite fallback"}
          </span>
          <button
            onClick={materialize}
            disabled={materializing || !graph.enabled}
            title={
              graph.enabled
                ? "Materialize pending evidence graph facts"
                : "Configure Neo4j before materializing graph facts"
            }
            className="ml-auto h-7 border border-border px-2 mono text-[9px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-35"
          >
            {materializing ? "Syncing" : "Sync Graph"}
          </button>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-px bg-border">
        <div className="col-span-12 bg-background p-4 lg:col-span-9">
          <div className="relative min-h-[420px] panel-flat grid-bg bracket md:min-h-[680px]">
            <svg viewBox="0 0 1000 680" className="h-full w-full">
              {[120, 200, 280, 360].map((radius) => (
                <circle
                  key={radius}
                  cx="500"
                  cy="340"
                  r={radius}
                  fill="none"
                  stroke="#1e2a38"
                  strokeDasharray="2 4"
                />
              ))}
              <line x1="500" y1="0" x2="500" y2="680" stroke="#1e2a38" strokeDasharray="2 4" />
              <line x1="0" y1="340" x2="1000" y2="340" stroke="#1e2a38" strokeDasharray="2 4" />
              {visibleEdges.map((edge, index) => {
                const sourceIndex = nodeMap.get(edge.data.source);
                const targetIndex = nodeMap.get(edge.data.target);
                if (sourceIndex === undefined || targetIndex === undefined) return null;
                return (
                  <line
                    key={`${edge.data.source}-${edge.data.target}-${index}`}
                    x1={positions[sourceIndex].x}
                    y1={positions[sourceIndex].y}
                    x2={positions[targetIndex].x}
                    y2={positions[targetIndex].y}
                    stroke="#38bdf8"
                    strokeOpacity={0.18}
                    strokeWidth={0.8}
                  />
                );
              })}
              {visibleNodes.map((node, index) => {
                const color = getColor(node.data.risk);
                const isSelected = node.data.id === selected;
                return (
                  <g
                    key={node.data.id}
                    transform={`translate(${positions[index].x}, ${positions[index].y})`}
                    onClick={() => setSelected(node.data.id)}
                    className="cursor-pointer"
                  >
                    {isSelected && <circle r={20} fill="none" stroke={color} strokeOpacity={0.6} />}
                    <circle
                      r={6 + node.data.risk * 0.05}
                      fill={color}
                      fillOpacity={0.25}
                      stroke={color}
                      strokeWidth={1}
                    />
                    <circle r={2.5} fill={color} />
                    {isSelected && (
                      <text
                        y={-14}
                        textAnchor="middle"
                        fill="#cfd6e0"
                        fontSize={10}
                        fontFamily="IBM Plex Mono"
                      >
                        {node.data.label.length > 28
                          ? `${node.data.label.slice(0, 25)}...`
                          : node.data.label}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
            <div className="pointer-events-none absolute left-3 top-3 mono text-[10px] uppercase tracking-wider text-signal/70">
              GRID_ALPHA / 200m rings
            </div>
            <div className="pointer-events-none absolute right-3 top-3 mono text-[10px] uppercase tracking-wider text-muted-foreground">
              {graph.available ? "EVIDENCE GRAPH" : "SQLITE SNAPSHOT"}
            </div>
          </div>
        </div>

        <div className="col-span-12 bg-background lg:col-span-3">
          <div className="border-b border-border px-4 py-3">
            <div className="section-label">/ INSPECTOR</div>
            <div className="text-sm tracking-tight text-foreground">Node Detail</div>
          </div>
          {selectedNode ? (
            <div className="space-y-4 p-4">
              <InspectorField label="HOSTNAME" value={selectedNode.data.label} />
              <InspectorField label="IP" value={selectedNode.data.id} accent />
              <InspectorField label="TYPE" value={selectedNode.data.type} />
              <div>
                <div className="section-label">INVESTIGATION PRIORITY</div>
                <div className="mt-1 flex items-baseline gap-2">
                  <span
                    className="numeral text-3xl"
                    style={{ color: getColor(selectedNode.data.risk) }}
                  >
                    {selectedNode.data.risk}
                  </span>
                  <span className="mono text-[10px] uppercase text-muted-foreground">/100</span>
                </div>
                <div className="mt-2 h-[3px] bg-border">
                  <div
                    className="h-full"
                    style={{
                      width: `${selectedNode.data.risk}%`,
                      background: getColor(selectedNode.data.risk),
                    }}
                  />
                </div>
              </div>
              <div>
                <div className="section-label">EVIDENCE GRAPH</div>
                {graph.available ? (
                  <div className="mt-1 mono text-[11px] text-foreground">
                    {graphDetail
                      ? `${graphDetail.nodes.length} facts / ${graphDetail.edges.length} relationships`
                      : "Loading neighborhood"}
                  </div>
                ) : (
                  <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                    Graph projection is not configured. This inspector is showing the durable SQLite
                    flow projection.
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="p-4 mono text-[11px] uppercase tracking-wider text-muted-foreground">
              Select a node in the viewport
            </div>
          )}
          {graphNotice && (
            <div className="border-t border-border px-4 py-3 mono text-[10px] leading-relaxed text-muted-foreground">
              {graphNotice}
            </div>
          )}
          <div className="border-t border-border px-4 py-3">
            <div className="section-label mb-2">/ LEGEND</div>
            <div className="space-y-1.5 mono text-[11px]">
              {[
                ["LOW", "#38bdf8", "0-19"],
                ["MEDIUM", "#f0b429", "20-49"],
                ["HIGH", "#f97316", "50-79"],
                ["CRITICAL", "#ef4444", "80+"],
              ].map(([label, color, range]) => (
                <div key={label} className="flex items-center gap-2">
                  <span className="h-2 w-2" style={{ background: color }} />
                  <span className="w-20 text-foreground">{label}</span>
                  <span className="text-muted-foreground">{range}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function InspectorField({
  label,
  value,
  accent = false,
}: {
  label: string;
  value: string;
  accent?: boolean;
}) {
  return (
    <div>
      <div className="section-label">{label}</div>
      <div
        className={`mt-1 break-all text-[12px] ${accent ? "mono text-signal" : "text-foreground"}`}
      >
        {value}
      </div>
    </div>
  );
}
