import cytoscape, { type Core } from "cytoscape";
import { Pause, Play, RotateCcw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { PcapTimelineData, PcapTopologyData } from "@/lib/pcap";

function timeLabel(value: number) {
  if (!value) return "--:--:--";
  return new Date(value * 1000).toLocaleTimeString();
}

export function PcapTemporalTopology({
  topology,
  timeline,
  findingTargets,
}: {
  topology: PcapTopologyData;
  timeline: PcapTimelineData;
  findingTargets: string[];
}) {
  const host = useRef<HTMLDivElement>(null);
  const graph = useRef<Core | null>(null);
  const start = Number(timeline.start_time || 0);
  const end = Number(timeline.end_time || start);
  const [position, setPosition] = useState(end);
  const [playing, setPlaying] = useState(false);
  const [mode, setMode] = useState<"cumulative" | "active">("cumulative");
  const [speed, setSpeed] = useState(4);
  const [protocol, setProtocol] = useState("all");
  const [entity, setEntity] = useState("");
  const [findingsOnly, setFindingsOnly] = useState(false);
  const [visibleCount, setVisibleCount] = useState(0);
  const targetSet = useMemo(() => new Set(findingTargets), [findingTargets]);
  const protocols = useMemo(
    () =>
      Array.from(
        new Set(topology.edges.map((edge) => String(edge.data.protocol || "OTHER"))),
      ).sort(),
    [topology],
  );

  useEffect(() => setPosition(end), [end]);

  useEffect(() => {
    if (!host.current || graph.current) return;
    graph.current = cytoscape({
      container: host.current,
      elements: [...topology.nodes, ...topology.edges] as cytoscape.ElementDefinition[],
      minZoom: 0.15,
      maxZoom: 3,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#42d8a1",
            "border-color": "#101b1c",
            "border-width": 2,
            color: "#e6f0ed",
            label: "",
            "font-family": "ui-monospace, monospace",
            "font-size": 9,
            "text-valign": "bottom",
            "text-margin-y": 7,
            "text-outline-color": "#091112",
            "text-outline-width": 2,
            width: 22,
            height: 22,
          },
        },
        {
          selector: "edge",
          style: {
            width: "mapData(bytes, 0, 10000000, 1, 5)",
            "line-color": "#385454",
            "target-arrow-color": "#42d8a1",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            opacity: 0.62,
          },
        },
        {
          selector: "node.finding",
          style: {
            "background-color": "#ffb84d",
            "border-color": "#ff695e",
            width: 30,
            height: 30,
          },
        },
        {
          selector: "edge.selected-time",
          style: { "line-color": "#42d8a1", opacity: 0.9 },
        },
      ],
      layout: {
        name: topology.nodes.length > 250 ? "grid" : "cose",
        animate: false,
        fit: true,
        padding: 32,
        nodeRepulsion: () => 9000,
        idealEdgeLength: () => 90,
      },
    });
    const updateLabels = () => {
      const showLabels = (graph.current?.zoom() ?? 0) >= 0.85;
      graph.current?.nodes().forEach((node) => {
        node.style("label", showLabels ? String(node.data("label") || node.id()) : "");
      });
    };
    graph.current.on("zoom", updateLabels);
    updateLabels();
    return () => {
      graph.current?.removeListener("zoom", updateLabels);
      graph.current?.destroy();
      graph.current = null;
    };
  }, [topology]);

  useEffect(() => {
    const cy = graph.current;
    if (!cy) return;
    const needle = entity.trim().toLowerCase();
    const visibleNodes = new Set<string>();
    let visibleEdges = 0;
    cy.edges().forEach((edge) => {
      const first = Number(edge.data("first_seen") || 0);
      const last = Number(edge.data("last_seen") || first);
      const source = String(edge.data("source"));
      const target = String(edge.data("target"));
      const inTime =
        mode === "cumulative" ? first <= position : first <= position && last >= position;
      const inProtocol = protocol === "all" || String(edge.data("protocol")) === protocol;
      const inEntity =
        !needle || source.toLowerCase().includes(needle) || target.toLowerCase().includes(needle);
      const inFinding = !findingsOnly || targetSet.has(source) || targetSet.has(target);
      const show = inTime && inProtocol && inEntity && inFinding;
      edge.style("display", show ? "element" : "none");
      edge.toggleClass("selected-time", show);
      if (show) {
        visibleEdges += 1;
        visibleNodes.add(source);
        visibleNodes.add(target);
      }
    });
    cy.nodes().forEach((node) => {
      node.style("display", visibleNodes.has(node.id()) ? "element" : "none");
      node.toggleClass("finding", targetSet.has(node.id()));
    });
    setVisibleCount(visibleEdges);
  }, [entity, findingsOnly, mode, position, protocol, targetSet]);

  useEffect(() => {
    if (!playing || end <= start) return;
    const span = Math.max(1, end - start);
    const timer = window.setInterval(() => {
      setPosition((current) => {
        const next = current + Math.max(0.2, span / 600) * speed;
        if (next >= end) {
          setPlaying(false);
          return end;
        }
        return next;
      });
    }, 100);
    return () => window.clearInterval(timer);
  }, [end, playing, speed, start]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 border-b border-border pb-3">
        <button
          title={playing ? "Pause topology playback" : "Play topology playback"}
          onClick={() => {
            if (position >= end) setPosition(start);
            setPlaying((value) => !value);
          }}
          className="grid h-8 w-8 place-items-center border border-border text-foreground hover:border-signal hover:text-signal"
        >
          {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
        </button>
        <button
          title="Reset playback"
          onClick={() => {
            setPlaying(false);
            setPosition(start);
          }}
          className="grid h-8 w-8 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
        >
          <RotateCcw className="h-3.5 w-3.5" />
        </button>
        <select
          value={mode}
          onChange={(event) => setMode(event.target.value as typeof mode)}
          className="h-8 border border-border bg-background px-2 mono text-[10px] uppercase text-foreground"
        >
          <option value="cumulative">Cumulative</option>
          <option value="active">Active only</option>
        </select>
        <select
          value={protocol}
          onChange={(event) => setProtocol(event.target.value)}
          className="h-8 border border-border bg-background px-2 mono text-[10px] uppercase text-foreground"
        >
          <option value="all">All protocols</option>
          {protocols.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <select
          value={speed}
          onChange={(event) => setSpeed(Number(event.target.value))}
          className="h-8 border border-border bg-background px-2 mono text-[10px] text-foreground"
        >
          {[1, 2, 4, 8, 16].map((item) => (
            <option key={item} value={item}>
              {item}x
            </option>
          ))}
        </select>
        <input
          value={entity}
          onChange={(event) => setEntity(event.target.value)}
          placeholder="Filter entity"
          className="h-8 min-w-40 border border-border bg-background px-2 mono text-[10px] text-foreground outline-none focus:border-signal"
        />
        <label className="flex h-8 items-center gap-2 border border-border px-2 mono text-[10px] uppercase text-muted-foreground">
          <input
            type="checkbox"
            checked={findingsOnly}
            onChange={(event) => setFindingsOnly(event.target.checked)}
            className="accent-signal"
          />
          Finding entities
        </label>
        <span className="ml-auto mono text-[10px] text-muted-foreground">
          {visibleCount.toLocaleString()} conversations visible
          {topology.analyst_omitted_conversations
            ? ` · ${topology.analyst_omitted_conversations.toLocaleString()} lower-priority conversations omitted`
            : ""}
        </span>
      </div>
      <div ref={host} className="h-[56vh] min-h-96 w-full bg-background grid-bg-fine" />
      <div className="grid grid-cols-[auto_1fr_auto] items-center gap-3">
        <span className="mono text-[10px] text-muted-foreground">{timeLabel(start)}</span>
        <input
          aria-label="Topology playback time"
          type="range"
          min={start}
          max={Math.max(start, end)}
          step={Math.max(0.01, (end - start) / 1000)}
          value={position}
          onChange={(event) => {
            setPlaying(false);
            setPosition(Number(event.target.value));
          }}
          className="w-full accent-signal"
        />
        <span className="mono text-[10px] text-signal">{timeLabel(position)}</span>
      </div>
    </div>
  );
}
