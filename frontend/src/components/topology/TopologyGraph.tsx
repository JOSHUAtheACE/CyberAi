import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { Maximize2, RotateCcw, Tags } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { TopologyEdge, TopologyNode } from "@/lib/types";
import { cn } from "@/lib/format";

const severityColor: Record<string, string> = {
  critical: "#FF5C7A",
  high: "#F5B84B",
  medium: "#4BA3FF",
  low: "#3DDC97",
};

export function TopologyGraph({
  nodes,
  edges,
  height = 520,
  className,
  onSelect,
  selectedId,
}: {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  height?: number | string;
  className?: string;
  onSelect?: (node: TopologyNode | null) => void;
  selectedId?: string | null;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [showLabels, setShowLabels] = useState(true);

  const elements = useMemo<ElementDefinition[]>(() => {
    const nodeIds = new Set(nodes.map((node) => node.id));
    const nodeElements = nodes.map((node) => {
      const severity = node.severity ?? "informational";
      return {
        data: {
          id: node.id,
          label: node.label,
          internal: node.internal,
          threat: node.threat,
          severity,
          alerts: node.alerts,
          color: node.threat ? severityColor[severity] ?? "#F5B84B" : node.internal ? "#4BA3FF" : "#64748B",
        },
        classes: [node.internal ? "internal" : "external", node.threat ? "threat" : "", `sev-${severity}`]
          .filter(Boolean)
          .join(" "),
      };
    });
    const edgeElements = edges
      .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
      .map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          protocol: edge.protocol,
          suspicious: edge.suspicious,
          flows: edge.flows,
          bytes: edge.bytes,
        },
        classes: edge.suspicious ? "suspicious" : "",
      }));
    return [...nodeElements, ...edgeElements];
  }, [nodes, edges]);

  useEffect(() => {
    if (!containerRef.current) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      wheelSensitivity: 0.18,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            width: "mapData(flows, 0, 600, 11, 30)",
            height: "mapData(flows, 0, 600, 11, 30)",
            "border-width": 1,
            "border-color": "rgba(148,163,184,0.35)",
            label: showLabels ? "data(label)" : "",
            color: "#a9b7ca",
            "font-size": 8,
            "font-family": "JetBrains Mono, monospace",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "text-outline-color": "#070B14",
            "text-outline-width": 2,
            "overlay-opacity": 0,
          },
        },
        { selector: "node.threat", style: { "border-width": 2, "border-color": "#FF5C7A" } },
        { selector: "node:selected", style: { "border-width": 3, "border-color": "#7FF0EA" } },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "rgba(148,163,184,0.20)",
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "rgba(148,163,184,0.28)",
            "arrow-scale": 0.6,
            "overlay-opacity": 0,
          },
        },
        {
          selector: "edge.suspicious",
          style: {
            width: 1.8,
            "line-color": "rgba(255,92,122,0.55)",
            "target-arrow-color": "rgba(255,92,122,0.6)",
            "line-style": "dashed",
          },
        },
      ],
      layout: {
        name: "cose",
        animate: !reduced,
        animationDuration: 400,
        fit: true,
        padding: 30,
        nodeRepulsion: 12000,
        idealEdgeLength: 80,
        gravity: 0.22,
        randomize: false,
      } as cytoscape.LayoutOptions,
      minZoom: 0.25,
      maxZoom: 3,
    });

    cy.on("tap", "node", (event) => {
      const id = event.target.id();
      const node = nodes.find((item) => item.id === id) ?? null;
      onSelect?.(node);
    });
    cy.on("tap", (event) => {
      if (event.target === cy) onSelect?.(null);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
    // Elements are applied via diff effect below.
  }, [elements, nodes, onSelect, showLabels]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().style("label", showLabels ? "data(label)" : "");
  }, [showLabels]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.$("node").unselect();
    if (selectedId) cy.$id(selectedId).select();
  }, [selectedId]);

  return (
    <div className={cn("relative overflow-hidden rounded-xl border border-white/[0.06] bg-ink-900/50", className)}>
      <div ref={containerRef} style={{ height }} className="w-full" aria-label="Network topology graph" role="img" />
      <div className="absolute right-2.5 top-2.5 flex items-center gap-1 rounded-lg border border-white/10 bg-ink-900/85 p-1 backdrop-blur">
        <button
          type="button"
          className="rounded p-1.5 text-slate-400 transition-colors hover:bg-white/[0.06] hover:text-slate-200"
          aria-label="Fit graph to view"
          title="Fit to view"
          onClick={() => cyRef.current?.fit(undefined, 30)}
        >
          <Maximize2 className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          className="rounded p-1.5 text-slate-400 transition-colors hover:bg-white/[0.06] hover:text-slate-200"
          aria-label="Reset layout"
          title="Re-run layout"
          onClick={() => {
            cyRef.current
              ?.layout({ name: "cose", animate: false, padding: 30, nodeRepulsion: 12000, idealEdgeLength: 80 } as cytoscape.LayoutOptions)
              .run();
          }}
        >
          <RotateCcw className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          className={cn(
            "rounded p-1.5 transition-colors hover:bg-white/[0.06]",
            showLabels ? "text-accent-soft" : "text-slate-500 hover:text-slate-200",
          )}
          aria-label={showLabels ? "Hide node labels" : "Show node labels"}
          title={showLabels ? "Hide labels" : "Show labels"}
          aria-pressed={showLabels}
          onClick={() => setShowLabels((value) => !value)}
        >
          <Tags className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="pointer-events-none absolute bottom-2.5 left-2.5 flex items-center gap-3 rounded-md border border-white/[0.07] bg-ink-900/80 px-2.5 py-1.5 text-[10px] text-slate-500 backdrop-blur">
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-signal-blue" /> Internal
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-slate-500" /> External
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full border border-signal-rose" /> Threat-linked
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-px w-4 border-t border-dashed border-signal-rose/70" /> Suspicious flow
        </span>
      </div>
    </div>
  );
}
