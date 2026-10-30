import Globe, { type GlobeInstance } from "globe.gl";
import { useEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/format";

export interface GlobeArc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  severity: string;
  count: number;
  bytes: number;
  srcCity?: string | null;
  dstCity?: string | null;
  srcCountry?: string | null;
  dstCountry?: string | null;
}

export interface GlobeNode {
  name: string;
  country?: string | null;
  lat: number;
  lng: number;
  volume: number;
  connections: number;
  severity: string;
}

const severityColor: Record<string, string> = {
  critical: "#FF5C7A",
  high: "#F5B84B",
  medium: "#4BA3FF",
  low: "#3DDC97",
  informational: "#8497b0",
};

function hasWebGL(): boolean {
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("webgl2") ?? canvas.getContext("webgl"));
  } catch {
    return false;
  }
}

export function GlobeView({
  arcs,
  nodes,
  className,
  height = 440,
  interactive = true,
  autoRotate = true,
  showAtmosphere = true,
  onSelect,
  demo = false,
}: {
  arcs: GlobeArc[];
  nodes: GlobeNode[];
  className?: string;
  height?: number | string;
  interactive?: boolean;
  autoRotate?: boolean;
  showAtmosphere?: boolean;
  onSelect?: (node: GlobeNode) => void;
  demo?: boolean;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const globeRef = useRef<GlobeInstance | undefined>(undefined);
  const [webgl, setWebgl] = useState<boolean | null>(null);
  const [ready, setReady] = useState(false);

  const reducedMotion = useMemo(
    () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    [],
  );

  useEffect(() => {
    setWebgl(hasWebGL());
  }, []);

  useEffect(() => {
    if (!webgl || !containerRef.current) return;
    const element = containerRef.current;
    const globe = new Globe(element)
      .globeImageUrl("/textures/earth-dark.jpg")
      .bumpImageUrl("/textures/earth-topology.png")
      .backgroundColor("rgba(0,0,0,0)")
      .showAtmosphere(showAtmosphere)
      .atmosphereColor("#2fbfb8")
      .atmosphereAltitude(0.16)
      .arcStroke(0.55)
      .arcAltitudeAutoScale(0.32)
      .arcDashLength(0.42)
      .arcDashGap(1.4)
      .arcDashAnimateTime(reducedMotion ? 0 : 3200)
      .arcsTransitionDuration(300)
      .pointAltitude(0.004)
      .pointRadius((point: object) => {
        const node = point as GlobeNode;
        return 0.14 + Math.min(0.42, Math.log10(Math.max(10, node.volume)) * 0.055);
      })
      .pointColor((point: object) => severityColor[(point as GlobeNode).severity] ?? "#36D9D0")
      .pointLabel((point: object) => {
        const node = point as GlobeNode;
        return `<div style="font-family:Inter,sans-serif;font-size:11px;color:#dbe6f5;background:rgba(11,18,32,.94);border:1px solid rgba(148,163,184,.2);padding:6px 8px;border-radius:6px;white-space:nowrap">
          <strong style="color:#7FF0EA">${node.name}</strong>${node.country ? ` · ${node.country}` : ""}<br/>
          ${node.connections.toLocaleString()} connections
        </div>`;
      })
      .ringColor(() => (t: number) => `rgba(54,217,208,${Math.max(0, 0.55 - t)})`)
      .ringMaxRadius(2.4)
      .ringPropagationSpeed(1.1)
      .ringRepeatPeriod(reducedMotion ? 0 : 1600);

    globe.controls().autoRotate = autoRotate && !reducedMotion;
    globe.controls().autoRotateSpeed = 0.38;
    globe.controls().enableZoom = interactive;
    globe.controls().enablePan = false;
    globe.controls().minDistance = 180;
    globe.controls().maxDistance = 520;
    if (!interactive) globe.controls().enabled = false;

    globe.pointOfView({ lat: 26, lng: 12, altitude: 2.15 }, 0);
    globe.onGlobeReady(() => setReady(true));
    globeRef.current = globe;

    return () => {
      (globe as unknown as { _destructor?: () => void })._destructor?.();
      globeRef.current = undefined;
    };
    // Recreate only if the WebGL availability or atmosphere mode changes.
  }, [webgl, interactive, autoRotate, reducedMotion, showAtmosphere]);

  useEffect(() => {
    const globe = globeRef.current;
    if (!globe) return;
    globe
      .pointsData(nodes)
      .arcsData(arcs)
      .ringsData(
        nodes
          .filter((node) => node.severity === "critical" || node.severity === "high")
          .map((node) => ({ lat: node.lat, lng: node.lng })),
      )
      .arcColor((arc: object) => {
        const value = arc as GlobeArc;
        const color = severityColor[value.severity] ?? "#36D9D0";
        return [color, color];
      })
      .onPointClick((point: object) => onSelect?.(point as GlobeNode));
  }, [nodes, arcs, onSelect]);

  if (webgl === false) {
    return (
      <div
        className={cn("relative overflow-hidden rounded-xl border border-white/[0.07] bg-ink-900/60", className)}
        style={{ height }}
      >
        <div className="absolute inset-0 grid-faint opacity-40" />
        <div className="relative flex h-full flex-col items-center justify-center px-6 text-center">
          <p className="label mb-2">2D fallback</p>
          <p className="max-w-sm text-[12.5px] leading-relaxed text-slate-400">
            This browser does not expose WebGL, so the 3D globe is disabled. All geographic evidence remains available
            in the connection table and detector workspaces.
          </p>
          {demo ? <p className="mt-3 text-[11px] text-slate-500">Illustrative demo topology — not live geolocation.</p> : null}
        </div>
      </div>
    );
  }

  return (
    <div className={cn("relative overflow-hidden rounded-xl", className)} style={{ height }}>
      <div ref={containerRef} className="absolute inset-0" aria-label="Interactive connection globe" role="img" />
      {!ready ? (
        <div className="absolute inset-0 flex items-center justify-center bg-ink-900/40">
          <div className="h-9 w-9 animate-spin rounded-full border border-accent/20 border-t-accent/80" />
        </div>
      ) : null}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-16 bg-gradient-to-t from-ink-900/60 to-transparent" />
      {demo ? (
        <div className="absolute left-3 top-3 rounded-md border border-white/10 bg-ink-900/80 px-2 py-1 text-[10px] font-medium uppercase tracking-[0.12em] text-slate-400 backdrop-blur">
          Illustrative synthetic topology
        </div>
      ) : null}
      <div className="absolute bottom-3 left-3 flex items-center gap-3 text-[10px] text-slate-500">
        {["critical", "high", "medium", "low"].map((severity) => (
          <span key={severity} className="inline-flex items-center gap-1.5 capitalize">
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: severityColor[severity] }} />
            {severity}
          </span>
        ))}
      </div>
    </div>
  );
}
