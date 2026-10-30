import { useQuery } from "@tanstack/react-query";
import {
  ArrowDownToLine,
  ArrowRight,
  ArrowUpFromLine,
  Flame,
  Globe2,
  Map as MapIcon,
  ShieldAlert,
  Sparkles,
  Waves,
  Zap,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTable, ChartPanel } from "@/components/app";
import { GlobeView } from "@/components/globe/GlobeView";
import {
  Badge,
  EmptyState,
  ErrorState,
  InfoHint,
  PageHeader,
  PageLoader,
  Panel,
  SeverityBadge,
} from "@/components/ui";
import {
  DonutCard,
  RankList,
  Ring,
  SparkKpi,
  TONES,
  WorldThreatMap,
  severityColor,
} from "@/components/visuals";
import { useAuth } from "@/context/AuthContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { barOption, lineOption, paletteCycle, shortBucket } from "@/lib/charts";
import { cn, formatBytes, formatDateTime, formatNumber, relativeTime, titleCase } from "@/lib/format";
import type {
  AiOverview,
  DetectionCatalogResponse,
  GeoResponse,
  Insight,
  OverviewResponse,
  SystemStatus,
  ThreatsResponse,
  TrafficResponse,
} from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

const DETECTOR_LABEL: Record<string, string> = {
  port_scan_detector: "Port scanning",
  exfiltration_detector: "Exfiltration",
  dns_detector: "DNS anomaly",
  beaconing_detector: "C2 beaconing",
  encrypted_metadata_detector: "TLS metadata",
  ddos_detector: "Volumetric DDoS",
};

function f1Color(value: number): string {
  if (value >= 0.9) return TONES.mint;
  if (value >= 0.8) return TONES.accent;
  if (value >= 0.7) return TONES.amber;
  return TONES.rose;
}

function InsightCard({ insight }: { insight: Insight }) {
  const color = severityColor(insight.severity);
  return (
    <div className="relative overflow-hidden rounded-lg border border-white/[0.06] bg-ink-900/50 py-2.5 pl-3.5 pr-3">
      <span className="absolute inset-y-2 left-0 w-[2px] rounded-full" style={{ background: color, boxShadow: `0 0 8px ${color}80` }} />
      <div className="flex items-start justify-between gap-2">
        <p className="text-[11.5px] font-medium leading-snug text-slate-200">{insight.title}</p>
        <SeverityBadge severity={insight.severity} />
      </div>
      <p className="mt-1 line-clamp-2 text-[10.5px] leading-relaxed text-slate-500">{insight.body}</p>
      <div className="mt-2 flex items-center justify-between gap-2">
        {insight.confidence !== null && insight.confidence !== undefined ? (
          <span className="flex min-w-0 flex-1 items-center gap-1.5">
            <span className="h-[3px] w-16 overflow-hidden rounded-full bg-white/[0.06]">
              <span
                className="block h-full rounded-full"
                style={{ width: `${Math.max(3, Math.min(100, insight.confidence * 100))}%`, background: color }}
              />
            </span>
            <span className="font-mono text-[9px] text-slate-500">{insight.confidence.toFixed(2)}</span>
          </span>
        ) : (
          <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-slate-600">
            {insight.grounded ? "evidence-linked" : "observation"}
          </span>
        )}
        {insight.alert_id ? (
          <Link to={`/app/alerts/${insight.alert_id}`} className="shrink-0 text-[10px] text-accent-soft hover:underline">
            open alert
          </Link>
        ) : null}
      </div>
    </div>
  );
}

export function Overview() {
  const { hasPermission } = useAuth();
  const { workspaceSlug, range, workspace, isDemo } = useWorkspace();
  const [selectedLocation, setSelectedLocation] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [mapMode, setMapMode] = useState<"map" | "globe">("map");

  const overview = useQuery({
    queryKey: ["overview", workspaceSlug, range],
    queryFn: () => api.get<OverviewResponse>("/dashboard/overview", { workspace: workspaceSlug, range }),
  });
  const traffic = useQuery({
    queryKey: ["traffic", workspaceSlug, range],
    queryFn: () => api.get<TrafficResponse>("/dashboard/traffic", { workspace: workspaceSlug, range }),
  });
  const geo = useQuery({
    queryKey: ["geo", workspaceSlug, range],
    queryFn: () => api.get<GeoResponse>("/dashboard/geo", { workspace: workspaceSlug, range }),
  });
  const threats = useQuery({
    queryKey: ["threats", workspaceSlug, range],
    queryFn: () => api.get<ThreatsResponse>("/dashboard/threats", { workspace: workspaceSlug, range }),
  });
  const status = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>("/system/status"),
    staleTime: 60_000,
  });
  const catalog = useQuery({
    queryKey: ["detections-catalog"],
    queryFn: () => api.get<DetectionCatalogResponse>("/detections"),
    enabled: hasPermission("detections.view"),
    staleTime: 120_000,
  });
  const ai = useQuery({
    queryKey: ["ai-overview"],
    queryFn: () => api.get<AiOverview>("/ai/overview"),
    enabled: hasPermission("ai.view"),
    staleTime: 120_000,
  });

  const data = overview.data;
  const timeline = traffic.data?.timeline ?? [];
  const trend = threats.data?.trend ?? [];

  const filteredArcs = useMemo(() => {
    if (!geo.data) return [];
    if (!severityFilter.length) return geo.data.arcs;
    return geo.data.arcs.filter((arc) => severityFilter.includes(arc.severity));
  }, [geo.data, severityFilter]);

  const trafficOption = useMemo(
    () =>
      lineOption({
        labels: timeline.map((point) => shortBucket(point.bucket)),
        series: [
          { name: "Inbound", data: timeline.map((point) => point.bytes_in_mib), area: true, color: paletteCycle[0] },
          { name: "Outbound", data: timeline.map((point) => point.bytes_out_mib), area: true, color: paletteCycle[1] },
        ],
        yFormatter: (value) => `${formatNumber(value, 1)} MiB`,
      }),
    [timeline],
  );

  const trendOption = useMemo(
    () =>
      barOption({
        labels: trend.map((point) => shortBucket(point.bucket)),
        series: [
          { name: "Critical", data: trend.map((point) => point.critical), stack: "alerts", color: TONES.rose },
          { name: "High", data: trend.map((point) => point.high), stack: "alerts", color: TONES.amber },
          { name: "Medium", data: trend.map((point) => point.medium), stack: "alerts", color: TONES.blue },
          { name: "Low", data: trend.map((point) => point.low), stack: "alerts", color: TONES.mint },
        ],
        yFormatter: (value) => formatNumber(value),
      }),
    [trend],
  );

  if (overview.isLoading) return <PageLoader label="Computing workspace metrics" />;
  if (overview.isError) {
    return (
      <ErrorState
        message={overview.error instanceof Error ? overview.error.message : "Metrics could not be loaded."}
        retry={() => overview.refetch()}
      />
    );
  }
  if (!data) return null;

  const kpi = (key: string) => data.kpis.find((item) => item.key === key);
  const value = (key: string, digits = 0) => {
    const item = kpi(key);
    return item?.value === null || item?.value === undefined ? "—" : formatNumber(item.value, digits);
  };
  const spark = (selector: (point: TrafficResponse["timeline"][number]) => number) =>
    timeline.length > 1 ? timeline.map(selector) : undefined;
  const trendSpark = (selector: (point: ThreatsResponse["trend"][number]) => number) =>
    trend.length > 1 ? trend.map(selector) : undefined;

  const locationNode = geo.data?.nodes.find((node) => node.name === selectedLocation) ?? null;
  const enabledDetectors = catalog.data?.modules.filter((module) => module.enabled).length ?? null;
  const detectorTotal = catalog.data?.modules.length ?? null;
  const models = [...(ai.data?.models ?? [])].sort((a, b) => b.metrics_summary.f1 - a.metrics_summary.f1).slice(0, 4);
  const collectors = data.sources;
  const unknownEndpoints =
    (geo.data?.unknown_locations.source_without_location ?? 0) + (geo.data?.unknown_locations.destination_without_location ?? 0);
  const geoConfigured = status.data?.geo.configured ?? false;
  const geoLabel = geo.data?.demo_geo
    ? "demo fixtures"
    : geoConfigured
      ? status.data?.geo.provider ?? "configured"
      : "not configured";
  const geoSourceInfo = geo.data?.geo.accuracy_notice ?? status.data?.geo.accuracy_notice;
  const lastFlow = status.data?.last_flow_at;
  const lastFlowFresh = lastFlow ? Date.now() - new Date(lastFlow).getTime() < 2 * 60 * 60 * 1000 : false;

  return (
    <div>
      <PageHeader
        eyebrow={`${data.workspace.environment} · ${isDemo ? "synthetic scenarios" : "passive capture"}`}
        title={workspace?.name ?? "Workspace overview"}
        description={`Computed on request from stored telemetry · ${data.range.label} · all times UTC. Nothing below is simulated at render time.`}
        actions={
          <>
            <span className="hidden font-mono text-[10px] text-slate-600 md:inline">
              {relativeTime(data.generated_at)}
            </span>
            <Link to="/app/reports" className="btn-secondary h-8">
              Reports
            </Link>
            <Link to="/app/alerts" className="btn-primary h-8">
              Alert centre
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </>
        }
      />

      {!data.has_data ? (
        <div className="mb-4 rounded-lg border border-signal-amber/20 bg-signal-amber/[0.05] px-4 py-2.5 text-[11.5px] leading-relaxed text-amber-200/80">
          No flows or alerts fall inside this window. Metrics stay at zero rather than being estimated — widen the range, start a
          replay, or upload a capture.
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-6">
        <SparkKpi
          label="Inbound"
          value={value("bandwidth_in", 2)}
          unit="Mbps"
          icon={ArrowDownToLine}
          tone="blue"
          delta={kpi("bandwidth_in")?.comparison ?? null}
          help={kpi("bandwidth_in")?.help}
          spark={spark((point) => point.bytes_in_mib)}
          sparkColor={TONES.blue}
        />
        <SparkKpi
          label="Outbound"
          value={value("bandwidth_out", 2)}
          unit="Mbps"
          icon={ArrowUpFromLine}
          tone="accent"
          delta={kpi("bandwidth_out")?.comparison ?? null}
          help={kpi("bandwidth_out")?.help}
          spark={spark((point) => point.bytes_out_mib)}
        />
        <SparkKpi
          label="Flows"
          value={value("flows")}
          unit="records"
          icon={Waves}
          tone="violet"
          delta={kpi("flows")?.comparison ?? null}
          help={kpi("flows")?.help}
          spark={spark((point) => point.flows)}
          sparkColor={TONES.violet}
        />
        <SparkKpi
          label="Packets / s"
          value={value("pps", 1)}
          unit="pps"
          icon={Zap}
          tone="amber"
          delta={kpi("pps")?.comparison ?? null}
          help={kpi("pps")?.help}
          spark={spark((point) => point.pps)}
          sparkColor={TONES.amber}
        />
        <SparkKpi
          label="Alerts"
          value={value("alerts")}
          unit="alerts"
          icon={ShieldAlert}
          tone="rose"
          delta={kpi("alerts")?.comparison ?? null}
          deltaPolarity="higher_is_worse"
          help={kpi("alerts")?.help}
          spark={trendSpark((point) => point.total)}
          sparkColor={TONES.rose}
          href="/app/alerts"
        />
        <SparkKpi
          label="Critical"
          value={value("critical")}
          unit="alerts"
          icon={Flame}
          tone="rose"
          delta={kpi("critical")?.comparison ?? null}
          deltaPolarity="higher_is_worse"
          help={kpi("critical")?.help}
          spark={trendSpark((point) => point.critical)}
          sparkColor={TONES.rose}
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <Panel className="flex flex-col p-4 xl:col-span-8">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div className="min-w-0">
              <h3 className="flex items-center gap-1.5 text-[12.5px] font-semibold tracking-tight text-slate-200">
                <Globe2 className="h-3.5 w-3.5 text-accent" />
                Threat geography
                {geo.data?.demo_geo ? <Badge tone="amber">demo coordinates</Badge> : null}
              </h3>
              <p className="mt-0.5 text-[10px] text-slate-600">Stored flow pairs with geolocation · arcs shaded by severity</p>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {SEVERITIES.map((severity) => {
                const active = severityFilter.includes(severity);
                return (
                  <button
                    key={severity}
                    type="button"
                    onClick={() =>
                      setSeverityFilter((current) =>
                        current.includes(severity) ? current.filter((item) => item !== severity) : [...current, severity],
                      )
                    }
                    className={cn(
                      "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[9.5px] font-medium capitalize transition-colors",
                      active
                        ? "border-white/20 bg-white/[0.06] text-slate-100"
                        : "border-white/[0.07] bg-white/[0.02] text-slate-500 hover:text-slate-300",
                    )}
                    aria-pressed={active}
                  >
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: severityColor(severity) }} />
                    {severity}
                  </button>
                );
              })}
              <div className="ml-1 flex items-center rounded-md border border-white/[0.08] bg-white/[0.02] p-0.5">
                {([
                  { key: "map" as const, label: "2D", icon: MapIcon },
                  { key: "globe" as const, label: "3D", icon: Globe2 },
                ]).map((mode) => (
                  <button
                    key={mode.key}
                    type="button"
                    onClick={() => setMapMode(mode.key)}
                    aria-pressed={mapMode === mode.key}
                    className={cn(
                      "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9.5px] font-medium transition-colors",
                      mapMode === mode.key ? "bg-accent/15 text-accent-soft" : "text-slate-500 hover:text-slate-300",
                    )}
                  >
                    <mode.icon className="h-2.5 w-2.5" />
                    {mode.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-3 flex-1">
            {geo.isLoading ? (
              <div className="flex h-[360px] items-center justify-center rounded-xl border border-white/[0.05]">
                <div className="h-8 w-8 animate-spin rounded-full border border-accent/20 border-t-accent/80" />
              </div>
            ) : geo.data?.status === "ready" && filteredArcs.length ? (
              mapMode === "map" ? (
                <WorldThreatMap
                  arcs={filteredArcs}
                  nodes={geo.data.nodes}
                  height={360}
                  onSelect={(node) => setSelectedLocation(node.name)}
                  selected={selectedLocation}
                />
              ) : (
                <GlobeView
                  arcs={filteredArcs}
                  nodes={geo.data.nodes}
                  height={360}
                  demo={geo.data.demo_geo}
                  onSelect={(node) => setSelectedLocation(node.name)}
                />
              )
            ) : (
              <EmptyState
                title={geo.data?.status === "insufficient_visibility" ? "Insufficient geolocation visibility" : "No geolocated flows"}
                description={geo.data?.message ?? "No stored flow pair in this window carries both an external address and a geolocation lookup."}
                icon={<Globe2 className="h-4 w-4" />}
              />
            )}
          </div>

          <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.05] pt-2.5 text-[10px] text-slate-500">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono">
              <span>{formatNumber(filteredArcs.length)} arcs</span>
              <span>{formatNumber(geo.data?.nodes.length ?? 0)} locations</span>
              <span>{formatNumber(data.totals.flows)} flows</span>
              {unknownEndpoints ? (
                <span className="font-sans text-signal-amber/80">{formatNumber(unknownEndpoints)} endpoints without location</span>
              ) : null}
            </div>
            <span className="flex items-center gap-1.5">
              <span className={cn("h-1.5 w-1.5 rounded-full", geoConfigured || geo.data?.demo_geo ? "bg-signal-mint" : "bg-slate-600")} />
              {geoLabel}
              {geoSourceInfo ? <InfoHint text={geoSourceInfo} label="About geolocation accuracy" /> : null}
            </span>
          </div>

          {locationNode ? (
            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-white/[0.07] bg-ink-900/60 px-3 py-2">
              <div className="flex items-center gap-2.5">
                <span className="h-2 w-2 rounded-full" style={{ background: severityColor(locationNode.severity) }} />
                <div>
                  <p className="text-[11px] font-medium text-slate-200">
                    {locationNode.name}
                    {locationNode.country ? <span className="text-slate-500"> · {locationNode.country}</span> : null}
                  </p>
                  <p className="font-mono text-[9.5px] text-slate-500">
                    {formatNumber(locationNode.connections)} connections · {formatBytes(locationNode.volume)}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={locationNode.severity} />
                <button type="button" className="btn-ghost px-1.5 py-0.5 text-[10px]" onClick={() => setSelectedLocation(null)}>
                  dismiss
                </button>
              </div>
            </div>
          ) : null}
        </Panel>

        <div className="grid gap-4 sm:grid-cols-2 xl:col-span-4 xl:grid-cols-1">
          <DonutCard
            title="Severity mix"
            subtitle="Alerts in this window"
            items={(threats.data?.severity_distribution ?? []).map((item) => ({
              name: titleCase(item.severity),
              value: item.count,
              color: severityColor(item.severity),
            }))}
            totalLabel="alerts"
            height={132}
            action={
              <Link to="/app/alerts" aria-label="Open alert centre" className="text-slate-600 transition-colors hover:text-accent-soft">
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            }
            emptyLabel="No alerts recorded in this window"
          />
          <RankList
            title="Threat classes"
            subtitle="Alerts grouped by class"
            icon={ShieldAlert}
            tone="violet"
            rows={(threats.data?.category_distribution ?? []).slice(0, 6).map((item) => ({
              label: titleCase(item.category),
              value: item.count,
              href: `/app/alerts?threat_class=${encodeURIComponent(item.category)}`,
            }))}
            emptyLabel="No classified alerts in this window"
          />
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <ChartPanel
          className="xl:col-span-8"
          title="Traffic volume"
          subtitle="Directional bytes per bucket, as recorded by the collector."
          option={trafficOption}
          height={236}
          empty={!traffic.data?.has_data}
          actions={<Badge tone="slate">{traffic.data?.range.bucket ?? "—"}</Badge>}
        />
        <div className="grid gap-4 sm:grid-cols-2 xl:col-span-4 xl:grid-cols-1">
          <DonutCard
            title="Protocol mix"
            subtitle="Flows by transport"
            items={(traffic.data?.protocols ?? []).slice(0, 6).map((item) => ({ name: item.protocol, value: item.count }))}
            totalLabel="flows"
            height={106}
            emptyLabel="No protocol data"
          />
          <RankList
            title="Top sources"
            subtitle="By recorded volume"
            icon={ArrowUpFromLine}
            tone="blue"
            rows={(traffic.data?.top_sources ?? []).slice(0, 5).map((item) => ({ label: item.ip, value: item.bytes }))}
            valueFormatter={formatBytes}
            emptyLabel="No external sources in this window"
          />
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <ChartPanel
          className="xl:col-span-5"
          title="Alert pressure"
          subtitle="Stacked alert counts per bucket."
          option={trendOption}
          height={232}
          empty={!threats.data?.total_alerts}
        />
        <Panel className="flex flex-col p-4 xl:col-span-4">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <h3 className="text-[12.5px] font-semibold tracking-tight text-slate-200">Model performance</h3>
              <p className="mt-0.5 truncate text-[10px] text-slate-600">Measured F1 on held-out synthetic split</p>
            </div>
            <InfoHint
              text="Scores come from the stored evaluation of each model version on its synthetic held-out split. They are not production accuracy and do not describe this workspace's traffic."
              label="About model performance"
            />
          </div>
          {models.length ? (
            <div className="mt-3 flex-1 space-y-2.5">
              {models.map((model) => {
                const metrics = model.metrics_summary;
                const color = f1Color(metrics.f1);
                return (
                  <div key={model.id}>
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="truncate text-[10.5px] text-slate-300">
                        {DETECTOR_LABEL[model.detector_code] ?? model.detector_code.replace(/_/g, " ")}
                      </span>
                      <span className="font-mono text-[10.5px] tabular-nums" style={{ color }}>
                        {metrics.f1.toFixed(3)}
                      </span>
                    </div>
                    <div className="mt-1 h-[3px] overflow-hidden rounded-full bg-white/[0.05]">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${Math.max(3, metrics.f1 * 100)}%`, background: color, boxShadow: `0 0 6px ${color}66` }}
                      />
                    </div>
                    <div className="mt-1 flex gap-3 font-mono text-[8.5px] text-slate-600">
                      <span>P {metrics.precision.toFixed(3)}</span>
                      <span>R {metrics.recall.toFixed(3)}</span>
                      <span>FPR {metrics.false_positive_rate.toFixed(3)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="mt-3 flex flex-1 flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed border-white/[0.07] py-8 text-center">
              <p className="px-3 text-[10px] text-slate-600">
                {hasPermission("ai.view") ? "No trained model versions are stored." : "Model metrics require AI access."}
              </p>
            </div>
          )}
        </Panel>
        <Panel className="flex flex-col p-4 xl:col-span-3">
          <div className="flex items-start justify-between gap-2">
            <h3 className="text-[12.5px] font-semibold tracking-tight text-slate-200">Platform pulse</h3>
            <span className="flex items-center gap-1 text-[8.5px] uppercase tracking-[0.1em] text-slate-600">
              <span className="h-1.5 w-1.5 rounded-full bg-signal-mint shadow-[0_0_6px_#3DDC97]" />
              status
            </span>
          </div>
          <div className="mt-3 flex items-center justify-around gap-2">
            <div className="flex flex-col items-center gap-1">
              <Ring
                ratio={collectors.total ? collectors.connected / collectors.total : 0}
                display={`${collectors.connected}/${collectors.total}`}
                color={collectors.disconnected ? TONES.amber : TONES.mint}
                size={68}
                thickness={6}
              />
              <span className="text-[8.5px] uppercase tracking-[0.1em] text-slate-600">sources</span>
            </div>
            <div className="flex flex-col items-center gap-1">
              <Ring
                ratio={detectorTotal ? (enabledDetectors ?? 0) / detectorTotal : 0}
                display={enabledDetectors === null || detectorTotal === null ? "—" : `${enabledDetectors}/${detectorTotal}`}
                color={TONES.accent}
                size={68}
                thickness={6}
              />
              <span className="text-[8.5px] uppercase tracking-[0.1em] text-slate-600">detectors</span>
            </div>
          </div>
          <div className="mt-3 flex-1 space-y-2 border-t border-white/[0.05] pt-2.5">
            {[
              {
                label: "Geolocation",
                value: geoLabel,
                tone: geoConfigured || geo.data?.demo_geo ? "mint" : "slate",
              },
              {
                label: "External enrichment",
                value: status.data?.external_enrichment ? "allowed" : "disabled",
                tone: status.data?.external_enrichment ? "amber" : "mint",
              },
              {
                label: "Last flow",
                value: lastFlow ? relativeTime(lastFlow) : "never",
                tone: lastFlowFresh ? "mint" : "amber",
              },
              {
                label: "Retention",
                value: status.data ? `${status.data.retention_days} days` : "—",
                tone: "slate",
              },
            ].map((row) => (
              <div key={row.label} className="flex items-center gap-2 text-[9.5px]">
                <span
                  className="h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: TONES[row.tone as keyof typeof TONES] ?? TONES.slate }}
                />
                <span className="min-w-0 flex-1 truncate text-slate-500">{row.label}</span>
                <span className="truncate font-mono text-slate-300">{row.value}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <Panel className="flex flex-col overflow-hidden xl:col-span-8">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-3.5 w-3.5 text-slate-500" />
              <h3 className="text-[12.5px] font-semibold tracking-tight text-slate-200">Recent alerts</h3>
              <Badge tone="slate">{formatNumber(data.recent_alerts.length)}</Badge>
            </div>
            <Link to="/app/alerts" className="text-[10.5px] text-accent-soft hover:underline">
              view all →
            </Link>
          </div>
          <AlertTable alerts={data.recent_alerts} emptyDescription="No alerts were recorded in the selected window." />
        </Panel>
        <Panel className="flex flex-col p-4 xl:col-span-4">
          <div className="flex items-start justify-between gap-2">
            <div>
              <h3 className="text-[12.5px] font-semibold tracking-tight text-slate-200">Analyst cues</h3>
              <p className="mt-0.5 text-[10px] text-slate-600">Deterministic, evidence-linked observations</p>
            </div>
            <Sparkles className="h-3.5 w-3.5 text-slate-600" />
          </div>
          <div className="mt-3 flex-1 space-y-2">
            {data.insights.length ? (
              data.insights.slice(0, 4).map((insight) => <InsightCard key={insight.id} insight={insight} />)
            ) : (
              <div className="flex h-full flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed border-white/[0.07] py-8 text-center">
                <Sparkles className="h-4 w-4 text-slate-600" />
                <p className="px-3 text-[10px] leading-relaxed text-slate-600">
                  No insight thresholds were crossed. Insights appear only from stored evidence.
                </p>
              </div>
            )}
          </div>
        </Panel>
      </div>

      <details className="group mt-4 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2 text-[10.5px] text-slate-500">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-2 [&::-webkit-details-marker]:hidden">
          <span className="flex items-center gap-1.5">
            <ShieldAlert className="h-3 w-3 text-slate-600" />
            Data caveats and scope
          </span>
          <span className="flex items-center gap-2 font-mono text-[9px] text-slate-600">
            {data.known_limitations.length} notes
            <span className="transition-transform group-open:rotate-180">▾</span>
          </span>
        </summary>
        <ul className="mt-2 grid gap-1.5 border-t border-white/[0.05] pt-2 leading-relaxed text-slate-500 sm:grid-cols-2">
          {data.known_limitations.map((item) => (
            <li key={item} className="flex gap-1.5">
              <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-slate-600" />
              {item}
            </li>
          ))}
        </ul>
        <p className="mt-2 font-mono text-[9px] text-slate-700">generated {formatDateTime(data.generated_at)}Z</p>
      </details>
    </div>
  );
}
