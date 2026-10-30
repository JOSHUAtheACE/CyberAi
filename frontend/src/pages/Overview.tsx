import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  Globe2,
  ShieldAlert,
  Sparkles,
  TriangleAlert,
  Waves,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTable, ChartPanel, KpiCard, SummaryStrip } from "@/components/app";
import { EChart } from "@/components/charts/EChart";
import { GlobeView } from "@/components/globe/GlobeView";
import {
  Badge,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  InfoHint,
  PageHeader,
  PageLoader,
  Panel,
  SectionTitle,
  SeverityBadge,
} from "@/components/ui";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { barOption, donutOption, lineOption, paletteCycle, shortBucket } from "@/lib/charts";
import { cn, formatBitrate, formatBytes, formatDateTime, formatNumber, titleCase } from "@/lib/format";
import type { GeoResponse, Insight, OverviewResponse, ThreatsResponse, TrafficResponse } from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export function Overview() {
  const { workspaceSlug, range, workspace, isDemo } = useWorkspace();
  const [selectedLocation, setSelectedLocation] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);

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

  const data = overview.data;
  const filteredArcs = useMemo(() => {
    if (!geo.data) return [];
    if (!severityFilter.length) return geo.data.arcs;
    return geo.data.arcs.filter((arc) => severityFilter.includes(arc.severity));
  }, [geo.data, severityFilter]);

  const trafficOption = useMemo(() => {
    const points = traffic.data?.timeline ?? [];
    return lineOption({
      labels: points.map((point) => shortBucket(point.bucket)),
      series: [
        { name: "Inbound MiB", data: points.map((point) => point.bytes_in_mib), area: true, color: paletteCycle[0] },
        { name: "Outbound MiB", data: points.map((point) => point.bytes_out_mib), area: true, color: paletteCycle[1] },
      ],
      yFormatter: (value) => `${formatNumber(value, 1)} MiB`,
    });
  }, [traffic.data]);

  const ppsOption = useMemo(() => {
    const points = traffic.data?.timeline ?? [];
    return lineOption({
      labels: points.map((point) => shortBucket(point.bucket)),
      series: [{ name: "Packets/s", data: points.map((point) => point.pps), color: paletteCycle[2], area: true }],
      yFormatter: (value) => formatNumber(value, 1),
      legend: false,
    });
  }, [traffic.data]);

  const severityOption = useMemo(
    () =>
      donutOption({
        items: (threats.data?.severity_distribution ?? []).map((item) => ({
          name: titleCase(item.severity),
          value: item.count,
        })),
        colors: ["#FF5C7A", "#F5B84B", "#4BA3FF", "#3DDC97", "#64748B"],
      }),
    [threats.data],
  );

  const trendOption = useMemo(() => {
    const points = threats.data?.trend ?? [];
    return barOption({
      labels: points.map((point) => shortBucket(point.bucket)),
      series: [
        { name: "Critical", data: points.map((point) => point.critical), stack: "alerts", color: "#FF5C7A" },
        { name: "High", data: points.map((point) => point.high), stack: "alerts", color: "#F5B84B" },
        { name: "Medium", data: points.map((point) => point.medium), stack: "alerts", color: "#4BA3FF" },
        { name: "Low", data: points.map((point) => point.low), stack: "alerts", color: "#3DDC97" },
      ],
      yFormatter: (value) => formatNumber(value),
    });
  }, [threats.data]);

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

  const locationNode = geo.data?.nodes.find((node) => node.name === selectedLocation) ?? null;

  return (
    <div>
      <PageHeader
        eyebrow="Operational overview"
        title={workspace?.name ?? "Workspace overview"}
        description={`Every value below is computed from stored ${isDemo ? "synthetic scenario" : "passive"} telemetry for the ${data.range.label.toLowerCase()}. Percentages appear only when the preceding period is fully covered.`}
        actions={
          <>
            <span className="hidden items-center gap-1.5 text-[10.5px] text-slate-600 sm:flex">
              generated {formatDateTime(data.generated_at)}Z
              <InfoHint text="The dashboard is recomputed on request from stored records. No metric is synthesised or cached across windows." />
            </span>
            <Link to="/app/reports" className="btn-secondary h-8">
              Generate report
            </Link>
            <Link to="/app/alerts" className="btn-primary h-8">
              Alert centre
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </>
        }
      />

      <SummaryStrip
        items={[
          { label: "Environment", value: data.workspace.environment },
          { label: "Sources", value: `${data.sources.connected} connected / ${data.sources.total}`, tone: data.sources.disconnected ? "danger" : "accent" },
          { label: "Flows", value: formatNumber(data.totals.flows) },
          { label: "Ingress", value: formatBytes(data.totals.bytes_in) },
          { label: "Egress", value: formatBytes(data.totals.bytes_out) },
          { label: "Unique sources", value: formatNumber(data.totals.unique_sources) },
          { label: "Alerts", value: formatNumber(data.totals.alerts), tone: "accent" },
          { label: "Critical", value: formatNumber(data.totals.critical), tone: data.totals.critical ? "danger" : "default" },
        ]}
      />

      {!data.has_data ? (
        <div className="mt-4 rounded-lg border border-signal-amber/20 bg-signal-amber/[0.05] px-4 py-3 text-[11.5px] leading-relaxed text-amber-200/80">
          No flows or alerts fall inside this window. Metrics stay at zero rather than being estimated. Try a wider range,
          start a replay, or upload a capture in Data ingestion.
        </div>
      ) : null}

      <div className="mt-4 grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-5">
        {data.kpis.map((kpi) => (
          <KpiCard key={kpi.key} kpi={kpi} />
        ))}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <Panel className="p-4 sm:p-5 xl:col-span-8">
          <SectionTitle
            eyebrow="Geographic context"
            title="Observed external paths"
            subtitle="Arcs represent stored flow pairs with available geolocation. Private addresses remain internal and are not geolocated."
            actions={
              <div className="flex flex-wrap items-center gap-1">
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
                        "rounded-md border px-2 py-1 text-[10px] font-medium capitalize transition-colors",
                        active
                          ? "border-accent/30 bg-accent/[0.08] text-accent-soft"
                          : "border-white/[0.07] bg-white/[0.02] text-slate-500 hover:text-slate-300",
                      )}
                      aria-pressed={active}
                    >
                      {severity}
                    </button>
                  );
                })}
                {severityFilter.length ? (
                  <button type="button" className="btn-ghost px-1.5 py-1 text-[10px]" onClick={() => setSeverityFilter([])}>
                    Clear
                  </button>
                ) : null}
              </div>
            }
          />
          <div className="mt-4">
            {geo.isLoading ? (
              <div className="flex h-[400px] items-center justify-center">
                <div className="h-8 w-8 animate-spin rounded-full border border-accent/20 border-t-accent/80" />
              </div>
            ) : geo.data?.status === "ready" && filteredArcs.length ? (
              <>
                <GlobeView
                  arcs={filteredArcs}
                  nodes={geo.data.nodes}
                  height={400}
                  demo={geo.data.demo_geo}
                  onSelect={(node) => setSelectedLocation(node.name)}
                />
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-[10.5px] text-slate-500">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                    <span>{formatNumber(filteredArcs.length)} arcs</span>
                    <span>{formatNumber(geo.data.nodes.length)} locations</span>
                    <span>{formatNumber(geo.data.unknown_locations.flows_total)} flows in window</span>
                    {geo.data.unknown_locations.source_without_location || geo.data.unknown_locations.destination_without_location ? (
                      <span className="text-signal-amber/80">
                        {formatNumber(geo.data.unknown_locations.source_without_location + geo.data.unknown_locations.destination_without_location)} endpoints without location
                      </span>
                    ) : null}
                  </div>
                  <span className="flex items-center gap-1.5 text-slate-600">
                    <Globe2 className="h-3 w-3" />
                    {geo.data.demo_geo
                      ? "demo fixture coordinates"
                      : geo.data.geo.configured
                        ? `${geo.data.geo.provider} · configured`
                        : "geolocation not configured"}
                    <InfoHint text={geo.data.geo.accuracy_notice} />
                  </span>
                </div>
                {locationNode ? (
                  <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-white/[0.07] bg-ink-900/60 px-3.5 py-2.5">
                    <div>
                      <p className="text-[12px] font-medium text-slate-200">
                        {locationNode.name}
                        {locationNode.country ? <span className="text-slate-500"> · {locationNode.country}</span> : null}
                      </p>
                      <p className="mt-0.5 font-mono text-[10.5px] text-slate-500">
                        {formatNumber(locationNode.connections)} connections · {formatBytes(locationNode.volume)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={locationNode.severity} />
                      <button type="button" className="btn-ghost px-2 py-1 text-[11px]" onClick={() => setSelectedLocation(null)}>
                        Dismiss
                      </button>
                    </div>
                  </div>
                ) : null}
              </>
            ) : (
              <EmptyState
                title={geo.data?.status === "insufficient_visibility" ? "Insufficient geolocation visibility" : "No geolocated flows"}
                description={geo.data?.message ?? "No stored flow pair in this window carries both an external address and a geolocation lookup."}
                icon={<Globe2 className="h-4 w-4" />}
                action={
                  <span className="text-[10.5px] text-slate-600">
                    Geographic enrichment is optional and never blocks detection.
                  </span>
                }
              />
            )}
          </div>
        </Panel>

        <div className="space-y-4 xl:col-span-4">
          <Panel className="p-4 sm:p-5">
            <SectionTitle
              eyebrow="Analyst cues"
              title="Grounded insights"
              subtitle="Deterministic observations derived from records in this window."
            />
            <div className="mt-3 space-y-2.5">
              {data.insights.length ? (
                data.insights.map((insight: Insight) => (
                  <div key={insight.id} className="rounded-lg border border-white/[0.06] bg-ink-900/50 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-[12px] font-medium leading-snug text-slate-200">{insight.title}</p>
                      <SeverityBadge severity={insight.severity} />
                    </div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">{insight.body}</p>
                    <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-[9.5px] uppercase tracking-[0.08em] text-slate-600">
                        {insight.grounded ? "evidence-linked" : "observation"} · {insight.data_source}
                      </span>
                      {insight.alert_id ? (
                        <Link to={`/app/alerts/${insight.alert_id}`} className="text-[10.5px] text-accent-soft hover:underline">
                          Open alert →
                        </Link>
                      ) : null}
                    </div>
                  </div>
                ))
              ) : (
                <div className="rounded-lg border border-dashed border-white/[0.08] px-4 py-6 text-center text-[11.5px] leading-relaxed text-slate-500">
                  <Sparkles className="mx-auto mb-2 h-4 w-4 text-slate-600" />
                  No insight thresholds were crossed. Insights are generated only from stored evidence.
                </div>
              )}
            </div>
          </Panel>

          <Panel className="p-4 sm:p-5">
            <SectionTitle eyebrow="Threat mix" title="Severity distribution" />
            {threats.data?.total_alerts ? (
              <>
                <div className="mt-2 flex items-center gap-4">
                  <div className="h-[130px] w-[130px] shrink-0">
                    <ChartWrapper option={severityOption} />
                  </div>
                  <ul className="min-w-0 flex-1 space-y-1.5">
                    {threats.data.severity_distribution.map((item, index) => (
                      <li key={item.severity} className="flex items-center justify-between gap-2 text-[11px]">
                        <span className="flex items-center gap-1.5 capitalize text-slate-400">
                          <span
                            className="h-1.5 w-1.5 rounded-full"
                            style={{ background: ["#FF5C7A", "#F5B84B", "#4BA3FF", "#3DDC97", "#64748B"][index % 5] }}
                          />
                          {item.severity}
                        </span>
                        <span className="font-mono text-slate-300">{formatNumber(item.count)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                <Link to="/app/alerts" className="mt-3 inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
                  Review alerts <ArrowRight className="h-3 w-3" />
                </Link>
              </>
            ) : (
              <EmptyState compact title="No alerts in this window" description="Severity is only rendered for recorded alerts." icon={<ShieldAlert className="h-4 w-4" />} />
            )}
          </Panel>
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <div className="xl:col-span-8 space-y-4">
          <ChartPanel
            title="Traffic volume"
            subtitle="Directional bytes per bucket. Directional fields originate from the collector."
            option={trafficOption}
            height={230}
            empty={!traffic.data?.has_data}
            actions={<Badge tone="slate">{traffic.data?.range.bucket ?? "—"}</Badge>}
          />
          <ChartPanel
            title="Packet rate"
            subtitle="Total captured packets divided by bucket duration."
            option={ppsOption}
            height={170}
            empty={!traffic.data?.has_data}
          />
          <Panel>
            <div className="flex items-center justify-between gap-3 px-4 pt-4 sm:px-5">
              <SectionTitle eyebrow="Latest detections" title="Recent alerts" className="flex-1" />
              <Link to="/app/alerts" className="text-[11px] text-accent-soft hover:underline">
                View all
              </Link>
            </div>
            <div className="mt-2">
              <AlertTable alerts={data.recent_alerts} emptyDescription="No alerts were recorded in the selected window." />
            </div>
          </Panel>
        </div>

        <div className="xl:col-span-4 space-y-4">
          <ChartPanel
            title="Alert trend by severity"
            subtitle="Stacked alert counts per bucket."
            option={trendOption}
            height={220}
            empty={!threats.data?.total_alerts}
          />
          <Panel className="p-4 sm:p-5">
            <SectionTitle eyebrow="Traffic shape" title="Protocol composition" />
            {traffic.data?.protocols.length ? (
              <ul className="mt-3 space-y-2">
                {traffic.data.protocols.slice(0, 6).map((item, index) => (
                  <li key={item.protocol}>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-300">{item.protocol}</span>
                      <span className="font-mono text-slate-500">
                        {formatNumber(item.count)} · {(item.share * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="mt-1 h-1 overflow-hidden rounded-full bg-white/[0.05]">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${Math.min(100, item.share * 100)}%`, background: paletteCycle[index % paletteCycle.length] }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState compact title="No protocol data" description="Protocol is only shown where the telemetry supplies it." icon={<Waves className="h-4 w-4" />} />
            )}
          </Panel>
          <Panel className="p-4 sm:p-5">
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <TriangleAlert className="h-3.5 w-3.5 text-signal-amber" />
              Known limitations
            </div>
            <ul className="mt-2 space-y-1.5 text-[10.5px] leading-relaxed text-slate-500">
              {data.known_limitations.map((item) => (
                <li key={item} className="flex gap-2">
                  <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                  {item}
                </li>
              ))}
            </ul>
            <div className="mt-3 grid grid-cols-2 gap-2 border-t border-white/[0.06] pt-3 text-[10.5px] text-slate-500">
              <div>
                <p className="label mb-0.5">Avg flow duration</p>
                <p className="font-mono text-slate-300">{formatNumber(data.totals.avg_duration_ms, 1)} ms</p>
              </div>
              <div>
                <p className="label mb-0.5">Packets</p>
                <p className="font-mono text-slate-300">{formatNumber(data.totals.packets)}</p>
              </div>
              <div>
                <p className="label mb-0.5">Ingress rate</p>
                <p className="font-mono text-slate-300">
                  {formatBitrate((data.totals.bytes_in * 8) / Math.max(1, data.totals.duration) / 1_000_000)}
                </p>
              </div>
              <div>
                <p className="label mb-0.5">High severity</p>
                <p className="font-mono text-slate-300">{formatNumber(data.totals.high)}</p>
              </div>
            </div>
          </Panel>
        </div>
      </div>

      {overview.data?.insights.some((insight) => insight.confidence_type) ? (
        <div className="mt-4 flex flex-wrap items-center gap-2 text-[10px] text-slate-600">
          <span>Insight confidence semantics:</span>
          {data.insights.map((insight) => (
            <span key={insight.id} className="inline-flex items-center gap-1">
              {insight.confidence !== null ? (
                <ConfidenceBadge type={insight.confidence_type} value={insight.confidence} />
              ) : (
                <span className="chip text-[9.5px]">{titleCase(insight.confidence_type)}</span>
              )}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function ChartWrapper({ option }: { option: ReturnType<typeof donutOption> }) {
  return <EChart option={option} height="100%" ariaLabel="Severity distribution" />;
}
