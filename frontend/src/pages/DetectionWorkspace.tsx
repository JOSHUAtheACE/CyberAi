import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  Crosshair,
  Database,
  Globe2,
  Info,
  Lock,
  Radar,
  ScanLine,
  ShieldCheck,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { AlertTable, ChartPanel } from "@/components/app";
import {
  Badge,
  EmptyState,
  ErrorState,
  InfoHint,
  PageHeader,
  Panel,
  SectionTitle,
  SeverityBadge,
  Skeleton,
} from "@/components/ui";
import { barOption, donutOption, lineOption, paletteCycle, scatterOption } from "@/lib/charts";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import {
  cn,
  compactNumber,
  formatBytes,
  formatDateTime,
  formatNumber,
  titleCase,
} from "@/lib/format";
import { Ring, TONES } from "@/components/visuals";
import type { DetectorPage } from "@/lib/types";

type Row = Record<string, unknown>;

type SeriesSpec = { key: string; name: string; color?: string; area?: boolean; stack?: string };

type ChartSpec = {
  key: string;
  title: string;
  subtitle?: string;
  kind: "line" | "bar" | "stacked" | "donut" | "scatter";
  labelKey?: string;
  label?: (row: Row) => string;
  series?: SeriesSpec[];
  valueKey?: string;
  xKey?: string;
  yKey?: string;
  horizontal?: boolean;
  colorByIndex?: boolean;
  yFormatter?: (value: number) => string;
};

const WORKSPACES = [
  { slug: "ddos", label: "DDoS", icon: Zap },
  { slug: "beaconing", label: "Beaconing", icon: Radar },
  { slug: "dns", label: "DNS / DGA", icon: Globe2 },
  { slug: "encrypted", label: "TLS / QUIC", icon: Lock },
  { slug: "scanning", label: "Scanning", icon: ScanLine },
  { slug: "exfiltration", label: "Exfiltration", icon: Crosshair },
];

const CHARTS: Record<string, ChartSpec[]> = {
  ddos: [
    {
      key: "pps_timeline",
      title: "Packet and bit rate",
      subtitle: "Rate per bucket from packet and byte counters. Missing counters disable rate analysis.",
      kind: "line",
      labelKey: "bucket",
      series: [
        { key: "pps", name: "packets/s", color: paletteCycle[0], area: true },
        { key: "bps", name: "bits/s", color: paletteCycle[1] },
      ],
      yFormatter: (value) => compactNumber(value),
    },
    {
      key: "syn_ack",
      title: "TCP flag mix",
      subtitle: "Flows carrying SYN or ACK. A SYN-heavy spike is consistent with handshake flooding.",
      kind: "line",
      labelKey: "bucket",
      series: [
        { key: "syn", name: "SYN", color: paletteCycle[4] },
        { key: "ack", name: "ACK", color: paletteCycle[2] },
      ],
    },
    {
      key: "unique_sources",
      title: "Distinct sources per bucket",
      subtitle: "Unusual source cardinality is a behavioural lead, not proof of spoofing.",
      kind: "line",
      labelKey: "bucket",
      series: [{ key: "sources", name: "sources", color: paletteCycle[3], area: true }],
      yFormatter: (value) => formatNumber(value),
    },
    {
      key: "source_entropy",
      title: "Source entropy",
      subtitle: "Shannon entropy of source addresses in each bucket (bits).",
      kind: "line",
      labelKey: "bucket",
      series: [{ key: "entropy", name: "entropy (bits)", color: paletteCycle[2], area: true }],
      yFormatter: (value) => value.toFixed(1),
    },
    {
      key: "udp_ports",
      title: "Top UDP destination ports",
      subtitle: "Reflector-style ports appear here when UDP telemetry is present.",
      kind: "bar",
      labelKey: "port",
      series: [{ key: "count", name: "flows", color: paletteCycle[4] }],
    },
    {
      key: "targets",
      title: "Most targeted destinations",
      subtitle: "Flow count per destination address in the window.",
      kind: "bar",
      labelKey: "ip",
      horizontal: true,
      series: [{ key: "flows", name: "flows", color: paletteCycle[0] }],
    },
  ],
  beaconing: [
    {
      key: "connections",
      title: "Most regular callback pairs",
      subtitle: "Ranked by coefficient of variation of inter-arrival intervals (lower is more regular).",
      kind: "bar",
      label: (row) => `${String(row.dst ?? "?")}:${String(row.port ?? "?")}`,
      horizontal: true,
      series: [{ key: "connections", name: "connections", color: paletteCycle[2] }],
    },
    {
      key: "interval_histogram",
      title: "Callback interval distribution",
      subtitle: "Observed intervals across the most regular pairs.",
      kind: "bar",
      labelKey: "bucket",
      series: [{ key: "count", name: "intervals", color: paletteCycle[1] }],
    },
    {
      key: "cv_trend",
      title: "Interval regularity (CV)",
      subtitle: "Lower CV means tighter periodic spacing. 0.15 is a typical weak-signal lead, not a verdict.",
      kind: "bar",
      labelKey: "pair",
      horizontal: true,
      series: [{ key: "cv", name: "CV", color: paletteCycle[3] }],
      yFormatter: (value) => value.toFixed(2),
    },
    {
      key: "heatmap",
      title: "Hourly activity bands",
      subtitle: "Flow counts by hour, banded by observed packets per flow. Indicative activity shape only.",
      kind: "stacked",
      labelKey: "hour",
      series: [
        { key: "low", name: "few packets", color: paletteCycle[0], stack: "volume" },
        { key: "medium", name: "moderate", color: paletteCycle[3], stack: "volume" },
        { key: "high", name: "many packets", color: paletteCycle[4], stack: "volume" },
      ],
    },
    {
      key: "destination_frequency",
      title: "Alert destination frequency",
      subtitle: "Destinations appearing in this module's alerts.",
      kind: "bar",
      labelKey: "destination",
      horizontal: true,
      series: [{ key: "alerts", name: "alerts", color: paletteCycle[1] }],
    },
  ],
  dns: [
    {
      key: "entropy_distribution",
      title: "Query-name entropy",
      subtitle: "Character entropy of the registered domain portion, in bits.",
      kind: "bar",
      labelKey: "bucket",
      series: [{ key: "count", name: "queries", color: paletteCycle[2] }],
    },
    {
      key: "length_distribution",
      title: "Query-name length",
      subtitle: "Full name length, in characters.",
      kind: "bar",
      labelKey: "bucket",
      series: [{ key: "count", name: "queries", color: paletteCycle[1] }],
    },
    {
      key: "label_length",
      title: "Left-most label length",
      subtitle: "Longer labels combined with high entropy are consistent with DGA output.",
      kind: "bar",
      labelKey: "bucket",
      series: [{ key: "count", name: "queries", color: paletteCycle[4] }],
    },
    {
      key: "qtypes",
      title: "Query types",
      subtitle: "Only observed record types are shown.",
      kind: "donut",
      labelKey: "type",
      valueKey: "count",
    },
    {
      key: "query_timeline",
      title: "DNS query volume",
      subtitle: "Queries per bucket in the selected window.",
      kind: "line",
      labelKey: "bucket",
      series: [{ key: "queries", name: "queries", color: paletteCycle[0], area: true }],
    },
    {
      key: "nxdomain",
      title: "Response outcomes",
      subtitle: "NXDOMAIN requires captured response codes; otherwise the split is not meaningful.",
      kind: "donut",
      labelKey: "label",
      valueKey: "count",
    },
  ],
  encrypted: [
    {
      key: "fingerprints",
      title: "TLS JA3 fingerprints",
      subtitle: "Observed handshake fingerprints by session count. Payloads are never decrypted.",
      kind: "bar",
      label: (row) => String(row.ja3 ?? "—").slice(0, 24),
      horizontal: true,
      series: [{ key: "count", name: "sessions", color: paletteCycle[1] }],
    },
    {
      key: "ciphers",
      title: "Negotiated cipher suites",
      subtitle: "Handshake metadata only.",
      kind: "donut",
      labelKey: "cipher",
      valueKey: "count",
    },
    {
      key: "versions",
      title: "TLS versions",
      subtitle: "Legacy versions are a hygiene lead, not evidence of compromise.",
      kind: "donut",
      labelKey: "version",
      valueKey: "count",
    },
    {
      key: "duration",
      title: "Session duration",
      subtitle: "Encrypted session length distribution.",
      kind: "bar",
      labelKey: "bucket",
      series: [{ key: "count", name: "sessions", color: paletteCycle[2] }],
    },
    {
      key: "sizes",
      title: "Session volume",
      subtitle: "Total bytes observed per encrypted session.",
      kind: "bar",
      labelKey: "bucket",
      series: [{ key: "count", name: "sessions", color: paletteCycle[3] }],
    },
    {
      key: "timeline",
      title: "Encrypted sessions over time",
      subtitle: "Session count per bucket.",
      kind: "line",
      labelKey: "bucket",
      series: [{ key: "sessions", name: "sessions", color: paletteCycle[0], area: true }],
    },
    {
      key: "protocols",
      title: "Transport mix",
      subtitle: "TCP/TLS versus QUIC on UDP.",
      kind: "donut",
      labelKey: "protocol",
      valueKey: "count",
    },
  ],
  scanning: [
    {
      key: "ports_timeline",
      title: "Unique destination ports",
      subtitle: "Port spread per bucket, with attempt volume on the same axis.",
      kind: "line",
      labelKey: "bucket",
      series: [
        { key: "unique_ports", name: "unique ports", color: paletteCycle[4], area: true },
        { key: "attempts", name: "attempts", color: paletteCycle[1] },
      ],
    },
    {
      key: "port_histogram",
      title: "Most probed ports",
      subtitle: "Top destination ports by flow count.",
      kind: "bar",
      labelKey: "port",
      series: [{ key: "count", name: "attempts", color: paletteCycle[3] }],
    },
    {
      key: "hosts_timeline",
      title: "Distinct hosts contacted",
      subtitle: "Horizontal host sweep appears as a widening host count.",
      kind: "line",
      labelKey: "bucket",
      series: [{ key: "hosts", name: "hosts", color: paletteCycle[0], area: true }],
    },
  ],
  exfiltration: [
    {
      key: "bytes_timeline",
      title: "Outbound vs inbound volume",
      subtitle: "Directionality derived from workspace internal CIDRs.",
      kind: "line",
      labelKey: "bucket",
      series: [
        { key: "out_mib", name: "outbound MiB", color: paletteCycle[4], area: true },
        { key: "in_mib", name: "inbound MiB", color: paletteCycle[0] },
      ],
      yFormatter: (value) => `${formatNumber(value, 2)} MiB`,
    },
    {
      key: "destination_ratios",
      title: "Volume by external destination",
      subtitle: "Destinations ranked by outbound volume; inbound shown for asymmetry.",
      kind: "bar",
      labelKey: "destination",
      horizontal: true,
      series: [
        { key: "out_mib", name: "out MiB", color: paletteCycle[4] },
        { key: "in_mib", name: "in MiB", color: paletteCycle[0] },
      ],
      yFormatter: (value) => formatNumber(value, 2),
    },
    {
      key: "scatter",
      title: "Duration versus outbound bytes",
      subtitle: "Each point is one outbound flow. Long-lived, high-volume flows cluster toward the upper right.",
      kind: "scatter",
      xKey: "duration_s",
      yKey: "out_bytes",
      labelKey: "destination",
      yFormatter: (value) => formatBytes(value),
    },
  ],
};

type Column = {
  key: string;
  label: string;
  kind?: "severity" | "confidence" | "time" | "number" | "boolean" | "text";
  maxWidth?: string;
};

const TABLES: Record<string, { title: string; subtitle: string; columns: Column[] }> = {
  ddos: {
    title: "Alert targets",
    subtitle: "Destinations with detections in the window.",
    columns: [
      { key: "destination", label: "Destination" },
      { key: "protocol", label: "Protocol" },
      { key: "severity", label: "Severity", kind: "severity" },
      { key: "confidence", label: "Score", kind: "confidence" },
      { key: "first_seen", label: "First seen", kind: "time" },
      { key: "summary", label: "Summary", kind: "text", maxWidth: "340px" },
    ],
  },
  beaconing: {
    title: "Beaconing alerts",
    subtitle: "Callback behaviour flagged by the detector.",
    columns: [
      { key: "source", label: "Source" },
      { key: "destination", label: "Destination" },
      { key: "port", label: "Port" },
      { key: "severity", label: "Severity", kind: "severity" },
      { key: "confidence", label: "Score", kind: "confidence" },
      { key: "summary", label: "Summary", kind: "text", maxWidth: "320px" },
    ],
  },
  dns: {
    title: "Frequent query names",
    subtitle: "Entropy and label length are computed from the observed name, not a blacklist.",
    columns: [
      { key: "domain", label: "Domain", kind: "text", maxWidth: "260px" },
      { key: "queries", label: "Queries", kind: "number" },
      { key: "entropy", label: "Entropy", kind: "number" },
      { key: "label_length", label: "Label len", kind: "number" },
      { key: "qtype", label: "Type" },
      { key: "suspect", label: "Lead", kind: "boolean" },
    ],
  },
  encrypted: {
    title: "Encrypted-session alerts",
    subtitle: "Assessments based only on observable handshake metadata.",
    columns: [
      { key: "source", label: "Source" },
      { key: "destination", label: "Destination" },
      { key: "port", label: "Port" },
      { key: "severity", label: "Severity", kind: "severity" },
      { key: "confidence", label: "Score", kind: "confidence" },
      { key: "summary", label: "Summary", kind: "text", maxWidth: "320px" },
    ],
  },
  scanning: {
    title: "Source behaviour",
    subtitle: "Port and host spread per source address.",
    columns: [
      { key: "source", label: "Source" },
      { key: "unique_ports", label: "Ports", kind: "number" },
      { key: "unique_hosts", label: "Hosts", kind: "number" },
      { key: "attempts", label: "Attempts", kind: "number" },
      { key: "first_seen", label: "First", kind: "time" },
      { key: "last_seen", label: "Last", kind: "time" },
    ],
  },
  exfiltration: {
    title: "Exfiltration alerts",
    subtitle: "Directional volume assessments; incomplete when byte direction is unavailable.",
    columns: [
      { key: "source", label: "Source" },
      { key: "destination", label: "Destination" },
      { key: "severity", label: "Severity", kind: "severity" },
      { key: "confidence", label: "Score", kind: "confidence" },
      { key: "first_seen", label: "First seen", kind: "time" },
      { key: "summary", label: "Summary", kind: "text", maxWidth: "320px" },
    ],
  },
};

const CONFIDENCE_LABEL: Record<string, string> = {
  calibrated_probability: "Calibrated probability",
  hybrid_score: "Hybrid score",
  heuristic_score: "Heuristic score",
  anomaly_score: "Anomaly score",
};

const CONFIDENCE_HINT: Record<string, string> = {
  calibrated_probability: "Produced by a calibrated classifier; interpretable as a probability on the evaluation split.",
  hybrid_score: "Rule evidence blended with a statistical or model score. Not a calibrated probability.",
  heuristic_score: "Deterministic rule strength. Not a calibrated probability.",
  anomaly_score: "Anomaly strength from an unsupervised model. Not a probability of compromise.",
};

function chartFor(spec: ChartSpec, rows: Row[]) {
  const labels = rows.map((row) => (spec.label ? spec.label(row) : String(row[spec.labelKey ?? ""] ?? "—")));
  if (spec.kind === "donut") {
    return donutOption({
      items: rows.map((row) => ({ name: String(row[spec.labelKey ?? ""] ?? "—"), value: Number(row[spec.valueKey ?? "count"] ?? 0) })),
      valueFormatter: (value) => formatNumber(value),
    });
  }
  if (spec.kind === "scatter") {
    return scatterOption({
      points: rows.map((row) => ({
        x: Number(row[spec.xKey ?? ""] ?? 0),
        y: Number(row[spec.yKey ?? ""] ?? 0),
        label: String(row[spec.labelKey ?? ""] ?? ""),
      })),
      xName: "duration (s)",
      yName: "outbound bytes",
      xFormatter: (value) => `${formatNumber(value, 1)}s`,
      yFormatter: spec.yFormatter ?? ((value) => formatNumber(value)),
      color: paletteCycle[4],
    });
  }
  const series = (spec.series ?? []).map((item) => ({
    name: item.name,
    data: rows.map((row) => Number(row[item.key] ?? 0)),
    color: item.color,
    area: item.area,
    stack: item.stack,
  }));
  if (spec.kind === "line") {
    return lineOption({ labels, series, yFormatter: spec.yFormatter ?? ((value) => formatNumber(value, 1)) });
  }
  return barOption({
    labels,
    series,
    horizontal: spec.horizontal,
    colorByIndex: spec.colorByIndex,
    yFormatter: spec.yFormatter,
  });
}

function Cell({ value, column }: { value: unknown; column: Column }) {
  if (value === null || value === undefined || value === "") return <span className="text-slate-600">—</span>;
  switch (column.kind) {
    case "severity":
      return <SeverityBadge severity={String(value)} />;
    case "confidence":
      return <span className="font-mono text-[11px] tabular-nums text-slate-300">{Number(value).toFixed(3)}</span>;
    case "time":
      return <span className="whitespace-nowrap font-mono text-[10.5px] text-slate-400">{formatDateTime(String(value))}</span>;
    case "number":
      return <span className="font-mono text-[11px] tabular-nums text-slate-300">{formatNumber(Number(value))}</span>;
    case "boolean":
      return value ? <Badge tone="rose">lead</Badge> : <Badge tone="slate">no</Badge>;
    default:
      return (
        <span className={cn("block truncate text-[11px]", column.maxWidth ? "" : "")} style={{ maxWidth: column.maxWidth }}>
          {String(value)}
        </span>
      );
  }
}

function DataTable({ rows, columns }: { rows: Row[]; columns: Column[] }) {
  if (!rows.length) {
    return <EmptyState compact title="No rows in this window" description="The table is empty because no qualifying observations were stored." icon={<Database className="h-4 w-4" />} />;
  }
  return (
    <div className="overflow-x-auto">
      <table className="table-base min-w-[640px]">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td key={column.key}>
                  <Cell value={row[column.key]} column={column} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function KpiTile({ kpi, icon: Icon }: { kpi: DetectorPage["kpis"][number]; icon: LucideIcon }) {
  const numeric = typeof kpi.value === "number";
  const ratio = numeric && kpi.unit === "0–1" ? Math.max(0, Math.min(1, kpi.value as number)) : null;
  const display =
    kpi.value === null || kpi.value === undefined
      ? "—"
      : numeric
        ? kpi.unit === "0–1"
          ? (kpi.value as number).toFixed(3)
          : formatNumber(kpi.value as number)
        : kpi.value;
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/[0.06] bg-ink-900/50 px-3.5 py-3">
      <span
        aria-hidden
        className="pointer-events-none absolute -right-6 -top-8 h-16 w-16 rounded-full opacity-[0.14] blur-2xl"
        style={{ background: TONES.accent }}
      />
      <div className="flex items-start justify-between gap-2">
        <p className="label min-w-0 truncate leading-tight">{kpi.label}</p>
        <span className="flex items-center gap-1">
          <InfoHint text={kpi.help} label={`About ${kpi.label}`} />
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-accent/20 bg-accent/[0.07] text-accent">
            <Icon className="h-3 w-3" />
          </span>
        </span>
      </div>
      {ratio !== null ? (
        <div className="mt-2 flex items-center gap-3">
          <Ring ratio={ratio} display={String(display)} caption={kpi.unit} size={58} thickness={5} />
          {kpi.note ? <p className="min-w-0 line-clamp-3 text-[9px] leading-relaxed text-amber-200/60">{kpi.note}</p> : null}
        </div>
      ) : (
        <>
          <p className="mt-2 font-mono text-[19px] font-medium tabular-nums text-slate-100">{display}</p>
          {kpi.value !== null && kpi.value !== undefined ? (
            <p className="mt-0.5 text-[10px] text-slate-600">{kpi.unit}</p>
          ) : null}
          {kpi.note ? <p className="mt-1 line-clamp-2 text-[9.5px] leading-relaxed text-amber-200/60">{kpi.note}</p> : null}
        </>
      )}
    </div>
  );
}

export function DetectionWorkspace() {
  const { slug = "" } = useParams();
  const { workspaceSlug, range } = useWorkspace();
  const enabled = WORKSPACES.some((item) => item.slug === slug);

  const query = useQuery({
    queryKey: ["detection-workspace", slug, workspaceSlug, range],
    queryFn: () => api.get<DetectorPage>(`/detections/${slug}`, { workspace: workspaceSlug, range }),
    enabled,
    staleTime: 20_000,
  });

  const current = WORKSPACES.find((item) => item.slug === slug);
  const Icon = current?.icon ?? ShieldCheck;

  const chartRows = (key: string): Row[] => {
    const rows = query.data?.charts?.[key];
    return Array.isArray(rows) ? (rows as Row[]) : [];
  };

  const charts = (CHARTS[slug] ?? []).filter((spec) => chartRows(spec.key).length);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
        <Link to="/app/detections" className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-200">
          <ArrowLeft className="h-3.5 w-3.5" /> Detection workspaces
        </Link>
        <span className="text-slate-700">/</span>
        <span className="text-slate-400">{current?.label ?? slug}</span>
      </div>

      <div className="mb-4 flex gap-1 overflow-x-auto rounded-lg border border-white/[0.07] bg-ink-900/60 p-1">
        {WORKSPACES.map((item) => {
          const TabIcon = item.icon;
          const active = item.slug === slug;
          return (
            <Link
              key={item.slug}
              to={`/app/detections/${item.slug}`}
              aria-current={active ? "page" : undefined}
              className={cn(
                "inline-flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[11.5px] transition-colors",
                active ? "bg-white/[0.08] text-slate-100" : "text-slate-500 hover:text-slate-300",
              )}
            >
              <TabIcon className={cn("h-3.5 w-3.5", active ? "text-accent" : "text-slate-600")} />
              {item.label}
            </Link>
          );
        })}
      </div>

      {!enabled ? (
        <ErrorState message={`Unknown detection workspace “${slug}”.`} />
      ) : query.isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-28 w-full" />
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-24 w-full" />
            ))}
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-64 w-full" />
            ))}
          </div>
        </div>
      ) : query.isError || !query.data ? (
        <ErrorState
          message={query.error instanceof Error ? query.error.message : "This detection workspace could not be loaded."}
          retry={() => void query.refetch()}
        />
      ) : (
        <>
          <PageHeader
            eyebrow={`${titleCase(query.data.module.threat_class)} · ${query.data.module.technique}`}
            title={query.data.module.name}
            description={query.data.module.description}
            actions={
              <>
                <Badge tone={query.data.module.status === "ACTIVE" ? "mint" : "slate"} dot={query.data.module.status === "ACTIVE"}>
                  {query.data.module.status}
                </Badge>
                <Badge tone="neutral">{CONFIDENCE_LABEL[query.data.module.confidence_badge] ?? titleCase(query.data.module.confidence_badge)}</Badge>
                <span className="text-[10.5px] text-slate-500">{query.data.range.label}</span>
              </>
            }
          />

          {query.data.coverage_note ? (
            <div className="mb-4 flex items-start gap-2 rounded-lg border border-signal-amber/25 bg-signal-amber/[0.05] px-3.5 py-2.5 text-[11px] leading-relaxed text-amber-100/80">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-signal-amber" />
              <span>
                <span className="font-medium text-signal-amber">Coverage gap. </span>
                {query.data.coverage_note}
              </span>
            </div>
          ) : null}

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
            {query.data.kpis.map((kpi) => (
              <KpiTile key={kpi.key} kpi={kpi} icon={Icon} />
            ))}
          </div>

          <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            {query.data.analysis.map((item) => (
              <div key={item.label} className="rounded-lg border border-white/[0.06] bg-ink-900/35 px-3.5 py-2.5">
                <p className="label">{item.label}</p>
                <p className="mt-1 truncate font-mono text-[13px] text-slate-200" title={String(item.value)}>{String(item.value)}</p>
                {item.note ? <p className="mt-1 text-[9.5px] leading-relaxed text-slate-600">{item.note}</p> : null}
              </div>
            ))}
          </div>

          {!query.data.has_data ? (
            <div className="mt-5">
              <EmptyState
                title="No telemetry for this module in the selected window"
                description="Charts and tables remain empty until matching flows or alerts are stored. Nothing is simulated to fill this view."
                action={
                  <Link to="/app/ingestion" className="btn-secondary">
                    Ingest a capture
                  </Link>
                }
              />
            </div>
          ) : null}

          {charts.length ? (
            <div className="mt-5 grid gap-4 xl:grid-cols-2">
              {charts.map((spec) => (
                <ChartPanel
                  key={spec.key}
                  title={spec.title}
                  subtitle={spec.subtitle}
                  option={chartFor(spec, chartRows(spec.key))}
                  height={230}
                />
              ))}
            </div>
          ) : query.data.has_data ? (
            <div className="mt-5 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2.5 text-[11px] text-slate-500">
              This window contains flows, but none of the module's chartable fields were populated.
            </div>
          ) : null}

          <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
            <Panel className="overflow-hidden">
              <div className="border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
                <SectionTitle title={TABLES[slug]?.title ?? "Observations"} subtitle={TABLES[slug]?.subtitle} />
              </div>
              <div className="p-4">
                <DataTable rows={(query.data.tables ?? []) as Row[]} columns={TABLES[slug]?.columns ?? []} />
              </div>
            </Panel>

            <Panel className="p-4">
              <SectionTitle
                eyebrow="Method"
                title="Thresholds and coverage"
                subtitle="Configured values for this module. Thresholds are stored settings, not model accuracy."
              />
              <div className="mt-3 space-y-1">
                {Object.entries(query.data.module.thresholds ?? {}).map(([key, value]) => (
                  <div key={key} className="flex items-baseline justify-between gap-3 border-b border-white/[0.04] py-1.5">
                    <span className="text-[10.5px] text-slate-500">{key.replace(/_/g, " ")}</span>
                    <span className="text-right font-mono text-[10.5px] text-slate-300">
                      {Array.isArray(value) ? value.join(" / ") : String(value)}
                    </span>
                  </div>
                ))}
                {!Object.keys(query.data.module.thresholds ?? {}).length ? (
                  <p className="text-[10.5px] text-slate-500">No thresholds exposed for this module.</p>
                ) : null}
              </div>

              <p className="label mb-1.5 mt-4">Telemetry availability</p>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(query.data.availability).map(([key, available]) => (
                  <span
                    key={key}
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[9.5px]",
                      available
                        ? "border-signal-mint/20 bg-signal-mint/[0.05] text-signal-mint"
                        : "border-white/[0.07] bg-white/[0.02] text-slate-500",
                    )}
                    title={available ? "Field present in the analysed telemetry" : "Field absent; dependent analysis is incomplete"}
                  >
                    <span className={cn("h-1 w-1 rounded-full", available ? "bg-signal-mint" : "bg-slate-600")} />
                    {key.replace(/_/g, " ")}
                  </span>
                ))}
              </div>

              <div className="mt-4 rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2.5">
                <p className="flex items-center gap-1.5 text-[10.5px] font-medium text-slate-300">
                  <ShieldCheck className="h-3 w-3 text-accent/80" /> Score semantics
                </p>
                <p className="mt-1 text-[10px] leading-relaxed text-slate-500">
                  {CONFIDENCE_HINT[query.data.module.confidence_badge] ?? "Score semantics are documented on the AI & models page."}
                </p>
                <p className="mt-1.5 font-mono text-[9.5px] text-slate-600">
                  model {query.data.module.model_name} · v{query.data.module.version}
                </p>
              </div>
            </Panel>
          </div>

          {slug === "beaconing" && chartRows("events").length ? (
            <Panel className="mt-5 overflow-hidden">
              <div className="border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
                <SectionTitle
                  title="Callback cadence events"
                  subtitle="Raw inter-arrival observations for the three most regular pairs. Null intervals mark the first observation."
                />
              </div>
              <div className="max-h-[320px] overflow-auto p-4">
                <table className="table-base min-w-[560px]">
                  <thead className="sticky top-0 bg-ink-850">
                    <tr>
                      <th>Timestamp</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>Interval</th>
                    </tr>
                  </thead>
                  <tbody>
                    {chartRows("events").map((row, index) => (
                      <tr key={index}>
                        <td className="whitespace-nowrap font-mono text-[10.5px] text-slate-400">{formatDateTime(String(row.ts))}</td>
                        <td className="font-mono text-[10.5px] text-slate-300">{String(row.src ?? "—")}</td>
                        <td className="font-mono text-[10.5px] text-slate-300">{String(row.dst ?? "—")}</td>
                        <td className="font-mono text-[10.5px] text-slate-300">{String(row.port ?? "—")}</td>
                        <td className="font-mono text-[10.5px] text-slate-300">{row.interval_s === null ? "first" : `${Number(row.interval_s).toFixed(1)} s`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          ) : null}

          <Panel className="mt-5 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
              <SectionTitle
                title="Alerts from this module"
                subtitle={`${formatNumber(query.data.alerts.length)} alert${query.data.alerts.length === 1 ? "" : "s"} in ${query.data.range.label.toLowerCase()}.`}
              />
              <Link to="/app/alerts" className="text-[11px] text-signal-blue hover:underline">
                Open alert centre
              </Link>
            </div>
            <AlertTable
              alerts={query.data.alerts}
              emptyDescription="The module did not emit alerts in this window. That can be a true negative, insufficient telemetry, or behaviour below threshold."
            />
          </Panel>

          <div className="mt-4 flex items-start gap-2 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2.5 text-[10px] leading-relaxed text-slate-600">
            <InfoHint
              label="About this workspace"
              text="Charts are aggregates over stored flow metadata for the selected workspace and time range. When a required field was not captured, the dependent analysis is marked unavailable instead of being estimated."
            />
            <span>
              Workspace computed at {formatDateTime(query.data.range.start)}Z → {formatDateTime(query.data.range.end)}Z.{" "}
              {query.data.coverage_note ? "A coverage gap is reported above." : "All required fields for this module were present."}
            </span>
          </div>

        </>
      )}
    </div>
  );
}
