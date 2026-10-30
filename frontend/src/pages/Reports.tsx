import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  FileBarChart,
  FileJson,
  FileSpreadsheet,
  FileText,
  Layers,
  Loader2,
  Plus,
  RefreshCw,
  ShieldAlert,
  TriangleAlert,
} from "lucide-react";
import { useState } from "react";
import { ChartPanel, Pagination } from "@/components/app";
import {
  Badge,
  EmptyState,
  ErrorState,
  Modal,
  Panel,
  PageHeader,
  SectionTitle,
  Skeleton,
  StatusBadge,
} from "@/components/ui";
import {
  DonutCard,
  MeterList,
  RankList,
  Ring,
  ScoreBar,
  severityColor,
  SparkKpi,
  TONES,
} from "@/components/visuals";
import { barOption, lineOption, shortBucket } from "@/lib/charts";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { cn, formatBytes, formatDateTime, formatNumber, formatPercent, relativeTime, titleCase } from "@/lib/format";
import type { ReportItem, ReportsListResponse } from "@/lib/types";

interface ReportTotals {
  flows: number;
  bytes_total: number;
  packets: number;
  unique_sources: number;
  unique_destinations: number;
  alerts: number;
  critical: number;
  high: number;
  false_positives: number;
  avg_confidence: number | null;
  flows_per_second: number;
}

interface ReportSummary {
  generated_at: string;
  workspace: { name: string; slug: string; environment: string };
  environment: string;
  period: { label: string; start: string; end: string };
  query: { description: string; record_limit: number; data_source: string };
  totals: ReportTotals;
  traffic_timeline: { bucket: string; bytes_in: number; bytes_out: number; flows: number; packets: number }[];
  protocol_distribution: { protocol: string; count: number }[];
  direction_distribution: { direction: string; count: number }[];
  severity_distribution: { severity: string; count: number }[];
  category_distribution: { category: string; count: number }[];
  alert_timeline: { bucket: string; total: number; critical: number; high: number; medium: number; low: number; informational: number }[];
  top_sources: { ip: string; bytes: number }[];
  top_destinations: { ip: string; bytes: number }[];
  detector_performance: {
    detector_code: string;
    name: string;
    alerts: number;
    avg_confidence: number | null;
    false_positives: number;
    confidence_type: string | null;
    technique: string | null;
  }[];
  review: { status_counts: { status: string; count: number }[]; reviewed: number; false_positive_rate_on_reviewed: number | null };
  processing: {
    completed_jobs: number;
    records_processed: number;
    avg_processing_ms: number | null;
    avg_detection_ms: number | null;
    note: string;
  };
  limitations: string[];
}

interface ReportDetail extends Omit<ReportItem, "summary"> {
  summary: ReportSummary | null;
  linkage: {
    query: { description: string; record_limit: number; data_source: string } | null;
    environment: string | null;
    limitations: string[];
    note: string;
  };
}

const KIND_TONE: Record<string, "blue" | "violet" | "mint"> = {
  security_summary: "blue",
  executive: "violet",
  detector_performance: "mint",
};

const SEVERITY_COLORS = ["#FF5C7A", "#F5B84B", "#4BA3FF", "#3DDC97", "#8497b0"];

function ExportButtons({ report, canExport }: { report: Pick<ReportItem, "id" | "reference">; canExport: boolean }) {
  const { toast } = useToast();
  const [pending, setPending] = useState<string | null>(null);

  const download = async (format: "pdf" | "csv" | "json") => {
    setPending(format);
    try {
      await api.download(`/reports/${report.id}/export?format=${format}`, `${report.reference}.${format}`);
    } catch (error) {
      toast("error", "Export failed", (error as Error).message);
    } finally {
      setPending(null);
    }
  };

  const options = [
    { format: "pdf" as const, label: "PDF", icon: FileText },
    { format: "csv" as const, label: "CSV", icon: FileSpreadsheet },
    { format: "json" as const, label: "JSON", icon: FileJson },
  ];

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {options.map((option) => (
        <button
          key={option.format}
          type="button"
          className="btn-ghost px-2 py-1 text-[10.5px]"
          disabled={!canExport || pending !== null}
          onClick={() => download(option.format)}
          title={canExport ? `Download ${option.label}` : "Requires reports.export permission"}
        >
          {pending === option.format ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <option.icon className="h-3 w-3" />
          )}
          {option.label}
        </button>
      ))}
    </div>
  );
}

function DetailStat({ label, value, hint, tone = "slate" }: { label: string; value: string; hint?: string; tone?: keyof typeof TONES }) {
  const color = TONES[tone];
  return (
    <div className="min-w-0 border-l border-white/[0.07] pl-2.5">
      <p className="flex items-center gap-1.5 text-[9px] uppercase tracking-[0.14em] text-slate-500">
        <span className="h-1 w-1 shrink-0 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}80` }} />
        <span className="truncate">{label}</span>
      </p>
      <p className="mt-1 font-mono text-[15px] leading-none tabular-nums text-slate-100">{value}</p>
      {hint ? <p className="mt-1 truncate text-[9px] text-slate-600">{hint}</p> : null}
    </div>
  );
}

function ReportDetailView({
  reportId,
  canExport,
  open,
  onClose,
}: {
  reportId: number | null;
  canExport: boolean;
  open: boolean;
  onClose: () => void;
}) {
  const query = useQuery({
    queryKey: ["report-detail", reportId],
    queryFn: () => api.get<ReportDetail>(`/reports/${reportId}`),
    enabled: open && reportId !== null,
  });
  const report = query.data;
  const summary = report?.summary ?? null;
  const directionTotal = summary ? summary.direction_distribution.reduce((sum, row) => sum + row.count, 0) : 0;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={report ? report.title : "Loading report"}
      description={report ? `${report.reference} · generated ${formatDateTime(report.created_at)}Z` : undefined}
      width="max-w-5xl"
      footer={
        report ? (
          <div className="flex w-full items-center justify-between gap-3">
            <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-slate-600">
              {report.environment} · {report.workspace ?? "workspace"}
            </span>
            <ExportButtons report={report} canExport={canExport} />
          </div>
        ) : null
      }
    >
      {query.isLoading ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} className="h-20 w-full" />
            ))}
          </div>
          <Skeleton className="h-56 w-full" />
        </div>
      ) : query.isError ? (
        <ErrorState message={(query.error as Error).message} retry={() => query.refetch()} />
      ) : !summary ? (
        <EmptyState
          title="No stored summary"
          description="This report was recorded without a stored aggregate and cannot be exported. Generate a new report to populate this view."
          icon={<FileBarChart className="h-4 w-4" />}
        />
      ) : (
        <div className="space-y-4">
          <Panel className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center">
            <div className="flex items-center justify-center gap-4 sm:justify-start">
              <Ring
                ratio={summary.review.false_positive_rate_on_reviewed ?? 0}
                display={formatPercent(summary.review.false_positive_rate_on_reviewed, 1)}
                caption="FP on reviewed"
                color={(summary.review.false_positive_rate_on_reviewed ?? 0) > 0 ? TONES.amber : TONES.mint}
                size={84}
              />
              <div className="h-14 w-px bg-white/[0.07]" />
              <Ring
                ratio={summary.totals.avg_confidence ?? 0}
                display={summary.totals.avg_confidence !== null ? summary.totals.avg_confidence.toFixed(3) : "—"}
                caption="mean score"
                color={TONES.accent}
                size={84}
              />
            </div>
            <div className="grid min-w-0 flex-1 grid-cols-2 gap-x-3 gap-y-3 sm:grid-cols-3">
              <DetailStat label="Flows" value={formatNumber(summary.totals.flows)} hint={`${summary.totals.flows_per_second.toFixed(2)} flows/s`} tone="blue" />
              <DetailStat label="Volume" value={formatBytes(summary.totals.bytes_total)} hint={`${formatNumber(summary.totals.packets)} packets`} tone="violet" />
              <DetailStat
                label="Alerts"
                value={formatNumber(summary.totals.alerts)}
                hint={`${summary.totals.critical} critical · ${summary.totals.high} high`}
                tone={summary.totals.critical ? "rose" : "accent"}
              />
              <DetailStat label="Sources" value={formatNumber(summary.totals.unique_sources)} hint="unique" tone="blue" />
              <DetailStat label="Destinations" value={formatNumber(summary.totals.unique_destinations)} hint="unique" tone="violet" />
              <DetailStat
                label="False positives"
                value={formatNumber(summary.totals.false_positives)}
                hint="stored in period"
                tone={summary.totals.false_positives ? "amber" : "mint"}
              />
            </div>
          </Panel>

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartPanel
              title="Traffic volume"
              subtitle="MiB in and out per bucket at generation time"
              option={lineOption({
                labels: summary.traffic_timeline.map((point) => shortBucket(point.bucket)),
                series: [
                  { name: "Inbound", data: summary.traffic_timeline.map((point) => point.bytes_in), color: "#4BA3FF", area: true },
                  { name: "Outbound", data: summary.traffic_timeline.map((point) => point.bytes_out), color: "#36D9D0", area: true },
                ],
                yFormatter: (value) => `${formatNumber(value, 0)} MiB`,
              })}
              height={200}
              empty={!summary.traffic_timeline.length}
            />
            <ChartPanel
              title="Alert volume"
              subtitle="Total alerts per bucket"
              option={barOption({
                labels: summary.alert_timeline.map((point) => shortBucket(point.bucket)),
                series: [
                  { name: "Critical", data: summary.alert_timeline.map((point) => point.critical), color: "#FF5C7A", stack: "severity" },
                  { name: "High", data: summary.alert_timeline.map((point) => point.high), color: "#F5B84B", stack: "severity" },
                  { name: "Medium", data: summary.alert_timeline.map((point) => point.medium), color: "#4BA3FF", stack: "severity" },
                  { name: "Low", data: summary.alert_timeline.map((point) => point.low), color: "#3DDC97", stack: "severity" },
                ],
              })}
              height={200}
              empty={!summary.alert_timeline.length}
            />
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <DonutCard
              title="Severity distribution"
              subtitle="Potential impact, not proof of compromise"
              items={summary.severity_distribution.map((item, index) => ({
                name: titleCase(item.severity),
                value: item.count,
                color: severityColor(item.severity) ?? SEVERITY_COLORS[index % SEVERITY_COLORS.length],
              }))}
              totalLabel="alerts"
              height={126}
              emptyLabel="No alerts in this period"
            />
            <DonutCard
              title="Threat categories"
              subtitle="Alert counts by recorded threat class"
              items={summary.category_distribution.map((item, index) => ({
                name: titleCase(item.category),
                value: item.count,
                color: [TONES.violet, TONES.blue, TONES.amber, TONES.rose, TONES.mint, TONES.accent][index % 6],
              }))}
              totalLabel="alerts"
              height={126}
              emptyLabel="No categories recorded"
            />
            <MeterList
              title="Traffic direction"
              subtitle="Flow counts by collector direction field"
              rows={summary.direction_distribution.map((row, index) => ({
                label: titleCase(row.direction),
                value: formatNumber(row.count),
                ratio: directionTotal ? row.count / directionTotal : 0,
                tone: (["blue", "accent", "violet", "amber"] as const)[index % 4],
              }))}
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartPanel
              title="Protocol mix"
              subtitle="Flow counts by transport protocol"
              option={barOption({
                labels: summary.protocol_distribution.map((item) => item.protocol),
                series: [{ name: "Flows", data: summary.protocol_distribution.map((item) => item.count) }],
                colorByIndex: true,
              })}
              height={230}
              empty={!summary.protocol_distribution.length}
            />
            <Panel className="flex min-w-0 flex-col p-4">
              <SectionTitle
                eyebrow="Detectors"
                title="Detector performance"
                subtitle="Mean confidence uses each detector's declared score type; values are not comparable across types."
              />
              {summary.detector_performance.length ? (
                <div className="mt-3 flex-1 space-y-3.5">
                  {summary.detector_performance.map((row) => {
                    const share = summary.totals.alerts ? row.alerts / summary.totals.alerts : 0;
                    return (
                      <div key={row.detector_code}>
                        <div className="flex items-baseline justify-between gap-2">
                          <p className="min-w-0 flex-1 truncate text-[11px] text-slate-300">{row.name}</p>
                          <span className="shrink-0 font-mono text-[10.5px] tabular-nums text-slate-400">
                            {formatNumber(row.alerts)} <span className="text-slate-600">alerts</span>
                          </span>
                        </div>
                        <p className="mt-0.5 text-[9px] uppercase tracking-[0.08em] text-slate-600">
                          {row.confidence_type?.replace(/_/g, " ") ?? "score"} · FP {row.false_positives}
                        </p>
                        <div className="mt-1.5 space-y-1.5">
                          <ScoreBar
                            label="Share of alerts"
                            value={row.alerts}
                            max={Math.max(1, summary.totals.alerts)}
                            display={formatPercent(share, 0)}
                            color={TONES.blue}
                          />
                          {row.avg_confidence !== null ? (
                            <ScoreBar
                              label="Mean confidence"
                              value={row.avg_confidence}
                              max={1}
                              display={row.avg_confidence.toFixed(3)}
                              color={TONES.accent}
                            />
                          ) : (
                            <p className="text-[9px] text-slate-600">Mean confidence not recorded</p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="mt-3 text-[11.5px] text-slate-500">No detector produced alerts in this period.</p>
              )}
            </Panel>
          </div>

          <Panel className="p-4">
            <SectionTitle
              eyebrow="Operations"
              title="Review and processing"
              subtitle="Review coverage and ingestion timings recorded alongside this report."
            />
            <div className="mt-3 flex flex-col gap-4 sm:flex-row">
              <div className="flex items-center justify-center gap-4 sm:justify-start">
                <Ring
                  ratio={summary.totals.alerts ? summary.review.reviewed / summary.totals.alerts : 0}
                  display={summary.totals.alerts ? formatPercent(summary.review.reviewed / summary.totals.alerts, 0) : "—"}
                  caption="reviewed"
                  color={TONES.blue}
                  size={78}
                />
                <Ring
                  ratio={summary.review.false_positive_rate_on_reviewed ?? 0}
                  display={formatPercent(summary.review.false_positive_rate_on_reviewed, 1)}
                  caption="FP · reviewed"
                  color={TONES.amber}
                  size={78}
                />
              </div>
              <div className="grid min-w-0 flex-1 grid-cols-2 gap-x-3 gap-y-3 sm:grid-cols-3">
                <DetailStat label="Reviewed" value={formatNumber(summary.review.reviewed)} hint="closed or false positive" tone="blue" />
                <DetailStat label="Completed jobs" value={formatNumber(summary.processing.completed_jobs)} tone="violet" />
                <DetailStat label="Records processed" value={formatNumber(summary.processing.records_processed)} tone="accent" />
                <DetailStat
                  label="Avg processing"
                  value={summary.processing.avg_processing_ms !== null ? `${summary.processing.avg_processing_ms} ms` : "—"}
                  tone="mint"
                />
                <DetailStat
                  label="Avg detection"
                  value={summary.processing.avg_detection_ms !== null ? `${summary.processing.avg_detection_ms} ms` : "—"}
                  tone="mint"
                />
                <DetailStat label="False positives" value={formatNumber(summary.totals.false_positives)} tone="amber" />
              </div>
            </div>
            <p className="mt-3 text-[10.5px] leading-relaxed text-slate-600">{summary.processing.note}</p>
          </Panel>

          <div className="grid gap-4 lg:grid-cols-2">
            <RankList
              title="Top sources"
              subtitle="Volume recorded from each source IP"
              rows={summary.top_sources.map((row) => ({ label: row.ip, value: row.bytes }))}
              valueFormatter={formatBytes}
              tone="blue"
              emptyLabel="No flows in this period"
            />
            <RankList
              title="Top destinations"
              subtitle="Volume recorded toward each destination IP"
              rows={summary.top_destinations.map((row) => ({ label: row.ip, value: row.bytes }))}
              valueFormatter={formatBytes}
              tone="violet"
              emptyLabel="No flows in this period"
            />
          </div>

          <Panel className="p-4">
            <SectionTitle
              eyebrow="Provenance"
              title="How these numbers were produced"
              subtitle={summary.query.description}
            />
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2">
                <p className="label mb-1">Data source</p>
                <p className="text-[11.5px] text-slate-300">{summary.query.data_source}</p>
              </div>
              <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2">
                <p className="label mb-1">Record limit</p>
                <p className="font-mono text-[11.5px] text-slate-300">{formatNumber(summary.query.record_limit)} flows per report</p>
              </div>
            </div>
            <div className="mt-3 rounded-lg border border-signal-amber/15 bg-signal-amber/[0.03] px-3 py-2">
              <p className="label mb-1 text-signal-amber/80">Known limitations</p>
              <ul className="space-y-1">
                {summary.limitations.map((item) => (
                  <li key={item} className="text-[11px] leading-relaxed text-slate-400">
                    · {item}
                  </li>
                ))}
              </ul>
            </div>
            <p className="mt-3 text-[10.5px] leading-relaxed text-slate-600">{report?.linkage.note}</p>
          </Panel>
        </div>
      )}
    </Modal>
  );
}

interface NewReportState {
  kind: string;
  period: "24h" | "7d" | "30d" | "custom";
  start: string;
  end: string;
}

export function Reports() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const { workspace, workspaces, workspaceSlug } = useWorkspace();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [draft, setDraft] = useState<NewReportState>({ kind: "security_summary", period: "24h", start: "", end: "" });
  const [targetWorkspace, setTargetWorkspace] = useState(workspaceSlug);

  const canExport = hasPermission("reports.export");

  const listQuery = useQuery({
    queryKey: ["reports", workspaceSlug, page],
    queryFn: () =>
      api.get<ReportsListResponse>("/reports", { workspace: workspaceSlug, page, page_size: 9 }),
    refetchInterval: 60_000,
  });

  const createReport = useMutation({
    mutationFn: () =>
      api.post<ReportItem>("/reports", {
        workspace: targetWorkspace,
        kind: draft.kind,
        period: draft.period,
        start: draft.period === "custom" ? new Date(draft.start).toISOString() : undefined,
        end: draft.period === "custom" ? new Date(draft.end).toISOString() : undefined,
      }),
    onSuccess: (report) => {
      toast("success", "Report generated", `${report.reference} is ready.`);
      setCreateOpen(false);
      setSelectedId(report.id);
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
    onError: (error: Error) => toast("error", "Report could not be generated", error.message),
  });

  const reports = listQuery.data?.items ?? [];
  const pageAlerts = reports.reduce((sum, report) => sum + (report.peek.alerts ?? 0), 0);
  const pageCritical = reports.reduce((sum, report) => sum + (report.peek.critical ?? 0), 0);
  const chronological = [...reports].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  const alertSpark = chronological.map((report) => report.peek.alerts ?? 0);
  const criticalSpark = chronological.map((report) => report.peek.critical ?? 0);
  const latestReport = reports.reduce<ReportItem | null>(
    (latest, report) =>
      !latest || new Date(report.created_at).getTime() > new Date(latest.created_at).getTime() ? report : latest,
    null,
  );
  const kinds = listQuery.data?.kinds ?? [
    { value: "security_summary", label: "Network threat & traffic summary" },
    { value: "executive", label: "Executive security posture" },
    { value: "detector_performance", label: "Detector effectiveness review" },
  ];

  const customInvalid =
    draft.period === "custom" &&
    (!draft.start || !draft.end || new Date(draft.start) >= new Date(draft.end));

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Reports"
        title="Evidence-backed reporting"
        description="Reports are computed server-side from stored flows and alerts at generation time. Each export carries its query, period and known limitations."
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="btn-ghost px-2.5 py-1.5"
              onClick={() => listQuery.refetch()}
              disabled={listQuery.isFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", listQuery.isFetching && "animate-spin")} />
              Refresh
            </button>
            <button type="button" className="btn-primary px-3 py-1.5" onClick={() => setCreateOpen(true)}>
              <Plus className="h-3.5 w-3.5" />
              Generate report
            </button>
          </div>
        }
      />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 text-[11.5px] text-slate-500">
          <span className="label">Workspace</span>
          <Badge tone="slate">{workspace?.name ?? workspaceSlug}</Badge>
          <span className="font-mono text-[10.5px] uppercase tracking-[0.08em] text-slate-600">
            {workspace?.environment ?? "—"}
          </span>
        </div>
        <p className="text-[11px] text-slate-500">
          Values reflect telemetry stored at generation time. Re-generating with a different period may yield different totals.
        </p>
      </div>

      {listQuery.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, index) => (
            <Skeleton key={index} className="h-56 w-full" />
          ))}
        </div>
      ) : listQuery.isError ? (
        <ErrorState message={(listQuery.error as Error).message} retry={() => listQuery.refetch()} />
      ) : !reports.length ? (
        <EmptyState
          title="No reports generated yet"
          description="Generate a report to capture a consistent snapshot of traffic, detections and review activity for the selected period."
          icon={<FileBarChart className="h-4 w-4" />}
          action={
            <button type="button" className="btn-primary px-3 py-1.5" onClick={() => setCreateOpen(true)}>
              <Plus className="h-3.5 w-3.5" /> Generate report
            </button>
          }
        />
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-2.5 xl:grid-cols-4">
            <SparkKpi
              label="Reports stored"
              value={formatNumber(listQuery.data?.total ?? reports.length)}
              icon={FileBarChart}
              tone="blue"
              help="Reports are stored aggregates scoped to the active workspace."
              footnote="workspace scope"
            />
            <SparkKpi
              label="On this page"
              value={formatNumber(reports.length)}
              icon={Layers}
              tone="violet"
              footnote={latestReport ? `latest ${relativeTime(latestReport.created_at)}` : undefined}
            />
            <SparkKpi
              label="Alerts captured"
              value={formatNumber(pageAlerts)}
              icon={ShieldAlert}
              tone="accent"
              spark={alertSpark}
              help="Sum of alert counts recorded inside each report on this page."
              footnote="sum over current page"
            />
            <SparkKpi
              label="Critical captured"
              value={formatNumber(pageCritical)}
              icon={TriangleAlert}
              tone="rose"
              spark={criticalSpark}
              sparkColor={TONES.rose}
              footnote="sum over current page"
            />
          </div>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {reports.map((report) => {
              const alerts = report.peek.alerts ?? 0;
              const critical = report.peek.critical ?? 0;
              const criticalShare = alerts > 0 ? critical / alerts : 0;
              const kindTone = KIND_TONE[report.kind] ?? "slate";
              const kindColor = TONES[kindTone as keyof typeof TONES] ?? TONES.slate;
              return (
                <Panel key={report.id} className="panel-hover flex flex-col p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={kindTone}>{report.kind_label}</Badge>
                        <StatusBadge status={report.status} />
                      </div>
                      <h3 className="mt-2 text-[13px] font-semibold leading-snug tracking-tight text-slate-100">
                        {report.title}
                      </h3>
                      <p className="mt-1 font-mono text-[10.5px] text-slate-500">{report.reference}</p>
                    </div>
                    <span
                      aria-hidden
                      className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border"
                      style={{ background: `${kindColor}14`, borderColor: `${kindColor}2b`, color: kindColor }}
                    >
                      <FileBarChart className="h-4 w-4" />
                    </span>
                  </div>

                  <dl className="mt-3 grid grid-cols-3 gap-2 border-y border-white/[0.06] py-2.5">
                    <div>
                      <dt className="label text-[9.5px]">Alerts</dt>
                      <dd className="font-mono text-[13px] tabular-nums text-slate-200">{formatNumber(alerts)}</dd>
                    </div>
                    <div>
                      <dt className="label text-[9.5px]">Flows</dt>
                      <dd className="font-mono text-[13px] tabular-nums text-slate-200">{formatNumber(report.peek.flows ?? 0)}</dd>
                    </div>
                    <div>
                      <dt className="label text-[9.5px]">Critical</dt>
                      <dd className={cn("font-mono text-[13px] tabular-nums", critical > 0 ? "text-signal-rose" : "text-slate-200")}>
                        {formatNumber(critical)}
                      </dd>
                    </div>
                  </dl>

                  <div className="mt-2.5">
                    <div className="flex items-baseline justify-between text-[9px] uppercase tracking-[0.1em] text-slate-600">
                      <span>critical share</span>
                      <span className="font-mono tabular-nums">{alerts ? formatPercent(criticalShare, 0) : "—"}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
                      <div
                        className="h-full rounded-full transition-[width] duration-700"
                        style={{
                          width: `${alerts ? Math.max(2, criticalShare * 100) : 0}%`,
                          background: TONES.rose,
                          boxShadow: `0 0 6px ${TONES.rose}66`,
                        }}
                      />
                    </div>
                  </div>

                  <div className="mt-2.5 space-y-1 text-[10.5px] text-slate-500">
                    <p>
                      Period{" "}
                      <span className="font-mono text-slate-400">
                        {formatDateTime(report.period.start)}Z → {formatDateTime(report.period.end)}Z
                      </span>
                    </p>
                    <p>
                      Generated {relativeTime(report.created_at)}
                      {report.created_by ? ` by ${report.created_by}` : ""}
                    </p>
                    <p className="font-mono text-[9.5px] uppercase tracking-[0.08em] text-slate-600">
                      {report.environment} · {report.workspace ?? "workspace"}
                    </p>
                  </div>

                  <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-3">
                    <button type="button" className="btn-secondary px-2.5 py-1 text-[11px]" onClick={() => setSelectedId(report.id)}>
                      <FileBarChart className="h-3 w-3" /> View
                    </button>
                    <ExportButtons report={report} canExport={canExport} />
                  </div>
                </Panel>
              );
            })}
          </div>
          {listQuery.data ? (
            <Pagination
              page={listQuery.data.page}
              pageSize={listQuery.data.page_size}
              total={listQuery.data.total}
              onChange={setPage}
            />
          ) : null}
        </>
      )}

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Generate a report"
        description="Aggregates are computed once at generation time and stored with the report."
        footer={
          <div className="flex items-center justify-end gap-2">
            <button type="button" className="btn-ghost px-3 py-1.5" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn-primary px-3 py-1.5"
              disabled={createReport.isPending || customInvalid}
              onClick={() => createReport.mutate()}
            >
              {createReport.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileBarChart className="h-3.5 w-3.5" />}
              Generate
            </button>
          </div>
        }
      >
        <div className="space-y-3">
          <label className="block">
            <span className="label mb-1.5 block">Workspace</span>
            <select
              value={targetWorkspace}
              onChange={(event) => setTargetWorkspace(event.target.value)}
              className="input w-full"
            >
              {workspaces.map((item) => (
                <option key={item.slug} value={item.slug}>
                  {item.name} · {item.environment}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Report kind</span>
            <select
              value={draft.kind}
              onChange={(event) => setDraft({ ...draft, kind: event.target.value })}
              className="input w-full"
            >
              {kinds.map((kind) => (
                <option key={kind.value} value={kind.value}>
                  {kind.label}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Period</span>
            <select
              value={draft.period}
              onChange={(event) => setDraft({ ...draft, period: event.target.value as NewReportState["period"] })}
              className="input w-full"
            >
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="custom">Custom range</option>
            </select>
          </label>
          {draft.period === "custom" ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="label mb-1.5 block">Start (UTC)</span>
                <input
                  type="datetime-local"
                  value={draft.start}
                  onChange={(event) => setDraft({ ...draft, start: event.target.value })}
                  className="input w-full"
                />
              </label>
              <label className="block">
                <span className="label mb-1.5 block">End (UTC)</span>
                <input
                  type="datetime-local"
                  value={draft.end}
                  onChange={(event) => setDraft({ ...draft, end: event.target.value })}
                  className="input w-full"
                />
              </label>
              {customInvalid ? (
                <p className="sm:col-span-2 text-[11px] text-signal-amber">
                  Provide a start and end time where start precedes end.
                </p>
              ) : null}
            </div>
          ) : null}
          <p className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
            Flow aggregation is capped at 300,000 records per report. If the selected period exceeds that,
            totals reflect the capped sample and the report retains the same limit in its metadata.
          </p>
        </div>
      </Modal>

      <ReportDetailView
        reportId={selectedId}
        canExport={canExport}
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
