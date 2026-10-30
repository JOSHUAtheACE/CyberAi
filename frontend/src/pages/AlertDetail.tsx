import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Download,
  ExternalLink,
  FileText,
  Gauge,
  Link2,
  Loader2,
  Lock,
  MessageSquarePlus,
  Network,
  ShieldAlert,
  ShieldOff,
  StickyNote,
} from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Badge,
  ConfidenceBadge,
  CopyButton,
  EmptyState,
  ErrorState,
  InfoHint,
  Panel,
  PageHeader,
  SectionTitle,
  SeverityBadge,
  Skeleton,
  StatusBadge,
} from "@/components/ui";
import { MetricTile } from "@/components/app";
import { Ring, TONES, severityColor } from "@/components/visuals";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { api } from "@/lib/api";
import {
  cn,
  formatBytes,
  formatDateTime,
  formatDuration,
  formatNumber,
  relativeTime,
  titleCase,
} from "@/lib/format";
import type { AlertDetail as AlertDetailType, AlertMeta, EvidenceItem } from "@/lib/types";

const STATUS_OPTIONS = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"];

const CONFIDENCE_LABEL: Record<string, string> = {
  calibrated_probability: "Calibrated probability",
  hybrid_score: "Hybrid score · not a probability",
  heuristic_score: "Heuristic score · not a probability",
  anomaly_score: "Anomaly score · relative, not a probability",
};

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-white/[0.04] py-1.5">
      <span className="text-[10.5px] text-slate-500">{label}</span>
      <span className="text-right font-mono text-[10.5px] text-slate-300">{value}</span>
    </div>
  );
}

function EvidenceCard({ item }: { item: EvidenceItem }) {
  const observed = Number(item.observed_value);
  const baseline = Number(item.baseline_value);
  const comparable =
    Number.isFinite(observed) && Number.isFinite(baseline) && observed >= 0 && baseline >= 0 && (observed > 0 || baseline > 0);
  const max = Math.max(observed, baseline, 1);
  const delta = comparable && baseline > 0 ? ((observed - baseline) / baseline) * 100 : null;

  return (
    <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-[11px] font-medium capitalize text-slate-200">{item.feature.replace(/_/g, " ")}</p>
          {item.kind ? <p className="mt-0.5 text-[9px] uppercase tracking-[0.1em] text-slate-600">{item.kind}</p> : null}
        </div>
        <p className="shrink-0 font-mono text-[13px] text-slate-100">
          {item.observed_value ?? "—"}
          {item.unit ? <span className="ml-1 text-[10px] text-slate-500">{item.unit}</span> : null}
        </p>
      </div>

      {comparable ? (
        <div className="mt-2.5 space-y-1.5">
          <div>
            <div className="flex items-baseline justify-between gap-2 text-[8.5px] text-slate-600">
              <span className="uppercase tracking-[0.08em]">baseline</span>
              <span className="font-mono">
                {baseline.toLocaleString()}
                {item.unit ? ` ${item.unit}` : ""}
              </span>
            </div>
            <div className="mt-0.5 h-[3px] overflow-hidden rounded-full bg-white/[0.05]">
              <div className="h-full rounded-full bg-slate-500/60" style={{ width: `${Math.max(2, (baseline / max) * 100)}%` }} />
            </div>
          </div>
          <div>
            <div className="flex items-baseline justify-between gap-2 text-[8.5px] text-slate-500">
              <span className="uppercase tracking-[0.08em]">observed</span>
              <span className="font-mono" style={{ color: TONES.accent }}>
                {observed.toLocaleString()}
                {item.unit ? ` ${item.unit}` : ""}
              </span>
            </div>
            <div className="mt-0.5 h-[3px] overflow-hidden rounded-full bg-white/[0.05]">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.max(2, (observed / max) * 100)}%`,
                  background: TONES.accent,
                  boxShadow: `0 0 6px ${TONES.accent}66`,
                }}
              />
            </div>
          </div>
          {delta !== null ? (
            <p className="text-right font-mono text-[8.5px] text-slate-600">
              {delta >= 0 ? "+" : ""}
              {delta.toFixed(1)}% vs baseline
            </p>
          ) : null}
        </div>
      ) : item.baseline_value ? (
        <p className="mt-1.5 font-mono text-[9.5px] text-slate-600">
          baseline {item.baseline_value}
          {item.unit ? ` ${item.unit}` : ""}
        </p>
      ) : null}

      {item.description ? <p className="mt-1.5 line-clamp-2 text-[10px] leading-relaxed text-slate-500">{item.description}</p> : null}
      {item.flow_ids?.length ? (
        <p className="mt-1.5 font-mono text-[9px] text-slate-700">
          flows {item.flow_ids.slice(0, 5).join(", ")}
          {item.flow_ids.length > 5 ? "…" : ""}
        </p>
      ) : null}
    </div>
  );
}

export function AlertDetail() {
  const { id } = useParams();
  const alertId = Number(id);
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");

  const canInvestigate = hasPermission("alerts.investigate");
  const canAssign = hasPermission("alerts.assign");
  const canExport = hasPermission("alerts.export");

  const alert = useQuery({
    queryKey: ["alert", alertId],
    queryFn: () => api.get<AlertDetailType>(`/alerts/${alertId}`),
    enabled: Number.isFinite(alertId),
    refetchInterval: 20_000,
  });

  const meta = useQuery({
    queryKey: ["alerts-meta"],
    queryFn: () => api.get<AlertMeta>("/alerts/meta"),
    staleTime: 60_000,
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["alert", alertId] });
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["overview"] });
  };

  const update = useMutation({
    mutationFn: (payload: { status?: string; assignee_id?: number }) => api.patch(`/alerts/${alertId}`, payload),
    onSuccess: (_data, variables) => {
      toast(
        "success",
        variables.status ? `Status set to ${titleCase(variables.status)}` : "Assignee updated",
        "The change is recorded in the audit log.",
      );
      refresh();
    },
    onError: (error) => toast("error", "Update failed", error instanceof Error ? error.message : "Try again."),
  });

  const addNote = useMutation({
    mutationFn: () => api.post<{ id: number }>(`/alerts/${alertId}/notes`, { body: note.trim() }),
    onSuccess: () => {
      setNote("");
      toast("success", "Investigation note added", "Notes are retained with the case and shown here.");
      refresh();
    },
    onError: (error) => toast("error", "Note not saved", error instanceof Error ? error.message : "Try again."),
  });

  const exportAlert = useMutation({
    mutationFn: async () => {
      const current = alert.data;
      await api.download(`/alerts/${alertId}/export`, `${current?.alert_code ?? "alert"}-evidence.json`);
    },
    onSuccess: () => toast("success", "Evidence export downloaded", "The JSON includes alert evidence, flows and investigation notes."),
    onError: (error) => toast("error", "Export failed", error instanceof Error ? error.message : "Try again."),
  });

  if (!Number.isFinite(alertId)) {
    return <ErrorState message="Invalid alert reference." />;
  }

  if (alert.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-24 w-full" />
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-80 w-full lg:col-span-2" />
          <Skeleton className="h-80 w-full" />
        </div>
      </div>
    );
  }

  if (alert.isError || !alert.data) {
    return (
      <div>
        <button type="button" className="btn-ghost mb-4 px-2 py-1" onClick={() => navigate("/app/alerts")}>
          <ArrowLeft className="h-3.5 w-3.5" /> Back to alerts
        </button>
        <ErrorState
          message={alert.error instanceof Error ? alert.error.message : "This alert could not be loaded. It may not exist in the selected workspace."}
          retry={() => void alert.refetch()}
        />
      </div>
    );
  }

  const data = alert.data;
  const caseData = data.case;
  const coverage = data.evidence_flow_coverage;
  const enrichmentAvailable = data.enrichment.length > 0;
  const firstLastSpan =
    data.first_seen && data.last_seen
      ? Math.max(0, new Date(data.last_seen).getTime() - new Date(data.first_seen).getTime())
      : null;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
        <Link to="/app/alerts" className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-200">
          <ArrowLeft className="h-3.5 w-3.5" /> Alert centre
        </Link>
        <span className="text-slate-700">/</span>
        <span className="font-mono text-slate-400">{data.alert_code}</span>
      </div>

      <PageHeader
        eyebrow={`${titleCase(data.threat_class)} · ${data.detector_code.replace(/_/g, " ")}`}
        title={data.summary}
        description={`${data.source_ip} → ${data.dest_ip} · ${data.protocol || "protocol not recorded"} · analytical assessment from stored metadata`}
        actions={
          <>
            <Badge tone={data.environment === "LIVE" ? "mint" : data.environment === "DEMO" ? "amber" : "blue"} dot>
              {data.environment}
            </Badge>
            <Badge tone="slate">{data.data_source.replace(/_/g, " ")}</Badge>
            {canExport ? (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => exportAlert.mutate()}
                disabled={exportAlert.isPending}
              >
                {exportAlert.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
                Export evidence
              </button>
            ) : null}
          </>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <SeverityBadge severity={data.severity} />
        <StatusBadge status={data.status} />
        <ConfidenceBadge type={data.confidence_type} value={data.confidence} />
        <span className="text-[10.5px] text-slate-500">
          first seen {formatDateTime(data.first_seen)}Z · last seen {formatDateTime(data.last_seen)}Z
        </span>
        {data.recurrence > 0 ? <Badge tone="amber">recurrence {data.recurrence}</Badge> : null}
      </div>

      {canInvestigate || canAssign ? (
        <Panel className="mb-5 flex flex-wrap items-center gap-2 p-3">
          <span className="label mr-1">Investigate</span>
          {canInvestigate ? (
            <>
              <label className="flex items-center gap-1.5">
                <span className="sr-only">Investigation status</span>
                <select
                  className="field w-auto py-1.5"
                  value={data.status}
                  disabled={update.isPending}
                  onChange={(event) => update.mutate({ status: event.target.value })}
                >
                  {STATUS_OPTIONS.map((status) => (
                    <option key={status} value={status}>
                      {titleCase(status)}
                    </option>
                  ))}
                </select>
              </label>
              {data.status !== "FALSE_POSITIVE" ? (
                <button
                  type="button"
                  className="btn-secondary px-2.5 py-1.5 text-[11px]"
                  disabled={update.isPending}
                  onClick={() => update.mutate({ status: "FALSE_POSITIVE" })}
                >
                  <ShieldOff className="h-3.5 w-3.5" /> Mark false positive
                </button>
              ) : null}
            </>
          ) : null}
          {canAssign ? (
            <label className="flex items-center gap-1.5">
              <span className="label">Assignee</span>
              <select
                className="field w-auto py-1.5"
                value={data.assignee_id ?? ""}
                disabled={update.isPending}
                onChange={(event) => update.mutate({ assignee_id: Number(event.target.value) })}
              >
                <option value={0}>Unassigned</option>
                {(meta.data?.assignees ?? []).map((assignee) => (
                  <option key={assignee.id} value={assignee.id}>
                    {assignee.name} · {assignee.role}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          <span className="ml-auto flex items-center gap-1 text-[10px] text-slate-600">
            <Lock className="h-3 w-3" /> Investigation only — no host action is taken
          </span>
        </Panel>
      ) : (
        <div className="mb-5 flex items-center gap-2 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2.5 text-[11px] text-slate-500">
          <Lock className="h-3.5 w-3.5" /> Your role can view this alert but cannot change its investigation state.
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-5">
          <Panel className="p-4 sm:p-5">
            <SectionTitle
              eyebrow="Evidence"
              title="Why this alert fired"
              subtitle="Values are read from the stored alert evidence. Confidence semantics are declared by the detector; they are not interchangeable with severity."
            />
            <div className="mt-4 grid gap-2 sm:grid-cols-2">
              {data.evidence.length ? (
                data.evidence.map((item, index) => <EvidenceCard key={item.id ?? `${item.feature}-${index}`} item={item} />)
              ) : (
                <div className="sm:col-span-2">
                  <EmptyState
                    compact
                    title="No structured evidence rows"
                    description="This alert carries a detection reason but no feature-level evidence. That is reported honestly rather than filled with invented values."
                    icon={<ShieldAlert className="h-4 w-4" />}
                  />
                </div>
              )}
            </div>

            {data.baseline && Object.keys(data.baseline).length ? (
              <div className="mt-4 rounded-lg border border-white/[0.06] bg-ink-900/35 p-3">
                <p className="flex items-center gap-1.5 text-[10.5px] font-medium text-slate-400">
                  <Gauge className="h-3 w-3" /> Baseline comparison
                  <InfoHint
                    text="Baselines are computed from the preceding observation window for the same entity or deployment. They are analytical context, not proof of compromise."
                    label="About baselines"
                  />
                </p>
                <div className="mt-2 grid gap-x-5 gap-y-1 sm:grid-cols-2">
                  {Object.entries(data.baseline).map(([key, value]) => (
                    <MetaRow key={key} label={key.replace(/_/g, " ")} value={typeof value === "number" ? formatNumber(value, 2) : String(value)} />
                  ))}
                </div>
              </div>
            ) : null}

            <div className="mt-4 rounded-lg border border-white/[0.06] bg-ink-900/35 p-3">
              <p className="label mb-1.5">Detection reason</p>
              <p className="text-[11.5px] leading-relaxed text-slate-300">{data.detection_reason}</p>
            </div>
          </Panel>

          <Panel className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
              <SectionTitle
                title="Underlying flows"
                subtitle={`${formatNumber(coverage.referenced)} referenced · ${formatNumber(coverage.loaded)} loaded${coverage.truncated ? " · truncated" : ""}`}
              />
              <span className="flex items-center gap-1 text-[10px] text-slate-600">
                <Network className="h-3 w-3" /> Metadata only
                <InfoHint text={coverage.note} label="About flow coverage" />
              </span>
            </div>
            {data.flows.length ? (
              <div className="max-h-[420px] overflow-auto">
                <table className="table-base min-w-[820px]">
                  <thead className="sticky top-0 bg-ink-850">
                    <tr>
                      <th>Timestamp (UTC)</th>
                      <th>Path</th>
                      <th>Protocol</th>
                      <th>Volume</th>
                      <th>Packets</th>
                      <th>Duration</th>
                      <th>Metadata</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.flows.map((flow) => (
                      <tr key={flow.id}>
                        <td className="whitespace-nowrap font-mono text-[10.5px] text-slate-400">{formatDateTime(flow.ts)}</td>
                        <td>
                          <p className="font-mono text-[11px] text-slate-300">
                            {flow.src_ip}:{flow.src_port}
                          </p>
                          <p className="font-mono text-[10.5px] text-slate-500">
                            → {flow.dst_ip}:{flow.dst_port}
                          </p>
                        </td>
                        <td>
                          <Badge tone="slate">{flow.protocol}</Badge>
                          {flow.app_proto ? <p className="mt-0.5 text-[9.5px] text-slate-600">{flow.app_proto}</p> : null}
                        </td>
                        <td>
                          <p className="font-mono text-[11px] text-slate-300">{formatBytes(flow.bytes_total)}</p>
                          <p className="text-[9.5px] text-slate-600">{formatBytes(flow.bytes_out)} out · {formatBytes(flow.bytes_in)} in</p>
                        </td>
                        <td className="font-mono text-[11px] text-slate-300">{formatNumber(flow.packets)}</td>
                        <td className="font-mono text-[11px] text-slate-300">{formatDuration(flow.duration_ms)}</td>
                        <td className="max-w-[210px]">
                          {flow.dns_query ? <p className="truncate font-mono text-[10px] text-slate-400">dns {flow.dns_query}</p> : null}
                          {flow.tls_sni ? <p className="truncate font-mono text-[10px] text-slate-400">sni {flow.tls_sni}</p> : null}
                          {flow.tls_ja3 ? <p className="truncate font-mono text-[9.5px] text-slate-600">ja3 {flow.tls_ja3}</p> : null}
                          {!flow.dns_query && !flow.tls_sni && !flow.tls_ja3 ? <span className="text-slate-700">—</span> : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-4">
                <EmptyState
                  compact
                  title="Flow records are not available"
                  description={coverage.note}
                  icon={<FileText className="h-4 w-4" />}
                />
              </div>
            )}
          </Panel>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Panel className="p-4">
              <SectionTitle title="Related alerts" subtitle="Explicit links created during investigations." />
              <div className="mt-3 space-y-1.5">
                {data.related.length ? (
                  data.related.map((item) => (
                    <Link key={item.id} to={`/app/alerts/${item.id}`} className="flex items-center gap-2 rounded-lg border border-white/[0.06] px-2.5 py-2 hover:border-white/[0.12]">
                      <SeverityBadge severity={item.severity} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[11px] text-slate-300">{item.summary}</p>
                        <p className="font-mono text-[9.5px] text-slate-600">{item.alert_code}</p>
                      </div>
                      <Link2 className="h-3 w-3 text-slate-600" />
                    </Link>
                  ))
                ) : (
                  <p className="py-2 text-[11px] text-slate-500">No linked alerts.</p>
                )}
              </div>
            </Panel>
            <Panel className="p-4">
              <SectionTitle title="Similar observations" subtitle="Same source or destination in the previous seven days." />
              <div className="mt-3 space-y-1.5">
                {data.similar.length ? (
                  data.similar.map((item) => (
                    <Link key={item.id} to={`/app/alerts/${item.id}`} className="flex items-center gap-2 rounded-lg border border-white/[0.06] px-2.5 py-2 hover:border-white/[0.12]">
                      <SeverityBadge severity={item.severity} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[11px] text-slate-300">{item.summary}</p>
                        <p className="text-[9.5px] text-slate-600">{item.relation}</p>
                      </div>
                      <span className="text-[9.5px] text-slate-600">{relativeTime(item.first_seen)}</span>
                    </Link>
                  ))
                ) : (
                  <p className="py-2 text-[11px] text-slate-500">No similar alerts stored for this entity.</p>
                )}
              </div>
            </Panel>
          </div>
        </div>

        <div className="min-w-0 space-y-5">
          <Panel className="p-4">
            <div className="flex items-start justify-between gap-2">
              <div>
                <h3 className="text-[12.5px] font-semibold tracking-tight text-slate-200">Confidence &amp; impact</h3>
                <p className="mt-0.5 text-[10px] text-slate-600">Detector certainty for this evidence</p>
              </div>
              <SeverityBadge severity={data.severity} />
            </div>
            <div className="mt-3 flex items-center gap-4">
              <Ring
                ratio={data.confidence}
                display={data.confidence.toFixed(3)}
                caption="confidence"
                size={112}
                thickness={9}
                color={severityColor(data.severity)}
              />
              <div className="min-w-0 flex-1 space-y-1.5 text-[10px]">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-slate-500">Score type</span>
                  <span className="truncate text-right font-mono text-slate-300">{data.confidence_type.replace(/_/g, " ")}</span>
                </div>
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-slate-500">Detector</span>
                  <span className="truncate text-right font-mono text-slate-300">{data.detector_code.replace(/_/g, " ").replace("detector", "").trim()}</span>
                </div>
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-slate-500">Protocol</span>
                  <span className="font-mono text-slate-300">{data.protocol || "—"}</span>
                </div>
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-slate-500">Last seen</span>
                  <span className="font-mono text-slate-300">{relativeTime(data.last_seen)}</span>
                </div>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <MetricTile label="Flows" value={formatNumber(data.flow_count)} />
              <MetricTile label="Recurrence" value={formatNumber(data.recurrence)} />
              <MetricTile label="First window" value={firstLastSpan === null ? "—" : formatDuration(firstLastSpan)} />
              <MetricTile label="Evidence rows" value={formatNumber(data.evidence.length)} />
            </div>
            <p className="mt-2 flex items-center gap-1 text-[9px] leading-relaxed text-slate-600">
              {CONFIDENCE_LABEL[data.confidence_type] ?? data.confidence_type.replace(/_/g, " ")}. Confidence is independent of severity.
              <InfoHint
                text="Confidence expresses detector certainty for the stored evidence. Hybrid, heuristic and anomaly scores are not calibrated probabilities. Severity expresses potential impact."
                label="About confidence semantics"
              />
            </p>
          </Panel>

          <Panel className="p-4">
            <SectionTitle
              eyebrow="Investigation"
              title={caseData ? caseData.case_code : "No case opened"}
              subtitle={caseData ? `Owner: ${caseData.owner ?? "unassigned"} · ${titleCase(caseData.status)}` : "Notes and status changes open a case automatically."}
            />

            <div className="mt-3">
              <div className="mb-2 flex items-center justify-between gap-2">
                <p className="label">Case notes</p>
                <span className="font-mono text-[9.5px] text-slate-600">{caseData?.notes.length ?? 0}</span>
              </div>
              {caseData?.notes.length ? (
                <div className="max-h-[260px] space-y-2 overflow-y-auto pr-1">
                  {caseData.notes.map((entry) => (
                    <div key={entry.id} className="rounded-lg border border-white/[0.05] bg-ink-900/40 px-3 py-2">
                      <div className="flex items-center justify-between gap-2 text-[9.5px] text-slate-600">
                        <span className="font-medium text-slate-400">{entry.author}</span>
                        <span title={`${formatDateTime(entry.created_at)}Z`}>{relativeTime(entry.created_at)}</span>
                      </div>
                      <p className="mt-1 whitespace-pre-wrap text-[11px] leading-relaxed text-slate-300">{entry.body}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="rounded-lg border border-dashed border-white/[0.08] px-3 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
                  No notes yet. Notes are timestamped, attributed and retained for audit.
                </p>
              )}

              {canInvestigate ? (
                <div className="mt-3">
                  <label className="block">
                    <span className="sr-only">Add investigation note</span>
                    <textarea
                      className="field min-h-[84px] resize-y text-[11.5px]"
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      placeholder="Record what you verified, what you ruled out, and the next step."
                      maxLength={4000}
                    />
                  </label>
                  <div className="mt-1.5 flex items-center justify-between gap-2">
                    <span className="text-[9.5px] text-slate-600">{note.length} / 4000</span>
                    <button
                      type="button"
                      className="btn-primary px-2.5 py-1 text-[11px]"
                      disabled={note.trim().length < 3 || addNote.isPending}
                      onClick={() => addNote.mutate()}
                    >
                      {addNote.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <MessageSquarePlus className="h-3 w-3" />} Add note
                    </button>
                  </div>
                </div>
              ) : null}
            </div>
          </Panel>

          <Panel className="p-4">
            <SectionTitle
              eyebrow="External context"
              title="Enrichment"
              subtitle="Only allowlisted indicators are eligible. External enrichment is disabled by default."
            />
            <div className="mt-3 space-y-2">
              {enrichmentAvailable ? (
                data.enrichment.map((item) => (
                  <div key={item.id} className="rounded-lg border border-white/[0.06] bg-ink-900/40 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-[11px] font-medium text-slate-200">{item.provider}</p>
                        <p className="mt-0.5 truncate font-mono text-[10px] text-slate-500">{item.indicator}</p>
                      </div>
                      <Badge tone={item.status === "OK" || item.status === "SUCCESS" ? "mint" : item.status === "NOT_CONFIGURED" ? "slate" : "amber"}>
                        {item.status}
                      </Badge>
                    </div>
                    <p className="mt-1.5 text-[9.5px] text-slate-600">
                      {item.cached ? "cached result" : "live lookup"} · {relativeTime(item.retrieved_at)}
                    </p>
                    {item.error ? <p className="mt-1 text-[10px] text-signal-rose">{item.error}</p> : null}
                    {item.payload ? (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-[10px] text-slate-500 hover:text-slate-300">Provider payload</summary>
                        <pre className="mt-1 max-h-40 overflow-auto rounded border border-white/[0.05] bg-ink-950/70 p-2 font-mono text-[9.5px] text-slate-500">
                          {JSON.stringify(item.payload, null, 2)}
                        </pre>
                      </details>
                    ) : null}
                  </div>
                ))
              ) : (
                <EmptyState
                  compact
                  title="No enrichment records"
                  description="External enrichment is disabled by default. No indicator was sent to a third party for this alert."
                  icon={<ExternalLink className="h-4 w-4" />}
                />
              )}
            </div>
            <p className="mt-3 flex items-start gap-1.5 text-[9.5px] leading-relaxed text-slate-600">
              <Lock className="mt-0.5 h-3 w-3 shrink-0" />
              Raw packets, internal hostnames and private addresses are never sent to external providers. Provider state is
              managed server-side; credentials are never exposed to this browser.
            </p>
          </Panel>

          <Panel className="p-4">
            <SectionTitle title="Alert metadata" subtitle="Identifiers and source attribution." />
            <div className="mt-2">
              <MetaRow label="Alert code" value={data.alert_code} />
              <MetaRow label="Detector" value={data.detector.code} />
              <MetaRow label="Detector model" value={data.detector.model_version_id ? `version #${data.detector.model_version_id}` : "rule-based / no model"} />
              <MetaRow label="Score type" value={data.confidence_type.replace(/_/g, " ")} />
              <MetaRow label="Protocol" value={data.protocol || "—"} />
              <MetaRow label="Data source" value={data.data_source} />
              <MetaRow label="Scenario" value={data.scenario_id ?? "—"} />
              <MetaRow label="Created" value={`${formatDateTime(data.created_at)}Z`} />
              <MetaRow label="Updated" value={`${formatDateTime(data.updated_at)}Z`} />
            </div>
            <div className="mt-3 flex items-center gap-2">
              <CopyButton value={data.alert_code} label="Copy code" />
              <span className="inline-flex items-center gap-1 text-[9.5px] text-slate-600">
                <StickyNote className="h-3 w-3" /> {data.environment} environment
              </span>
            </div>
          </Panel>
        </div>
      </div>

      <div className={cn("mt-5 flex items-start gap-2 rounded-lg border px-3.5 py-2.5 text-[10px] leading-relaxed", data.environment === "LIVE" ? "border-white/[0.06] bg-ink-900/30 text-slate-600" : "border-signal-amber/20 bg-signal-amber/[0.04] text-amber-100/60")}>
        <InfoHint
          label="About this alert"
          text="An alert is an analytical assessment derived from stored metadata. It does not confirm compromise, intent or attribution, and it does not trigger any action against a host or network."
        />
        {data.environment === "LIVE"
          ? "This alert was derived from live collector telemetry. Severity and confidence are analytical assessments, not confirmation of compromise."
          : "This alert belongs to a demo or replay environment. It is permanently labelled and must not be read as live detection."}
      </div>
    </div>
  );
}
