import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight,
  CheckCircle2,
  Database,
  FileWarning,
  Fingerprint,
  KeyRound,
  Loader2,
  Lock,
  Radio,
  RefreshCw,
  ShieldCheck,
  UploadCloud,
  Usb,
} from "lucide-react";
import { useCallback, useMemo, useRef, useState, type DragEvent } from "react";
import {
  Badge,
  CopyButton,
  EmptyState,
  ErrorState,
  InfoHint,
  Modal,
  Panel,
  PageHeader,
  SectionTitle,
  Skeleton,
  StatusBadge,
} from "@/components/ui";
import { Pagination, SummaryStrip } from "@/components/app";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api, ApiError } from "@/lib/api";
import {
  cn,
  formatBytes,
  formatDateTime,
  formatNumber,
  relativeTime,
  titleCase,
} from "@/lib/format";
import type {
  IngestionJob,
  JobsResponse,
  PreviewResponse,
  SourcesResponse,
  SystemStatus,
  TrafficSource,
} from "@/lib/types";

type Quality = {
  total_rows?: number;
  valid_records?: number;
  rejected_records?: number;
  rejection_reasons?: Record<string, number>;
  columns_detected?: string[];
  column_mapping?: Record<string, string>;
  supported_modules?: string[];
  absence_report?: Record<string, string | number | boolean> | string[];
  notes?: string[];
  log_records?: number;
  direction_available?: boolean;
};

function qualityOf(preview: PreviewResponse | null): Quality | null {
  if (!preview?.quality) return null;
  return preview.quality as Quality;
}

function Field({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <p className="label">{label}</p>
      <p className="mt-1 font-mono text-[11.5px] leading-relaxed text-slate-300 break-words">{value}</p>
      {hint ? <p className="mt-0.5 text-[10.5px] leading-relaxed text-slate-600">{hint}</p> : null}
    </div>
  );
}

function QualityReport({ preview }: { preview: PreviewResponse }) {
  const quality = qualityOf(preview);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {preview.valid ? (
          <Badge tone="mint" dot>
            Validated
          </Badge>
        ) : (
          <Badge tone="rose" dot>
            Rejected
          </Badge>
        )}
        <Badge tone="slate">{preview.kind === "pcap" ? "Packet capture" : `Flow export · ${preview.format ?? "csv"}`}</Badge>
        <span className="font-mono text-[10.5px] text-slate-500">{formatBytes(preview.size_bytes)}</span>
      </div>

      {preview.errors?.length ? (
        <div className="rounded-lg border border-signal-rose/25 bg-signal-rose/[0.05] px-3 py-2.5">
          <p className="flex items-center gap-1.5 text-[11.5px] font-medium text-signal-rose">
            <FileWarning className="h-3.5 w-3.5" /> Validation failed
          </p>
          <ul className="mt-1.5 space-y-1 text-[11px] leading-relaxed text-rose-200/80">
            {preview.errors.map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3">
        {preview.kind === "pcap" ? (
          <>
            <Field label="Packets sampled" value={formatNumber(preview.packet_count ?? 0)} hint="Preview reads the first 20,000 packets." />
            <Field label="Flows derived" value={formatNumber(preview.flow_count ?? 0)} />
            <Field label="Link types" value={(preview.link_types ?? []).join(", ") || "—"} hint="Standard pcap link-layer values." />
            <Field label="Capture start" value={formatDateTime(preview.capture_start)} />
            <Field label="Capture end" value={formatDateTime(preview.capture_end)} />
          </>
        ) : (
          <>
            <Field label="Records detected" value={formatNumber(preview.record_count ?? 0)} />
            <Field label="Accepted" value={formatNumber(quality?.valid_records ?? 0)} />
            <Field label="Rejected" value={formatNumber(quality?.rejected_records ?? 0)} />
            <Field label="Timestamp start" value={formatDateTime(preview.timestamp_range?.start)} />
            <Field label="Timestamp end" value={formatDateTime(preview.timestamp_range?.end)} />
            <Field
              label="Direction"
              value={quality?.direction_available ? "Present" : "Not present"}
              hint="Without direction, outbound volume is estimated from the internal CIDR map."
            />
          </>
        )}
      </div>

      {quality ? (
        <>
          <div>
            <p className="label mb-1.5">Columns detected</p>
            <div className="flex flex-wrap gap-1">
              {(quality.columns_detected ?? []).slice(0, 24).map((column) => (
                <span key={column} className="rounded border border-white/[0.07] bg-white/[0.025] px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                  {column}
                </span>
              ))}
              {(quality.columns_detected ?? []).length > 24 ? (
                <span className="px-1 text-[10px] text-slate-600">+{(quality.columns_detected ?? []).length - 24} more</span>
              ) : null}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <p className="label mb-1.5">Detector inputs available</p>
              {(quality.supported_modules ?? []).length ? (
                <div className="flex flex-wrap gap-1">
                  {(quality.supported_modules ?? []).map((module) => (
                    <Badge key={module} tone="accent">
                      {module}
                    </Badge>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-slate-500">No detector-required fields were recognised.</p>
              )}
            </div>
            <div>
              <p className="label mb-1.5">Rejection reasons</p>
              {Object.keys(quality.rejection_reasons ?? {}).length ? (
                <ul className="space-y-0.5 text-[11px] text-slate-400">
                  {Object.entries(quality.rejection_reasons ?? {}).map(([reason, count]) => (
                    <li key={reason} className="flex justify-between gap-3">
                      <span>{titleCase(reason)}</span>
                      <span className="font-mono text-slate-300">{formatNumber(count)}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-[11px] text-slate-500">Every sampled record satisfied the contract.</p>
              )}
            </div>
          </div>
        </>
      ) : null}

      {preview.notes?.length ? (
        <ul className="space-y-1 rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
          {preview.notes.map((note) => (
            <li key={note} className="flex gap-1.5">
              <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
              {note}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function PreviewTable({ rows, kind }: { rows: Record<string, unknown>[]; kind: string }) {
  if (!rows.length) return null;
  const keys = Array.from(new Set(rows.flatMap((row) => Object.keys(row)))).slice(0, kind === "pcap" ? 6 : 8);
  return (
    <div className="overflow-x-auto rounded-lg border border-white/[0.06]">
      <table className="table-base min-w-[620px]">
        <thead>
          <tr>
            {keys.map((key) => (
              <th key={key}>{key.replace(/_/g, " ")}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 6).map((row, index) => (
            <tr key={index}>
              {keys.map((key) => (
                <td key={key} className="max-w-[220px] truncate font-mono text-[10.5px]">
                  {row[key] === null || row[key] === undefined || row[key] === "" ? "—" : String(row[key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function JobDetail({ job }: { job: IngestionJob }) {
  const stats = job.stats ?? {};
  const quality = (stats.quality ?? {}) as Quality;
  const detection = (stats.detection ?? {}) as Record<string, unknown>;
  const parseNotes = Array.isArray(stats.parse_notes) ? (stats.parse_notes as string[]) : [];
  return (
    <div className="space-y-4">
      <div className="grid gap-x-5 gap-y-3 sm:grid-cols-2">
        <Field label="Reference" value={job.reference} />
        <Field label="Filename" value={job.filename ?? "—"} />
        <Field label="SHA-256" value={job.sha256 ?? "—"} hint="Used to detect duplicate uploads." />
        <Field label="Kind" value={titleCase(job.kind)} />
        <Field label="Created" value={`${formatDateTime(job.created_at)}Z`} />
        <Field label="Finished" value={job.finished_at ? `${formatDateTime(job.finished_at)}Z` : "—"} />
      </div>

      {job.capture ? (
        <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 p-3">
          <p className="label mb-2">Capture validation</p>
          <div className="grid grid-cols-2 gap-3 text-[11.5px] sm:grid-cols-3">
            <span className="text-slate-500">Packets: <span className="font-mono text-slate-300">{formatNumber(job.capture.packet_count)}</span></span>
            <span className="text-slate-500">Start: <span className="font-mono text-slate-300">{formatDateTime(job.capture.capture_start)}</span></span>
            <span className="text-slate-500">End: <span className="font-mono text-slate-300">{formatDateTime(job.capture.capture_end)}</span></span>
          </div>
          {Array.isArray(job.capture.validation.notes) && (job.capture.validation.notes as string[]).length ? (
            <ul className="mt-2 space-y-1 text-[11px] text-slate-500">
              {(job.capture.validation.notes as string[]).map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {Object.keys(quality).length ? (
        <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 p-3">
          <p className="label mb-2">Flow quality report</p>
          <div className="grid grid-cols-2 gap-2 text-[11.5px] sm:grid-cols-4">
            <span className="text-slate-500">Total rows <span className="ml-1 font-mono text-slate-300">{formatNumber(quality.total_rows ?? 0)}</span></span>
            <span className="text-slate-500">Valid <span className="ml-1 font-mono text-slate-300">{formatNumber(quality.valid_records ?? 0)}</span></span>
            <span className="text-slate-500">Rejected <span className="ml-1 font-mono text-slate-300">{formatNumber(quality.rejected_records ?? 0)}</span></span>
            <span className="text-slate-500">Log rows <span className="ml-1 font-mono text-slate-300">{formatNumber(quality.log_records ?? 0)}</span></span>
          </div>
          {Array.isArray(quality.notes) && quality.notes.length ? (
            <ul className="mt-2 space-y-1 text-[11px] text-slate-500">
              {quality.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {parseNotes.length ? (
        <div>
          <p className="label mb-1.5">Parser notes</p>
          <ul className="space-y-1 text-[11.5px] text-slate-400">
            {parseNotes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {Object.keys(detection).length ? (
        <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 p-3">
          <p className="label mb-2">Detection pass</p>
          <div className="grid grid-cols-2 gap-2 text-[11.5px] sm:grid-cols-3">
            <span className="text-slate-500">Alerts created <span className="ml-1 font-mono text-slate-300">{formatNumber(Number(detection.alerts_created ?? 0))}</span></span>
            <span className="text-slate-500">Alerts updated <span className="ml-1 font-mono text-slate-300">{formatNumber(Number(detection.alerts_updated ?? 0))}</span></span>
            <span className="text-slate-500">Flows evaluated <span className="ml-1 font-mono text-slate-300">{formatNumber(Number(detection.flows_evaluated ?? 0))}</span></span>
          </div>
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-x-5 gap-y-3 sm:grid-cols-3">
        <Field label="Valid records" value={formatNumber(job.records_valid)} />
        <Field label="Rejected" value={formatNumber(job.records_rejected)} />
        <Field label="Alerts generated" value={formatNumber(job.alerts_generated)} />
        <Field label="Parse time" value={stats.parse_ms ? `${Number(stats.parse_ms).toFixed(1)} ms` : "—"} />
        <Field label="Detection time" value={stats.detection_ms ? `${Number(stats.detection_ms).toFixed(1)} ms` : "—"} />
        <Field label="Total time" value={stats.total_ms ? `${Number(stats.total_ms).toFixed(1)} ms` : "—"} />
      </div>

      {job.error ? (
        <div className="rounded-lg border border-signal-rose/25 bg-signal-rose/[0.05] px-3 py-2.5 text-[11.5px] leading-relaxed text-rose-200/90">
          {job.error}
        </div>
      ) : null}
    </div>
  );
}

function JobsTable({
  jobs,
  loading,
  onInspect,
}: {
  jobs: IngestionJob[];
  loading: boolean;
  onInspect: (job: IngestionJob) => void;
}) {
  if (loading) {
    return (
      <div className="space-y-2 p-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-11 w-full" />
        ))}
      </div>
    );
  }
  if (!jobs.length) {
    return (
      <EmptyState
        compact
        title="No ingestion jobs in this workspace"
        description="Upload a capture or flow export to validate and process it. Collector-fed workspaces receive records continuously without creating job rows."
        icon={<Database className="h-4 w-4" />}
      />
    );
  }
  const active = (status: string) => ["QUEUED", "PARSING", "PROCESSING"].includes(status.toUpperCase());
  return (
    <div className="overflow-x-auto">
      <table className="table-base min-w-[920px]">
        <thead>
          <tr>
            <th>Job</th>
            <th>Kind</th>
            <th>Status</th>
            <th>Progress</th>
            <th>Records</th>
            <th>Alerts</th>
            <th>Environment</th>
            <th>Created</th>
            <th aria-label="Inspect" />
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => (
            <tr key={job.id}>
              <td>
                <button
                  type="button"
                  onClick={() => onInspect(job)}
                  className="text-left font-mono text-[11.5px] text-accent-soft hover:underline"
                >
                  {job.reference}
                </button>
                <p className="mt-0.5 max-w-[220px] truncate text-[10.5px] text-slate-600" title={job.filename ?? undefined}>
                  {job.filename ?? "—"}
                </p>
              </td>
              <td>
                <Badge tone="slate">{titleCase(job.kind)}</Badge>
              </td>
              <td>
                <StatusBadge status={job.status} />
                {job.error ? <p className="mt-1 max-w-[180px] truncate text-[10px] text-signal-rose" title={job.error}>{job.error}</p> : null}
              </td>
              <td className="min-w-[120px]">
                <div className="flex items-center gap-2">
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                    <div
                      className={cn("h-full rounded-full transition-all", job.status === "FAILED" ? "bg-signal-rose" : "bg-accent/70")}
                      style={{ width: `${Math.min(100, Math.max(0, job.progress))}%` }}
                    />
                  </div>
                  <span className="font-mono text-[10px] text-slate-500">{job.progress}%</span>
                </div>
              </td>
              <td>
                <span className="font-mono text-[11.5px] text-slate-300">{formatNumber(job.records_valid)}</span>
                {job.records_rejected ? (
                  <p className="text-[10px] text-signal-amber">{formatNumber(job.records_rejected)} rejected</p>
                ) : null}
              </td>
              <td className="font-mono text-[11.5px] text-slate-300">{formatNumber(job.alerts_generated)}</td>
              <td>
                <Badge tone={job.environment === "DEMO" ? "amber" : job.environment === "REPLAY" ? "blue" : "mint"}>{job.environment}</Badge>
              </td>
              <td>
                <span className="text-[11px] text-slate-400" title={`${formatDateTime(job.created_at)}Z`}>
                  {relativeTime(job.created_at)}
                </span>
              </td>
              <td>
                <button type="button" className="btn-ghost px-2 py-1 text-[11px]" onClick={() => onInspect(job)}>
                  Inspect <ArrowRight className="h-3 w-3" />
                </button>
                {active(job.status) ? <Loader2 className="ml-1 inline h-3 w-3 animate-spin text-accent" /> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CollectorCard({
  source,
  canManage,
  onRotate,
  rotating,
  onIssueKey,
}: {
  source: TrafficSource;
  canManage: boolean;
  onRotate: (source: TrafficSource) => void;
  rotating: boolean;
  onIssueKey: (source: TrafficSource) => void;
}) {
  const state = source.connection_state ?? source.status;
  const tone = state === "LIVE" || state === "CONNECTED" ? "mint" : state === "STALE" ? "amber" : "slate";
  return (
    <div className="rounded-xl border border-white/[0.06] bg-ink-900/45 p-3.5">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-[12.5px] font-medium text-slate-200">{source.name}</p>
          <p className="mt-0.5 font-mono text-[10px] text-slate-500">{source.identifier}</p>
        </div>
        <Badge tone={tone} dot>
          {state}
        </Badge>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-[10.5px]">
        <span className="text-slate-500">Kind <span className="ml-1 font-mono text-slate-300">{source.kind}</span></span>
        <span className="text-slate-500">Invalid <span className="ml-1 font-mono text-slate-300">{formatNumber(source.records_invalid)}</span></span>
        <span className="text-slate-500">Records <span className="ml-1 font-mono text-slate-300">{formatNumber(source.records_total)}</span></span>
        <span className="text-slate-500">Rate <span className="ml-1 font-mono text-slate-300">{source.records_per_second.toFixed(2)}/s</span></span>
        <span className="text-slate-500">Latency <span className="ml-1 font-mono text-slate-300">{source.avg_latency_ms === null ? "—" : `${source.avg_latency_ms} ms`}</span></span>
        <span className="text-slate-500">Last seen <span className="ml-1 text-slate-300">{source.last_seen_at ? relativeTime(source.last_seen_at) : "never"}</span></span>
      </div>
      {canManage ? (
        <div className="mt-3 flex items-center gap-1.5 border-t border-white/[0.05] pt-2.5">
          <button type="button" className="btn-secondary px-2 py-1 text-[10.5px]" onClick={() => onIssueKey(source)}>
            <KeyRound className="h-3 w-3" /> Issue new key
          </button>
          <button
            type="button"
            className="btn-ghost px-2 py-1 text-[10.5px]"
            onClick={() => onRotate(source)}
            disabled={rotating || !source.has_key}
            title={source.has_key ? "Invalidate the current key and issue a new one" : "This collector has no key configured"}
          >
            {rotating ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />} Rotate
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function Ingestion() {
  const { hasPermission } = useAuth();
  const { workspaceSlug, environment } = useWorkspace();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<PreviewResponse | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [attribution, setAttribution] = useState<string>("");
  const [jobPage, setJobPage] = useState(1);
  const [inspectJob, setInspectJob] = useState<IngestionJob | null>(null);
  const [sourceModal, setSourceModal] = useState(false);
  const [issued, setIssued] = useState<{ sourceId: number; collectorId: string; key: string; notice: string } | null>(null);
  const [newSource, setNewSource] = useState({ name: "", kind: "netflow", description: "" });
  const [rotatingId, setRotatingId] = useState<number | null>(null);

  const canUpload = hasPermission("ingestion.upload");
  const canManageSources = hasPermission("sources.manage");

  const jobs = useQuery({
    queryKey: ["ingestion-jobs", workspaceSlug, jobPage],
    queryFn: () =>
      api.get<JobsResponse>("/ingestion/jobs", { workspace: workspaceSlug, page: jobPage, page_size: 12 }),
    refetchInterval: (query) => {
      const data = query.state.data;
      const active = data?.items?.some((job) =>
        ["QUEUED", "PARSING", "PROCESSING"].includes(job.status.toUpperCase()),
      );
      return active ? 2500 : 20_000;
    },
  });

  const sources = useQuery({
    queryKey: ["sources", workspaceSlug],
    queryFn: () => api.get<SourcesResponse>("/sources", { workspace: workspaceSlug }),
    staleTime: 20_000,
  });

  const status = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>("/system/status"),
    staleTime: 60_000,
  });

  const resetFile = useCallback(() => {
    setFile(null);
    setPreview(null);
    setPreviewError(null);
    setAttribution("");
    if (inputRef.current) inputRef.current.value = "";
  }, []);

  const runPreview = useCallback(
    async (candidate: File) => {
      setFile(candidate);
      setPreview(null);
      setPreviewError(null);
      setPreviewing(true);
      try {
        const form = new FormData();
        form.append("file", candidate);
        const result = await api.post<PreviewResponse>("/ingestion/preview", form);
        setPreview(result);
      } catch (error) {
        setPreviewError(
          error instanceof ApiError
            ? error.message
            : "Preview failed. Confirm the file is a supported PCAP/PCAPNG or flow export.",
        );
      } finally {
        setPreviewing(false);
      }
    },
    [],
  );

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    const candidate = event.dataTransfer.files?.[0];
    if (candidate) void runPreview(candidate);
  };

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose a file first.");
      const form = new FormData();
      form.append("file", file);
      form.append("workspace", workspaceSlug);
      if (attribution) form.append("source_id", attribution);
      return api.post<IngestionJob>("/ingestion/upload", form);
    },
    onSuccess: (job) => {
      toast("success", `Queued ${job.reference}`, "Parsing and detection run server-side; the job list refreshes automatically.");
      resetFile();
      setJobPage(1);
      void queryClient.invalidateQueries({ queryKey: ["ingestion-jobs"] });
      void queryClient.invalidateQueries({ queryKey: ["overview"] });
    },
    onError: (error) => {
      toast("error", "Upload rejected", error instanceof Error ? error.message : "The file could not be queued.");
    },
  });

  const createSource = useMutation({
    mutationFn: () => api.post<{ id: number; collector_id: string; collector_key: string; key_notice: string }>("/sources", { ...newSource, workspace: workspaceSlug }),
    onSuccess: (result) => {
      setSourceModal(false);
      setNewSource({ name: "", kind: "netflow", description: "" });
      setIssued({ sourceId: result.id, collectorId: result.collector_id, key: result.collector_key, notice: result.key_notice });
      toast("success", "Collector registered", "Copy the key now — it cannot be retrieved again.");
      void queryClient.invalidateQueries({ queryKey: ["sources"] });
    },
    onError: (error) => {
      toast("error", "Collector not created", error instanceof Error ? error.message : "Try again.");
    },
  });

  const rotateKey = useMutation({
    mutationFn: (source: TrafficSource) =>
      api.post<{ collector_id: string; collector_key: string; key_notice: string }>(`/sources/${source.id}/rotate-key`),
    onMutate: (source) => setRotatingId(source.id),
    onSuccess: (result, source) => {
      setIssued({ sourceId: source.id, collectorId: result.collector_id, key: result.collector_key, notice: result.key_notice });
      toast("success", "Collector key rotated", "The previous key is invalid immediately.");
      void queryClient.invalidateQueries({ queryKey: ["sources"] });
    },
    onError: (error) => toast("error", "Rotation failed", error instanceof Error ? error.message : "Try again."),
    onSettled: () => setRotatingId(null),
  });

  const sourceOptions = sources.data?.sources ?? [];
  const contractSample = useMemo(
    () =>
      JSON.stringify(
        {
          format: "flow_json",
          sent_at: "2026-10-30T10:15:00Z",
          records: [
            {
              ts: "2026-10-30T10:14:52Z",
              src_ip: "10.20.4.18",
              src_port: 51422,
              dst_ip: "203.0.113.44",
              dst_port: 443,
              protocol: "TCP",
              bytes: 48213,
              packets: 41,
              duration_ms: 1840,
              direction: "outbound",
            },
          ],
        },
        null,
        2,
      ),
    [],
  );

  const statusCounts = jobs.data?.status_counts ?? {};
  const previewQuality = qualityOf(preview);

  return (
    <div>
      <PageHeader
        eyebrow="Data ingestion"
        title="Evidence intake"
        description="Validate captures and flow exports before they enter the pipeline. Continuous telemetry arrives from enclave collectors that push metadata one way; this browser never captures packets and the platform never connects back to monitored hosts."
        actions={
          <Badge tone={environment === "LIVE" ? "mint" : environment === "DEMO" ? "amber" : "blue"} dot>
            {environment} workspace
          </Badge>
        }
      />

      <SummaryStrip
        items={[
          { label: "Jobs", value: formatNumber(jobs.data?.total ?? 0) },
          { label: "Complete", value: formatNumber(statusCounts.COMPLETE ?? 0), tone: "accent" },
          { label: "Processing", value: formatNumber((statusCounts.QUEUED ?? 0) + (statusCounts.PARSING ?? 0) + (statusCounts.PROCESSING ?? 0)) },
          { label: "Failed", value: formatNumber(statusCounts.FAILED ?? 0), tone: "danger" },
          { label: "Collectors", value: `${formatNumber(sourceOptions.filter((s) => (s.connection_state ?? s.status) === "LIVE").length)} / ${formatNumber(sourceOptions.length)} live` },
        ]}
      />

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.02fr)_minmax(0,1fr)]">
        <Panel className="p-4 sm:p-5">
          <SectionTitle
            eyebrow="Validate then ingest"
            title="Upload a capture or flow export"
            subtitle="PCAP/PCAPNG, CSV/TSV, JSON/JSONL and Zeek logs. Preview runs the same parser as ingestion without storing the file."
            actions={<Badge tone="slate">Max {status.data?.storage.upload_limit_mb ?? 50} MB</Badge>}
          />
          {!canUpload ? (
            <div className="mt-4 rounded-lg border border-white/[0.07] bg-ink-900/50 px-3.5 py-3 text-[11.5px] leading-relaxed text-slate-400">
              Your role can view ingestion jobs but cannot upload captures. Ask a security administrator if you need upload
              rights.
            </div>
          ) : (
            <>
              <div
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") inputRef.current?.click();
                }}
                className={cn(
                  "mt-4 flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-6 py-9 text-center transition-colors",
                  dragging
                    ? "border-accent/60 bg-accent/[0.06]"
                    : "border-white/[0.12] bg-ink-900/40 hover:border-white/[0.2] hover:bg-ink-900/60",
                )}
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-accent-soft">
                  <UploadCloud className="h-5 w-5" />
                </div>
                <p className="mt-3 text-[12.5px] font-medium text-slate-200">
                  {file ? file.name : "Drop a file here or select one"}
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  {file ? `${formatBytes(file.size)} · validated on the server before any row is stored` : "The file is sent to the API for validation; nothing executes in the browser."}
                </p>
                <input
                  ref={inputRef}
                  type="file"
                  className="hidden"
                  accept=".pcap,.pcapng,.cap,.csv,.tsv,.json,.jsonl,.ndjson,.log,.txt"
                  onChange={(event) => {
                    const candidate = event.target.files?.[0];
                    if (candidate) void runPreview(candidate);
                  }}
                />
              </div>

              {file ? (
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <select
                    aria-label="Attribute upload to a collector"
                    value={attribution}
                    onChange={(event) => setAttribution(event.target.value)}
                    className="field flex-1"
                  >
                    <option value="">No collector attribution</option>
                    {sourceOptions.map((source) => (
                      <option key={source.id} value={source.id}>
                        Attribute to {source.name} ({source.kind})
                      </option>
                    ))}
                  </select>
                  <button type="button" className="btn-ghost" onClick={resetFile}>
                    Clear
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={() => upload.mutate()}
                    disabled={!preview?.valid || previewing || upload.isPending}
                  >
                    {upload.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                    {upload.isPending ? "Queuing…" : "Queue for processing"}
                  </button>
                </div>
              ) : null}

              <div className="mt-4 rounded-lg border border-white/[0.06] bg-ink-900/35 px-3.5 py-3">
                <p className="flex items-center gap-1.5 text-[11.5px] font-medium text-slate-300">
                  <Lock className="h-3.5 w-3.5 text-slate-500" /> Evidence handling
                </p>
                <ul className="mt-1.5 space-y-1 text-[10.5px] leading-relaxed text-slate-500">
                  <li>Uploads are hashed with SHA-256 and stored inside the platform upload directory.</li>
                  <li>TLS/QUIC payloads are never decrypted; only flow metadata is parsed.</li>
                  <li>Preview samples at most 20,000 rows or packets and is discarded without storing flows.</li>
                </ul>
              </div>
            </>
          )}
        </Panel>

        <Panel className="p-4 sm:p-5">
          <SectionTitle
            eyebrow="Quality report"
            title="Validation output"
            subtitle="Everything shown here is produced by the server-side parser for the selected file."
            actions={
              preview ? (
                <Badge tone={preview.valid ? "mint" : "rose"} dot>
                  {preview.valid ? "Ready" : "Not ingestible"}
                </Badge>
              ) : (
                <Badge tone="slate">Awaiting file</Badge>
              )
            }
          />
          <div className="mt-4 max-h-[520px] overflow-y-auto pr-1">
            {previewing ? (
              <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                <Loader2 className="h-5 w-5 animate-spin text-accent" />
                <p className="mt-2 text-[11.5px]">Validating on the server…</p>
              </div>
            ) : previewError ? (
              <ErrorState message={previewError} />
            ) : preview ? (
              <div className="space-y-4">
                <QualityReport preview={preview} />
                <PreviewTable rows={preview.kind === "pcap" ? preview.sample_flows ?? [] : preview.preview ?? []} kind={preview.kind} />
                {previewQuality?.column_mapping && Object.keys(previewQuality.column_mapping).length ? (
                  <div>
                    <p className="label mb-1.5">Column mapping</p>
                    <div className="grid gap-x-4 gap-y-1 text-[10.5px] sm:grid-cols-2">
                      {Object.entries(previewQuality.column_mapping).map(([target, source]) => (
                        <div key={target} className="flex items-baseline justify-between gap-3 border-b border-white/[0.04] py-0.5">
                          <span className="text-slate-500">{target}</span>
                          <span className="font-mono text-slate-300">{source}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            ) : (
              <EmptyState
                compact
                title="No file validated yet"
                description="Select a capture or export to see record counts, rejected rows, detector-ready fields and a sample before queuing the job."
                icon={<Fingerprint className="h-4 w-4" />}
              />
            )}
          </div>
        </Panel>
      </div>

      <Panel className="mt-5 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
          <SectionTitle title="Ingestion jobs" subtitle="Processing is asynchronous; progress and outcomes come from the API job record." />
          <button
            type="button"
            className="btn-secondary"
            onClick={() => void jobs.refetch()}
            disabled={jobs.isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", jobs.isFetching && "animate-spin")} /> Refresh
          </button>
        </div>
        {jobs.isError ? (
          <div className="p-4">
            <ErrorState message={jobs.error instanceof Error ? jobs.error.message : "Jobs could not be loaded."} retry={() => void jobs.refetch()} />
          </div>
        ) : (
          <>
            <JobsTable jobs={jobs.data?.items ?? []} loading={jobs.isLoading} onInspect={setInspectJob} />
            <Pagination
              page={jobs.data?.page ?? jobPage}
              pageSize={jobs.data?.page_size ?? 12}
              total={jobs.data?.total ?? 0}
              onChange={setJobPage}
            />
          </>
        )}
      </Panel>

      <Panel className="mt-5 p-4 sm:p-5">
        <SectionTitle
          eyebrow="Continuous intake"
          title="Enclave collectors"
          subtitle="Collectors run inside the monitored enclave and push one-way metadata. Keys are stored as scrypt fingerprints; the raw value is shown once at registration or rotation."
          actions={
            canManageSources ? (
              <button type="button" className="btn-primary" onClick={() => setSourceModal(true)}>
                <Radio className="h-3.5 w-3.5" /> Register collector
              </button>
            ) : (
              <Badge tone="slate">Read-only</Badge>
            )
          }
        />

        {sources.isError ? (
          <div className="mt-4">
            <ErrorState message={sources.error instanceof Error ? sources.error.message : "Collectors could not be loaded."} retry={() => void sources.refetch()} />
          </div>
        ) : sources.isLoading ? (
          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-32 w-full" />
            ))}
          </div>
        ) : sourceOptions.length ? (
          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {sourceOptions.map((source) => (
              <CollectorCard
                key={source.id}
                source={source}
                canManage={canManageSources}
                onRotate={(target) => rotateKey.mutate(target)}
                rotating={rotatingId === source.id}
                onIssueKey={(target) => rotateKey.mutate(target)}
              />
            ))}
          </div>
        ) : (
          <div className="mt-4">
            <EmptyState
              compact
              title="No collectors registered for this workspace"
              description="Register a collector to receive a one-time key and the push contract. Uploads stay available for offline analysis."
              icon={<Usb className="h-4 w-4" />}
              action={
                canManageSources ? (
                  <button type="button" className="btn-secondary" onClick={() => setSourceModal(true)}>
                    Register the first collector
                  </button>
                ) : undefined
              }
            />
          </div>
        )}

        <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
          <div className="rounded-xl border border-white/[0.06] bg-ink-900/40 p-4">
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="label">Collector push contract</p>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
                  The collector posts to the API over the approved one-way monitoring path. The platform never initiates a
                  connection to monitored hosts.
                </p>
              </div>
              <Badge tone="slate">v1.0</Badge>
            </div>
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-white/[0.07] bg-ink-950/60 px-2.5 py-1.5">
              <span className="rounded bg-accent/15 px-1.5 py-0.5 font-mono text-[9.5px] font-semibold text-accent-soft">
                {sources.data?.contract.method ?? "POST"}
              </span>
              <code className="flex-1 truncate font-mono text-[11px] text-slate-300">{sources.data?.ingest_endpoint ?? "—"}</code>
              <CopyButton value={sources.data?.ingest_endpoint ?? ""} />
            </div>
            <p className="mt-3 text-[10.5px] text-slate-500">
              Required headers:{" "}
              <span className="font-mono text-slate-300">{(sources.data?.contract.auth_headers ?? ["X-Collector-Id", "X-Collector-Key"]).join(", ")}</span>
            </p>
            <ul className="mt-2 space-y-1 text-[10.5px] leading-relaxed text-slate-500">
              {(sources.data?.contract.notes ?? []).map((note) => (
                <li key={note} className="flex gap-1.5">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                  {note}
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-xl border border-white/[0.06] bg-ink-900/40 p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="label">Example request body</p>
              <CopyButton value={contractSample} label="Copy JSON" />
            </div>
            <pre className="mt-2 max-h-[246px] overflow-auto rounded-lg border border-white/[0.06] bg-ink-950/70 p-3 font-mono text-[10.5px] leading-relaxed text-slate-400">
              {contractSample}
            </pre>
            <p className="mt-2 flex items-start gap-1.5 text-[10px] leading-relaxed text-slate-600">
              <InfoHint text="Fields map to the documented flow contract. Missing optional fields degrade specific detectors; the coverage note on each detection workspace tells you what was unavailable." label="About the flow contract" />
              Missing fields degrade only the detectors that require them — no detector invents visibility.
            </p>
          </div>
        </div>

        {sources.data?.collector_kinds?.length ? (
          <div className="mt-4 rounded-xl border border-white/[0.06] bg-ink-900/35 p-4">
            <p className="label mb-2.5">Supported collector kinds</p>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {sources.data.collector_kinds.map((kind) => (
                <div key={kind.kind} className="rounded-lg border border-white/[0.05] bg-ink-950/35 px-3 py-2">
                  <p className="flex items-center gap-1.5 text-[11.5px] font-medium text-slate-200">
                    <CheckCircle2 className="h-3 w-3 text-accent/80" /> {kind.label}
                  </p>
                  <p className="mt-1 text-[10px] leading-relaxed text-slate-500">{kind.transport}</p>
                  <p className="mt-1 text-[10px] leading-relaxed text-slate-600">{kind.record_contract}</p>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </Panel>

      <Modal
        open={Boolean(inspectJob)}
        onClose={() => setInspectJob(null)}
        title={inspectJob ? `Job ${inspectJob.reference}` : "Ingestion job"}
        description="Server-reported processing details for this upload."
        width="max-w-2xl"
        footer={
          <>
            <button type="button" className="btn-secondary" onClick={() => setInspectJob(null)}>
              Close
            </button>
          </>
        }
      >
        {inspectJob ? <JobDetail job={inspectJob} /> : null}
      </Modal>

      <Modal
        open={sourceModal}
        onClose={() => setSourceModal(false)}
        title="Register an enclave collector"
        description="The key is returned once. Store it in the enclave secret manager; it is never displayed again."
        footer={
          <>
            <button type="button" className="btn-secondary" onClick={() => setSourceModal(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn-primary"
              disabled={newSource.name.trim().length < 3 || createSource.isPending}
              onClick={() => createSource.mutate()}
            >
              {createSource.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <KeyRound className="h-3.5 w-3.5" />}
              Register and issue key
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <label className="block">
            <span className="label mb-1.5 block">Collector name</span>
            <input
              className="field"
              value={newSource.name}
              onChange={(event) => setNewSource((state) => ({ ...state, name: event.target.value }))}
              placeholder="Core switch NetFlow export"
              maxLength={160}
            />
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Kind</span>
            <select
              className="field"
              value={newSource.kind}
              onChange={(event) => setNewSource((state) => ({ ...state, kind: event.target.value }))}
            >
              {(sources.data?.collector_kinds ?? []).map((kind) => (
                <option key={kind.kind} value={kind.kind}>
                  {kind.label}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Description</span>
            <textarea
              className="field min-h-[72px] resize-y"
              value={newSource.description}
              onChange={(event) => setNewSource((state) => ({ ...state, description: event.target.value }))}
              placeholder="Where the collector runs and which segment it observes."
              maxLength={400}
            />
          </label>
          <p className="rounded-lg border border-white/[0.06] bg-ink-900/50 px-3 py-2 text-[10.5px] leading-relaxed text-slate-500">
            Registration does not start any capture. A network engineer must deploy the collector inside the enclave and
            configure it with the issued key.
          </p>
        </div>
      </Modal>

      <Modal
        open={Boolean(issued)}
        onClose={() => setIssued(null)}
        title="Collector key issued"
        description="This value is shown once. Copy it into the enclave secret manager now."
        footer={
          <button type="button" className="btn-primary" onClick={() => setIssued(null)}>
            I have stored the key
          </button>
        }
      >
        {issued ? (
          <div className="space-y-3">
            <div>
              <p className="label mb-1.5">Collector ID</p>
              <div className="flex items-center gap-2 rounded-lg border border-white/[0.08] bg-ink-900/60 px-2.5 py-2">
                <code className="flex-1 truncate font-mono text-[11.5px] text-slate-300">{issued.collectorId}</code>
                <CopyButton value={issued.collectorId} />
              </div>
            </div>
            <div>
              <p className="label mb-1.5">Collector key</p>
              <div className="flex items-center gap-2 rounded-lg border border-signal-amber/25 bg-signal-amber/[0.05] px-2.5 py-2">
                <code className="flex-1 break-all font-mono text-[11.5px] text-amber-200">{issued.key}</code>
                <CopyButton value={issued.key} />
              </div>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500">{issued.notice}</p>
            <p className="text-[10.5px] leading-relaxed text-slate-600">
              This dialog is the only place the key appears. The server stores only a scrypt fingerprint, so a lost key must
              be rotated.
            </p>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
