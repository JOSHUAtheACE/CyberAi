import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  CircleStop,
  Clock3,
  FlaskConical,
  Gauge,
  History,
  Layers,
  Pause,
  Play,
  Radio,
  RotateCcw,
  Sparkles,
  Tags,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Badge,
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
import { Ring, SparkKpi, TONES } from "@/components/visuals";
import { useToast } from "@/context/ToastContext";
import { api } from "@/lib/api";
import { cn, formatNumber, relativeTime, titleCase } from "@/lib/format";
import type {
  ReplayDataset,
  ReplayDatasetsResponse,
  ReplaySession,
  UploadedReplayDataset,
} from "@/lib/types";

function timespanLabel(timespan: ReplayDataset["timespan"]): string | null {
  if (!timespan) return null;
  if (typeof timespan === "string") return timespan;
  return `${timespan.start.slice(0, 10)} → ${timespan.end.slice(0, 10)}`;
}

const CATEGORY_LABELS: Record<string, string> = {
  ddos: "DDoS",
  beaconing: "Beaconing",
  dns: "DNS / DGA",
  encrypted: "TLS / QUIC",
  scanning: "Scanning",
  exfiltration: "Exfiltration",
};

const THREAT_LABELS: Record<string, string> = {
  ddos: "DDoS",
  dns: "DNS / DGA",
  encrypted: "TLS / QUIC",
  beaconing: "C2 beaconing",
  scanning: "Port scan",
  exfiltration: "Data exfiltration",
};

function categoryLabel(slug: string): string {
  return CATEGORY_LABELS[slug] ?? titleCase(slug);
}

function groundTruthLabel(groundTruth: ReplayDataset["ground_truth"]): string {
  if (typeof groundTruth === "string") return groundTruth;
  const threat = THREAT_LABELS[groundTruth.threat] ?? titleCase(groundTruth.threat);
  return `${threat} · ${groundTruth.technique.replaceAll("_", " ")}`;
}

function DatasetCard({
  dataset,
  selected,
  onSelect,
}: {
  dataset: ReplayDataset;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={cn(
        "w-full rounded-xl border p-3.5 text-left transition-colors",
        selected
          ? "border-accent/45 bg-accent/[0.06]"
          : "border-white/[0.06] bg-ink-900/40 hover:border-white/[0.12] hover:bg-ink-900/60",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-[12.5px] font-medium text-slate-100">{dataset.name}</p>
          <p className="mt-0.5 font-mono text-[9.5px] uppercase tracking-[0.1em] text-slate-500">{dataset.scenario_id}</p>
        </div>
        <Badge tone="amber" className="shrink-0">
          DEMO
        </Badge>
      </div>
      <p className="mt-2 line-clamp-2 text-[11px] leading-relaxed text-slate-500">{dataset.description}</p>
      <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
        <Badge tone="rose">{titleCase(dataset.threat_class)}</Badge>
        <Badge tone="slate">{formatNumber(dataset.flow_count)} flows</Badge>
        {timespanLabel(dataset.timespan) ? <Badge tone="slate">{timespanLabel(dataset.timespan)}</Badge> : null}
      </div>
      <p className="mt-2 flex items-start gap-1.5 text-[10px] leading-relaxed text-slate-600">
        <Tags className="mt-0.5 h-3 w-3 shrink-0" />
        {dataset.expected_features.slice(0, 4).join(" · ")}
      </p>
    </button>
  );
}

function UploadedCard({
  dataset,
  selected,
  onSelect,
}: {
  dataset: UploadedReplayDataset;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={cn(
        "w-full rounded-xl border p-3 text-left transition-colors",
        selected
          ? "border-accent/45 bg-accent/[0.06]"
          : "border-white/[0.06] bg-ink-900/40 hover:border-white/[0.12]",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="min-w-0 truncate text-[11.5px] font-medium text-slate-200">{dataset.filename ?? dataset.reference}</p>
        <Badge tone={dataset.environment === "LIVE" ? "mint" : dataset.environment === "DEMO" ? "amber" : "blue"}>
          {dataset.environment}
        </Badge>
      </div>
      <p className="mt-1 font-mono text-[10px] text-slate-500">
        {dataset.reference} · {formatNumber(dataset.records)} records · {titleCase(dataset.kind)}
      </p>
      <p className="mt-1 text-[10px] text-slate-600">
        {dataset.finished_at ? `Completed ${relativeTime(dataset.finished_at)}` : "—"}
      </p>
    </button>
  );
}

function ProgressBar({ value, tone = "accent" }: { value: number; tone?: "accent" | "blue" }) {
  return (
    <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]">
      <div
        className={cn("h-full rounded-full transition-all duration-500", tone === "accent" ? "bg-accent/75" : "bg-signal-blue/75")}
        style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
      />
    </div>
  );
}

function SessionRow({ session, onSelect, selected }: { session: ReplaySession; onSelect: () => void; selected: boolean }) {
  return (
    <tr className={cn(selected && "bg-white/[0.03]")}>
      <td>
        <button type="button" onClick={onSelect} className="text-left font-mono text-[11px] text-accent-soft hover:underline">
          {session.reference}
        </button>
        <p className="mt-0.5 max-w-[220px] truncate text-[10px] text-slate-600">{session.dataset_label}</p>
      </td>
      <td>
        <StatusBadge status={session.status} />
      </td>
      <td>
        <Badge tone={session.demo ? "amber" : "blue"}>{session.demo ? "DEMO" : "REPLAY"}</Badge>
      </td>
      <td className="font-mono text-[11px] text-slate-300">{session.speed.toFixed(1)}×</td>
      <td>
        <div className="flex items-center gap-2">
          <div className="w-20">
            <ProgressBar value={session.progress} tone={session.demo ? "accent" : "blue"} />
          </div>
          <span className="font-mono text-[10px] text-slate-500">{session.progress.toFixed(0)}%</span>
        </div>
      </td>
      <td className="font-mono text-[11px] text-slate-300">{formatNumber(session.alerts_generated)}</td>
      <td>
        <span className="text-[10.5px] text-slate-500">
          {session.finished_at ? relativeTime(session.finished_at) : session.started_at ? `started ${relativeTime(session.started_at)}` : "—"}
        </span>
      </td>
    </tr>
  );
}

export function Replay() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selection, setSelection] = useState<string | null>(null);
  const [speed, setSpeed] = useState(1);
  const [categories, setCategories] = useState<string[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);

  const datasets = useQuery({
    queryKey: ["replay-datasets"],
    queryFn: () => api.get<ReplayDatasetsResponse>("/replay/datasets"),
    staleTime: 30_000,
  });

  const sessions = useQuery({
    queryKey: ["replay-sessions"],
    queryFn: () => api.get<{ items: ReplaySession[] }>("/replay/sessions"),
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      return items.some((item) => item.status === "RUNNING" || item.status === "PAUSED") ? 2500 : 12_000;
    },
  });

  useEffect(() => {
    const items = sessions.data?.items ?? [];
    if (activeId === null && items.length) setActiveId(items[0].id);
  }, [sessions.data, activeId]);

  useEffect(() => {
    if (selection === null && datasets.data?.demo_datasets.length) {
      const first = datasets.data.demo_datasets[0];
      setSelection(`demo:${first.id}`);
      setCategories([first.scenario_id]);
    }
  }, [datasets.data, selection]);

  const session = useQuery({
    queryKey: ["replay-session", activeId],
    queryFn: () => api.get<ReplaySession>(`/replay/sessions/${activeId}`),
    enabled: activeId !== null,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data && (data.status === "RUNNING" || data.status === "PAUSED") ? 1500 : 6000;
    },
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["replay-sessions"] });
    void queryClient.invalidateQueries({ queryKey: ["replay-session"] });
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["overview"] });
  };

  const start = useMutation({
    mutationFn: () =>
      api.post<ReplaySession>("/replay/sessions", {
        dataset: selection,
        speed,
        categories,
      }),
    onSuccess: (created) => {
      setActiveId(created.id);
      toast("success", "Replay session started", `${created.dataset_label} · ${formatNumber(created.total_records)} records at ${created.speed}×.`);
      invalidate();
    },
    onError: (error) => toast("error", "Replay could not start", error instanceof Error ? error.message : "Try again."),
  });

  const control = useMutation({
    mutationFn: ({ action }: { action: "pause" | "resume" | "stop" }) =>
      api.post<ReplaySession>(`/replay/sessions/${activeId}/${action}`),
    onSuccess: (updated, variables) => {
      toast("info", `Replay ${variables.action}`, updated.reference);
      invalidate();
    },
    onError: (error) => toast("error", "Control failed", error instanceof Error ? error.message : "Try again."),
  });

  const selectedDemo = useMemo(() => {
    if (!selection?.startsWith("demo:")) return null;
    const id = Number(selection.split(":")[1]);
    return datasets.data?.demo_datasets.find((item) => item.id === id) ?? null;
  }, [selection, datasets.data]);

  const selectedUpload = useMemo(() => {
    if (!selection?.startsWith("job:")) return null;
    const id = Number(selection.split(":")[1]);
    return datasets.data?.uploaded_datasets.find((item) => item.id === id) ?? null;
  }, [selection, datasets.data]);

  const current = session.data;
  const running = current?.status === "RUNNING";
  const paused = current?.status === "PAUSED";
  const active = running || paused;
  const canStart = Boolean(selection) && !active && !start.isPending;

  const sessionItems = sessions.data?.items ?? [];
  const totalAlerts = sessionItems.reduce((sum, item) => sum + item.alerts_generated, 0);

  return (
    <div>
      <PageHeader
        eyebrow="Replay lab"
        title="Deterministic replay"
        description="Reprocess recorded or synthetic captures at a controlled speed inside an isolated REPLAY workspace. Ground truth is attached to synthetic scenarios for evaluation only — it is never used at detection time, and every synthetic replay carries a permanent DEMO label."
        actions={<Badge tone="amber" dot>DEMO-labelled scenarios</Badge>}
      />

      <div className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        <SparkKpi
          label="Sessions"
          value={formatNumber(sessionItems.length)}
          icon={History}
          tone="blue"
          footnote={`${sessionItems.filter((item) => item.status === "RUNNING").length} running · ${sessionItems.filter((item) => item.status === "PAUSED").length} paused`}
        />
        <SparkKpi
          label="Datasets"
          value={formatNumber((datasets.data?.demo_datasets.length ?? 0) + (datasets.data?.uploaded_datasets.length ?? 0))}
          icon={Layers}
          tone="violet"
          footnote={`${datasets.data?.demo_datasets.length ?? 0} demo · ${datasets.data?.uploaded_datasets.length ?? 0} uploaded`}
        />
        <SparkKpi
          label="Alerts generated"
          value={formatNumber(totalAlerts)}
          icon={AlertTriangle}
          tone="rose"
          footnote="across listed sessions"
        />
        <SparkKpi
          label="Replay speed"
          value={`${speed}×`}
          icon={Gauge}
          tone="accent"
          footnote={(datasets.data?.speeds ?? [0.5, 1, 2, 5]).map((value) => `${value}×`).join(" · ")}
        />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.18fr)_minmax(0,1fr)]">
        <Panel className="p-4 sm:p-5">
          <SectionTitle
            eyebrow="Step 1 · dataset"
            title="Choose what to replay"
            subtitle="Synthetic scenarios cover each detection category. Uploaded captures replay only after a completed ingestion job."
            actions={<Badge tone="slate">{formatNumber((datasets.data?.demo_datasets.length ?? 0) + (datasets.data?.uploaded_datasets.length ?? 0))} available</Badge>}
          />

          {datasets.isLoading ? (
            <div className="mt-4 grid gap-2 sm:grid-cols-2">
              {Array.from({ length: 4 }).map((_, index) => (
                <Skeleton key={index} className="h-32 w-full" />
              ))}
            </div>
          ) : datasets.isError ? (
            <div className="mt-4">
              <ErrorState message={datasets.error instanceof Error ? datasets.error.message : "Datasets could not be loaded."} retry={() => void datasets.refetch()} />
            </div>
          ) : (
            <>
              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                {(datasets.data?.demo_datasets ?? []).map((dataset) => (
                  <DatasetCard
                    key={dataset.id}
                    dataset={dataset}
                    selected={selection === `demo:${dataset.id}`}
                    onSelect={() => {
                      setSelection(`demo:${dataset.id}`);
                      setCategories([dataset.scenario_id]);
                    }}
                  />
                ))}
              </div>

              <div className="mt-4">
                <p className="label mb-2 flex items-center gap-1.5">
                  <History className="h-3 w-3" /> Uploaded captures
                </p>
                {(datasets.data?.uploaded_datasets ?? []).length ? (
                  <div className="grid gap-2 sm:grid-cols-2">
                    {(datasets.data?.uploaded_datasets ?? []).map((dataset) => (
                      <UploadedCard
                        key={dataset.id}
                        dataset={dataset}
                        selected={selection === `job:${dataset.id}`}
                        onSelect={() => setSelection(`job:${dataset.id}`)}
                      />
                    ))}
                  </div>
                ) : (
                  <p className="rounded-lg border border-dashed border-white/[0.08] px-3 py-2.5 text-[11px] text-slate-500">
                    No completed uploads are available yet. Finish an ingestion job to replay it here.
                  </p>
                )}
              </div>
            </>
          )}

          <div className="mt-5 border-t border-white/[0.06] pt-4">
            <SectionTitle
              eyebrow="Step 2 · controls"
              title="Speed and detection scope"
              subtitle="Detection categories filter which detectors run against the replayed records. An empty scope runs every detector."
            />
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="label mr-1">Speed</span>
              {(datasets.data?.speeds ?? [0.5, 1, 2, 5]).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setSpeed(value)}
                  aria-pressed={speed === value}
                  className={cn(
                    "rounded-md border px-2.5 py-1 font-mono text-[11.5px] transition-colors",
                    speed === value
                      ? "border-accent/45 bg-accent/10 text-accent-soft"
                      : "border-white/10 bg-white/[0.03] text-slate-400 hover:text-slate-200",
                  )}
                >
                  {value}×
                </button>
              ))}
              <span className="ml-2 flex items-center gap-1 text-[10px] text-slate-600">
                <Gauge className="h-3 w-3" /> Timelines are compressed for interactive use.
                <InfoHint text="Replay preserves record order and relative timestamps, compressing the wall-clock span so a scenario finishes in a couple of minutes. The API reports exact processed record counts." label="About replay timing" />
              </span>
            </div>

            <div className="mt-3">
              <p className="label mb-1.5 flex items-center gap-1.5">
                <Layers className="h-3 w-3" /> Detection categories
              </p>
              <div className="flex flex-wrap gap-1.5">
                {(datasets.data?.categories ?? []).map((category) => {
                  const isActive = categories.includes(category.slug);
                  return (
                    <button
                      key={category.slug}
                      type="button"
                      onClick={() =>
                        setCategories((state) =>
                          state.includes(category.slug)
                            ? state.filter((item) => item !== category.slug)
                            : [...state, category.slug],
                        )
                      }
                      aria-pressed={isActive}
                      title={category.detector}
                      className={cn(
                        "rounded-md border px-2 py-1 text-[10.5px] transition-colors",
                        isActive
                          ? "border-accent/40 bg-accent/[0.08] text-accent-soft"
                          : "border-white/10 bg-white/[0.02] text-slate-500 hover:text-slate-300",
                      )}
                    >
                      {categoryLabel(category.slug)}
                    </button>
                  );
                })}
                <button
                  type="button"
                  onClick={() => setCategories([])}
                  className={cn(
                    "rounded-md border px-2 py-1 text-[10.5px] transition-colors",
                    categories.length === 0
                      ? "border-accent/40 bg-accent/[0.08] text-accent-soft"
                      : "border-white/10 bg-white/[0.02] text-slate-500 hover:text-slate-300",
                  )}
                >
                  All detectors
                </button>
              </div>
            </div>

            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-white/[0.06] bg-ink-900/40 px-3.5 py-3">
              <div className="min-w-0">
                <p className="text-[11.5px] text-slate-300">
                  {selectedDemo
                    ? selectedDemo.name
                    : selectedUpload
                      ? selectedUpload.filename ?? selectedUpload.reference
                      : "Select a dataset to continue"}
                </p>
                <p className="mt-0.5 text-[10.5px] text-slate-600">
                  {selectedDemo
                    ? `${formatNumber(selectedDemo.flow_count)} synthetic flows · ground truth: ${groundTruthLabel(selectedDemo.ground_truth)}`
                    : selectedUpload
                      ? `${formatNumber(selectedUpload.records)} records · ${selectedUpload.environment} environment`
                      : "Starting a session resets previous REPLAY-workspace results."}
                </p>
              </div>
              <button type="button" className="btn-primary" disabled={!canStart} onClick={() => start.mutate()}>
                {start.isPending ? <RotateCcw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                {active ? "Session active" : "Start replay"}
              </button>
            </div>

            <ul className="mt-3 space-y-1 text-[10px] leading-relaxed text-slate-600">
              {(datasets.data?.notes ?? []).map((note) => (
                <li key={note} className="flex gap-1.5">
                  <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-slate-700" />
                  {note}
                </li>
              ))}
            </ul>
          </div>
        </Panel>

        <div className="space-y-5">
          <Panel className="p-4 sm:p-5">
            <SectionTitle
              eyebrow="Live session"
              title={current ? current.reference : "No session selected"}
              subtitle={current ? `${current.dataset_label} · ${current.environment} environment` : "Start a replay or select a previous session."}
              actions={
                current ? (
                  <div className="flex items-center gap-1.5">
                    <Badge tone={current.demo ? "amber" : "blue"} dot>
                      {current.demo ? "DEMO" : "REPLAY"}
                    </Badge>
                    <StatusBadge status={current.status} />
                  </div>
                ) : null
              }
            />

            {activeId === null ? (
              <div className="mt-4">
                <EmptyState compact title="No replay session yet" description="Pick a dataset and start a session to watch progress and alerts arrive." icon={<Radio className="h-4 w-4" />} />
              </div>
            ) : session.isLoading ? (
              <div className="mt-4 space-y-3">
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-24 w-full" />
              </div>
            ) : !current ? (
              <div className="mt-4">
                <ErrorState message="This session could not be loaded." retry={() => void session.refetch()} />
              </div>
            ) : (
              <>
                <div className="mt-4 rounded-xl border border-white/[0.06] bg-ink-900/40 p-3.5">
                  <div className="flex items-center gap-4">
                    <Ring
                      ratio={Math.max(0, Math.min(1, current.progress / 100))}
                      display={`${current.progress.toFixed(0)}%`}
                      caption="progress"
                      color={current.demo ? TONES.accent : TONES.blue}
                      size={74}
                      thickness={6}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2 text-[11px]">
                        <span className="min-w-0 truncate text-slate-400">
                          {formatNumber(current.records_processed)} / {formatNumber(current.total_records)} records
                        </span>
                        <span className="shrink-0 font-mono text-slate-500">{current.progress.toFixed(1)}%</span>
                      </div>
                      <div className="mt-2">
                        <ProgressBar value={current.progress} tone={current.demo ? "accent" : "blue"} />
                      </div>
                      <div className="mt-3 grid grid-cols-2 gap-2 text-[10.5px] sm:grid-cols-4">
                        <div>
                          <p className="text-slate-600">Alerts</p>
                          <p className="font-mono text-[13px] text-slate-200">{formatNumber(current.alerts_generated)}</p>
                        </div>
                        <div>
                          <p className="text-slate-600">Remaining</p>
                          <p className="font-mono text-[13px] text-slate-200">{formatNumber(current.remaining_records)}</p>
                        </div>
                        <div>
                          <p className="text-slate-600">Rate</p>
                          <p className="font-mono text-[13px] text-slate-200">{formatNumber(current.current_rate, 1)}/s</p>
                        </div>
                        <div>
                          <p className="text-slate-600">Lag</p>
                          <p className="font-mono text-[13px] text-slate-200">
                            {current.processing_latency_ms === null ? "—" : `${current.processing_latency_ms.toFixed(1)} ms`}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-white/[0.05] pt-3">
                    {paused ? (
                      <button type="button" className="btn-primary" onClick={() => control.mutate({ action: "resume" })}>
                        <Play className="h-3.5 w-3.5" /> Resume
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => control.mutate({ action: "pause" })}
                        disabled={!running}
                      >
                        <Pause className="h-3.5 w-3.5" /> Pause
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn-danger"
                      onClick={() => control.mutate({ action: "stop" })}
                      disabled={!active}
                    >
                      <CircleStop className="h-3.5 w-3.5" /> Stop
                    </button>
                    <span className="ml-auto text-[10px] text-slate-600">
                      {current.finished_at ? `finished ${relativeTime(current.finished_at)}` : current.started_at ? `started ${relativeTime(current.started_at)}` : "queued"}
                    </span>
                  </div>
                </div>

                {current.categories.length ? (
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    <span className="label">Scope</span>
                    {current.categories.map((category) => (
                      <Badge key={category} tone="slate">{titleCase(category)}</Badge>
                    ))}
                  </div>
                ) : (
                  <p className="mt-3 text-[10.5px] text-slate-600">All detectors were in scope for this session.</p>
                )}

                <div className="mt-4">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <p className="label">Alerts produced by this session</p>
                    <Link to="/app/alerts" className="text-[10.5px] text-signal-blue hover:underline">
                      Open alert centre
                    </Link>
                  </div>
                  {current.recent_alerts?.length ? (
                    <div className="space-y-1.5">
                      {current.recent_alerts.map((alert) => (
                        <Link
                          key={alert.id}
                          to={`/app/alerts/${alert.id}`}
                          className="flex items-center gap-2.5 rounded-lg border border-white/[0.06] bg-ink-900/35 px-3 py-2 transition-colors hover:border-white/[0.12]"
                        >
                          <SeverityBadge severity={alert.severity} />
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-[11.5px] text-slate-200">{alert.summary}</p>
                            <p className="mt-0.5 font-mono text-[9.5px] text-slate-600">
                              {alert.alert_code} · {alert.source_ip} → {alert.dest_ip}
                            </p>
                          </div>
                          <span className="text-[10px] text-slate-600">{relativeTime(alert.first_seen)}</span>
                          <ArrowRight className="h-3 w-3 text-slate-600" />
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <EmptyState
                      compact
                      title="No alerts emitted yet"
                      description="Alerts appear as replayed records cross detector thresholds. Some benign datasets legitimately produce none."
                      icon={<AlertTriangle className="h-4 w-4" />}
                    />
                  )}
                </div>

                {selectedDemo ? (
                  <div className="mt-4 rounded-lg border border-signal-amber/20 bg-signal-amber/[0.04] px-3.5 py-3">
                    <p className="flex items-center gap-1.5 text-[11px] font-medium text-signal-amber">
                      <FlaskConical className="h-3.5 w-3.5" /> Synthetic ground truth
                    </p>
                    <p className="mt-1 text-[10.5px] leading-relaxed text-amber-100/60">
                      This scenario is labelled <span className="font-mono">{groundTruthLabel(selectedDemo.ground_truth)}</span>. Ground truth is
                      stored with the dataset for evaluation and is never read by a detector. Detected alerts remain evidence
                      produced from flow metadata.
                    </p>
                  </div>
                ) : null}
              </>
            )}
          </Panel>

          <Panel className="p-4 sm:p-5">
            <SectionTitle
              eyebrow="Throughput"
              title="Session characteristics"
              subtitle="Replay compresses wall time. Record order and relative spacing are preserved."
            />
            <div className="mt-3 grid grid-cols-2 gap-2.5">
              <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2.5">
                <p className="label flex items-center gap-1"><Clock3 className="h-3 w-3" /> Speed</p>
                <p className="mt-1 font-mono text-[15px] text-slate-100">{current ? `${current.speed}×` : `${speed}×`}</p>
              </div>
              <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2.5">
                <p className="label flex items-center gap-1"><Sparkles className="h-3 w-3" /> Category scope</p>
                <p className="mt-1 font-mono text-[15px] text-slate-100">{current ? current.categories.length || "all" : categories.length || "all"}</p>
              </div>
            </div>
            <ul className="mt-3 space-y-1.5 text-[10.5px] leading-relaxed text-slate-500">
              <li>Replay results are isolated from LIVE telemetry and labelled REPLAY or DEMO.</li>
              <li>Starting a new session clears previous REPLAY-workspace results so charts match the current run.</li>
              <li>Alerts carry the DEMO data source; they never claim to be live detections.</li>
            </ul>
          </Panel>
        </div>
      </div>

      <Panel className="mt-5 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
          <SectionTitle title="Recent sessions" subtitle="The last 30 replay sessions across workspaces." />
          <button type="button" className="btn-secondary" onClick={() => void sessions.refetch()} disabled={sessions.isFetching}>
            <RotateCcw className={cn("h-3.5 w-3.5", sessions.isFetching && "animate-spin")} /> Refresh
          </button>
        </div>
        {sessions.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-11 w-full" />
            ))}
          </div>
        ) : sessions.isError ? (
          <div className="p-4">
            <ErrorState message={sessions.error instanceof Error ? sessions.error.message : "Sessions could not be loaded."} retry={() => void sessions.refetch()} />
          </div>
        ) : sessionItems.length ? (
          <div className="overflow-x-auto">
            <table className="table-base min-w-[860px]">
              <thead>
                <tr>
                  <th>Session</th>
                  <th>Status</th>
                  <th>Environment</th>
                  <th>Speed</th>
                  <th>Progress</th>
                  <th>Alerts</th>
                  <th>Timing</th>
                </tr>
              </thead>
              <tbody>
                {sessionItems.map((item) => (
                  <SessionRow key={item.id} session={item} selected={item.id === activeId} onSelect={() => setActiveId(item.id)} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-4">
            <EmptyState compact title="No replay history" description="Sessions appear here once you start one." icon={<Radio className="h-4 w-4" />} />
          </div>
        )}
      </Panel>

      <div className="mt-4 flex items-start gap-2 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2.5 text-[10.5px] leading-relaxed text-slate-600">
        <InfoHint
          label="About replay isolation"
          text="Replay writes into a dedicated REPLAY workspace. Alerts and flows created during a session are tagged with the replay environment and demo data source, so they can never be confused with live telemetry."
        />
        Replay is intentionally isolated: sessions never write to the LIVE workspace, and the browser never reads capture files
        directly. Everything shown is produced by the API from stored flows.
      </div>
    </div>
  );
}
