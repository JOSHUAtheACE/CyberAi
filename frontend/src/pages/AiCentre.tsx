import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { EChartsOption } from "echarts";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  FlaskConical,
  Gauge,
  GitBranch,
  Loader2,
  Rewind,
  Settings2,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { RadarCard, Ring, TONES, type Tone } from "@/components/visuals";
import { EChart, chartPalette } from "@/components/charts/EChart";
import {
  Badge,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  InfoHint,
  Modal,
  Panel,
  PageHeader,
  SectionTitle,
  Skeleton,
  Toggle,
} from "@/components/ui";
import { barOption, lineOption } from "@/lib/charts";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { cn, formatDate, formatDateTime, formatNumber, formatPercent, relativeTime, titleCase } from "@/lib/format";
import type { AiOverview, DetectionModule, Evaluation, Insight, ModelVersion } from "@/lib/types";

const CONFIDENCE_LABEL: Record<string, string> = {
  calibrated_probability: "Calibrated probability",
  hybrid_score: "Hybrid score",
  heuristic_score: "Heuristic score",
  anomaly_score: "Anomaly score",
};

const DETECTOR_LABEL: Record<string, string> = {
  port_scan_detector: "Port scanning",
  exfiltration_detector: "Exfiltration",
  dns_detector: "DGA & DNS tunnelling",
  beaconing_detector: "C2 beaconing",
  ddos_detector: "DDoS & volumetric",
  encrypted_metadata_detector: "TLS / QUIC metadata",
};

function curveOption(
  points: { x: number; y: number }[],
  xName: string,
  yName: string,
  color: string,
  diagonal = false,
): EChartsOption {
  const series: Record<string, unknown>[] = [
    {
      type: "line",
      data: points.map((point) => [point.x, point.y]),
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 1.7, color },
      itemStyle: { color },
      areaStyle: {
        color: {
          type: "linear",
          x: 0,
          y: 0,
          x2: 0,
          y2: 1,
          colorStops: [
            { offset: 0, color: `${color}33` },
            { offset: 1, color: `${color}00` },
          ],
        },
      },
    },
  ];
  if (diagonal) {
    series.push({
      type: "line",
      data: [
        [0, 0],
        [1, 1],
      ],
      showSymbol: false,
      lineStyle: { width: 1, type: "dashed", color: "rgba(148,163,184,0.35)" },
      itemStyle: { color: "rgba(148,163,184,0.35)" },
    });
  }
  return {
    animationDuration: 420,
    grid: { left: 8, right: 16, top: 14, bottom: 6, containLabel: true },
    tooltip: { trigger: "axis" },
    xAxis: {
      type: "value",
      min: 0,
      max: 1,
      name: xName,
      nameTextStyle: { color: chartPalette.axis, fontSize: 9.5 },
      axisLabel: { color: chartPalette.axis, fontSize: 9.5, formatter: (value: number) => value.toFixed(1) },
      splitLine: { lineStyle: { color: chartPalette.grid } },
    },
    yAxis: {
      type: "value",
      min: 0,
      max: 1,
      name: yName,
      nameTextStyle: { color: chartPalette.axis, fontSize: 9.5 },
      axisLabel: { color: chartPalette.axis, fontSize: 9.5, formatter: (value: number) => value.toFixed(1) },
      splitLine: { lineStyle: { color: chartPalette.grid } },
    },
    series: series as never,
  };
}

function MetricCard({
  label,
  value,
  display,
  help,
  tone = "accent",
}: {
  label: string;
  value: number;
  display: string;
  help: string;
  tone?: Tone;
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/[0.06] bg-ink-900/50 px-2.5 py-2.5">
      <span
        aria-hidden
        className="pointer-events-none absolute -right-6 -top-8 h-16 w-16 rounded-full opacity-[0.12] blur-2xl"
        style={{ background: TONES[tone] }}
      />
      <div className="flex items-start justify-between gap-1">
        <p className="label text-[8.5px] leading-tight">{label}</p>
        <InfoHint text={help} label={`About ${label}`} />
      </div>
      <div className="mt-1 flex justify-center">
        <Ring ratio={value} display={display} color={TONES[tone]} size={74} thickness={5.5} />
      </div>
    </div>
  );
}

function AiTile({
  label,
  value,
  icon: Icon,
  tone,
  ratio,
  footnote,
}: {
  label: string;
  value: string;
  icon: LucideIcon;
  tone: Tone;
  ratio?: number;
  footnote?: string;
}) {
  const color = TONES[tone];
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/[0.07] bg-ink-800/60 p-3">
      <span
        aria-hidden
        className="pointer-events-none absolute -right-6 -top-9 h-16 w-16 rounded-full opacity-[0.15] blur-2xl"
        style={{ background: color }}
      />
      <div className="flex items-start justify-between gap-1.5">
        <p className="label min-w-0 truncate leading-tight">{label}</p>
        <span
          className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border"
          style={{ background: `${color}14`, borderColor: `${color}2b`, color }}
        >
          <Icon className="h-3 w-3" />
        </span>
      </div>
      <p className="mt-2 font-mono text-[19px] font-medium leading-none tabular-nums text-slate-100">{value}</p>
      {ratio !== undefined ? (
        <div className="mt-2 h-[3px] overflow-hidden rounded-full bg-white/[0.06]">
          <div
            className="h-full rounded-full"
            style={{ width: `${Math.max(2, Math.min(100, ratio * 100))}%`, background: color, boxShadow: `0 0 6px ${color}55` }}
          />
        </div>
      ) : null}
      {footnote ? <p className="mt-1 truncate text-[9px] text-slate-600">{footnote}</p> : null}
    </div>
  );
}

function ModelCard({ model, selected, onSelect }: { model: ModelVersion; selected: boolean; onSelect: () => void }) {
  const metrics = model.metrics_summary;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={cn(
        "w-full rounded-xl border p-3.5 text-left transition-colors",
        selected ? "border-accent/40 bg-accent/[0.05]" : "border-white/[0.06] bg-ink-900/40 hover:border-white/[0.13]",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-[12px] font-medium text-slate-100">{DETECTOR_LABEL[model.detector_code] ?? model.name}</p>
          <p className="mt-0.5 font-mono text-[9.5px] text-slate-500">
            {model.name} · v{model.version}
          </p>
        </div>
        <Badge tone={model.loaded ? "mint" : "slate"} dot={model.loaded}>
          {model.loaded ? "LOADED" : "ON DISK"}
        </Badge>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <Badge tone="violet">{CONFIDENCE_LABEL[model.confidence_type] ?? model.confidence_type}</Badge>
        <Badge tone="slate">{model.algorithm}</Badge>
      </div>
      <div className="mt-2.5 grid grid-cols-3 gap-2 border-t border-white/[0.05] pt-2.5">
        {[
          { key: "P", value: metrics.precision, color: TONES.blue },
          { key: "R", value: metrics.recall, color: TONES.violet },
          { key: "F1", value: metrics.f1, color: TONES.accent },
        ].map((metric) => (
          <div key={metric.key}>
            <div className="flex items-baseline justify-between gap-1 text-[9px] text-slate-600">
              <span>{metric.key}</span>
              <span className="font-mono text-slate-300">{metric.value?.toFixed(3) ?? "—"}</span>
            </div>
            <div className="mt-1 h-[2px] overflow-hidden rounded-full bg-white/[0.06]">
              <div
                className="h-full rounded-full"
                style={{ width: `${Math.max(2, Math.min(100, (metric.value ?? 0) * 100))}%`, background: metric.color }}
              />
            </div>
          </div>
        ))}
      </div>
      <p className="mt-2 truncate text-[9.5px] text-slate-600" title={model.dataset_name}>
        {model.dataset_name} · {model.dataset_version}
      </p>
    </button>
  );
}

function ConfusionMatrix({ confusion }: { confusion: { tp: number; fp: number; fn: number; tn: number } }) {
  const total = confusion.tp + confusion.fp + confusion.fn + confusion.tn;
  const cells = [
    { label: "True positive", value: confusion.tp, tone: "text-signal-mint border-signal-mint/20 bg-signal-mint/[0.05]" },
    { label: "False positive", value: confusion.fp, tone: "text-signal-rose border-signal-rose/20 bg-signal-rose/[0.05]" },
    { label: "False negative", value: confusion.fn, tone: "text-signal-amber border-signal-amber/20 bg-signal-amber/[0.05]" },
    { label: "True negative", value: confusion.tn, tone: "text-slate-300 border-white/10 bg-white/[0.03]" },
  ];
  return (
    <div>
      <div className="grid grid-cols-2 gap-1.5">
        {cells.map((cell) => (
          <div key={cell.label} className={cn("rounded-lg border px-3 py-2.5", cell.tone)}>
            <p className="text-[9.5px] uppercase tracking-[0.08em] opacity-70">{cell.label}</p>
            <p className="mt-1 font-mono text-[16px] tabular-nums">{formatNumber(cell.value)}</p>
            <p className="text-[9px] opacity-60">{total ? formatPercent(cell.value / total, 1) : "—"}</p>
          </div>
        ))}
      </div>
      <p className="mt-2 text-[9.5px] leading-relaxed text-slate-600">
        Confusion counts from the held-out synthetic split at the stored decision threshold.
      </p>
    </div>
  );
}

function EvaluationView({ evaluation }: { evaluation: Evaluation }) {
  const scores = evaluation.scores;
  const fi = useMemo(() => {
    if (!evaluation.feature_importance) return [];
    if (Array.isArray(evaluation.feature_importance)) return evaluation.feature_importance;
    return Object.entries(evaluation.feature_importance).map(([feature, importance]) => ({ feature, importance }));
  }, [evaluation.feature_importance]);
  const topFeatures = useMemo(() => [...fi].sort((a, b) => b.importance - a.importance).slice(0, 10), [fi]);
  const drift = evaluation.drift as
    | { method?: string; per_feature?: Record<string, number>; max?: number; mean?: number }
    | null;
  const splits = evaluation.splits as Record<string, unknown> | null;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
        <MetricCard label="Precision" value={scores.precision} display={scores.precision.toFixed(3)} tone="blue" help="Of alerts raised at the stored threshold, the share matching the synthetic ground truth." />
        <MetricCard label="Recall" value={scores.recall} display={scores.recall.toFixed(3)} tone="violet" help="Of positive synthetic scenarios, the share the model flagged at the stored threshold." />
        <MetricCard label="F1" value={scores.f1} display={scores.f1.toFixed(3)} tone="accent" help="Harmonic mean of precision and recall on the held-out synthetic split." />
        <MetricCard label="FP rate" value={scores.false_positive_rate} display={formatPercent(scores.false_positive_rate, 2)} tone={scores.false_positive_rate > 0.1 ? "rose" : "amber"} help="Benign synthetic flows incorrectly flagged at the stored threshold. Lower is better." />
        <MetricCard label="ROC AUC" value={scores.roc_auc ?? 0} display={scores.roc_auc === null ? "—" : scores.roc_auc.toFixed(3)} tone="mint" help="Ranking quality across thresholds on the synthetic evaluation split." />
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-lg border border-white/[0.06] bg-ink-900/35 px-3.5 py-2.5 text-[10.5px]">
        <span className="text-slate-500">Dataset <span className="text-slate-300">{evaluation.dataset.name}</span></span>
        <span className="text-slate-500">Version <span className="font-mono text-slate-300">{evaluation.dataset.version}</span></span>
        <span className="text-slate-500">Samples <span className="font-mono text-slate-300">{formatNumber(evaluation.dataset.sample_count)}</span></span>
        <span className="text-slate-500">Threshold <span className="font-mono text-slate-300">{evaluation.threshold === null ? "—" : evaluation.threshold.toFixed(3)}</span></span>
        <span className="text-slate-500">Inference <span className="font-mono text-slate-300">{evaluation.inference_latency_ms === null ? "—" : `${evaluation.inference_latency_ms.toFixed(2)} ms`}</span></span>
        <span className="ml-auto text-slate-600">evaluated {relativeTime(evaluation.evaluated_at)}</span>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        {evaluation.pr_curve?.length ? (
          <Panel className="p-4">
            <SectionTitle title="Precision–recall curve" subtitle="Trade-off across decision thresholds on the held-out split." />
            <EChart
              option={curveOption(
                evaluation.pr_curve.map((point) => ({ x: point.recall, y: point.precision })),
                "recall",
                "precision",
                chartPalette.accent,
              )}
              height={220}
              ariaLabel="Precision recall curve"
            />
          </Panel>
        ) : null}
        {evaluation.roc_curve?.length ? (
          <Panel className="p-4">
            <SectionTitle title="ROC curve" subtitle="Dashed line is the no-skill diagonal." />
            <EChart
              option={curveOption(
                evaluation.roc_curve.map((point) => ({ x: point.fpr, y: point.tpr })),
                "false positive rate",
                "true positive rate",
                chartPalette.blue,
                true,
              )}
              height={220}
              ariaLabel="ROC curve"
            />
          </Panel>
        ) : null}
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <Panel className="p-4">
          <SectionTitle title="Feature importance" subtitle="Model-derived importance on the synthetic evaluation split. Not causal evidence." />
          {topFeatures.length ? (
            <div className="mt-2">
              <EChart
                option={barOption({
                  labels: topFeatures.map((item) => item.feature.replace(/_/g, " ")),
                  series: [{ name: "importance", data: topFeatures.map((item) => item.importance), color: chartPalette.violet }],
                  horizontal: true,
                  legend: false,
                  yFormatter: (value) => value.toFixed(3),
                })}
                height={230}
                ariaLabel="Feature importance"
              />
            </div>
          ) : (
            <p className="mt-3 text-[11px] text-slate-500">This model does not report feature importance.</p>
          )}
        </Panel>
        <Panel className="p-4">
          <SectionTitle title="Confusion matrix" subtitle="Counts at the stored threshold." />
          <div className="mt-3">
            {evaluation.confusion ? (
              <ConfusionMatrix confusion={evaluation.confusion} />
            ) : (
              <p className="text-[11px] text-slate-500">Confusion counts are not available for this evaluation.</p>
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel className="p-4">
          <SectionTitle
            title="Distribution drift"
            subtitle={drift?.method ?? "Train versus held-out test comparison."}
            actions={<Badge tone={drift && drift.max !== undefined && drift.max > 0.2 ? "amber" : "slate"}>max {drift?.max === undefined ? "—" : drift.max.toFixed(3)}</Badge>}
          />
          {drift?.per_feature && Object.keys(drift.per_feature).length ? (
            <div className="mt-3 max-h-[220px] overflow-y-auto pr-1">
              {Object.entries(drift.per_feature)
                .sort(([, a], [, b]) => b - a)
                .map(([feature, value]) => (
                  <div key={feature} className="flex items-center gap-2 border-b border-white/[0.04] py-1.5">
                    <span className="flex-1 truncate text-[10.5px] text-slate-400">{feature.replace(/_/g, " ")}</span>
                    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-white/[0.06]">
                      <div className={cn("h-full rounded-full", value > 0.2 ? "bg-signal-amber/80" : "bg-accent/60")} style={{ width: `${Math.min(100, value * 100)}%` }} />
                    </div>
                    <span className="w-10 text-right font-mono text-[10px] text-slate-400">{value.toFixed(3)}</span>
                  </div>
                ))}
            </div>
          ) : (
            <p className="mt-3 text-[11px] text-slate-500">Drift statistics are not available for this evaluation.</p>
          )}
          <p className="mt-2 text-[9.5px] leading-relaxed text-slate-600">
            Drift here compares synthetic train and test splits; it is not a production drift monitor.
          </p>
        </Panel>
        <Panel className="p-4">
          <SectionTitle title="Split composition" subtitle="Grouped by scenario so records from one scenario never span splits." />
          {splits && Object.keys(splits).length ? (
            <div className="mt-3 space-y-1">
              {Object.entries(splits).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-3 border-b border-white/[0.04] py-1.5">
                  <span className="text-[10.5px] text-slate-500">{titleCase(key)}</span>
                  <span className="font-mono text-[10.5px] text-slate-300">
                    {typeof value === "number" ? formatNumber(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-3 text-[11px] text-slate-500">Split composition was not recorded for this evaluation.</p>
          )}
          {(() => {
            const comments = Array.isArray(evaluation.comments)
              ? evaluation.comments
              : evaluation.comments
                ? [evaluation.comments]
                : [];
            if (!comments.length) return null;
            return (
              <ul className="mt-3 space-y-1 text-[10px] leading-relaxed text-slate-500">
                {comments.map((comment, index) => (
                  <li key={index} className="flex gap-1.5">
                    <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                    {comment}
                  </li>
                ))}
              </ul>
            );
          })()}
        </Panel>
      </div>

      {evaluation.dataset.class_distribution ? (
        <Panel className="p-4">
          <SectionTitle title="Class distribution" subtitle="Labelled synthetic counts used for evaluation." />
          <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {Object.entries(evaluation.dataset.class_distribution).map(([label, count]) => (
              <div key={label} className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2">
                <p className="label">{label}</p>
                <p className="mt-1 font-mono text-[13px] text-slate-200">{formatNumber(count)}</p>
              </div>
            ))}
          </div>
        </Panel>
      ) : null}
    </div>
  );
}

function DetectorConfigModal({
  detector,
  open,
  onClose,
  onSaved,
}: {
  detector: DetectionModule | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [enabled, setEnabled] = useState(detector?.enabled ?? true);
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      Object.entries(detector?.thresholds ?? {})
        .filter(([, value]) => typeof value === "number")
        .map(([key, value]) => [key, String(value)]),
    ),
  );

  const save = useMutation({
    mutationFn: () => {
      if (!detector) throw new Error("No detector selected");
      const thresholds: Record<string, number> = {};
      for (const [key, raw] of Object.entries(values)) {
        const parsed = Number(raw);
        if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`Threshold ${key} must be a non-negative number.`);
        const original = detector.thresholds[key];
        if (typeof original === "number" && parsed !== original) thresholds[key] = parsed;
      }
      return api.patch(`/ai/detectors/${detector.code}`, { thresholds, enabled });
    },
    onSuccess: () => {
      toast("success", "Detector configuration saved", "Changes are recorded in the audit log and apply to subsequent detection passes.");
      onSaved();
      onClose();
    },
    onError: (error) => toast("error", "Configuration not saved", error instanceof Error ? error.message : "Try again."),
  });

  if (!detector) return null;
  const numericThresholds = Object.entries(detector.thresholds ?? {}).filter(([, value]) => typeof value === "number");

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Configure ${detector.name}`}
      description="Threshold changes affect future detection passes only. Existing alerts are not rewritten."
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
          <button type="button" className="btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Settings2 className="h-3.5 w-3.5" />} Save configuration
          </button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-3 rounded-lg border border-white/[0.07] bg-ink-900/50 px-3.5 py-3">
          <div>
            <p className="text-[12px] font-medium text-slate-200">Detector enabled</p>
            <p className="mt-0.5 text-[10.5px] text-slate-500">Disabled modules stop producing new alerts.</p>
          </div>
          <Toggle checked={enabled} onChange={setEnabled} label="Enable detector" />
        </div>
        {numericThresholds.length ? (
          numericThresholds.map(([key, original]) => (
            <label key={key} className="block">
              <span className="label mb-1.5 block">{key.replace(/_/g, " ")}</span>
              <input
                type="number"
                min={0}
                step="0.01"
                className="field"
                value={values[key] ?? String(original)}
                onChange={(event) => setValues((state) => ({ ...state, [key]: event.target.value }))}
              />
              <span className="mt-1 block font-mono text-[9.5px] text-slate-600">current {String(original)}</span>
            </label>
          ))
        ) : (
          <p className="text-[11px] text-slate-500">This detector exposes no numeric thresholds.</p>
        )}
        {Object.entries(detector.thresholds ?? {}).filter(([, value]) => Array.isArray(value)).length ? (
          <p className="text-[10px] leading-relaxed text-slate-600">
            Read-only list thresholds:{" "}
            {Object.entries(detector.thresholds)
              .filter(([, value]) => Array.isArray(value))
              .map(([key, value]) => `${key} = ${(value as number[]).join(", ")}`)
              .join("; ")}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}

export function AiCentre() {
  const { hasPermission } = useAuth();
  const { workspaceSlug, range } = useWorkspace();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [trainOpen, setTrainOpen] = useState(false);
  const [trainVersion, setTrainVersion] = useState("");
  const [configDetector, setConfigDetector] = useState<DetectionModule | null>(null);

  const canManageModels = hasPermission("ai.models.manage");
  const canManageThresholds = hasPermission("thresholds.manage");

  const overview = useQuery({
    queryKey: ["ai-overview"],
    queryFn: () => api.get<AiOverview>("/ai/overview"),
    staleTime: 30_000,
  });

  const insights = useQuery({
    queryKey: ["ai-insights", workspaceSlug, range],
    queryFn: () =>
      api.get<{ insights: Insight[]; notice: string; period: { label: string; start: string; end: string }; workspace: { slug: string; environment: string } }>(
        "/ai/insights",
        { workspace: workspaceSlug, range },
      ),
    refetchInterval: 45_000,
  });

  const train = useMutation({
    mutationFn: () => api.post<{ version: string; trained: number; notice: string }>("/ai/train", { version: trainVersion || null }),
    onSuccess: (result) => {
      toast("success", `${result.trained} models trained`, `${result.notice} Version ${result.version}.`);
      setTrainOpen(false);
      setTrainVersion("");
      void queryClient.invalidateQueries({ queryKey: ["ai-overview"] });
      void queryClient.invalidateQueries({ queryKey: ["detections-catalog"] });
    },
    onError: (error) => toast("error", "Training failed", error instanceof Error ? error.message : "Training could not be completed."),
  });

  const data = overview.data;
  const models = data?.models ?? [];
  const activeId = selectedId ?? models[0]?.id ?? null;
  const selectedModel = models.find((model) => model.id === activeId) ?? null;
  const selectedDetector = data?.detectors.find((detector) => detector.model?.id === activeId) ?? null;
  const evaluation = selectedDetector?.evaluation ?? null;
  const loadedCount = models.filter((model) => model.loaded).length;
  const mlCount = data?.detectors.filter((detector) => detector.ml_supported).length ?? 0;
  const evaluatedCount = data?.detectors.filter((detector) => detector.evaluation).length ?? 0;
  const hasAuc =
    Boolean(selectedModel) &&
    models.every((model) => model.metrics_summary.roc_auc !== null) &&
    selectedModel?.metrics_summary.roc_auc !== null;
  const radarIndicators = [
    { name: "Precision" },
    { name: "Recall" },
    { name: "F1" },
    { name: "Specificity" },
    ...(hasAuc ? [{ name: "ROC AUC" }] : []),
  ];
  const radarSeries = selectedModel
    ? (() => {
        const suiteMean = (pick: (model: ModelVersion) => number) =>
          models.length ? models.reduce((sum, model) => sum + pick(model), 0) / models.length : 0;
        const selectedMetrics = selectedModel.metrics_summary;
        const build = (precision: number, recall: number, f1: number, fpr: number, auc: number | null) => [
          precision,
          recall,
          f1,
          1 - fpr,
          ...(hasAuc ? [auc ?? 0] : []),
        ];
        return [
          {
            name: "Selected",
            values: build(selectedMetrics.precision, selectedMetrics.recall, selectedMetrics.f1, selectedMetrics.false_positive_rate, selectedMetrics.roc_auc),
            color: TONES.accent,
          },
          ...(models.length > 1
            ? [
                {
                  name: "Suite mean",
                  values: build(
                    suiteMean((model) => model.metrics_summary.precision),
                    suiteMean((model) => model.metrics_summary.recall),
                    suiteMean((model) => model.metrics_summary.f1),
                    suiteMean((model) => model.metrics_summary.false_positive_rate),
                    suiteMean((model) => model.metrics_summary.roc_auc ?? 0),
                  ),
                  color: TONES.violet,
                },
              ]
            : []),
        ];
      })()
    : [];

  return (
    <div>
      <PageHeader
        eyebrow="AI & models"
        title="Measured, not asserted"
        description="Model quality is shown only where a real evaluation ran. Every number below comes from the stored evaluation record of the active model on the labelled synthetic corpus. These are engineering benchmarks, not production accuracy claims."
        actions={
          <>
            <Badge tone="slate">{formatDate(data?.generated_at)}</Badge>
            {canManageModels ? (
              <button type="button" className="btn-secondary" onClick={() => setTrainOpen(true)}>
                <Rewind className="h-3.5 w-3.5" /> Retrain models
              </button>
            ) : null}
          </>
        }
      />

      {data?.dataset_provenance.not_production_accuracy ? (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-signal-amber/25 bg-signal-amber/[0.05] px-3.5 py-2.5 text-[11px] leading-relaxed text-amber-100/75">
          <FlaskConical className="mt-0.5 h-3.5 w-3.5 shrink-0 text-signal-amber" />
          <span>{data.disclaimer}</span>
        </div>
      ) : null}

      {overview.isLoading ? (
        <div className="mt-5 grid gap-4 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.6fr)]">
          <Skeleton className="h-96 w-full" />
          <Skeleton className="h-96 w-full" />
        </div>
      ) : overview.isError || !data ? (
        <div className="mt-5">
          <ErrorState message={overview.error instanceof Error ? overview.error.message : "Model information could not be loaded."} retry={() => void overview.refetch()} />
        </div>
      ) : (
        <>
          <div className="mt-4 grid gap-4 xl:grid-cols-12">
            <RadarCard
              className="xl:col-span-7"
              title="Suite scorecard"
              subtitle="Stored evaluation metrics · selected model versus suite mean"
              indicators={radarIndicators}
              series={radarSeries}
              height={230}
              empty={!radarSeries.length}
              emptyLabel="No evaluated model versions are stored."
              footer={
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[9px] text-slate-600">
                  <span className="inline-flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: TONES.accent }} />
                    selected model
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: TONES.violet }} />
                    mean of {formatNumber(models.length)} active models
                  </span>
                  <span className="ml-auto font-mono">{data.dataset_provenance.versions.join(" · ")}</span>
                </div>
              }
            />
            <div className="grid grid-cols-2 gap-2.5 xl:col-span-5">
              <AiTile
                label="Active models"
                value={formatNumber(models.length)}
                icon={BrainCircuit}
                tone="violet"
                ratio={models.length ? loadedCount / models.length : 0}
                footnote={`${formatNumber(loadedCount)} loaded in memory`}
              />
              <AiTile
                label="Detection modules"
                value={formatNumber(data.detectors.length)}
                icon={ShieldCheck}
                tone="accent"
                ratio={data.detectors.length ? mlCount / data.detectors.length : 0}
                footnote={`${formatNumber(mlCount)} ML-backed`}
              />
              <AiTile
                label="Evaluations"
                value={formatNumber(evaluatedCount)}
                icon={FlaskConical}
                tone="mint"
                ratio={data.detectors.length ? evaluatedCount / data.detectors.length : 0}
                footnote="stored evaluation records"
              />
              <AiTile
                label="Insights"
                value={formatNumber(insights.data?.insights.length ?? 0)}
                icon={Sparkles}
                tone="amber"
                footnote="evidence-linked observations"
              />
            </div>
          </div>

          <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,0.78fr)_minmax(0,1.7fr)]">
            <Panel className="p-4">
              <SectionTitle
                eyebrow="Registry"
                title="Active model versions"
                subtitle="Only ACTIVE versions are listed. Superseded versions stay in the audit history."
              />
              <div className="mt-3 space-y-2">
                {models.length ? (
                  models.map((model) => (
                    <ModelCard key={model.id} model={model} selected={model.id === activeId} onSelect={() => setSelectedId(model.id)} />
                  ))
                ) : (
                  <EmptyState compact title="No active models" description="Train the model suite to create active versions." icon={<BrainCircuit className="h-4 w-4" />} />
                )}
              </div>
              <div className="mt-3 rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2.5 text-[9.5px] leading-relaxed text-slate-600">
                <p className="flex items-center gap-1.5 text-[10px] font-medium text-slate-400">
                  <ShieldCheck className="h-3 w-3 text-accent/80" /> Artifact integrity
                </p>
                <p className="mt-1">
                  {models.every((model) => model.artifact_exists)
                    ? "Every active model artifact exists on disk and is loaded by the detector runtime."
                    : "One or more active model artifacts are missing on disk; those detectors fall back to rules and report it."}
                </p>
              </div>
            </Panel>

            <div className="space-y-5">
              {selectedModel ? (
                <Panel className="p-4 sm:p-5">
                  <SectionTitle
                    eyebrow={selectedModel.detector_code.replace(/_/g, " ")}
                    title={`${selectedModel.name} · ${selectedModel.version}`}
                    subtitle={`${selectedModel.algorithm} · trained ${relativeTime(selectedModel.trained_at)} · ${selectedModel.dataset_licence}`}
                    actions={
                      <>
                        <Badge tone={selectedModel.loaded ? "mint" : "slate"} dot={selectedModel.loaded}>
                          {selectedModel.loaded ? "LOADED" : "NOT LOADED"}
                        </Badge>
                        <Badge tone="violet">{CONFIDENCE_LABEL[selectedModel.confidence_type] ?? selectedModel.confidence_type}</Badge>
                        {selectedDetector ? (
                          <Link to={`/app/detections/${selectedDetector.model_code ?? ""}`} className="text-[10.5px] text-signal-blue hover:underline">
                            Open detector
                          </Link>
                        ) : null}
                      </>
                    }
                  />
                  <div className="mt-3">
                    {evaluation ? (
                      <EvaluationView evaluation={evaluation} />
                    ) : (
                      <EmptyState
                        compact
                        title="No evaluation recorded for this version"
                        description="Metrics are only rendered from stored evaluation records. Run training to produce a documented evaluation."
                        icon={<Gauge className="h-4 w-4" />}
                      />
                    )}
                  </div>
                </Panel>
              ) : null}

              <Panel className="p-4">
                <SectionTitle
                  eyebrow="Score semantics"
                  title="What each score type means"
                  subtitle="Confidence is never silently reinterpreted as probability or accuracy."
                />
                <div className="mt-3 space-y-1.5">
                  {data.score_semantics.map((semantic) => (
                    <div key={semantic.type} className="flex flex-col gap-1 rounded-lg border border-white/[0.05] bg-ink-900/35 px-3 py-2 sm:flex-row sm:items-center sm:gap-3">
                      <Badge tone="violet" className="w-fit shrink-0">{CONFIDENCE_LABEL[semantic.type] ?? semantic.type}</Badge>
                      <span className="text-[10.5px] leading-relaxed text-slate-500">{semantic.meaning}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>
          </div>

          <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
            <Panel className="overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
                <SectionTitle
                  title="Detection modules"
                  subtitle="Six categories; four have trained models. Modules without a model are rule-driven and say so."
                />
                <GitBranch className="h-4 w-4 text-slate-600" />
              </div>
              <div className="overflow-x-auto">
                <table className="table-base min-w-[760px]">
                  <thead>
                    <tr>
                      <th>Module</th>
                      <th>Model</th>
                      <th>Confidence type</th>
                      <th>Coverage</th>
                      <th>Status</th>
                      <th aria-label="Configure" />
                    </tr>
                  </thead>
                  <tbody>
                    {data.detectors.map((detector) => {
                      const coverage = data.coverage_notes.find((note) => note.detector === detector.code);
                      return (
                        <tr key={detector.code}>
                          <td>
                            <p className="text-[11.5px] text-slate-200">{detector.name}</p>
                            <p className="mt-0.5 font-mono text-[9.5px] text-slate-600">{detector.code}</p>
                          </td>
                          <td>
                            {detector.model ? (
                              <>
                                <p className="text-[10.5px] text-slate-300">{detector.model.name}</p>
                                <p className="font-mono text-[9.5px] text-slate-600">v{detector.model.version}</p>
                              </>
                            ) : (
                              <Badge tone="slate">rules only</Badge>
                            )}
                          </td>
                          <td>
                            <Badge tone={detector.ml_supported ? "violet" : "amber"}>
                              {detector.model ? CONFIDENCE_LABEL[detector.model.confidence_type] ?? detector.model.confidence_type : "heuristic score"}
                            </Badge>
                          </td>
                          <td className="max-w-[220px]">
                            <p className="truncate text-[10px] text-slate-500" title={coverage?.reason}>{coverage?.reason ?? "—"}</p>
                          </td>
                          <td>
                            <Badge tone={detector.status === "ACTIVE" ? "mint" : "slate"} dot={detector.status === "ACTIVE"}>
                              {detector.status}
                            </Badge>
                          </td>
                          <td>
                            {canManageThresholds ? (
                              <button
                                type="button"
                                className="btn-ghost px-2 py-1 text-[10.5px]"
                                onClick={() => setConfigDetector(detector)}
                              >
                                <Settings2 className="h-3 w-3" /> Configure
                              </button>
                            ) : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel className="p-4">
              <SectionTitle
                eyebrow="Provenance"
                title="Evaluation dataset"
                subtitle="Every metric on this page belongs to this corpus."
              />
              <div className="mt-3 rounded-lg border border-white/[0.06] bg-ink-900/40 p-3">
                <p className="text-[11px] leading-relaxed text-slate-400">{data.dataset_provenance.description}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {data.dataset_provenance.names.map((name) => (
                    <Badge key={name} tone="slate">{name}</Badge>
                  ))}
                  {data.dataset_provenance.versions.map((version) => (
                    <Badge key={version} tone="blue">{version}</Badge>
                  ))}
                </div>
                <p className="mt-2 text-[10px] text-slate-600">{data.dataset_provenance.licence}</p>
              </div>
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3 py-2.5 text-[10px] leading-relaxed text-slate-600">
                <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-signal-amber/80" />
                <span>
                  Synthetic benchmarks cannot establish production precision. Real-world precision depends on traffic mix,
                  telemetry completeness and tuning. Treat these numbers as regression evidence, not a guarantee.
                </span>
              </div>
            </Panel>
          </div>
        </>
      )}

      <Panel className="mt-5 p-4 sm:p-5">
        <SectionTitle
          eyebrow="Deterministic insights"
          title="Traceable observations"
          subtitle={insights.data?.period.label ? `Window: ${insights.data.period.label}` : "Derived from stored alerts and evidence."}
          actions={<Badge tone="accent" dot>evidence-linked</Badge>}
        />
        {insights.isLoading ? (
          <div className="mt-3 space-y-2">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-20 w-full" />
            ))}
          </div>
        ) : insights.isError ? (
          <div className="mt-3">
            <ErrorState message={insights.error instanceof Error ? insights.error.message : "Insights could not be loaded."} retry={() => void insights.refetch()} />
          </div>
        ) : (
          <>
            <div className="mt-3 grid gap-2 lg:grid-cols-2">
              {(insights.data?.insights ?? []).map((insight) => (
                <div key={insight.id} className="rounded-xl border border-white/[0.06] bg-ink-900/40 p-3.5">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-[12px] font-medium capitalize text-slate-200">{insight.title}</p>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {insight.confidence_type ? (
                        <ConfidenceBadge type={insight.confidence_type} value={insight.confidence ?? null} />
                      ) : (
                        <Badge tone="slate">{titleCase(insight.severity)}</Badge>
                      )}
                    </div>
                  </div>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">{insight.body}</p>
                  <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[9.5px] text-slate-600">
                    <span className="inline-flex items-center gap-1">
                      <Sparkles className="h-2.5 w-2.5" /> {insight.grounded ? "evidence-linked" : "observation"}
                    </span>
                    <span>{insight.data_source}</span>
                    {insight.detector ? <span className="font-mono">{insight.detector}</span> : null}
                    {insight.alert_id ? (
                      <Link to={`/app/alerts/${insight.alert_id}`} className="text-signal-blue hover:underline">
                        open alert
                      </Link>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
            {insights.data?.notice ? (
              <p className="mt-3 flex items-start gap-1.5 text-[10px] leading-relaxed text-slate-600">
                <InfoHint label="About insights" text={insights.data.notice} />
                {insights.data.notice}
              </p>
            ) : null}
          </>
        )}
      </Panel>

      <div className="mt-4 flex items-center gap-2 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2.5 text-[10px] leading-relaxed text-slate-600">
        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-signal-mint/70" />
        Inference runs locally inside the platform. No flow metadata, hostname or address is sent to an external model provider.
        {data ? <span className="ml-auto font-mono">{formatDateTime(data.generated_at)}Z</span> : null}
      </div>

      <Modal
        open={trainOpen}
        onClose={() => setTrainOpen(false)}
        title="Retrain the model suite"
        description="Training and evaluation run locally on the labelled synthetic corpus. This can take up to a minute."
        footer={
          <>
            <button type="button" className="btn-secondary" onClick={() => setTrainOpen(false)}>Cancel</button>
            <button type="button" className="btn-primary" disabled={train.isPending} onClick={() => train.mutate()}>
              {train.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Rewind className="h-3.5 w-3.5" />}
              {train.isPending ? "Training…" : "Train and evaluate"}
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <label className="block">
            <span className="label mb-1.5 block">Version label (optional)</span>
            <input
              className="field"
              value={trainVersion}
              onChange={(event) => setTrainVersion(event.target.value)}
              placeholder="e.g. 2026.10.30-01"
              maxLength={24}
            />
          </label>
          <ul className="space-y-1.5 rounded-lg border border-white/[0.06] bg-ink-900/50 px-3 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
            <li>New ACTIVE versions supersede the current ones; evaluation records are written for each model.</li>
            <li>Training uses grouped scenario splits to keep synthetic scenarios from leaking across splits.</li>
            <li>Detector thresholds are preserved unless you change them explicitly.</li>
            <li>This action is audited with your identity and the version label.</li>
          </ul>
        </div>
      </Modal>

      <DetectorConfigModal
        key={configDetector?.code ?? "none"}
        detector={configDetector}
        open={Boolean(configDetector)}
        onClose={() => setConfigDetector(null)}
        onSaved={() => {
          void queryClient.invalidateQueries({ queryKey: ["ai-overview"] });
          void queryClient.invalidateQueries({ queryKey: ["detections-catalog"] });
        }}
      />

      <div className="mt-2 flex justify-center">
        <Link to="/app/detections" className="text-[10.5px] text-slate-600 hover:text-slate-400">
          Explore detection workspaces <Activity className="ml-1 inline h-3 w-3" />
        </Link>
      </div>
    </div>
  );
}
