import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Crosshair,
  Database,
  Globe2,
  Lock,
  Radar,
  ScanLine,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Badge, EmptyState, ErrorState, InfoHint, Panel, PageHeader, SectionTitle, Skeleton } from "@/components/ui";
import { SparkKpi, TONES } from "@/components/visuals";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { formatDateTime, formatNumber, relativeTime, titleCase } from "@/lib/format";
import type { DetectionCatalogItem, DetectionCatalogResponse } from "@/lib/types";

const ICONS: Record<string, typeof Zap> = {
  ddos: Zap,
  beaconing: Radar,
  dns: Globe2,
  encrypted: Lock,
  scanning: ScanLine,
  exfiltration: Crosshair,
};

const ACCENTS: Record<string, { text: string; ring: string; bg: string }> = {
  ddos: { text: "text-signal-rose", ring: "border-signal-rose/20", bg: "bg-signal-rose/[0.06]" },
  beaconing: { text: "text-signal-violet", ring: "border-signal-violet/20", bg: "bg-signal-violet/[0.06]" },
  dns: { text: "text-signal-blue", ring: "border-signal-blue/20", bg: "bg-signal-blue/[0.06]" },
  encrypted: { text: "text-signal-amber", ring: "border-signal-amber/20", bg: "bg-signal-amber/[0.06]" },
  scanning: { text: "text-accent", ring: "border-accent/20", bg: "bg-accent/[0.06]" },
  exfiltration: { text: "text-signal-mint", ring: "border-signal-mint/20", bg: "bg-signal-mint/[0.06]" },
};

const CONFIDENCE_LABEL: Record<string, string> = {
  calibrated_probability: "Calibrated probability",
  hybrid_score: "Hybrid score",
  heuristic_score: "Heuristic score",
  anomaly_score: "Anomaly score",
};

function ModuleCard({ module, share }: { module: DetectionCatalogItem; share: number }) {
  const slug = module.slug ?? module.code;
  const Icon = ICONS[slug] ?? ShieldCheck;
  const accent = ACCENTS[slug] ?? ACCENTS.scanning;
  const href = `/app/detections/${slug}`;
  const disabled = module.status === "DISABLED" || !module.enabled;
  return (
    <Panel className="panel-hover flex flex-col p-4 sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <div className={`flex h-9 w-9 items-center justify-center rounded-lg border ${accent.ring} ${accent.bg} ${accent.text}`}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="flex items-center gap-1.5">
          <Badge tone={disabled ? "slate" : module.status === "ACTIVE" ? "mint" : "blue"} dot={!disabled}>
            {module.status}
          </Badge>
          <Badge tone="slate">v{module.version}</Badge>
        </div>
      </div>

      <h3 className="mt-3 text-[13.5px] font-semibold tracking-tight text-slate-100">{module.name}</h3>
      <p className="mt-1 line-clamp-2 text-[11.5px] leading-relaxed text-slate-500">{module.description}</p>

      <div className="mt-3 flex flex-wrap gap-1.5">
        <Badge tone="slate">{titleCase(module.threat_class)}</Badge>
        <Badge tone="neutral">{CONFIDENCE_LABEL[module.confidence_badge] ?? titleCase(module.confidence_badge)}</Badge>
      </div>

      <div className="mt-3">
        <div className="flex items-baseline justify-between text-[9px] uppercase tracking-[0.1em] text-slate-600">
          <span>share of detections</span>
          <span className="font-mono tabular-nums">{(share * 100).toFixed(0)}%</span>
        </div>
        <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
          <div
            className="h-full rounded-full transition-[width] duration-700"
            style={{
              width: `${Math.max(2, share * 100)}%`,
              background: `linear-gradient(90deg, ${TONES.accent}55, ${TONES.accent})`,
              boxShadow: `0 0 6px ${TONES.accent}55`,
            }}
          />
        </div>
      </div>

      <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1.5 border-t border-white/[0.05] pt-3 text-[10.5px]">
        <div className="flex justify-between gap-2">
          <dt className="text-slate-600">Detections</dt>
          <dd className="font-mono text-slate-300">{formatNumber(module.detections_total)}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-slate-600">Features</dt>
          <dd className="font-mono text-slate-300">{formatNumber(module.feature_count)}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-slate-600">Last run</dt>
          <dd className="text-slate-400" title={module.last_run_at ? `${formatDateTime(module.last_run_at)}Z` : undefined}>
            {module.last_run_at ? relativeTime(module.last_run_at) : "never"}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-slate-600">Model</dt>
          <dd className="max-w-[110px] truncate text-right text-slate-400">{module.model_name}</dd>
        </div>
      </dl>

      <div className="mt-3 flex flex-wrap gap-1">
        {module.supported_inputs.slice(0, 5).map((input) => (
          <span key={input} className="rounded border border-white/[0.06] bg-white/[0.025] px-1.5 py-0.5 font-mono text-[9px] text-slate-500">
            {input}
          </span>
        ))}
      </div>

      <div className="mt-4 flex items-center justify-between border-t border-white/[0.05] pt-3">
        <span className="text-[9.5px] uppercase tracking-[0.12em] text-slate-600">{module.technique}</span>
        <Link to={href} className="inline-flex items-center gap-1 text-[11.5px] font-medium text-accent-soft hover:underline">
          Open workspace <ArrowUpRight className="h-3 w-3" />
        </Link>
      </div>
    </Panel>
  );
}

export function Detections() {
  const { workspaceSlug } = useWorkspace();
  const catalog = useQuery({
    queryKey: ["detections-catalog"],
    queryFn: () => api.get<DetectionCatalogResponse>("/detections"),
    staleTime: 30_000,
  });

  const modules = catalog.data?.modules ?? [];
  const activeModules = modules.filter((module) => module.status === "ACTIVE" && module.enabled).length;
  const detectionsTotal = modules.reduce((sum, module) => sum + module.detections_total, 0);
  const telemetryFields = new Set(modules.flatMap((module) => module.supported_inputs)).size;

  return (
    <div>
      <PageHeader
        eyebrow="Detection workspaces"
        title="Six observable behaviours"
        description="Each workspace focuses on one behavioural family and exposes the telemetry fields it actually used. Where a field is missing, the workspace says so instead of estimating. Scores are labelled by semantics: only calibrated probability is a probability."
        actions={<Badge tone="slate">{workspaceSlug}</Badge>}
      />

      <div className="mb-5 grid grid-cols-2 gap-2.5 sm:grid-cols-4">
        <SparkKpi label="Modules" value={formatNumber(modules.length)} icon={ShieldCheck} tone="blue" footnote="registered detectors" />
        <SparkKpi label="Active" value={formatNumber(activeModules)} icon={Radar} tone="mint" footnote="enabled at runtime" />
        <SparkKpi label="Detections" value={formatNumber(detectionsTotal)} icon={ScanLine} tone="rose" footnote="stored across modules" />
        <SparkKpi
          label="Telemetry fields"
          value={formatNumber(telemetryFields)}
          icon={Database}
          tone="violet"
          footnote="declared inputs across modules"
        />
      </div>

      {catalog.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, index) => (
            <Skeleton key={index} className="h-64 w-full" />
          ))}
        </div>
      ) : catalog.isError ? (
        <ErrorState message={catalog.error instanceof Error ? catalog.error.message : "Detection modules could not be loaded."} retry={() => void catalog.refetch()} />
      ) : catalog.data?.modules.length ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {catalog.data.modules.map((module) => (
            <ModuleCard
              key={module.code}
              module={module}
              share={detectionsTotal ? module.detections_total / detectionsTotal : 0}
            />
          ))}
        </div>
      ) : (
        <EmptyState title="No detection modules registered" description="The backend has not provisioned detection modules." />
      )}

      <Panel className="mt-5 p-4 sm:p-5">
        <SectionTitle
          eyebrow="Method"
          title="How detections are produced"
          subtitle="The pipeline is deterministic and inspectable. Rules and statistical baselines run first; where a trained model exists, its score is blended or evaluated separately."
        />
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[
            { step: "01", title: "Normalise metadata", text: "Capture-derived or collector-pushed flow records are validated against the documented contract." },
            { step: "02", title: "Extract features", text: "Rates, intervals, entropy, port spread, directionality and handshake metadata are computed over the window." },
            { step: "03", title: "Evaluate", text: "Detector thresholds and models produce per-behaviour evidence with declared score semantics." },
            { step: "04", title: "Explain", text: "Alerts retain feature-level evidence, baseline context and flow references for investigation." },
          ].map((item) => (
            <div key={item.step} className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3.5 py-3">
              <p className="font-mono text-[10px] text-accent/80">{item.step}</p>
              <p className="mt-1.5 text-[11.5px] font-medium text-slate-200">{item.title}</p>
              <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">{item.text}</p>
            </div>
          ))}
        </div>
        <ul className="mt-4 space-y-1 text-[10.5px] leading-relaxed text-slate-600">
          {(catalog.data?.notes ?? []).map((note) => (
            <li key={note} className="flex gap-1.5">
              <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
              {note}
            </li>
          ))}
        </ul>
        <p className="mt-3 flex items-start gap-1.5 text-[10px] leading-relaxed text-slate-600">
          <InfoHint
            label="About score semantics"
            text="Calibrated probability is produced by a calibrated classifier and can be read as a probability on the evaluation split. Hybrid, heuristic and anomaly scores are relative strengths, not probabilities. The AI & models page lists the active model and its evaluation data for each detector."
          />
          Confidence is never presented as accuracy. Model quality is reported only where a real evaluation was run on a documented dataset.
        </p>
      </Panel>
    </div>
  );
}
