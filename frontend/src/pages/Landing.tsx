import { motion, useReducedMotion } from "framer-motion";
import {
  ArrowRight,
  BrainCircuit,
  Check,
  CircleSlash,
  Database,
  FileCheck2,
  Fingerprint,
  Globe2,
  KeyRound,
  Layers3,
  Lock,
  Network,
  Radar,
  ScrollText,
  ShieldCheck,
  Sparkles,
  UploadCloud,
  Workflow,
} from "lucide-react";
import { Link } from "react-router-dom";
import { GlobeView } from "@/components/globe/GlobeView";
import { SentinelLogo } from "@/components/layout/Logo";
import { Badge } from "@/components/ui";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/format";
import { heroArcs, heroNodes } from "@/lib/illustrative";

const capabilities = [
  {
    icon: UploadCloud,
    title: "One-way ingestion",
    body: "Normalise PCAP/PCAPNG captures, Zeek JSON, CSV and JSONL exports, or accept a collector push. Every record is validated before it reaches analytics.",
  },
  {
    icon: Network,
    title: "Traffic intelligence",
    body: "Flow tables, host profiles, protocol and port distributions, and a Cytoscape topology derived from stored observations — not synthetic overlays.",
  },
  {
    icon: Radar,
    title: "Six detection workspaces",
    body: "DDoS, C2 beaconing, DGA/DNS, encrypted metadata, port scanning and exfiltration, each with its own evidence model and coverage checks.",
  },
  {
    icon: BrainCircuit,
    title: "Evaluated models",
    body: "Four trained models with stored evaluation artefacts, confidence semantics displayed beside every score, and drift and latency reporting.",
  },
  {
    icon: ScrollText,
    title: "Investigation workflow",
    body: "Deduplicated alerts, evidence-linked flows, case notes, assignment, false-positive handling, and exports that preserve context.",
  },
  {
    icon: FileCheck2,
    title: "Graphical reporting",
    body: "Operational and executive summaries generated from stored records over an explicit period, with PDF, CSV and JSON exports.",
  },
];

const detectors = [
  { name: "DDoS & volumetric", technique: "Rate, entropy and SYN/ACK ratio", slug: "ddos" },
  { name: "C2 beaconing", technique: "Interval regularity and connection cadence", slug: "beaconing" },
  { name: "DGA & DNS tunnelling", technique: "Character entropy, label length, NXDOMAIN", slug: "dns" },
  { name: "TLS / QUIC metadata", technique: "JA3, SNI and handshake metadata only", slug: "encrypted" },
  { name: "Port scanning", technique: "Port spread and host sweep velocity", slug: "scanning" },
  { name: "Data exfiltration", technique: "Directional volume and destination ratios", slug: "exfiltration" },
];

const principles = [
  {
    icon: Fingerprint,
    title: "Evidence, not assertion",
    body: "Every alert carries the observed value, the baseline it was compared against, and the flows that support it.",
  },
  {
    icon: CircleSlash,
    title: "Passive by design",
    body: "The platform observes mirrored metadata. It never probes, blocks, isolates or changes a monitored device.",
  },
  {
    icon: Layers3,
    title: "Explicit coverage",
    body: "When telemetry lacks fields a detector needs, the workspace reports insufficient visibility instead of guessing.",
  },
];

const security = [
  "scrypt password hashing and signed httpOnly session cookies",
  "CSRF validation on every mutating request",
  "Server-enforced RBAC across five roles and 22 permissions",
  "Rate limiting on authentication, APIs and collector feeds",
  "Upload type, size and structure validation with SHA-256 tracking",
  "Audit log for authentication, investigation and configuration events",
  "Content-Security-Policy and hardened response headers",
  "External intelligence disabled by default; private addresses never leave the platform",
];

const environments = [
  {
    label: "LIVE",
    tone: "mint" as const,
    title: "Collector telemetry",
    body: "Only approved one-way collector pushes and uploads. Dashboards stay empty until real records arrive.",
  },
  {
    label: "REPLAY",
    tone: "blue" as const,
    title: "Time-compressed analysis",
    body: "Recorded or synthetic captures reprocessed at 0.5× to 5× with the DEMO data source preserved.",
  },
  {
    label: "DEMO",
    tone: "amber" as const,
    title: "Synthetic scenarios",
    body: "A labelled 24-hour baseline plus scenario bursts, permanently marked as synthetic in every view.",
  },
];

export function Landing() {
  const { session } = useAuth();
  const reduce = useReducedMotion();
  const reveal = reduce
    ? {}
    : {
        initial: { opacity: 0, y: 18 },
        whileInView: { opacity: 1, y: 0 },
        viewport: { once: true, margin: "-60px" },
        transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as const },
      };

  return (
    <div className="min-h-screen bg-ink-950 text-slate-200">
      <header className="fixed inset-x-0 top-0 z-50 border-b border-white/[0.06] bg-ink-950/75 backdrop-blur-xl">
        <div className="mx-auto flex h-[64px] max-w-[1240px] items-center gap-6 px-5">
          <Link to="/" aria-label="SENTINEL AI home">
            <SentinelLogo />
          </Link>
          <nav className="ml-6 hidden items-center gap-6 text-[12.5px] text-slate-400 md:flex" aria-label="Landing">
            <a className="transition-colors hover:text-slate-200" href="#platform">
              Platform
            </a>
            <a className="transition-colors hover:text-slate-200" href="#detection">
              Detection
            </a>
            <a className="transition-colors hover:text-slate-200" href="#integrity">
              Model integrity
            </a>
            <a className="transition-colors hover:text-slate-200" href="#security">
              Security
            </a>
          </nav>
          <div className="ml-auto flex items-center gap-2.5">
            <Link to={session ? "/app/overview" : "/login"} className="btn-ghost hidden sm:inline-flex">
              {session ? "Open console" : "Sign in"}
            </Link>
            <Link to={session ? "/app/overview" : "/login?demo=1"} className="btn-primary">
              {session ? "Continue" : "Open demo"}
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </header>

      <main id="main-content">
        <section className="relative overflow-hidden pt-[64px]">
          <div className="pointer-events-none absolute inset-0 bg-radial-fade" aria-hidden="true" />
          <div className="pointer-events-none absolute inset-0 grid-faint opacity-30" aria-hidden="true" />
          <div className="relative mx-auto grid max-w-[1240px] items-center gap-10 px-5 pb-16 pt-14 lg:grid-cols-[1.02fr_1fr] lg:gap-6 lg:pb-24 lg:pt-20">
            <div>
              <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-accent/20 bg-accent/[0.06] py-1 pl-1 pr-3 text-[10.5px] text-accent-soft">
                <span className="rounded-full bg-accent/15 px-2 py-0.5 font-mono text-[9px] font-semibold tracking-[0.14em]">
                  SENTINEL AI
                </span>
                <span className="tracking-[0.06em]">Passive network threat intelligence</span>
              </div>
              <h1 className="max-w-[18ch] text-[40px] font-semibold leading-[1.04] tracking-[-0.035em] text-slate-50 sm:text-[54px]">
                Know what crossed your network.
                <span className="mt-1 block text-slate-400">Understand why it mattered.</span>
              </h1>
              <p className="mt-6 max-w-[56ch] text-[14px] leading-relaxed text-slate-400">
                SENTINEL AI turns mirrored traffic and flow metadata into evidence-backed alerts, evaluated model
                signals and analyst-ready investigations — without touching a monitored host.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <Link to={session ? "/app/overview" : "/login?demo=1"} className="btn-primary h-10 px-4">
                  <Sparkles className="h-4 w-4" />
                  {session ? "Return to console" : "Explore the demo workspace"}
                </Link>
                <Link to={session ? "/app/ai" : "/login"} className="btn-secondary h-10 px-4">
                  {session ? "Inspect models" : "Sign in to a workspace"}
                </Link>
              </div>
              <div className="mt-8 flex flex-wrap items-center gap-x-6 gap-y-3">
                {[
                  ["6", "detection workspaces"],
                  ["4", "evaluated models"],
                  ["3", "isolated environments"],
                  ["5", "enforced roles"],
                ].map(([value, label]) => (
                  <div key={label} className="flex items-baseline gap-2">
                    <span className="font-mono text-[20px] font-medium text-slate-100">{value}</span>
                    <span className="text-[11px] text-slate-500">{label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="relative">
              <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-ink-900/45 p-2 shadow-[0_40px_120px_-60px_rgba(54,217,208,0.35)]">
                <GlobeView
                  arcs={heroArcs}
                  nodes={heroNodes}
                  height={460}
                  demo
                  autoRotate={!reduce}
                  className="!rounded-xl"
                />
                <div className="pointer-events-none absolute inset-x-4 top-4 flex items-start justify-between">
                  <Badge tone="accent" dot>
                    Illustrative topology
                  </Badge>
                  <span className="rounded-md border border-white/10 bg-ink-950/70 px-2 py-1 font-mono text-[9px] tracking-[0.12em] text-slate-400 backdrop-blur">
                    SYNTHETIC SCENARIO
                  </span>
                </div>
                <div className="pointer-events-none absolute bottom-4 right-4 rounded-lg border border-white/[0.08] bg-ink-950/80 px-3 py-2 backdrop-blur">
                  <p className="label mb-1">What this shows</p>
                  <p className="text-[10.5px] leading-relaxed text-slate-400">
                    A marketing illustration built from fixed coordinates. It is not live geolocation or customer
                    telemetry.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="border-y border-white/[0.06] bg-ink-900/35">
          <div className="mx-auto grid max-w-[1240px] gap-6 px-5 py-12 md:grid-cols-3">
            {principles.map((item) => (
              <motion.div key={item.title} {...reveal} className="flex gap-3.5">
                <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/[0.07] bg-white/[0.025] text-accent">
                  <item.icon className="h-4 w-4" />
                </span>
                <div>
                  <h2 className="text-[13px] font-semibold text-slate-200">{item.title}</h2>
                  <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">{item.body}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </section>

        <section id="platform" className="mx-auto max-w-[1240px] px-5 py-20">
          <motion.div {...reveal} className="max-w-2xl">
            <p className="label mb-2">Operating surface</p>
            <h2 className="text-[30px] font-semibold leading-tight tracking-[-0.025em] text-slate-50">
              A full analyst loop, not a dashboard skin
            </h2>
            <p className="mt-3 text-[13px] leading-relaxed text-slate-400">
              Ingestion, enrichment, detection, triage, reporting and governance share one data model. Every screen
              reads from stored records with an explicit time window.
            </p>
          </motion.div>
          <div className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {capabilities.map((item, index) => (
              <motion.article
                key={item.title}
                {...reveal}
                transition={{ duration: 0.45, delay: Math.min(index * 0.04, 0.2) }}
                className="group rounded-xl border border-white/[0.06] bg-ink-900/40 p-5 transition-colors hover:border-accent/20 hover:bg-ink-900/65"
              >
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/[0.07] bg-white/[0.025] text-slate-400 transition-colors group-hover:text-accent">
                  <item.icon className="h-4 w-4" />
                </div>
                <h3 className="mt-4 text-[13.5px] font-semibold text-slate-200">{item.title}</h3>
                <p className="mt-1.5 text-[12px] leading-relaxed text-slate-500">{item.body}</p>
              </motion.article>
            ))}
          </div>
        </section>

        <section id="detection" className="border-y border-white/[0.06] bg-ink-900/30">
          <div className="mx-auto max-w-[1240px] px-5 py-20">
            <div className="flex flex-wrap items-end justify-between gap-4">
              <div className="max-w-2xl">
                <p className="label mb-2">Detection workspaces</p>
                <h2 className="text-[30px] font-semibold leading-tight tracking-[-0.025em] text-slate-50">
                  Six behaviours, six evidence models
                </h2>
                <p className="mt-3 text-[13px] leading-relaxed text-slate-400">
                  Each workspace uses the fields its behaviour actually requires — and states what it cannot assess
                  when those fields are missing.
                </p>
              </div>
              <Badge tone="slate">Deterministic rules + evaluated models</Badge>
            </div>
            <div className="mt-8 grid gap-3 md:grid-cols-2 lg:grid-cols-3">
              {detectors.map((detector, index) => (
                <div
                  key={detector.slug}
                  className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-ink-950/40 px-4 py-3.5"
                >
                  <span className="font-mono text-[10px] text-slate-600">{String(index + 1).padStart(2, "0")}</span>
                  <div className="min-w-0">
                    <p className="text-[12.5px] font-medium text-slate-200">{detector.name}</p>
                    <p className="mt-0.5 truncate text-[11px] text-slate-500">{detector.technique}</p>
                  </div>
                  <Check className="ml-auto h-3.5 w-3.5 shrink-0 text-accent/60" />
                </div>
              ))}
            </div>

            <div className="mt-10 rounded-xl border border-white/[0.06] bg-ink-950/50 p-5 sm:p-6">
              <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
                <div>
                  <p className="label mb-3">Evidence path</p>
                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    {[
                      { icon: Network, label: "Collector / capture" },
                      { icon: Database, label: "Normalised flows" },
                      { icon: Workflow, label: "Detectors + ML" },
                      { icon: ShieldCheck, label: "Alert evidence" },
                      { icon: FileCheck2, label: "Case + report" },
                    ].map((step, index) => (
                      <div key={step.label} className="flex items-center gap-2">
                        <span className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.03] px-2.5 py-1.5 text-slate-300">
                          <step.icon className="h-3.5 w-3.5 text-slate-500" />
                          {step.label}
                        </span>
                        {index < 4 ? <ArrowRight className="h-3 w-3 text-slate-700" /> : null}
                      </div>
                    ))}
                  </div>
                  <p className="mt-4 max-w-[60ch] text-[11px] leading-relaxed text-slate-500">
                    The browser is never a packet source. A collector inside the monitoring enclave pushes a one-way
                    copy of flow metadata; the platform never connects back to monitored hosts.
                  </p>
                </div>
                <div className="rounded-lg border border-white/[0.06] bg-ink-900/50 p-4">
                  <p className="label mb-2">Confidence semantics</p>
                  <ul className="space-y-2 text-[11px] text-slate-400">
                    <li className="flex items-start gap-2">
                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-signal-mint" />
                      Calibrated probability — from a calibrated classifier on the labelled synthetic split.
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-signal-blue" />
                      Hybrid score — rule evidence blended with a model score; not a probability.
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-signal-amber" />
                      Heuristic score — deterministic strength; not a probability.
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-signal-violet" />
                      Anomaly score — Isolation Forest strength; not a probability of compromise.
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="integrity" className="mx-auto max-w-[1240px] px-5 py-20">
          <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr]">
            <motion.div {...reveal}>
              <p className="label mb-2">Model integrity</p>
              <h2 className="text-[30px] font-semibold leading-tight tracking-[-0.025em] text-slate-50">
                Benchmarks with their limits attached
              </h2>
              <p className="mt-3 max-w-[48ch] text-[13px] leading-relaxed text-slate-400">
                Models are trained and evaluated locally on a labelled synthetic corpus with grouped scenario
                splits. Precision, recall, false-positive rate, PR/ROC curves, drift and inference latency are stored
                per model version — and shown as engineering benchmarks, not production accuracy claims.
              </p>
              <Link to={session ? "/app/ai" : "/login"} className="btn-secondary mt-6 h-9">
                <BrainCircuit className="h-4 w-4" />
                {session ? "Open AI & models" : "Sign in to inspect evaluations"}
              </Link>
            </motion.div>
            <motion.div {...reveal} className="grid gap-3 sm:grid-cols-2">
              {[
                { name: "Scanning", algorithm: "Calibrated Random Forest", type: "calibrated_probability", tone: "mint" as const },
                { name: "Exfiltration", algorithm: "Calibrated Gradient Boosting", type: "calibrated_probability", tone: "mint" as const },
                { name: "DNS / DGA", algorithm: "Character n-gram TF-IDF + Logistic Regression", type: "calibrated_probability", tone: "mint" as const },
                { name: "Beaconing", algorithm: "Benign-only Isolation Forest", type: "anomaly_score", tone: "violet" as const },
              ].map((model) => (
                <div key={model.name} className="rounded-xl border border-white/[0.06] bg-ink-900/40 p-4">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-slate-500">{model.name}</p>
                    <Lock className="h-3 w-3 text-slate-600" />
                  </div>
                  <p className="mt-2 text-[12px] leading-relaxed text-slate-300">{model.algorithm}</p>
                  <Badge tone={model.tone} className="mt-3">
                    {model.type.replace(/_/g, " ")}
                  </Badge>
                </div>
              ))}
              <div className="sm:col-span-2 rounded-lg border border-dashed border-white/[0.09] px-4 py-3 text-[11px] leading-relaxed text-slate-500">
                Dataset: synthetic 24-hour behavioural baseline plus labelled scenario bursts. No third-party personal
                data. Evaluation metrics are reproducible with the local training command.
              </div>
            </motion.div>
          </div>
        </section>

        <section id="security" className="border-y border-white/[0.06] bg-ink-900/30">
          <div className="mx-auto max-w-[1240px] px-5 py-20">
            <div className="grid gap-10 lg:grid-cols-[0.8fr_1.2fr]">
              <motion.div {...reveal}>
                <p className="label mb-2">Security & governance</p>
                <h2 className="text-[30px] font-semibold leading-tight tracking-[-0.025em] text-slate-50">
                  Controls that hold at the boundary
                </h2>
                <p className="mt-3 max-w-[46ch] text-[13px] leading-relaxed text-slate-400">
                  Access is enforced server-side, secrets never reach the browser, and external lookups require an
                  explicit deployment-level approval plus a per-provider decision.
                </p>
                <div className="mt-6 rounded-lg border border-white/[0.06] bg-ink-950/50 p-4">
                  <div className="flex items-center gap-2 text-[11.5px] text-slate-300">
                    <KeyRound className="h-3.5 w-3.5 text-accent" />
                    Five roles, 22 permissions
                  </div>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">
                    Security Administrator, SOC Analyst, Network Security Engineer, ML Engineer and Auditor. Navigation
                    and actions both respect the server-side policy.
                  </p>
                </div>
              </motion.div>
              <motion.ul {...reveal} className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
                {security.map((item) => (
                  <li key={item} className="flex items-start gap-2.5 text-[11.5px] leading-relaxed text-slate-400">
                    <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent/70" />
                    {item}
                  </li>
                ))}
              </motion.ul>
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-[1240px] px-5 py-20">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="max-w-2xl">
              <p className="label mb-2">Environment separation</p>
              <h2 className="text-[30px] font-semibold leading-tight tracking-[-0.025em] text-slate-50">
                Three states that never blur
              </h2>
              <p className="mt-3 text-[13px] leading-relaxed text-slate-400">
                Workspace selection changes the dataset, the label and the permitted actions. Synthetic telemetry is
                never presented as live observation.
              </p>
            </div>
          </div>
          <div className="mt-8 grid gap-3 md:grid-cols-3">
            {environments.map((env) => (
              <div key={env.label} className="relative overflow-hidden rounded-xl border border-white/[0.06] bg-ink-900/40 p-5">
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
                <Badge tone={env.tone} dot>
                  {env.label}
                </Badge>
                <h3 className="mt-4 text-[14px] font-semibold text-slate-200">{env.title}</h3>
                <p className="mt-1.5 text-[12px] leading-relaxed text-slate-500">{env.body}</p>
              </div>
            ))}
          </div>

          <div className="mt-14 flex flex-col items-start justify-between gap-6 rounded-2xl border border-accent/15 bg-gradient-to-br from-accent/[0.07] via-ink-900/60 to-ink-900/30 p-6 sm:p-8 lg:flex-row lg:items-center">
            <div className="max-w-2xl">
              <div className="flex items-center gap-2 text-[11px] text-accent-soft">
                <Globe2 className="h-3.5 w-3.5" />
                Ready when you are
              </div>
              <h2 className="mt-2 text-[22px] font-semibold tracking-[-0.02em] text-slate-50">
                Walk the full investigation loop in the demo workspace.
              </h2>
              <p className="mt-2 text-[12.5px] leading-relaxed text-slate-400">
                Synthetic scenarios, six detector workspaces, stored model evaluations, replay controls and an audit
                trail — no production traffic required.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <Link to={session ? "/app/overview" : "/login?demo=1"} className="btn-primary h-10 px-4">
                {session ? "Continue session" : "Open demo"}
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
              <Link to={session ? "/app/monitoring" : "/login"} className="btn-secondary h-10 px-4">
                Sign in
              </Link>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-white/[0.06] bg-ink-950">
        <div className="mx-auto max-w-[1240px] px-5 py-10">
          <div className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between">
            <div className="max-w-sm">
              <SentinelLogo />
              <p className="mt-3 text-[11.5px] leading-relaxed text-slate-500">
                Passive network threat intelligence for security operations. Evidence-backed detection, transparent
                model semantics and no active remediation.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-10 text-[11.5px] sm:grid-cols-3">
              <div>
                <p className="label mb-2">Product</p>
                <ul className="space-y-1.5 text-slate-500">
                  <li><a href="#platform" className="hover:text-slate-300">Platform</a></li>
                  <li><a href="#detection" className="hover:text-slate-300">Detection</a></li>
                  <li><a href="#integrity" className="hover:text-slate-300">Models</a></li>
                </ul>
              </div>
              <div>
                <p className="label mb-2">Trust</p>
                <ul className="space-y-1.5 text-slate-500">
                  <li><a href="#security" className="hover:text-slate-300">Security controls</a></li>
                  <li><a href="#security" className="hover:text-slate-300">Data handling</a></li>
                </ul>
              </div>
              <div>
                <p className="label mb-2">Access</p>
                <ul className="space-y-1.5 text-slate-500">
                  <li><Link to="/login" className="hover:text-slate-300">Sign in</Link></li>
                  <li><Link to="/login?demo=1" className="hover:text-slate-300">Demo workspace</Link></li>
                </ul>
              </div>
            </div>
          </div>
          <div className="mt-8 flex flex-col gap-2 border-t border-white/[0.06] pt-5 text-[10.5px] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
            <span>© {new Date().getFullYear()} SENTINEL AI. Controlled demonstration build.</span>
            <span className={cn("font-mono tracking-[0.08em]")}>UTC · PASSIVE OBSERVATION ONLY</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
