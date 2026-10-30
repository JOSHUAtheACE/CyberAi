import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronRight,
  Copy,
  HelpCircle,
  Info,
  Loader2,
  ShieldAlert,
  X,
} from "lucide-react";
import {
  createContext,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { cn, severityRank, titleCase } from "@/lib/format";

export function Panel({
  className,
  children,
  as: Tag = "section",
}: {
  className?: string;
  children: ReactNode;
  as?: "section" | "div" | "article";
}) {
  return <Tag className={cn("panel", className)}>{children}</Tag>;
}

export function SectionTitle({
  eyebrow,
  title,
  subtitle,
  actions,
  className,
}: {
  eyebrow?: string;
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-4", className)}>
      <div className="min-w-0">
        {eyebrow ? <p className="label mb-1.5">{eyebrow}</p> : null}
        <h2 className="text-[15px] font-semibold tracking-tight text-slate-100">{title}</h2>
        {subtitle ? <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-slate-400">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-white/[0.06] pb-5">
      <div className="min-w-0">
        <p className="label mb-2">{eyebrow}</p>
        <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-slate-50 sm:text-[26px]">{title}</h1>
        {description ? (
          <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-slate-400">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

type Tone = "neutral" | "accent" | "blue" | "violet" | "amber" | "rose" | "mint" | "slate";

const toneStyles: Record<Tone, string> = {
  neutral: "border-white/10 bg-white/[0.04] text-slate-300",
  accent: "border-accent/25 bg-accent/[0.08] text-accent-soft",
  blue: "border-signal-blue/25 bg-signal-blue/[0.08] text-signal-blue",
  violet: "border-signal-violet/25 bg-signal-violet/[0.08] text-[#b9b0ff]",
  amber: "border-signal-amber/25 bg-signal-amber/[0.08] text-signal-amber",
  rose: "border-signal-rose/25 bg-signal-rose/[0.08] text-signal-rose",
  mint: "border-signal-mint/25 bg-signal-mint/[0.08] text-signal-mint",
  slate: "border-white/[0.07] bg-ink-900/70 text-slate-400",
};

export function Badge({
  children,
  tone = "neutral",
  className,
  dot = false,
}: {
  children: ReactNode;
  tone?: Tone;
  className?: string;
  dot?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10.5px] font-semibold uppercase tracking-[0.08em]",
        toneStyles[tone],
        className,
      )}
    >
      {dot ? <span className="h-1.5 w-1.5 rounded-full bg-current" /> : null}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: string | null | undefined; className?: string }) {
  const value = (severity ?? "informational").toLowerCase();
  const tone: Tone =
    value === "critical" ? "rose" : value === "high" ? "amber" : value === "medium" ? "blue" : value === "low" ? "mint" : "slate";
  return (
    <Badge tone={tone} dot className={className}>
      {value}
    </Badge>
  );
}

export function StatusBadge({ status, className }: { status: string | null | undefined; className?: string }) {
  const value = (status ?? "unknown").toUpperCase();
  const tone: Tone =
    value === "OPEN" ? "amber" : value === "ACKNOWLEDGED" ? "blue" : value === "INVESTIGATING" ? "violet" : value === "CLOSED" ? "mint" : value === "FALSE_POSITIVE" ? "slate" : value === "COMPLETE" || value === "READY" ? "mint" : value === "RUNNING" ? "accent" : value === "FAILED" ? "rose" : "slate";
  return (
    <Badge tone={tone} className={className}>
      {value.replace(/_/g, " ")}
    </Badge>
  );
}

const confidenceLabels: Record<string, { label: string; tone: Tone; hint: string }> = {
  calibrated_probability: {
    label: "Calibrated probability",
    tone: "mint",
    hint: "A probability produced by a calibrated classifier on the labelled synthetic evaluation split.",
  },
  hybrid_score: {
    label: "Hybrid score",
    tone: "blue",
    hint: "Rule evidence blended with a model score. Not a calibrated probability.",
  },
  heuristic_score: {
    label: "Heuristic score",
    tone: "amber",
    hint: "Deterministic rule strength. Not a calibrated probability.",
  },
  anomaly_score: {
    label: "Anomaly score",
    tone: "violet",
    hint: "Isolation Forest anomaly strength. Not a probability of compromise.",
  },
};

export function ConfidenceBadge({
  type,
  value,
  className,
}: {
  type: string | null | undefined;
  value?: number | null;
  className?: string;
}) {
  const meta = confidenceLabels[type ?? ""] ?? {
    label: titleCase(type ?? "score"),
    tone: "slate" as Tone,
    hint: "Score semantics are shown on the AI & models page.",
  };
  return (
    <span className={cn("inline-flex items-center gap-2", className)} title={meta.hint}>
      <span className="font-mono text-[12px] tabular-nums text-slate-200">
        {value === null || value === undefined ? "—" : value.toFixed(3)}
      </span>
      <Badge tone={meta.tone}>{meta.label}</Badge>
    </span>
  );
}

export function Spinner({ className, label = "Loading" }: { className?: string; label?: string }) {
  return (
    <span role="status" aria-label={label} className={cn("inline-flex items-center text-slate-400", className)}>
      <Loader2 className="h-4 w-4 animate-spin" />
    </span>
  );
}

export function PageLoader({ label = "Loading workspace data" }: { label?: string }) {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center gap-3 text-slate-500">
      <div className="relative h-10 w-10">
        <div className="absolute inset-0 rounded-full border border-accent/20" />
        <div className="absolute inset-0 animate-spin rounded-full border border-transparent border-t-accent/80" />
      </div>
      <p className="text-[12px]">{label}</p>
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("shimmer rounded-lg bg-white/[0.04]", className)} />;
}

export function EmptyState({
  title,
  description,
  icon,
  action,
  compact = false,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-xl border border-dashed border-white/[0.09] bg-ink-900/40 px-6 text-center",
        compact ? "py-8" : "py-14",
      )}
    >
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-slate-500">
        {icon ?? <Info className="h-4 w-4" />}
      </div>
      <p className="text-[13px] font-medium text-slate-300">{title}</p>
      {description ? <p className="mt-1.5 max-w-md text-[12px] leading-relaxed text-slate-500">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-signal-rose/20 bg-signal-rose/[0.04] px-6 py-12 text-center">
      <AlertTriangle className="mb-3 h-5 w-5 text-signal-rose" />
      <p className="text-[13px] font-medium text-slate-200">Could not load this view</p>
      <p className="mt-1.5 max-w-md text-[12px] leading-relaxed text-slate-400">{message}</p>
      {retry ? (
        <button type="button" className="btn-secondary mt-4" onClick={retry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function InfoHint({ text, label = "More information" }: { text: string; label?: string }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        aria-label={label}
        aria-describedby={open ? id : undefined}
        className="flex h-5 w-5 items-center justify-center rounded-full text-slate-500 transition-colors hover:text-slate-300 focus-visible:text-slate-200"
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={() => setOpen((value) => !value)}
      >
        <HelpCircle className="h-3.5 w-3.5" />
      </button>
      <AnimatePresence>
        {open ? (
          <motion.span
            id={id}
            role="tooltip"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            transition={{ duration: 0.14 }}
            className="absolute bottom-full left-1/2 z-40 mb-2 w-64 -translate-x-1/2 rounded-lg border border-white/10 bg-ink-700 px-3 py-2 text-left text-[11.5px] font-normal leading-relaxed text-slate-300 shadow-xl"
          >
            {text}
          </motion.span>
        ) : null}
      </AnimatePresence>
    </span>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: { value: T; label: string; count?: number }[];
  value: T;
  onChange: (value: T) => void;
  className?: string;
}) {
  return (
    <div role="tablist" className={cn("flex flex-wrap items-center gap-1 rounded-lg border border-white/[0.07] bg-ink-900/60 p-1", className)}>
      {tabs.map((tab) => {
        const active = tab.value === value;
        return (
          <button
            key={tab.value}
            role="tab"
            type="button"
            aria-selected={active}
            onClick={() => onChange(tab.value)}
            className={cn(
              "relative rounded-md px-3 py-1.5 text-[12px] font-medium transition-colors",
              active ? "bg-white/[0.08] text-slate-100" : "text-slate-400 hover:text-slate-200",
            )}
          >
            {tab.label}
            {tab.count !== undefined ? (
              <span className={cn("ml-2 font-mono text-[10.5px]", active ? "text-accent" : "text-slate-500")}>{tab.count}</span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors disabled:opacity-40",
        checked ? "border-accent/50 bg-accent/30" : "border-white/10 bg-white/[0.06]",
      )}
    >
      <span
        className={cn(
          "inline-block h-3.5 w-3.5 rounded-full transition-transform",
          checked ? "translate-x-[18px] bg-accent-soft" : "translate-x-[3px] bg-slate-400",
        )}
      />
    </button>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[11px] text-slate-400 transition-colors hover:text-slate-200"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? <Check className="h-3 w-3 text-signal-mint" /> : <Copy className="h-3 w-3" />}
      {copied ? "Copied" : label}
    </button>
  );
}

const ModalContext = createContext<{ close: () => void }>({ close: () => undefined });

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = "max-w-lg",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const timer = setTimeout(() => {
      const focusable = panelRef.current?.querySelector<HTMLElement>(
        "input, select, textarea, button, [href], [tabindex]:not([tabindex='-1'])",
      );
      focusable?.focus();
    }, 30);
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      clearTimeout(timer);
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      previous?.focus();
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open ? (
        <ModalContext.Provider value={{ close: onClose }}>
          <motion.div
            className="fixed inset-0 z-[100] flex items-center justify-center p-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="absolute inset-0 bg-ink-950/80 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
            <motion.div
              ref={panelRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="modal-title"
              initial={{ opacity: 0, y: 14, scale: 0.985 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.99 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
              className={cn("relative w-full rounded-2xl border border-white/10 bg-ink-800 shadow-2xl", width)}
            >
              <div className="flex items-start justify-between gap-4 border-b border-white/[0.07] px-5 py-4">
                <div>
                  <h2 id="modal-title" className="text-[14px] font-semibold text-slate-100">
                    {title}
                  </h2>
                  {description ? <p className="mt-1 text-[12px] text-slate-400">{description}</p> : null}
                </div>
                <button type="button" onClick={onClose} aria-label="Close dialog" className="btn-ghost -mr-1 -mt-1 px-2 py-1.5">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="max-h-[70vh] overflow-y-auto px-5 py-4">{children}</div>
              {footer ? <div className="flex justify-end gap-2 border-t border-white/[0.07] px-5 py-3.5">{footer}</div> : null}
            </motion.div>
          </motion.div>
        </ModalContext.Provider>
      ) : null}
    </AnimatePresence>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone = "default",
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "default" | "danger" | "accent";
  icon?: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-ink-900/50 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <p className="label">{label}</p>
        {icon ? <span className="text-slate-500">{icon}</span> : null}
      </div>
      <p
        className={cn(
          "mt-2 font-mono text-[18px] font-medium tracking-tight tabular-nums",
          tone === "danger" ? "text-signal-rose" : tone === "accent" ? "text-accent-soft" : "text-slate-100",
        )}
      >
        {value}
      </p>
      {hint ? <p className="mt-1 text-[11px] leading-relaxed text-slate-500">{hint}</p> : null}
    </div>
  );
}

export function ConfidenceLegend({ className }: { className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      {Object.entries(confidenceLabels).map(([key, meta]) => (
        <span key={key} className="inline-flex items-center gap-1.5 text-[10.5px] text-slate-500" title={meta.hint}>
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              meta.tone === "mint" ? "bg-signal-mint" : meta.tone === "blue" ? "bg-signal-blue" : meta.tone === "amber" ? "bg-signal-amber" : "bg-signal-violet",
            )}
          />
          {meta.label}
        </span>
      ))}
    </div>
  );
}

export function SeverityIcon({ severity }: { severity: string | null | undefined }) {
  const value = (severity ?? "").toLowerCase();
  if (severityRank(value) <= 1) return <ShieldAlert className="h-3.5 w-3.5" />;
  if (value === "medium") return <AlertTriangle className="h-3.5 w-3.5" />;
  return <CheckCircle2 className="h-3.5 w-3.5" />;
}

export function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className="inline-flex items-center gap-1 text-[12px] text-signal-blue hover:underline"
    >
      {children}
      <ChevronRight className="h-3 w-3" />
    </a>
  );
}
