import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, FileText, Fingerprint, Mails, Network, Search, ShieldAlert, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { cn } from "@/lib/format";

interface SearchResult {
  type: string;
  id: number;
  title: string;
  subtitle: string;
  href: string;
}

const typeMeta: Record<string, { icon: typeof Search; tone: string; label: string }> = {
  alert: { icon: ShieldAlert, tone: "text-signal-rose", label: "Alert" },
  flow: { icon: Network, tone: "text-signal-blue", label: "Flow" },
  ingestion: { icon: FileText, tone: "text-signal-amber", label: "Ingestion" },
  detector: { icon: Fingerprint, tone: "text-signal-violet", label: "Detector" },
  report: { icon: Mails, tone: "text-accent-soft", label: "Report" },
};

export function GlobalSearch({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setResults([]);
    setActive(0);
    setError(null);
    const timer = setTimeout(() => inputRef.current?.focus(), 60);
    return () => clearTimeout(timer);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const term = query.trim();
    if (term.length < 2) {
      setResults([]);
      setBusy(false);
      return;
    }
    let cancelled = false;
    setBusy(true);
    const timer = setTimeout(async () => {
      try {
        const data = await api.get<{ results: SearchResult[] }>("/search", { q: term });
        if (!cancelled) {
          setResults(data.results);
          setActive(0);
          setError(null);
        }
      } catch {
        if (!cancelled) setError("Search is temporarily unavailable.");
      } finally {
        if (!cancelled) setBusy(false);
      }
    }, 220);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query, open]);

  const grouped = useMemo(() => {
    const map = new Map<string, SearchResult[]>();
    results.forEach((result) => {
      const list = map.get(result.type) ?? [];
      list.push(result);
      map.set(result.type, list);
    });
    return Array.from(map.entries());
  }, [results]);

  const flat = useMemo(() => grouped.flatMap(([, items]) => items), [grouped]);

  const go = (result: SearchResult) => {
    onClose();
    navigate(result.href);
  };

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          className="fixed inset-0 z-[110] flex items-start justify-center px-4 pt-[10vh]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <div className="absolute inset-0 bg-ink-950/75 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Global search"
            initial={{ opacity: 0, y: -10, scale: 0.99 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.16 }}
            className="relative w-full max-w-xl overflow-hidden rounded-2xl border border-white/10 bg-ink-800 shadow-2xl"
            onKeyDown={(event) => {
              if (event.key === "Escape") onClose();
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setActive((value) => Math.min(flat.length - 1, value + 1));
              }
              if (event.key === "ArrowUp") {
                event.preventDefault();
                setActive((value) => Math.max(0, value - 1));
              }
              if (event.key === "Enter" && flat[active]) {
                event.preventDefault();
                go(flat[active]);
              }
            }}
          >
            <div className="flex items-center gap-3 border-b border-white/[0.07] px-4 py-3">
              <Search className="h-4 w-4 shrink-0 text-slate-500" />
              <input
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search alerts, flows, hosts, detectors, reports…"
                className="w-full bg-transparent text-[13px] text-slate-100 placeholder:text-slate-600 focus:outline-none"
                aria-label="Search query"
              />
              {busy ? <span className="h-3.5 w-3.5 animate-spin rounded-full border border-accent/30 border-t-accent" /> : null}
              <button type="button" onClick={onClose} aria-label="Close search" className="text-slate-500 hover:text-slate-300">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="max-h-[52vh] overflow-y-auto p-2">
              {query.trim().length < 2 ? (
                <p className="px-3 py-8 text-center text-[12px] text-slate-500">
                  Search by IP address, alert code, hostname, detector or report title.
                </p>
              ) : error ? (
                <p className="px-3 py-8 text-center text-[12px] text-signal-rose">{error}</p>
              ) : !busy && results.length === 0 ? (
                <p className="px-3 py-8 text-center text-[12px] text-slate-500">
                  No stored records match “{query.trim()}”. Results are limited to telemetry this workspace can see.
                </p>
              ) : (
                grouped.map(([type, items]) => {
                  const meta = typeMeta[type] ?? typeMeta.flow;
                  const Icon = meta.icon;
                  return (
                    <div key={type} className="mb-1">
                      <p className="px-3 pb-1 pt-2 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-slate-600">
                        {meta.label}
                      </p>
                      {items.map((result) => {
                        const index = flat.indexOf(result);
                        return (
                          <button
                            key={`${result.type}-${result.id}`}
                            type="button"
                            onClick={() => go(result)}
                            onMouseEnter={() => setActive(index)}
                            className={cn(
                              "flex w-full items-start gap-3 rounded-lg px-3 py-2 text-left transition-colors",
                              index === active ? "bg-white/[0.06]" : "hover:bg-white/[0.03]",
                            )}
                          >
                            <Icon className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", meta.tone)} />
                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-[12.5px] text-slate-200">{result.title}</span>
                              <span className="mt-0.5 block truncate font-mono text-[10.5px] text-slate-500">{result.subtitle}</span>
                            </span>
                            <ArrowRight className="mt-1 h-3 w-3 shrink-0 text-slate-600" />
                          </button>
                        );
                      })}
                    </div>
                  );
                })
              )}
            </div>
            <div className="flex items-center justify-between border-t border-white/[0.07] px-4 py-2 text-[10px] text-slate-600">
              <span className="flex items-center gap-3">
                <span><span className="kbd">↑</span> <span className="kbd">↓</span> navigate</span>
                <span><span className="kbd">↵</span> open</span>
              </span>
              <span><span className="kbd">esc</span> close</span>
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
