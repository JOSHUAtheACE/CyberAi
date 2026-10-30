import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCheck,
  Filter,
  Inbox,
  Layers,
  RefreshCw,
  Search,
  ShieldAlert,
  UserCheck,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTable, Pagination, SummaryStrip } from "@/components/app";
import {
  Badge,
  EmptyState,
  ErrorState,
  InfoHint,
  Panel,
  PageHeader,
  SectionTitle,
  Spinner,
} from "@/components/ui";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { cn, formatNumber, titleCase } from "@/lib/format";
import type { AlertMeta, AlertsListResponse } from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const STATUSES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"];
const SORTS = [
  { value: "first_seen", label: "First seen" },
  { value: "last_seen", label: "Last seen" },
  { value: "confidence", label: "Confidence" },
  { value: "severity", label: "Severity" },
];

function splitParam(value: string | null): string[] {
  return (value ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex min-w-[130px] flex-1 flex-col gap-1">
      <span className="label">{label}</span>
      <select className="field py-1.5" value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">All</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function FacetChip({
  label,
  count,
  active,
  tone,
  onClick,
}: {
  label: string;
  count?: number;
  active: boolean;
  tone?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[10.5px] font-medium transition-colors",
        active
          ? "border-accent/45 bg-accent/[0.1] text-accent-soft"
          : "border-white/[0.08] bg-white/[0.02] text-slate-400 hover:border-white/[0.16] hover:text-slate-200",
      )}
    >
      {tone ? <span className={cn("h-1.5 w-1.5 rounded-full", tone)} /> : null}
      {label}
      {count !== undefined ? <span className="font-mono text-[9.5px] text-slate-500">{formatNumber(count)}</span> : null}
    </button>
  );
}

export function Alerts() {
  const { hasPermission, session } = useAuth();
  const { workspaceSlug, range, environment } = useWorkspace();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [selected, setSelected] = useState<number[]>([]);

  const q = params.get("q") ?? "";
  const severity = splitParam(params.get("severity"));
  const status = splitParam(params.get("status"));
  const threatClass = params.get("threat_class") ?? "";
  const detector = params.get("detector") ?? "";
  const assignee = params.get("assignee") ?? "";
  const sort = params.get("sort") ?? "first_seen";
  const page = Math.max(1, Number(params.get("page") ?? "1"));

  const canInvestigate = hasPermission("alerts.investigate");
  const canAssign = hasPermission("alerts.assign");

  const update = (patch: Record<string, string | null>, resetPage = true) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(patch)) {
      if (!value) next.delete(key);
      else next.set(key, value);
    }
    if (resetPage) next.delete("page");
    setParams(next, { replace: true });
  };

  useEffect(() => {
    if (search === q) return;
    const timer = setTimeout(() => update({ q: search || null }), 350);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const meta = useQuery({
    queryKey: ["alerts-meta"],
    queryFn: () => api.get<AlertMeta>("/alerts/meta"),
    staleTime: 60_000,
  });

  const alerts = useQuery({
    queryKey: ["alerts", workspaceSlug, range, q, severity.join(","), status.join(","), threatClass, detector, assignee, sort, page],
    queryFn: () =>
      api.get<AlertsListResponse>("/alerts", {
        workspace: workspaceSlug,
        range,
        q: q || undefined,
        severity: severity.length ? severity.join(",") : undefined,
        status: status.length ? status.join(",") : undefined,
        threat_class: threatClass || undefined,
        detector: detector || undefined,
        assignee: assignee || undefined,
        sort,
        page,
        page_size: 25,
      }),
    refetchInterval: 30_000,
  });

  const toggleFacet = (key: "severity" | "status", value: string) => {
    const current = key === "severity" ? severity : status;
    const next = current.includes(value) ? current.filter((item) => item !== value) : [...current, value];
    update({ [key]: next.length ? next.join(",") : null });
  };

  const bulk = useMutation({
    mutationFn: (action: { type: "acknowledge" | "assign" | "close"; assigneeId?: number }) =>
      api.post<{ updated: number; requested: number }>("/alerts/bulk", {
        ids: selected,
        action: action.type,
        assignee_id: action.assigneeId,
      }),
    onSuccess: (result, variables) => {
      toast("success", `${formatNumber(result.updated)} alerts updated`, `Bulk ${variables.type} applied to the selected alerts.`);
      setSelected([]);
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["overview"] });
    },
    onError: (error) => toast("error", "Bulk action failed", error instanceof Error ? error.message : "Try again."),
  });

  const facets = alerts.data?.facets;
  const severityCounts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const item of facets?.severities ?? []) map[item.value] = item.count;
    return map;
  }, [facets?.severities]);
  const statusCounts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const item of facets?.statuses ?? []) map[item.value] = item.count;
    return map;
  }, [facets?.statuses]);

  const activeFilters = [
    ...severity.map((value) => ({ key: "severity" as const, value, label: titleCase(value) })),
    ...status.map((value) => ({ key: "status" as const, value, label: titleCase(value) })),
    ...(threatClass ? [{ key: "threat_class" as const, value: threatClass, label: titleCase(threatClass) }] : []),
    ...(detector ? [{ key: "detector" as const, value: detector, label: detector.replace(/_/g, " ") }] : []),
    ...(assignee ? [{ key: "assignee" as const, value: assignee, label: assignee === "me" ? "Assigned to me" : assignee === "unassigned" ? "Unassigned" : "Assignee" }] : []),
    ...(q ? [{ key: "q" as const, value: q, label: `“${q}”` }] : []),
  ];

  const selectedToggle = (id: number) =>
    setSelected((state) => (state.includes(id) ? state.filter((item) => item !== id) : [...state, id]));

  const detectionsNote =
    "Duplicate observations are collapsed server-side into a single alert with a recurrence counter. Alerts are grouped by detector, threat class and the source/destination relationship so one campaign does not flood the queue.";

  return (
    <div>
      <PageHeader
        eyebrow="Alert centre"
        title="Evidence-backed alerts"
        description="Every alert is derived from stored flows and carries the detector, score semantics, evidence features and a path to the underlying records. Severity expresses potential impact; confidence expresses detector certainty for that evidence."
        actions={
          <>
            <Badge tone={environment === "LIVE" ? "mint" : environment === "DEMO" ? "amber" : "blue"} dot>
              {environment}
            </Badge>
            <Badge tone="slate">No active remediation</Badge>
          </>
        }
      />

      <SummaryStrip
        items={[
          { label: "Matching", value: formatNumber(alerts.data?.total ?? 0) },
          { label: "Critical", value: formatNumber(severityCounts.critical ?? 0), tone: "danger" },
          { label: "High", value: formatNumber(severityCounts.high ?? 0) },
          { label: "Open", value: formatNumber(statusCounts.OPEN ?? 0), tone: "accent" },
          { label: "Investigating", value: formatNumber(statusCounts.INVESTIGATING ?? 0) },
          { label: "False positive", value: formatNumber(statusCounts.FALSE_POSITIVE ?? 0) },
        ]}
      />

      <Panel className="mt-5 p-4 sm:p-5">
        <SectionTitle
          eyebrow="Filter"
          title="Narrow the queue"
          subtitle={`Window: ${alerts.data?.period.label ?? range}. Counts on the chips reflect the whole window, not only the current filter.`}
          actions={
            <button type="button" className="btn-secondary" onClick={() => void alerts.refetch()} disabled={alerts.isFetching}>
              {alerts.isFetching ? <Spinner className="h-3.5 w-3.5" /> : <RefreshCw className="h-3.5 w-3.5" />} Refresh
            </button>
          }
        />
        <div className="mt-4 flex flex-wrap items-end gap-2.5">
          <label className="flex min-w-[220px] flex-1 flex-col gap-1">
            <span className="label">Search</span>
            <span className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
              <input
                className="field py-1.5 pl-8"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Alert code, IP, threat class or summary"
                maxLength={120}
              />
              {search ? (
                <button
                  type="button"
                  aria-label="Clear search"
                  onClick={() => setSearch("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              ) : null}
            </span>
          </label>
          <FilterSelect
            label="Threat class"
            value={threatClass}
            onChange={(value) => update({ threat_class: value || null })}
            options={(facets?.threat_classes ?? []).map((item) => ({ value: item.value, label: `${titleCase(item.value)} · ${formatNumber(item.count)}` }))}
          />
          <FilterSelect
            label="Detector"
            value={detector}
            onChange={(value) => update({ detector: value || null })}
            options={(facets?.detectors ?? []).map((item) => ({ value: item.value, label: `${item.value.replace(/_/g, " ")} · ${formatNumber(item.count)}` }))}
          />
          <FilterSelect
            label="Assignee"
            value={assignee}
            onChange={(value) => update({ assignee: value || null })}
            options={[
              { value: "me", label: "Assigned to me" },
              { value: "unassigned", label: "Unassigned" },
              ...(meta.data?.assignees ?? []).map((item) => ({ value: String(item.id), label: item.name })),
            ]}
          />
          <FilterSelect
            label="Sort"
            value={sort}
            onChange={(value) => update({ sort: value === "first_seen" ? null : value })}
            options={SORTS}
          />
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-white/[0.05] pt-3">
          <span className="label mr-1 flex items-center gap-1">
            <Filter className="h-3 w-3" /> Severity
          </span>
          {SEVERITIES.map((value) => (
            <FacetChip
              key={value}
              label={titleCase(value)}
              count={severityCounts[value] ?? 0}
              active={severity.includes(value)}
              tone={
                value === "critical" ? "bg-signal-rose" : value === "high" ? "bg-signal-amber" : value === "medium" ? "bg-signal-blue" : value === "low" ? "bg-signal-mint" : "bg-slate-500"
              }
              onClick={() => toggleFacet("severity", value)}
            />
          ))}
          <span className="mx-1.5 h-4 w-px bg-white/10" />
          <span className="label mr-1">Status</span>
          {STATUSES.map((value) => (
            <FacetChip
              key={value}
              label={titleCase(value)}
              count={statusCounts[value] ?? 0}
              active={status.includes(value)}
              onClick={() => toggleFacet("status", value)}
            />
          ))}
          {activeFilters.length ? (
            <button
              type="button"
              className="ml-auto text-[10.5px] text-slate-500 hover:text-slate-300"
              onClick={() => {
                setSearch("");
                setParams(new URLSearchParams(), { replace: true });
              }}
            >
              Clear all filters
            </button>
          ) : null}
        </div>

        {activeFilters.length ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {activeFilters.map((item) => (
              <span key={`${item.key}-${item.value}`} className="inline-flex items-center gap-1 rounded border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.5 text-[10px] text-slate-400">
                {item.label}
                <button
                  type="button"
                  aria-label={`Remove ${item.label}`}
                  onClick={() => {
                    if (item.key === "q") setSearch("");
                    else if (item.key === "severity" || item.key === "status") toggleFacet(item.key, item.value);
                    else update({ [item.key]: null });
                  }}
                  className="text-slate-600 hover:text-slate-300"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
          </div>
        ) : null}
      </Panel>

      {selected.length && canInvestigate ? (
        <div className="mt-4 flex flex-wrap items-center gap-2 rounded-xl border border-accent/20 bg-accent/[0.04] px-3.5 py-2.5">
          <span className="text-[11.5px] text-slate-300">
            <span className="font-mono text-accent-soft">{selected.length}</span> selected
          </span>
          <button type="button" className="btn-secondary px-2.5 py-1 text-[11px]" onClick={() => bulk.mutate({ type: "acknowledge" })} disabled={bulk.isPending}>
            <CheckCheck className="h-3 w-3" /> Acknowledge
          </button>
          {canAssign && session ? (
            <button
              type="button"
              className="btn-secondary px-2.5 py-1 text-[11px]"
              onClick={() => bulk.mutate({ type: "assign", assigneeId: session.user.id })}
              disabled={bulk.isPending}
            >
              <UserCheck className="h-3 w-3" /> Assign to me
            </button>
          ) : null}
          <button type="button" className="btn-secondary px-2.5 py-1 text-[11px]" onClick={() => bulk.mutate({ type: "close" })} disabled={bulk.isPending}>
            Close
          </button>
          <button type="button" className="btn-ghost ml-auto px-2 py-1 text-[11px]" onClick={() => setSelected([])}>
            Clear selection
          </button>
        </div>
      ) : null}

      <Panel className="mt-4 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3">
          <div className="flex items-center gap-2">
            <h3 className="text-[12.5px] font-semibold text-slate-200">Alerts</h3>
            <span className="font-mono text-[10.5px] text-slate-500">{formatNumber(alerts.data?.total ?? 0)} in window</span>
          </div>
          <span className="flex items-center gap-1 text-[10px] text-slate-600">
            <Layers className="h-3 w-3" /> Deduplicated with recurrence counters
            <InfoHint text={detectionsNote} label="About alert deduplication" />
          </span>
        </div>
        {alerts.isError ? (
          <div className="p-4">
            <ErrorState message={alerts.error instanceof Error ? alerts.error.message : "Alerts could not be loaded."} retry={() => void alerts.refetch()} />
          </div>
        ) : (
          <>
            <AlertTable
              alerts={alerts.data?.items ?? []}
              loading={alerts.isLoading}
              selectedIds={selected}
              onToggle={canInvestigate ? selectedToggle : undefined}
              emptyDescription={`No alerts in ${alerts.data?.period.label ?? range} for this workspace. Detection runs server-side; an empty queue can also mean the detectors found nothing above their thresholds.`}
            />
            <Pagination
              page={alerts.data?.page ?? page}
              pageSize={alerts.data?.page_size ?? 25}
              total={alerts.data?.total ?? 0}
              onChange={(next) => update({ page: String(next) }, false)}
            />
          </>
        )}
      </Panel>

      {!alerts.isLoading && !alerts.data?.total && activeFilters.length ? (
        <div className="mt-4">
          <EmptyState
            compact
            title="No alerts match these filters"
            description="Remove a filter or widen the time range. Filters never fabricate results: the table reflects exactly what is stored."
            icon={<Inbox className="h-4 w-4" />}
            action={
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  setSearch("");
                  setParams(new URLSearchParams(), { replace: true });
                }}
              >
                Reset filters
              </button>
            }
          />
        </div>
      ) : null}

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <div className="flex items-start gap-2 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2.5 text-[10.5px] leading-relaxed text-slate-600">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
          <span>
            SENTINEL AI is passive and read-only with respect to monitored infrastructure. Investigation actions — acknowledge,
            assign, notes, status, false positive and export — update records inside the platform only. Nothing is blocked,
            isolated or reconfigured.
          </span>
        </div>
        <div className="flex items-start gap-2 rounded-lg border border-white/[0.06] bg-ink-900/30 px-3.5 py-2.5 text-[10.5px] leading-relaxed text-slate-600">
          <Layers className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
          <span>
            A false-positive decision is retained with its author and timestamp for audit. It changes the investigation status
            only; the underlying flows and evidence remain visible.
          </span>
        </div>
      </div>
    </div>
  );
}
