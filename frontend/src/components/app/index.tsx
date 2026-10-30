import type { EChartsOption } from "echarts";
import { ArrowDownRight, ArrowRight, ArrowUpRight, Inbox, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { EChart } from "@/components/charts/EChart";
import {
  Badge,
  EmptyState,
  InfoHint,
  Panel,
  SeverityBadge,
  Skeleton,
  StatusBadge,
} from "@/components/ui";
import { cn, formatDateTime, formatNumber, relativeTime, titleCase } from "@/lib/format";
import type { AlertSummary, Kpi } from "@/lib/types";

function formatKpiValue(kpi: Kpi): string {
  if (kpi.value === null || kpi.value === undefined) return "—";
  const value = kpi.value;
  switch (kpi.unit) {
    case "Mbps":
      return value >= 1000 ? `${(value / 1000).toFixed(2)} Gbps` : `${value.toFixed(2)} Mbps`;
    case "pps":
      return value >= 1_000_000
        ? `${(value / 1_000_000).toFixed(2)} Mpps`
        : value >= 1000
          ? `${(value / 1000).toFixed(1)} Kpps`
          : `${value.toFixed(1)} pps`;
    case "ms":
      return `${value.toFixed(1)} ms`;
    case "0–1":
      return value.toFixed(3);
    case "flows/s":
      return value.toFixed(2);
    default:
      return formatNumber(value, kpi.unit === "Mbps" ? 2 : 0);
  }
}

export function KpiCard({ kpi, className }: { kpi: Kpi; className?: string }) {
  const comparison = kpi.comparison;
  const DirectionIcon =
    !comparison || comparison.direction === "flat"
      ? ArrowRight
      : comparison.direction === "up"
        ? ArrowUpRight
        : ArrowDownRight;
  return (
    <div
      className={cn(
        "group relative flex flex-col rounded-xl border border-white/[0.06] bg-ink-900/55 px-4 py-3.5 transition-colors hover:border-white/[0.1]",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="label leading-tight">{kpi.label}</p>
        <InfoHint text={kpi.help} label={`About ${kpi.label}`} />
      </div>
      <p className="mt-2.5 font-mono text-[21px] font-medium leading-none tracking-tight text-slate-100 tabular-nums">
        {formatKpiValue(kpi)}
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[10.5px]">
        {kpi.value !== null && kpi.value !== undefined ? <span className="text-slate-500">{kpi.unit}</span> : null}
        {comparison ? (
          <span
            className={cn(
              "inline-flex items-center gap-0.5 font-mono tabular-nums",
              comparison.direction === "flat" ? "text-slate-500" : "text-slate-400",
            )}
            title="Change versus the immediately preceding period of equal length"
          >
            <DirectionIcon className="h-3 w-3" />
            {Math.abs(comparison.value).toFixed(1)}%
          </span>
        ) : (
          <span className="text-slate-600" title="No comparable preceding period is fully covered by stored telemetry">
            no comparison
          </span>
        )}
      </div>
      {kpi.note ? (
        <p className="mt-1.5 line-clamp-2 text-[10px] leading-relaxed text-slate-600">{kpi.note}</p>
      ) : null}
      {kpi.updated_at ? (
        <p className="mt-auto pt-2 font-mono text-[9.5px] text-slate-700" title={formatDateTime(kpi.updated_at)}>
          {relativeTime(kpi.updated_at)}
        </p>
      ) : null}
    </div>
  );
}

export function ChartPanel({
  title,
  subtitle,
  option,
  height = 240,
  actions,
  empty,
  className,
  ariaLabel,
}: {
  title: string;
  subtitle?: string;
  option: EChartsOption;
  height?: number;
  actions?: ReactNode;
  empty?: boolean;
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <Panel className={cn("p-4 sm:p-5", className)}>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-[13px] font-semibold tracking-tight text-slate-200">{title}</h3>
          {subtitle ? <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">{subtitle}</p> : null}
        </div>
        {actions}
      </div>
      {empty ? (
        <EmptyState compact title="No observations in this window" description="Charts only render stored telemetry. Adjust the range or ingest a capture to populate this view." icon={<Inbox className="h-4 w-4" />} />
      ) : (
        <EChart option={option} height={height} ariaLabel={ariaLabel ?? title} />
      )}
    </Panel>
  );
}

export function MetricTile({
  label,
  value,
  hint,
  tone = "default",
  icon: Icon,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "default" | "danger" | "accent" | "warning";
  icon?: LucideIcon;
}) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-ink-900/50 px-3.5 py-3">
      <div className="flex items-center justify-between gap-2">
        <p className="label">{label}</p>
        {Icon ? <Icon className="h-3.5 w-3.5 text-slate-600" /> : null}
      </div>
      <p
        className={cn(
          "mt-1.5 font-mono text-[17px] font-medium tabular-nums",
          tone === "danger"
            ? "text-signal-rose"
            : tone === "warning"
              ? "text-signal-amber"
              : tone === "accent"
                ? "text-accent-soft"
                : "text-slate-100",
        )}
      >
        {value}
      </p>
      {hint ? <p className="mt-0.5 text-[10.5px] leading-relaxed text-slate-600">{hint}</p> : null}
    </div>
  );
}

export function AlertTable({
  alerts,
  loading = false,
  emptyDescription = "No alerts match the current filters and time window.",
  selectedIds,
  onToggle,
}: {
  alerts: AlertSummary[];
  loading?: boolean;
  emptyDescription?: string;
  selectedIds?: number[];
  onToggle?: (id: number) => void;
}) {
  if (loading) {
    return (
      <div className="space-y-2 p-4">
        {Array.from({ length: 5 }).map((_, index) => (
          <Skeleton key={index} className="h-12 w-full" />
        ))}
      </div>
    );
  }
  if (!alerts.length) {
    return <EmptyState title="No alerts" description={emptyDescription} icon={<Inbox className="h-4 w-4" />} compact />;
  }
  return (
    <div className="overflow-x-auto">
      <table className="table-base min-w-[900px]">
        <thead>
          <tr>
            {onToggle ? <th className="w-8" aria-label="Select" /> : null}
            <th>Alert</th>
            <th>Threat class</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Path</th>
            <th>Detector</th>
            <th>First seen</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const checked = selectedIds?.includes(alert.id) ?? false;
            return (
              <tr key={alert.id} className="group">
                {onToggle ? (
                  <td className="pr-0">
                    <input
                      type="checkbox"
                      aria-label={`Select ${alert.alert_code}`}
                      checked={checked}
                      onChange={() => onToggle(alert.id)}
                      className="h-3.5 w-3.5 rounded border-white/20 bg-transparent accent-[#36D9D0]"
                    />
                  </td>
                ) : null}
                <td>
                  <Link
                    to={`/app/alerts/${alert.id}`}
                    className="font-mono text-[11.5px] text-accent-soft hover:underline"
                  >
                    {alert.alert_code}
                  </Link>
                  <p className="mt-0.5 max-w-[240px] truncate text-[10.5px] text-slate-600" title={alert.summary}>
                    {alert.summary}
                  </p>
                </td>
                <td>
                  <span className="text-[12px] text-slate-300">{titleCase(alert.threat_class)}</span>
                  <p className="mt-0.5 text-[10px] text-slate-600">
                    {alert.recurrence > 0 ? `recurrence ${alert.recurrence}` : `${alert.flow_count} flows`}
                  </p>
                </td>
                <td>
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td>
                  <span className="font-mono text-[11.5px] tabular-nums text-slate-300">{alert.confidence.toFixed(3)}</span>
                  <p className="mt-0.5 text-[9.5px] uppercase tracking-[0.06em] text-slate-600">
                    {alert.confidence_type.replace(/_/g, " ")}
                  </p>
                </td>
                <td>
                  <span className="font-mono text-[11px] text-slate-300">
                    {alert.source_ip}
                    <span className="text-slate-600">:{alert.source_port || "—"}</span>
                  </span>
                  <p className="font-mono text-[10.5px] text-slate-500">
                    → {alert.dest_ip}
                    <span className="text-slate-600">:{alert.dest_port || "—"}</span>
                  </p>
                </td>
                <td>
                  <Badge tone="slate">{alert.detector_code.replace(/_/g, " ").replace("detector", "").trim()}</Badge>
                  <p className="mt-0.5 text-[9.5px] uppercase tracking-[0.06em] text-slate-600">{alert.data_source}</p>
                </td>
                <td>
                  <span className="text-[11px] text-slate-400" title={formatDateTime(alert.first_seen)}>
                    {relativeTime(alert.first_seen)}
                  </span>
                  <p className="font-mono text-[9.5px] text-slate-600">{formatDateTime(alert.first_seen)}Z</p>
                </td>
                <td>
                  <StatusBadge status={alert.status} />
                  {alert.assignee ? (
                    <p className="mt-1 max-w-[100px] truncate text-[10px] text-slate-600">{alert.assignee}</p>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onChange: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total === 0) return null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] px-4 py-3 text-[11px] text-slate-500">
      <span className="font-mono">
        {formatNumber((page - 1) * pageSize + 1)}–{formatNumber(Math.min(page * pageSize, total))} of {formatNumber(total)}
      </span>
      <div className="flex items-center gap-1.5">
        <button type="button" className="btn-ghost px-2 py-1" disabled={page <= 1} onClick={() => onChange(page - 1)}>
          Previous
        </button>
        <span className="font-mono text-slate-400">
          {page} / {pages}
        </span>
        <button
          type="button"
          className="btn-ghost px-2 py-1"
          disabled={page >= pages}
          onClick={() => onChange(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}

export function SummaryStrip({
  items,
}: {
  items: { label: string; value: ReactNode; tone?: "default" | "danger" | "accent" }[];
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border border-white/[0.06] bg-ink-900/40 px-4 py-2.5">
      {items.map((item) => (
        <div key={item.label} className="flex items-baseline gap-2">
          <span className="label">{item.label}</span>
          <span
            className={cn(
              "font-mono text-[13px] tabular-nums",
              item.tone === "danger"
                ? "text-signal-rose"
                : item.tone === "accent"
                  ? "text-accent-soft"
                  : "text-slate-200",
            )}
          >
            {item.value}
          </span>
        </div>
      ))}
    </div>
  );
}
