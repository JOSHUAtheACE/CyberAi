import type { EChartsOption } from "echarts";
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Inbox,
  type LucideIcon,
} from "lucide-react";
import { useId, type KeyboardEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { EChart } from "@/components/charts/EChart";
import { InfoHint, Panel } from "@/components/ui";
import { radarOption } from "@/lib/charts";
import { cn, formatNumber } from "@/lib/format";
import type { GeoResponse } from "@/lib/types";

export const TONES = {
  accent: "#36D9D0",
  blue: "#4BA3FF",
  violet: "#8B7CF6",
  amber: "#F5B84B",
  rose: "#FF5C7A",
  mint: "#3DDC97",
  slate: "#8497b0",
} as const;

export type Tone = keyof typeof TONES;

export const SEVERITY_TONE: Record<string, Tone> = {
  critical: "rose",
  high: "amber",
  medium: "blue",
  low: "mint",
  informational: "slate",
};

export function severityColor(severity: string | null | undefined): string {
  return TONES[SEVERITY_TONE[severity ?? ""] ?? "slate"];
}

export function MiniSparkline({
  data,
  color = TONES.accent,
  height = 34,
  className,
  filled = true,
}: {
  data: number[];
  color?: string;
  height?: number;
  className?: string;
  filled?: boolean;
}) {
  const gradientId = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  if (data.length < 2) return null;
  const width = 100;
  const top = 3;
  const bottom = height - 3;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min || 1;
  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * width;
    const y = bottom - ((value - min) / span) * (bottom - top);
    return [x, y] as const;
  });
  let path = `M ${points[0][0].toFixed(2)} ${points[0][1].toFixed(2)}`;
  for (let index = 1; index < points.length; index += 1) {
    const [px, py] = points[index - 1];
    const [x, y] = points[index];
    const mid = (px + x) / 2;
    path += ` C ${mid.toFixed(2)} ${py.toFixed(2)}, ${mid.toFixed(2)} ${y.toFixed(2)}, ${x.toFixed(2)} ${y.toFixed(2)}`;
  }
  const area = `${path} L ${width} ${height} L 0 ${height} Z`;
  const last = points[points.length - 1];

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      height={height}
      className={cn("w-full overflow-visible", className)}
      aria-hidden
    >
      <defs>
        <linearGradient id={`spark-${gradientId}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.32} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      {filled ? <path d={area} fill={`url(#spark-${gradientId})`} /> : null}
      <path
        d={path}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
      <circle
        cx={last[0]}
        cy={last[1]}
        r={2}
        fill={color}
        stroke="#0B1220"
        strokeWidth={0.8}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

function DeltaChip({
  value,
  polarity = "neutral",
}: {
  value: { value: number; direction: "up" | "down" | "flat" };
  polarity?: "higher_is_better" | "higher_is_worse" | "neutral";
}) {
  const Icon = value.direction === "up" ? ArrowUpRight : value.direction === "down" ? ArrowDownRight : ArrowRight;
  const good =
    polarity === "neutral"
      ? null
      : polarity === "higher_is_better"
        ? value.direction === "up"
        : value.direction === "down";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 rounded border px-1 py-px font-mono text-[9.5px] tabular-nums",
        value.direction === "flat"
          ? "border-white/[0.07] bg-white/[0.02] text-slate-500"
          : good === null
            ? "border-white/[0.09] bg-white/[0.03] text-slate-400"
            : good
              ? "border-signal-mint/20 bg-signal-mint/[0.07] text-signal-mint"
              : "border-signal-rose/20 bg-signal-rose/[0.07] text-signal-rose",
      )}
      title="Change versus the immediately preceding period of equal length"
    >
      <Icon className="h-2.5 w-2.5" />
      {Math.abs(value.value).toFixed(1)}%
    </span>
  );
}

export function SparkKpi({
  label,
  value,
  unit,
  icon: Icon,
  tone = "accent",
  delta,
  deltaPolarity = "neutral",
  help,
  spark,
  sparkColor,
  footnote,
  className,
  href,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  icon: LucideIcon;
  tone?: Tone;
  delta?: { value: number; direction: "up" | "down" | "flat" } | null;
  deltaPolarity?: "higher_is_better" | "higher_is_worse" | "neutral";
  help?: string;
  spark?: number[];
  sparkColor?: string;
  footnote?: string;
  className?: string;
  href?: string;
}) {
  const color = TONES[tone];
  const body = (
    <div
      className={cn(
        "group relative h-full overflow-hidden rounded-xl border border-white/[0.07] bg-ink-800/60 px-3.5 pb-2.5 pt-3 shadow-panel transition-colors hover:border-white/[0.13]",
        className,
      )}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute -right-7 -top-10 h-20 w-20 rounded-full opacity-[0.16] blur-2xl"
        style={{ background: color }}
      />
      <div className="flex items-start justify-between gap-2">
        <p className="label flex min-w-0 items-center gap-1 leading-tight">
          <span className="truncate">{label}</span>
          {help ? <InfoHint text={help} label={`About ${label}`} /> : null}
        </p>
        <span
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border"
          style={{ background: `${color}14`, borderColor: `${color}2b`, color }}
        >
          <Icon className="h-3.5 w-3.5" />
        </span>
      </div>
      <div className="mt-2 flex items-end gap-1.5">
        <p className="font-mono text-[21px] font-medium leading-none tracking-tight text-slate-100 tabular-nums">{value}</p>
        {unit ? <span className="pb-[1px] text-[10px] text-slate-500">{unit}</span> : null}
      </div>
      <div className="mt-1.5 flex h-4 items-center gap-1.5">
        {delta ? (
          <>
            <DeltaChip value={delta} polarity={deltaPolarity} />
            <span className="text-[9px] text-slate-600">vs prev</span>
          </>
        ) : null}
      </div>
      {spark && spark.length > 1 ? (
        <MiniSparkline data={spark} color={sparkColor ?? color} height={30} className="mt-1 -mx-1" />
      ) : (
        <div className="mt-1 h-[30px]" />
      )}
      {footnote ? <p className="mt-0.5 truncate text-[9px] text-slate-600">{footnote}</p> : null}
    </div>
  );
  return href ? (
    <Link to={href} className="block h-full">
      {body}
    </Link>
  ) : (
    body
  );
}

export function DonutCard({
  title,
  subtitle,
  items,
  colors,
  totalLabel = "total",
  valueFormatter = formatNumber,
  action,
  emptyLabel = "No records in this window",
  height = 136,
  legend = true,
  className,
}: {
  title: string;
  subtitle?: string;
  items: { name: string; value: number; color?: string }[];
  colors?: string[];
  totalLabel?: string;
  valueFormatter?: (value: number) => string;
  action?: ReactNode;
  emptyLabel?: string;
  height?: number;
  legend?: boolean;
  className?: string;
}) {
  const total = items.reduce((sum, item) => sum + item.value, 0);
  const palette = colors ?? [TONES.accent, TONES.blue, TONES.violet, TONES.amber, TONES.rose, TONES.mint];
  const option = {
    animationDuration: 460,
    tooltip: {
      trigger: "item",
      formatter: (params: unknown) => {
        const item = params as { name: string; value: number; percent: number };
        return `${item.name}<br/><strong>${valueFormatter(item.value)}</strong> · ${item.percent}%`;
      },
    },
    series: [
      {
        type: "pie",
        radius: ["66%", "88%"],
        center: ["50%", "50%"],
        padAngle: 2,
        itemStyle: { borderColor: "#0B1220", borderWidth: 2, borderRadius: 5 },
        label: { show: false },
        emphasis: { scale: true, scaleSize: 4 },
        data: items.map((item, index) => ({
          name: item.name,
          value: item.value,
          itemStyle: { color: item.color ?? palette[index % palette.length] },
        })),
      },
    ],
  } as EChartsOption;

  return (
    <Panel className={cn("flex h-full min-w-0 flex-col p-4", className)}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate text-[12.5px] font-semibold tracking-tight text-slate-200">{title}</h3>
          {subtitle ? <p className="mt-0.5 truncate text-[10px] text-slate-600">{subtitle}</p> : null}
        </div>
        {action}
      </div>
      {!total ? (
        <div className="mt-3 flex flex-1 flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed border-white/[0.07] py-6 text-center">
          <Inbox className="h-4 w-4 text-slate-600" />
          <p className="px-3 text-[10px] text-slate-600">{emptyLabel}</p>
        </div>
      ) : (
        <div className="mt-2 flex flex-1 flex-col items-center gap-3 sm:flex-row">
          <div className="relative shrink-0" style={{ width: height, height }}>
            <EChart option={option} height={height} ariaLabel={title} />
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-mono text-[19px] font-medium leading-none text-slate-100 tabular-nums">
                {valueFormatter(total)}
              </span>
              <span className="mt-1 text-[8.5px] uppercase tracking-[0.14em] text-slate-600">{totalLabel}</span>
            </div>
          </div>
          {legend ? (
            <ul className="min-w-0 flex-1 space-y-1.5">
              {items.map((item, index) => {
                const color = item.color ?? palette[index % palette.length];
                return (
                  <li key={item.name} className="flex items-center gap-1.5 text-[10.5px]">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}70` }} />
                    <span className="min-w-0 flex-1 truncate capitalize text-slate-400">{item.name}</span>
                    <span className="font-mono tabular-nums text-slate-300">{valueFormatter(item.value)}</span>
                    <span className="w-9 text-right font-mono text-[9.5px] tabular-nums text-slate-600">
                      {total ? `${((item.value / total) * 100).toFixed(0)}%` : "0%"}
                    </span>
                  </li>
                );
              })}
            </ul>
          ) : null}
        </div>
      )}
    </Panel>
  );
}

export function Ring({
  ratio,
  display,
  caption,
  color = TONES.accent,
  size = 78,
  thickness = 7,
  className,
}: {
  ratio: number;
  display: string;
  caption?: string;
  color?: string;
  size?: number;
  thickness?: number;
  className?: string;
}) {
  const safe = Math.max(0, Math.min(1, Number.isFinite(ratio) ? ratio : 0));
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const stroke = (thickness / size) * 100;
  return (
    <div className={cn("relative inline-flex shrink-0 items-center justify-center", className)} style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
        <circle cx="50" cy="50" r={radius} fill="none" stroke="rgba(148,163,184,0.11)" strokeWidth={stroke} />
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - safe)}
          style={{ transition: "stroke-dashoffset 700ms cubic-bezier(0.22,1,0.36,1)", filter: `drop-shadow(0 0 4px ${color}66)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-none">
        <span className="font-mono text-[15px] font-medium tabular-nums text-slate-100">{display}</span>
        {caption ? <span className="mt-1 text-[8px] uppercase tracking-[0.12em] text-slate-600">{caption}</span> : null}
      </div>
    </div>
  );
}

export function RadarCard({
  title,
  subtitle,
  indicators,
  series,
  height = 220,
  action,
  footer,
  empty,
  emptyLabel = "No scored records for a radar view",
  className,
}: {
  title: string;
  subtitle?: string;
  indicators: { name: string; max?: number }[];
  series: { name: string; values: number[]; color?: string }[];
  height?: number;
  action?: ReactNode;
  footer?: ReactNode;
  empty?: boolean;
  emptyLabel?: string;
  className?: string;
}) {
  return (
    <Panel className={cn("flex h-full min-w-0 flex-col p-4", className)}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate text-[12.5px] font-semibold tracking-tight text-slate-200">{title}</h3>
          {subtitle ? <p className="mt-0.5 truncate text-[10px] text-slate-600">{subtitle}</p> : null}
        </div>
        {action}
      </div>
      {empty || !series.length ? (
        <div className="mt-3 flex flex-1 flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed border-white/[0.07] py-10 text-center">
          <Inbox className="h-4 w-4 text-slate-600" />
          <p className="px-3 text-[10px] text-slate-600">{emptyLabel}</p>
        </div>
      ) : (
        <div className="mt-1 flex-1">
          <EChart option={radarOption({ indicators, series })} height={height} ariaLabel={title} />
        </div>
      )}
      {footer ? <div className="mt-1 border-t border-white/[0.05] pt-2">{footer}</div> : null}
    </Panel>
  );
}

export function RankList({
  title,
  subtitle,
  rows,
  tone = "accent",
  valueFormatter = formatNumber,
  maxValue,
  action,
  emptyLabel = "Nothing recorded in this window",
  className,
  icon: Icon,
}: {
  title: string;
  subtitle?: string;
  rows: { label: string; value: number; hint?: string; color?: string; href?: string; onClick?: () => void }[];
  tone?: Tone;
  valueFormatter?: (value: number) => string;
  maxValue?: number;
  action?: ReactNode;
  emptyLabel?: string;
  className?: string;
  icon?: LucideIcon;
}) {
  const max = maxValue ?? Math.max(1, ...rows.map((row) => row.value));
  return (
    <Panel className={cn("flex h-full min-w-0 flex-col p-4", className)}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="flex items-center gap-1.5 truncate text-[12.5px] font-semibold tracking-tight text-slate-200">
            {Icon ? <Icon className="h-3.5 w-3.5 text-slate-500" /> : null}
            {title}
          </h3>
          {subtitle ? <p className="mt-0.5 truncate text-[10px] text-slate-600">{subtitle}</p> : null}
        </div>
        {action}
      </div>
      {rows.length ? (
        <ol className="mt-3 flex-1 space-y-2.5">
          {rows.map((row, index) => {
            const color = row.color ?? TONES[tone];
            const pct = Math.max(2, (row.value / max) * 100);
            const content = (
              <>
                <div className="flex items-baseline gap-2">
                  <span className="w-4 shrink-0 font-mono text-[8.5px] text-slate-600">{String(index + 1).padStart(2, "0")}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-[10.5px] text-slate-300" title={row.label}>
                    {row.label}
                  </span>
                  {row.hint ? <span className="shrink-0 text-[9px] text-slate-600">{row.hint}</span> : null}
                  <span className="shrink-0 font-mono text-[10.5px] tabular-nums text-slate-400">{valueFormatter(row.value)}</span>
                </div>
                <div className="ml-6 mt-1 h-[3px] overflow-hidden rounded-full bg-white/[0.05]">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${pct}%`,
                      background: `linear-gradient(90deg, ${color}66, ${color})`,
                      boxShadow: `0 0 6px ${color}55`,
                    }}
                  />
                </div>
              </>
            );
            return (
              <li key={`${row.label}-${index}`} className="group">
                {row.href ? (
                  <Link to={row.href} className="block rounded transition-colors hover:bg-white/[0.02]">
                    {content}
                  </Link>
                ) : row.onClick ? (
                  <button
                    type="button"
                    onClick={row.onClick}
                    className="block w-full rounded text-left transition-colors hover:bg-white/[0.02]"
                  >
                    {content}
                  </button>
                ) : (
                  content
                )}
              </li>
            );
          })}
        </ol>
      ) : (
        <div className="mt-3 flex flex-1 flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed border-white/[0.07] py-8 text-center">
          <Inbox className="h-4 w-4 text-slate-600" />
          <p className="px-3 text-[10px] text-slate-600">{emptyLabel}</p>
        </div>
      )}
    </Panel>
  );
}

export function MeterList({
  title,
  subtitle,
  rows,
  action,
  className,
}: {
  title: string;
  subtitle?: string;
  rows: { label: string; value: string; ratio?: number; tone?: Tone; hint?: string }[];
  action?: ReactNode;
  className?: string;
}) {
  return (
    <Panel className={cn("flex h-full min-w-0 flex-col p-4", className)}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate text-[12.5px] font-semibold tracking-tight text-slate-200">{title}</h3>
          {subtitle ? <p className="mt-0.5 truncate text-[10px] text-slate-600">{subtitle}</p> : null}
        </div>
        {action}
      </div>
      <div className="mt-3 flex-1 space-y-3">
        {rows.map((row) => {
          const color = TONES[row.tone ?? "accent"];
          return (
            <div key={row.label}>
              <div className="flex items-center gap-2 text-[10.5px]">
                <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}80` }} />
                <span className="min-w-0 flex-1 truncate text-slate-400">{row.label}</span>
                <span className="shrink-0 font-mono tabular-nums text-slate-300">{row.value}</span>
              </div>
              {row.ratio !== undefined ? (
                <div className="ml-3.5 mt-1.5 h-[3px] overflow-hidden rounded-full bg-white/[0.05]">
                  <div
                    className="h-full rounded-full transition-[width] duration-700"
                    style={{ width: `${Math.max(2, Math.min(100, row.ratio * 100))}%`, background: color, boxShadow: `0 0 6px ${color}55` }}
                  />
                </div>
              ) : row.hint ? (
                <p className="ml-3.5 mt-0.5 text-[9px] text-slate-600">{row.hint}</p>
              ) : null}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

export function ScoreBar({
  label,
  value,
  max = 1,
  color = TONES.accent,
  display,
  className,
}: {
  label: string;
  value: number;
  max?: number;
  color?: string;
  display?: string;
  className?: string;
}) {
  const ratio = max > 0 ? Math.max(0, Math.min(1, value / max)) : 0;
  return (
    <div className={className}>
      <div className="flex items-baseline justify-between gap-2 text-[10px]">
        <span className="uppercase tracking-[0.1em] text-slate-500">{label}</span>
        <span className="font-mono tabular-nums text-slate-300">{display ?? value.toFixed(3)}</span>
      </div>
      <div className="mt-1 h-[3px] overflow-hidden rounded-full bg-white/[0.05]">
        <div
          className="h-full rounded-full transition-[width] duration-700"
          style={{ width: `${Math.max(2, ratio * 100)}%`, background: color, boxShadow: `0 0 6px ${color}66` }}
        />
      </div>
    </div>
  );
}

type MapNode = GeoResponse["nodes"][number];

export function WorldThreatMap({
  arcs,
  nodes,
  height = 360,
  onSelect,
  selected,
  className,
}: {
  arcs: GeoResponse["arcs"];
  nodes: MapNode[];
  height?: number;
  onSelect?: (node: MapNode) => void;
  selected?: string | null;
  className?: string;
}) {
  const project = (lat: number, lng: number) => [lng + 180, 90 - lat] as const;
  const validArcs = arcs.filter(
    (arc) =>
      Number.isFinite(arc.startLat) &&
      Number.isFinite(arc.startLng) &&
      Number.isFinite(arc.endLat) &&
      Number.isFinite(arc.endLng),
  );
  const topNodes = [...nodes]
    .filter((node) => Number.isFinite(node.lat) && Number.isFinite(node.lng))
    .sort((a, b) => b.volume - a.volume)
    .slice(0, 5);

  return (
    <div
      className={cn("relative w-full overflow-hidden rounded-xl border border-white/[0.06] bg-[#040a14]", className)}
      style={{ aspectRatio: "2 / 1", minHeight: 200, maxHeight: height }}
    >
      <div
        aria-hidden
        className="absolute inset-0 opacity-[0.7]"
        style={{
          backgroundImage: "url('/textures/earth-dark.jpg')",
          backgroundSize: "100% 100%",
          backgroundRepeat: "no-repeat",
          filter: "saturate(0.65) brightness(0.9)",
        }}
      />
      <div
        aria-hidden
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse at 50% 45%, rgba(54,217,208,0.08), transparent 55%), linear-gradient(180deg, rgba(5,8,15,0.30), rgba(5,8,15,0.62))",
        }}
      />
      <svg viewBox="0 0 360 180" preserveAspectRatio="none" className="absolute inset-0 h-full w-full">
        <defs>
          <filter id="map-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="1.4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {validArcs.map((arc, index) => {
          const [x1, y1] = project(arc.startLat, arc.startLng);
          const [x2, y2] = project(arc.endLat, arc.endLng);
          const dx = x2 - x1;
          const dy = y2 - y1;
          const distance = Math.hypot(dx, dy);
          const lift = Math.min(34, Math.max(7, distance * 0.24));
          const cx = (x1 + x2) / 2 - dy * 0.08;
          const cy = (y1 + y2) / 2 - lift;
          const color = severityColor(arc.severity);
          return (
            <path
              key={`${arc.flow_ids[0] ?? index}-${index}`}
              d={`M ${x1.toFixed(2)} ${y1.toFixed(2)} Q ${cx.toFixed(2)} ${cy.toFixed(2)} ${x2.toFixed(2)} ${y2.toFixed(2)}`}
              fill="none"
              stroke={color}
              strokeWidth={arc.severity === "critical" ? 0.55 : 0.38}
              strokeOpacity={0.5}
              strokeLinecap="round"
              className="map-arc"
              style={{ animationDelay: `${(index % 9) * 0.28}s` }}
            >
              <title>
                {`${arc.srcCity ?? arc.srcCountry ?? "unknown"} → ${arc.dstCity ?? arc.dstCountry ?? "unknown"} · ${arc.count} ${arc.count === 1 ? "flow" : "flows"} · ${arc.severity}`}
              </title>
            </path>
          );
        })}
        {nodes
          .filter((node) => Number.isFinite(node.lat) && Number.isFinite(node.lng))
          .map((node, index) => {
            const [x, y] = project(node.lat, node.lng);
            const color = severityColor(node.severity);
            const radius = Math.min(2.4, Math.max(0.7, 0.7 + Math.log10(node.volume + 10) / 5));
            const active = selected === node.name;
            const interactive = Boolean(onSelect);
            const activate = () => onSelect?.(node);
            return (
              <g
                key={node.name}
                role={interactive ? "button" : undefined}
                tabIndex={interactive ? 0 : undefined}
                aria-label={interactive ? `Inspect ${node.name}` : undefined}
                onClick={interactive ? activate : undefined}
                onKeyDown={
                  interactive
                    ? (event: KeyboardEvent<SVGGElement>) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          activate();
                        }
                      }
                    : undefined
                }
                className={interactive ? "cursor-pointer outline-none" : undefined}
              >
                <title>
                  {`${node.name}${node.country ? ` · ${node.country}` : ""} · ${node.connections} connections · ${node.severity}`}
                </title>
                <circle cx={x} cy={y} r={radius * 3.4} fill={color} fillOpacity={active ? 0.24 : 0.1} />
                {index < 14 ? (
                  <circle
                    cx={x}
                    cy={y}
                    r={radius}
                    fill="none"
                    stroke={color}
                    strokeWidth={0.22}
                    className="map-node-pulse"
                    style={{ animationDelay: `${(index % 8) * 0.4}s` }}
                  />
                ) : null}
                <circle
                  cx={x}
                  cy={y}
                  r={radius}
                  fill={color}
                  filter="url(#map-glow)"
                  stroke={active ? "#e8fffd" : "rgba(5,11,20,0.7)"}
                  strokeWidth={active ? 0.34 : 0.18}
                />
              </g>
            );
          })}
      </svg>
      {topNodes.map((node) => {
        const [x, y] = project(node.lat, node.lng);
        return (
          <span
            key={`label-${node.name}`}
            className="pointer-events-none absolute z-10 -translate-y-full whitespace-nowrap rounded border border-white/[0.06] bg-[#050b16]/85 px-1 py-px font-mono text-[8.5px] text-slate-300"
            style={{ left: `${(x / 360) * 100}%`, top: `${(y / 180) * 100}%`, transform: "translate(6px, -120%)" }}
          >
            {node.name}
          </span>
        );
      })}
      <div className="pointer-events-none absolute left-3 top-2.5 flex items-center gap-2 text-[8.5px] uppercase tracking-[0.16em] text-slate-500">
        <span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_8px_#36D9D0]" />
        live flow geography
      </div>
      <div className="pointer-events-none absolute bottom-2.5 left-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[8.5px] text-slate-500">
        {["critical", "high", "medium", "low"].map((severity) => (
          <span key={severity} className="inline-flex items-center gap-1 capitalize">
            <span className="h-1 w-1 rounded-full" style={{ background: severityColor(severity) }} />
            {severity}
          </span>
        ))}
      </div>
    </div>
  );
}
