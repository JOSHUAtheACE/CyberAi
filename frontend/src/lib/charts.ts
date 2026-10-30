import type { EChartsOption } from "echarts";
import { chartPalette } from "@/components/charts/EChart";
import { formatNumber } from "@/lib/format";

const axisStyle = {
  axisLine: { lineStyle: { color: "rgba(148,163,184,0.14)" } },
  axisTick: { show: false },
  axisLabel: { color: chartPalette.axis, fontSize: 9.5 },
  splitLine: { lineStyle: { color: chartPalette.grid } },
};

export const paletteCycle = [
  chartPalette.accent,
  chartPalette.blue,
  chartPalette.violet,
  chartPalette.amber,
  chartPalette.rose,
  chartPalette.mint,
];

export interface SeriesSpec {
  name: string;
  data: number[];
  color?: string;
  area?: boolean;
  dashed?: boolean;
  stack?: string;
  yAxisIndex?: number;
  smooth?: boolean;
}

function areaGradient(color: string, opacity = 0.22) {
  return {
    type: "linear" as const,
    x: 0,
    y: 0,
    x2: 0,
    y2: 1,
    colorStops: [
      { offset: 0, color: `${color}${Math.round(opacity * 255).toString(16).padStart(2, "0")}` },
      { offset: 1, color: `${color}00` },
    ],
  };
}

export function lineOption({
  labels,
  series,
  yFormatter = (value: number) => formatNumber(value, 1),
  legend = true,
  grid,
}: {
  labels: string[];
  series: SeriesSpec[];
  yFormatter?: (value: number) => string;
  legend?: boolean;
  grid?: Record<string, number>;
}): EChartsOption {
  return {
    animationDuration: 420,
    grid: { left: 6, right: 14, top: legend && series.length > 1 ? 28 : 12, bottom: 4, containLabel: true, ...grid },
    legend: legend ? { show: true, top: 0, right: 4 } : { show: false },
    tooltip: { trigger: "axis" },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: labels,
      ...axisStyle,
      splitLine: { show: false },
    },
    yAxis: {
      type: "value",
      ...axisStyle,
      axisLabel: { ...axisStyle.axisLabel, formatter: (value: number) => yFormatter(value) },
      splitNumber: 4,
    },
    series: series.map((item, index) => ({
      name: item.name,
      type: "line",
      data: item.data,
      smooth: item.smooth ?? true,
      showSymbol: false,
      symbol: "circle",
      symbolSize: 4,
      stack: item.stack,
      yAxisIndex: item.yAxisIndex ?? 0,
      lineStyle: {
        width: 1.6,
        color: item.color ?? paletteCycle[index % paletteCycle.length],
        type: item.dashed ? "dashed" : "solid",
      },
      itemStyle: { color: item.color ?? paletteCycle[index % paletteCycle.length] },
      areaStyle: item.area
        ? { color: areaGradient(item.color ?? paletteCycle[index % paletteCycle.length]) }
        : undefined,
    })),
  } as EChartsOption;
}

export function barOption({
  labels,
  series,
  horizontal = false,
  legend = true,
  colorByIndex = false,
  yFormatter,
  grid,
}: {
  labels: string[];
  series: SeriesSpec[];
  horizontal?: boolean;
  legend?: boolean;
  colorByIndex?: boolean;
  yFormatter?: (value: number) => string;
  grid?: Record<string, number>;
}): EChartsOption {
  const categoryAxis = {
    type: "category" as const,
    data: labels,
    ...axisStyle,
    axisLabel: { ...axisStyle.axisLabel, interval: 0, rotate: horizontal ? 0 : labels.length > 8 ? 32 : 0 },
    splitLine: { show: false },
  };
  const valueAxis = {
    type: "value" as const,
    ...axisStyle,
    axisLabel: { ...axisStyle.axisLabel, formatter: yFormatter ? (value: number) => yFormatter(value) : undefined },
  };
  return {
    animationDuration: 420,
    grid: { left: 6, right: 16, top: legend && series.length > 1 ? 28 : 12, bottom: 4, containLabel: true, ...grid },
    legend: legend && series.length > 1 ? { show: true, top: 0, right: 4 } : { show: false },
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    xAxis: horizontal ? valueAxis : categoryAxis,
    yAxis: horizontal ? { ...categoryAxis, inverse: true } : valueAxis,
    series: series.map((item, index) => ({
      name: item.name,
      type: "bar",
      data: colorByIndex
        ? item.data.map((value, itemIndex) => ({ value, itemStyle: { color: paletteCycle[itemIndex % paletteCycle.length] } }))
        : item.data,
      stack: item.stack,
      barMaxWidth: 22,
      itemStyle: {
        color: colorByIndex ? undefined : item.color ?? paletteCycle[index % paletteCycle.length],
        borderRadius: horizontal ? [0, 3, 3, 0] : [3, 3, 0, 0],
      },
    })),
  } as EChartsOption;
}

export function donutOption({
  items,
  colors = paletteCycle,
  valueFormatter = (value: number) => formatNumber(value),
}: {
  items: { name: string; value: number }[];
  colors?: string[];
  valueFormatter?: (value: number) => string;
}): EChartsOption {
  return {
    animationDuration: 420,
    tooltip: {
      trigger: "item",
      formatter: (params: unknown) => {
        const item = params as { name: string; value: number; percent: number };
        return `${item.name}<br/><strong>${valueFormatter(item.value)}</strong> · ${item.percent}%`;
      },
    },
    legend: { show: false },
    series: [
      {
        type: "pie",
        radius: ["58%", "82%"],
        center: ["50%", "50%"],
        avoidLabelOverlap: true,
        padAngle: 2,
        itemStyle: { borderColor: "#0B1220", borderWidth: 2, borderRadius: 4 },
        label: { show: false },
        emphasis: { scale: true, scaleSize: 4 },
        data: items.map((item, index) => ({
          name: item.name,
          value: item.value,
          itemStyle: { color: colors[index % colors.length] },
        })),
      },
    ],
  } as EChartsOption;
}

export function scatterOption({
  points,
  xName,
  yName,
  xFormatter,
  yFormatter,
  color = chartPalette.blue,
}: {
  points: { x: number; y: number; label?: string }[];
  xName: string;
  yName: string;
  xFormatter?: (value: number) => string;
  yFormatter?: (value: number) => string;
  color?: string;
}): EChartsOption {
  return {
    animationDuration: 420,
    grid: { left: 6, right: 18, top: 16, bottom: 8, containLabel: true },
    tooltip: {
      trigger: "item",
      formatter: (params: unknown) => {
        const item = params as { data: { value: number[]; label?: string } };
        const [x, y] = item.data.value;
        return `${item.data.label ?? ""}<br/>${xName}: ${xFormatter ? xFormatter(x) : x}<br/>${yName}: ${yFormatter ? yFormatter(y) : y}`;
      },
    },
    xAxis: {
      type: "value",
      name: xName,
      nameTextStyle: { color: chartPalette.axis, fontSize: 9.5 },
      ...axisStyle,
      axisLabel: { ...axisStyle.axisLabel, formatter: xFormatter },
      scale: true,
    },
    yAxis: {
      type: "value",
      name: yName,
      nameTextStyle: { color: chartPalette.axis, fontSize: 9.5 },
      ...axisStyle,
      axisLabel: { ...axisStyle.axisLabel, formatter: yFormatter },
      scale: true,
    },
    series: [
      {
        type: "scatter",
        symbolSize: 7,
        data: points.map((point) => ({ value: [point.x, point.y], label: point.label })),
        itemStyle: { color, opacity: 0.66, borderColor: `${color}80`, borderWidth: 1 },
      },
    ],
  } as EChartsOption;
}

export function radarOption({
  indicators,
  series,
  max = 1,
  splitNumber = 4,
  legend = true,
}: {
  indicators: { name: string; max?: number }[];
  series: { name: string; values: number[]; color?: string }[];
  max?: number;
  splitNumber?: number;
  legend?: boolean;
}): EChartsOption {
  return {
    animationDuration: 460,
    tooltip: { trigger: "item" },
    legend: legend && series.length > 1 ? { show: true, top: 0, right: 4 } : { show: false },
    radar: {
      indicator: indicators.map((indicator) => ({ name: indicator.name, max: indicator.max ?? max })),
      radius: legend && series.length > 1 ? "62%" : "70%",
      center: ["50%", legend && series.length > 1 ? "56%" : "52%"],
      splitNumber,
      shape: "polygon",
      axisName: { color: chartPalette.axis, fontSize: 9.5 },
      splitLine: { lineStyle: { color: "rgba(148,163,184,0.12)" } },
      splitArea: {
        areaStyle: { color: ["rgba(148,163,184,0.015)", "rgba(148,163,184,0.04)"] },
      },
      axisLine: { lineStyle: { color: "rgba(148,163,184,0.14)" } },
    },
    series: [
      {
        type: "radar",
        symbolSize: 3.5,
        data: series.map((item, index) => {
          const color = item.color ?? paletteCycle[index % paletteCycle.length];
          return {
            name: item.name,
            value: item.values,
            lineStyle: { width: 1.6, color },
            itemStyle: { color },
            areaStyle: { color: `${color}2e` },
          };
        }),
      },
    ],
  } as EChartsOption;
}

export function gaugeOption({
  value,
  max = 1,
  name,
  color = chartPalette.accent,
  formatter,
  startAngle = 220,
  endAngle = -40,
  detailSize = 24,
}: {
  value: number;
  max?: number;
  name?: string;
  color?: string;
  formatter?: (value: number) => string;
  startAngle?: number;
  endAngle?: number;
  detailSize?: number;
}): EChartsOption {
  const safeMax = max > 0 ? max : 1;
  return {
    animationDuration: 520,
    series: [
      {
        type: "gauge",
        startAngle,
        endAngle,
        min: 0,
        max: safeMax,
        radius: "92%",
        center: ["50%", "58%"],
        progress: { show: true, width: 9, roundCap: true, itemStyle: { color } },
        axisLine: {
          roundCap: true,
          lineStyle: {
            width: 9,
            color: [[1, "rgba(148,163,184,0.10)"]],
          },
        },
        pointer: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        anchor: { show: false },
        title: name
          ? { show: true, offsetCenter: [0, "34%"], color: chartPalette.axis, fontSize: 9.5 }
          : { show: false },
        detail: {
          valueAnimation: true,
          offsetCenter: [0, name ? "-6%" : "0%"],
          color: "#dbe6f5",
          fontSize: detailSize,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          formatter: (raw: number) => (formatter ? formatter(raw) : raw.toFixed(2)),
        },
        data: [{ value, name }],
      },
    ],
  } as EChartsOption;
}

export function shortBucket(label: string): string {
  const parsed = new Date(label);
  if (Number.isNaN(parsed.getTime())) return label;
  const hour = parsed.toISOString().slice(11, 16);
  return hour.endsWith(":00") ? hour.slice(0, 2) + ":00" : hour;
}
