import * as echarts from "echarts";
import { useEffect, useRef } from "react";

const prefersReducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export const chartPalette = {
  accent: "#36D9D0",
  blue: "#4BA3FF",
  violet: "#8B7CF6",
  amber: "#F5B84B",
  rose: "#FF5C7A",
  mint: "#3DDC97",
  grid: "rgba(148,163,184,0.10)",
  axis: "rgba(148,163,184,0.55)",
  text: "#8497b0",
};

export const baseChartOption: echarts.EChartsOption = {
  animation: !prefersReducedMotion(),
  animationDuration: 500,
  textStyle: {
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
    color: chartPalette.text,
  },
  grid: { left: 8, right: 12, top: 24, bottom: 8, containLabel: true },
  tooltip: {
    backgroundColor: "rgba(11,18,32,0.96)",
    borderColor: "rgba(148,163,184,0.18)",
    borderWidth: 1,
    textStyle: { color: "#dbe6f5", fontSize: 11.5, fontFamily: "Inter, sans-serif" },
    padding: [8, 10],
  },
  legend: {
    textStyle: { color: chartPalette.text, fontSize: 10.5 },
    icon: "roundRect",
    itemWidth: 8,
    itemHeight: 8,
    top: 0,
  },
};

export function EChart({
  option,
  height = 240,
  className,
  ariaLabel,
}: {
  option: echarts.EChartsOption;
  height?: number | string;
  className?: string;
  ariaLabel?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const chart = echarts.init(containerRef.current, undefined, { renderer: "canvas" });
    chartRef.current = chart;
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(containerRef.current);
    return () => {
      observer.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;
    const merged: echarts.EChartsOption = {
      ...baseChartOption,
      ...option,
      tooltip: { ...(baseChartOption.tooltip as object), ...(option.tooltip as object) },
      grid: { ...(baseChartOption.grid as object), ...(option.grid as object) },
      textStyle: { ...(baseChartOption.textStyle as object), ...(option.textStyle as object) },
    };
    chart.setOption(merged, { notMerge: true });
  }, [option]);

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label={ariaLabel ?? "Data visualisation"}
      className={className}
      style={{ width: "100%", height }}
    />
  );
}
