import { cn } from "@/lib/format";

export function SentinelMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={cn("h-8 w-8", className)} aria-hidden="true">
      <defs>
        <linearGradient id="sentinel-mark" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#7FF0EA" />
          <stop offset="100%" stopColor="#2E9FD8" />
        </linearGradient>
      </defs>
      <path
        d="M16 3.2 26.4 7.5v7.3c0 6.3-4.3 11.1-10.4 13.9C9.9 25.9 5.6 21.1 5.6 14.8V7.5L16 3.2Z"
        fill="rgba(54,217,208,0.06)"
        stroke="url(#sentinel-mark)"
        strokeWidth="1.35"
      />
      <circle cx="16" cy="14.6" r="3.1" fill="none" stroke="#7FF0EA" strokeWidth="1.25" />
      <path
        d="M16 9.2v2.2M16 17.8v2.2M10.6 14.6h2.2M19.2 14.6h2.2"
        stroke="#7FF0EA"
        strokeWidth="1.25"
        strokeLinecap="round"
      />
      <circle cx="16" cy="14.6" r="0.85" fill="#7FF0EA" />
    </svg>
  );
}

export function SentinelLogo({ compact = false }: { compact?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <SentinelMark />
      {!compact ? (
        <span className="leading-none">
          <span className="block text-[13.5px] font-semibold tracking-[0.16em] text-slate-100">SENTINEL</span>
          <span className="mt-1 block text-[8.5px] font-medium uppercase tracking-[0.34em] text-slate-500">
            Network Intelligence
          </span>
        </span>
      ) : null}
    </span>
  );
}
