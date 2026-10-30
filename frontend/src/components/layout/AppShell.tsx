import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bell,
  BrainCircuit,
  ChevronDown,
  ChevronsUpDown,
  Crosshair,
  FileText,
  Globe2,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Radio,
  Search,
  Settings2,
  ShieldAlert,
  UploadCloud,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { GlobalSearch } from "@/components/layout/GlobalSearch";
import { SentinelLogo } from "@/components/layout/Logo";
import { Modal } from "@/components/ui";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { useWorkspace, type RangeKey } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { cn, formatNumber, initials, titleCase } from "@/lib/format";
import type { SystemStatus } from "@/lib/types";
import { useEventStream } from "@/lib/useEventStream";

interface NavItem {
  label: string;
  to: string;
  icon: typeof LayoutDashboard;
  permission?: string;
  children?: { label: string; to: string }[];
}

const DETECTION_ITEMS = [
  { label: "DDoS & volumetric", to: "/app/detections/ddos" },
  { label: "C2 beaconing", to: "/app/detections/beaconing" },
  { label: "DGA & DNS tunnelling", to: "/app/detections/dns" },
  { label: "TLS / QUIC metadata", to: "/app/detections/encrypted" },
  { label: "Port scanning", to: "/app/detections/scanning" },
  { label: "Data exfiltration", to: "/app/detections/exfiltration" },
];

const SEGMENT_LABELS: Record<string, string> = {
  overview: "Overview",
  monitoring: "Traffic & topology",
  ingestion: "Data ingestion",
  replay: "Replay lab",
  alerts: "Alert centre",
  detections: "Detection workspaces",
  ddos: "DDoS",
  beaconing: "C2 beaconing",
  dns: "DGA & DNS",
  encrypted: "TLS / QUIC",
  scanning: "Port scanning",
  exfiltration: "Data exfiltration",
  ai: "AI & models",
  intel: "Threat intel",
  reports: "Reports",
  admin: "Admin",
};

function segmentLabel(segment: string): string {
  return SEGMENT_LABELS[segment] ?? titleCase(segment);
}

const NAV: NavItem[] = [
  { label: "Overview", to: "/app/overview", icon: LayoutDashboard, permission: "dashboard.view" },
  { label: "Traffic & topology", to: "/app/monitoring", icon: Network, permission: "monitoring.view" },
  { label: "Data ingestion", to: "/app/ingestion", icon: UploadCloud, permission: "ingestion.view" },
  { label: "Replay lab", to: "/app/replay", icon: Radio, permission: "replay.run" },
  { label: "Alert centre", to: "/app/alerts", icon: ShieldAlert, permission: "alerts.view" },
  { label: "Detection workspaces", to: "/app/detections", icon: Crosshair, permission: "detections.view", children: DETECTION_ITEMS },
  { label: "AI & models", to: "/app/ai", icon: BrainCircuit, permission: "ai.view" },
  { label: "Threat intelligence", to: "/app/intel", icon: Globe2, permission: "intel.view" },
  { label: "Reports", to: "/app/reports", icon: FileText, permission: "reports.view" },
  { label: "Administration", to: "/app/admin", icon: Settings2, permission: "settings.view" },
];

const RANGES: { key: RangeKey; label: string }[] = [
  { key: "1h", label: "Last hour" },
  { key: "6h", label: "Last 6 hours" },
  { key: "24h", label: "Last 24 hours" },
  { key: "7d", label: "Last 7 days" },
  { key: "30d", label: "Last 30 days" },
];

function useStatus() {
  return useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>("/system/status"),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
}

function useActivity() {
  return useQuery({
    queryKey: ["activity"],
    queryFn: () =>
      api.get<{ alerts: number; critical: number; flows: number; events: { ts: string; level: string; message: string }[] }>(
        "/activity",
      ),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
}

function EnvironmentStatus({ active, status }: { active: string; status?: SystemStatus }) {
  const modes = [
    { key: "LIVE", color: "bg-signal-mint", label: "Live" },
    { key: "REPLAY", color: "bg-signal-blue", label: "Replay" },
    { key: "DEMO", color: "bg-signal-amber", label: "Demo" },
    { key: "OFFLINE", color: "bg-slate-500", label: "Offline" },
  ];
  const offline = !status?.last_flow_at;
  return (
    <div className="hidden items-center gap-1.5 rounded-lg border border-white/[0.07] bg-ink-900/60 px-2 py-1 lg:flex" aria-label="Environment indicators">
      {modes.map((mode) => {
        const lit = mode.key === "OFFLINE" ? offline : mode.key === active && !offline;
        return (
          <span
            key={mode.key}
            className={cn(
              "inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-[0.1em] transition-opacity",
              lit ? "text-slate-200" : "text-slate-600",
            )}
          >
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                lit ? mode.color : "bg-slate-700",
                lit && mode.key !== "OFFLINE" ? "animate-pulse-soft" : "",
              )}
            />
            {mode.label}
          </span>
        );
      })}
    </div>
  );
}

function EnvironmentBanner() {
  const { workspace } = useWorkspace();
  const { data } = useStatus();
  if (!workspace) return null;
  const env = workspace.environment;
  if (env === "DEMO") {
    return (
      <div className="mb-5 flex items-center gap-2 rounded-lg border border-signal-amber/25 bg-signal-amber/[0.06] px-3 py-2 text-[11.5px] text-amber-200/90">
        <span className="rounded border border-signal-amber/30 bg-signal-amber/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold tracking-[0.12em] text-signal-amber">DEMO</span>
        <span>
          Synthetic scenario telemetry. This workspace is permanently labelled demo and is never mixed with live
          collector data.
        </span>
      </div>
    );
  }
  if (env === "REPLAY") {
    return (
      <div className="mb-5 flex items-center gap-2 rounded-lg border border-signal-blue/25 bg-signal-blue/[0.06] px-3 py-2 text-[11.5px] text-sky-200/90">
        <span className="rounded border border-signal-blue/30 bg-signal-blue/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold tracking-[0.12em] text-signal-blue">REPLAY</span>
        <span>Recorded or synthetic captures are reprocessed here at a controlled speed. Replay alerts carry the DEMO data source.</span>
      </div>
    );
  }
  if (env === "LIVE" && data && !data.last_flow_at) {
    return (
      <div className="mb-5 flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.025] px-3 py-2 text-[11.5px] text-slate-400">
        <span className="rounded border border-white/15 bg-white/[0.05] px-1.5 py-0.5 font-mono text-[9px] font-semibold tracking-[0.12em] text-slate-300">LIVE</span>
        <span>No collector telemetry has been received yet. Dashboards will stay empty until an approved collector pushes records.</span>
      </div>
    );
  }
  return null;
}

function ChangePasswordModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (open) {
      setCurrent("");
      setNext("");
      setConfirm("");
    }
  }, [open]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Change password"
      description="New passwords must be at least 12 characters. Sessions remain valid until they expire."
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={busy || next.length < 12 || next !== confirm || !current}
            onClick={async () => {
              setBusy(true);
              try {
                await api.post("/auth/change-password", { current_password: current, new_password: next });
                toast("success", "Password updated", "Use the new password the next time you sign in.");
                onClose();
              } catch (err) {
                toast("error", "Password change failed", err instanceof Error ? err.message : "Try again.");
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Updating…" : "Update password"}
          </button>
        </>
      }
    >
      <div className="space-y-3">
        <label className="block">
          <span className="label mb-1.5 block">Current password</span>
          <input type="password" className="field" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" />
        </label>
        <label className="block">
          <span className="label mb-1.5 block">New password</span>
          <input type="password" className="field" value={next} onChange={(event) => setNext(event.target.value)} autoComplete="new-password" />
        </label>
        <label className="block">
          <span className="label mb-1.5 block">Confirm new password</span>
          <input type="password" className="field" value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" />
        </label>
        {confirm && confirm !== next ? <p className="text-[11.5px] text-signal-rose">Passwords do not match.</p> : null}
      </div>
    </Modal>
  );
}

export function AppShell() {
  const { session, logout, hasPermission } = useAuth();
  const { workspace, workspaces, setWorkspaceSlug, range, setRange, environment } = useWorkspace();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [detectionsOpen, setDetectionsOpen] = useState(false);
  const userRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const navigate = useNavigate();
  const status = useStatus();
  const activity = useActivity();
  const queryClient = useQueryClient();
  const onStreamEvent = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ["overview"] });
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["activity"] });
    void queryClient.invalidateQueries({ queryKey: ["system-status"] });
  }, [queryClient]);
  const stream = useEventStream(environment, onStreamEvent);

  useEffect(() => {
    setMobileOpen(false);
    setUserOpen(false);
    if (location.pathname.startsWith("/app/detections")) setDetectionsOpen(true);
  }, [location.pathname]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      if (userRef.current && !userRef.current.contains(event.target as Node)) setUserOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const nav = NAV.filter((item) => !item.permission || hasPermission(item.permission));
  const user = session?.user;
  const isDetectionActive = location.pathname.startsWith("/app/detections");

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex h-[64px] items-center justify-between px-5">
        <NavLink to="/app/overview" aria-label="SENTINEL AI overview">
          <SentinelLogo />
        </NavLink>
        <button type="button" className="btn-ghost px-2 py-1.5 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close navigation">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="mx-4 mb-3 rounded-lg border border-white/[0.06] bg-ink-900/60 px-3 py-2.5">
        <p className="label mb-1">Workspace</p>
        <div className="relative">
          <select
            aria-label="Select workspace"
            value={workspace?.slug ?? ""}
            onChange={(event) => setWorkspaceSlug(event.target.value)}
            className="w-full appearance-none bg-transparent pr-6 text-[12.5px] font-medium text-slate-200 focus:outline-none"
          >
            {workspaces.map((item) => (
              <option key={item.slug} value={item.slug} className="bg-ink-800 text-slate-200">
                {item.name}
              </option>
            ))}
          </select>
          <ChevronsUpDown className="pointer-events-none absolute right-0 top-0.5 h-3.5 w-3.5 text-slate-500" />
        </div>
        <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">{environment}</p>
      </div>
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 pb-4" aria-label="Primary">
        {nav.map((item) => {
          const Icon = item.icon;
          const active = item.children
            ? isDetectionActive
            : location.pathname === item.to || location.pathname.startsWith(`${item.to}/`);
          return (
            <div key={item.to}>
              <div
                className={cn(
                  "flex items-center rounded-lg transition-colors",
                  active ? "bg-white/[0.07]" : "hover:bg-white/[0.035]",
                )}
              >
                <NavLink
                  to={item.to}
                  end={item.to === "/app/detections"}
                  className={cn(
                    "group flex flex-1 items-center gap-2.5 rounded-lg px-2.5 py-2 text-[12.5px] font-medium transition-colors",
                    active ? "text-slate-100" : "text-slate-400 hover:text-slate-200",
                  )}
                >
                  <Icon className={cn("h-4 w-4 shrink-0", active ? "text-accent" : "text-slate-500 group-hover:text-slate-300")} />
                  <span className="flex-1">{item.label}</span>
                </NavLink>
                {item.children ? (
                  <button
                    type="button"
                    aria-label={detectionsOpen ? "Collapse detection workspaces" : "Expand detection workspaces"}
                    aria-expanded={detectionsOpen}
                    onClick={() => setDetectionsOpen((value) => !value)}
                    className="mr-1.5 rounded p-0.5 text-slate-500 hover:text-slate-300"
                  >
                    <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", detectionsOpen ? "rotate-180" : "")} />
                  </button>
                ) : null}
              </div>
              {item.children && detectionsOpen ? (
                <div className="mb-1 ml-[26px] mt-0.5 space-y-0.5 border-l border-white/[0.07] pl-2">
                  {item.children.map((child) => (
                    <NavLink
                      key={child.to}
                      to={child.to}
                      className={({ isActive }) =>
                        cn(
                          "block rounded-md px-2 py-1.5 text-[11.5px] transition-colors",
                          isActive ? "bg-white/[0.05] text-accent-soft" : "text-slate-500 hover:bg-white/[0.03] hover:text-slate-300",
                        )
                      }
                    >
                      {child.label}
                    </NavLink>
                  ))}
                </div>
              ) : null}
            </div>
          );
        })}
      </nav>
      <div className="border-t border-white/[0.06] p-3">
        <button
          type="button"
          onClick={() => navigate("/app/ai")}
          className="w-full rounded-lg border border-white/[0.07] bg-ink-900/60 px-3 py-2.5 text-left transition-colors hover:border-white/[0.12]"
        >
          <div className="flex items-center gap-2 text-[11.5px] text-slate-300">
            <Activity className="h-3.5 w-3.5 text-accent" />
            <span className="font-medium">Detection pipeline</span>
            <span className={cn("ml-auto h-1.5 w-1.5 rounded-full", status.data?.last_flow_at ? "bg-signal-mint" : "bg-slate-600")} />
          </div>
          <p className="mt-1 text-[10.5px] text-slate-500">
            {status.data ? `${status.data.active_detectors} active modules · retention ${status.data.retention_days}d` : "Status unavailable"}
          </p>
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[200] focus:rounded-lg focus:bg-accent focus:px-3 focus:py-2 focus:text-ink-950"
      >
        Skip to content
      </a>
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] border-r border-white/[0.06] bg-ink-850/80 backdrop-blur-xl lg:block">
        {sidebar}
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-[90] lg:hidden">
          <div className="absolute inset-0 bg-ink-950/70 backdrop-blur-sm" onClick={() => setMobileOpen(false)} aria-hidden="true" />
          <aside className="relative h-full w-[270px] border-r border-white/10 bg-ink-850 shadow-2xl">{sidebar}</aside>
        </div>
      ) : null}

      <div className="lg:pl-[248px]">
        <header className="sticky top-0 z-30 flex h-[64px] items-center gap-3 border-b border-white/[0.06] bg-ink-900/80 px-4 backdrop-blur-xl sm:px-6">
          <button
            type="button"
            className="btn-ghost px-2 py-2 lg:hidden"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
          >
            <Menu className="h-5 w-5" />
          </button>

          <button
            type="button"
            onClick={() => setSearchOpen(true)}
            className="hidden h-8 w-[230px] items-center gap-2 rounded-lg border border-white/[0.07] bg-white/[0.025] px-2.5 text-left text-[12px] text-slate-500 transition-colors hover:border-white/[0.12] hover:text-slate-400 sm:flex"
          >
            <Search className="h-3.5 w-3.5" />
            <span className="flex-1">Search telemetry…</span>
            <span className="kbd">⌘K</span>
          </button>

          <div className="ml-auto flex items-center gap-2">
            <EnvironmentStatus active={environment} status={status.data} />

            <label className="hidden items-center gap-2 rounded-lg border border-white/[0.07] bg-ink-900/60 px-2.5 py-1.5 md:flex">
              <span className="text-[9.5px] font-semibold uppercase tracking-[0.12em] text-slate-500">Range</span>
              <select
                aria-label="Time range"
                value={range}
                onChange={(event) => setRange(event.target.value as RangeKey)}
                className="bg-transparent text-[11.5px] font-medium text-slate-300 focus:outline-none"
              >
                {RANGES.map((item) => (
                  <option key={item.key} value={item.key} className="bg-ink-800">
                    {item.label}
                  </option>
                ))}
              </select>
            </label>

            <NavLink
              to="/app/alerts?severity=critical"
              className="relative rounded-lg border border-white/[0.07] bg-ink-900/60 p-2 text-slate-400 transition-colors hover:text-slate-200"
              aria-label={`Open critical alerts (${activity.data?.critical ?? 0})`}
            >
              <Bell className="h-4 w-4" />
              {activity.data?.critical ? (
                <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-signal-rose px-1 font-mono text-[9px] font-bold text-ink-950">
                  {activity.data.critical}
                </span>
              ) : null}
            </NavLink>

            <div className="relative" ref={userRef}>
              <button
                type="button"
                onClick={() => setUserOpen((value) => !value)}
                aria-haspopup="menu"
                aria-expanded={userOpen}
                className="flex items-center gap-2 rounded-lg border border-white/[0.07] bg-ink-900/60 py-1 pl-1 pr-2 transition-colors hover:border-white/[0.14]"
              >
                <span className="flex h-6 w-6 items-center justify-center rounded-md bg-accent/15 font-mono text-[10px] font-semibold text-accent-soft">
                  {user ? initials(user.name) : "—"}
                </span>
                <span className="hidden text-left sm:block">
                  <span className="block text-[11.5px] font-medium leading-tight text-slate-200">{user?.name}</span>
                  <span className="block text-[9.5px] leading-tight text-slate-500">{user?.role.name}</span>
                </span>
                <ChevronDown className="h-3 w-3 text-slate-500" />
              </button>
              {userOpen ? (
                <div
                  role="menu"
                  className="absolute right-0 top-full z-50 mt-2 w-64 overflow-hidden rounded-xl border border-white/10 bg-ink-750 shadow-2xl"
                >
                  <div className="border-b border-white/[0.07] px-3.5 py-3">
                    <p className="truncate text-[12.5px] font-medium text-slate-200">{user?.name}</p>
                    <p className="truncate font-mono text-[10.5px] text-slate-500">{user?.email}</p>
                    <p className="mt-2 text-[10px] uppercase tracking-[0.12em] text-slate-500">{user?.role.name}</p>
                    {user?.is_demo ? (
                      <p className="mt-1 text-[10px] text-signal-amber">Demo account · session-only access</p>
                    ) : null}
                  </div>
                  <div className="p-1.5">
                    <button
                      type="button"
                      role="menuitem"
                      className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-[12px] text-slate-300 hover:bg-white/[0.05]"
                      onClick={() => {
                        setUserOpen(false);
                        setPasswordOpen(true);
                      }}
                    >
                      <KeyRound className="h-3.5 w-3.5" /> Change password
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-[12px] text-signal-rose hover:bg-signal-rose/[0.08]"
                      onClick={async () => {
                        await logout();
                        navigate("/login");
                      }}
                    >
                      <LogOut className="h-3.5 w-3.5" /> Sign out
                    </button>
                  </div>
                  <div className="border-t border-white/[0.07] px-3.5 py-2 font-mono text-[9.5px] text-slate-600">
                    {activity.data ? `${formatNumber(activity.data.flows)} flows · ${formatNumber(activity.data.alerts)} alerts / 24h` : "—"}
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </header>

        <main id="main-content" className="mx-auto w-full max-w-[1560px] px-4 pb-16 pt-6 sm:px-6">
          <div className="mb-4 flex items-center gap-2 text-[10.5px] text-slate-600">
            <span>{workspace?.name ?? "Workspace"}</span>
            <span>/</span>
            <span className="text-slate-500">{location.pathname.split("/").filter(Boolean).slice(1).map(segmentLabel).join(" / ") || "Overview"}</span>
            <span className="ml-auto font-mono">
              {status.data?.last_flow_at ? `last telemetry ${new Date(status.data.last_flow_at).toLocaleTimeString("en-GB", { hour12: false, timeZone: "UTC" })}Z` : "no telemetry"}
              <span className="ml-2 text-slate-700">·</span>
              <span className={cn("ml-2", stream === "live" ? "text-accent/80" : stream === "connecting" ? "text-slate-500" : "text-slate-700")}>
                {stream === "live" ? "stream live" : stream === "connecting" ? "connecting" : "stream offline"}
              </span>
            </span>
          </div>
          <EnvironmentBanner />
          <Outlet />
        </main>
      </div>

      <GlobalSearch open={searchOpen} onClose={() => setSearchOpen(false)} />
      <ChangePasswordModal open={passwordOpen} onClose={() => setPasswordOpen(false)} />
    </div>
  );
}
