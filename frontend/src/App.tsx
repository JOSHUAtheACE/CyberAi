import { Component, lazy, Suspense, type ErrorInfo, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { PageLoader } from "@/components/ui";
import { useAuth } from "@/context/AuthContext";

const Landing = lazy(async () => ({ default: (await import("@/pages/Landing")).Landing }));
const Login = lazy(async () => ({ default: (await import("@/pages/Login")).Login }));
const Overview = lazy(async () => ({ default: (await import("@/pages/Overview")).Overview }));
const Monitoring = lazy(async () => ({ default: (await import("@/pages/Monitoring")).Monitoring }));
const Ingestion = lazy(async () => ({ default: (await import("@/pages/Ingestion")).Ingestion }));
const Replay = lazy(async () => ({ default: (await import("@/pages/Replay")).Replay }));
const Alerts = lazy(async () => ({ default: (await import("@/pages/Alerts")).Alerts }));
const AlertDetail = lazy(async () => ({ default: (await import("@/pages/AlertDetail")).AlertDetail }));
const Detections = lazy(async () => ({ default: (await import("@/pages/Detections")).Detections }));
const DetectionWorkspace = lazy(async () => ({
  default: (await import("@/pages/DetectionWorkspace")).DetectionWorkspace,
}));
const AiCentre = lazy(async () => ({ default: (await import("@/pages/AiCentre")).AiCentre }));
const Intelligence = lazy(async () => ({ default: (await import("@/pages/Intelligence")).Intelligence }));
const Reports = lazy(async () => ({ default: (await import("@/pages/Reports")).Reports }));
const Admin = lazy(async () => ({ default: (await import("@/pages/Admin")).Admin }));
const NotFound = lazy(async () => ({ default: (await import("@/pages/NotFound")).NotFound }));

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled UI error", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-ink-950 px-6">
          <div className="max-w-md rounded-xl border border-signal-rose/20 bg-ink-900/70 p-6 text-center">
            <p className="text-[13px] font-medium text-slate-200">The interface encountered an unexpected error</p>
            <p className="mt-2 text-[12px] leading-relaxed text-slate-500">{this.state.error.message}</p>
            <button type="button" className="btn-secondary mt-4" onClick={() => window.location.reload()}>
              Reload application
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function RequireAuth({ children }: { children: ReactNode }) {
  const { session, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-ink-950">
        <PageLoader label="Verifying session" />
      </div>
    );
  }
  if (!session) {
    return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}` }} />;
  }
  return <>{children}</>;
}

function RequirePermission({ permission, children }: { permission: string; children: ReactNode }) {
  const { hasPermission } = useAuth();
  if (!hasPermission(permission)) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="max-w-md rounded-xl border border-white/[0.08] bg-ink-900/60 px-6 py-8 text-center">
          <p className="label mb-2">Access restricted</p>
          <h2 className="text-[16px] font-semibold text-slate-200">Your role cannot open this workspace</h2>
          <p className="mt-2 text-[12px] leading-relaxed text-slate-500">
            The server enforces role permissions on every request. Ask a security administrator to adjust your role if
            this access is required.
          </p>
          <p className="mt-3 font-mono text-[10px] text-slate-600">required permission · {permission}</p>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <ErrorBoundary>
        <Suspense
          fallback={
            <div className="flex min-h-screen items-center justify-center bg-ink-950">
              <PageLoader label="Loading workspace" />
            </div>
          }
        >
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/login" element={<Login />} />
            <Route
              path="/app"
              element={
                <RequireAuth>
                  <AppShell />
                </RequireAuth>
              }
            >
              <Route index element={<Navigate to="/app/overview" replace />} />
              <Route
                path="overview"
                element={
                  <RequirePermission permission="dashboard.view">
                    <Overview />
                  </RequirePermission>
                }
              />
              <Route
                path="monitoring"
                element={
                  <RequirePermission permission="monitoring.view">
                    <Monitoring />
                  </RequirePermission>
                }
              />
              <Route
                path="ingestion"
                element={
                  <RequirePermission permission="ingestion.view">
                    <Ingestion />
                  </RequirePermission>
                }
              />
              <Route
                path="replay"
                element={
                  <RequirePermission permission="replay.run">
                    <Replay />
                  </RequirePermission>
                }
              />
              <Route
                path="alerts"
                element={
                  <RequirePermission permission="alerts.view">
                    <Alerts />
                  </RequirePermission>
                }
              />
              <Route
                path="alerts/:id"
                element={
                  <RequirePermission permission="alerts.view">
                    <AlertDetail />
                  </RequirePermission>
                }
              />
              <Route
                path="detections"
                element={
                  <RequirePermission permission="detections.view">
                    <Detections />
                  </RequirePermission>
                }
              />
              <Route
                path="detections/:slug"
                element={
                  <RequirePermission permission="detections.view">
                    <DetectionWorkspace />
                  </RequirePermission>
                }
              />
              <Route
                path="ai"
                element={
                  <RequirePermission permission="ai.view">
                    <AiCentre />
                  </RequirePermission>
                }
              />
              <Route
                path="intel"
                element={
                  <RequirePermission permission="intel.view">
                    <Intelligence />
                  </RequirePermission>
                }
              />
              <Route
                path="reports"
                element={
                  <RequirePermission permission="reports.view">
                    <Reports />
                  </RequirePermission>
                }
              />
              <Route
                path="admin"
                element={
                  <RequirePermission permission="settings.view">
                    <Admin />
                  </RequirePermission>
                }
              />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </ErrorBoundary>
  );
}
