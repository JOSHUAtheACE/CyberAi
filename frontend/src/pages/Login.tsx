import { Eye, EyeOff, LockKeyhole, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { GlobeView } from "@/components/globe/GlobeView";
import { SentinelLogo } from "@/components/layout/Logo";
import { Badge, Spinner } from "@/components/ui";
import { useAuth } from "@/context/AuthContext";
import { heroArcs, heroNodes } from "@/lib/illustrative";

const demoAccounts = [
  { email: "admin@sentinela.ai", name: "Avery Stone", role: "Security Administrator" },
  { email: "analyst@sentinela.ai", name: "Maya Chen", role: "SOC Analyst" },
  { email: "engineer@sentinela.ai", name: "Jonas Weber", role: "Network Security Engineer" },
  { email: "ml@sentinela.ai", name: "Priya Raman", role: "ML Engineer" },
  { email: "auditor@sentinela.ai", name: "Alex Morgan", role: "Auditor / Management" },
];

const DEMO_PASSWORD = "Sentinel!Demo2026";

export function Login() {
  const { session, loading, login, demoLogin, error } = useAuth();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("analyst@sentinela.ai");
  const [password, setPassword] = useState(DEMO_PASSWORD);
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [demoBusy, setDemoBusy] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const attemptedDemo = useRef(false);

  const destination =
    (location.state as { from?: string } | null)?.from ??
    (new URLSearchParams(location.search).get("next") || "/app/overview");
  const wantsDemo = params.get("demo") === "1";

  useEffect(() => {
    if (loading || session || !wantsDemo || attemptedDemo.current) return;
    attemptedDemo.current = true;
    setDemoBusy(true);
    demoLogin()
      .then(() => navigate(destination, { replace: true }))
      .catch((err: unknown) => setLocalError(err instanceof Error ? err.message : "Demo sign-in failed."))
      .finally(() => setDemoBusy(false));
  }, [demoLogin, destination, loading, navigate, session, wantsDemo]);

  if (!loading && session) return <Navigate to={destination} replace />;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setLocalError(null);
    setBusy(true);
    try {
      await login(email.trim(), password, remember);
      navigate(destination, { replace: true });
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  };

  const startDemo = async () => {
    setLocalError(null);
    setDemoBusy(true);
    try {
      await demoLogin();
      navigate("/app/overview", { replace: true });
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : "Demo sign-in failed.");
    } finally {
      setDemoBusy(false);
    }
  };

  const message = localError ?? error;

  return (
    <div className="relative min-h-screen overflow-hidden bg-ink-950">
      <div className="pointer-events-none absolute inset-0 bg-radial-fade" aria-hidden="true" />
      <div className="relative mx-auto grid min-h-screen max-w-[1320px] gap-8 px-5 py-8 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:px-8">
        <div className="hidden flex-col justify-between lg:flex">
          <Link to="/" aria-label="Back to landing page">
            <SentinelLogo />
          </Link>
          <div className="mt-8">
            <p className="label mb-3">Sign in to a controlled workspace</p>
            <h1 className="max-w-[22ch] text-[34px] font-semibold leading-[1.08] tracking-[-0.03em] text-slate-50">
              Evidence stays attached to the investigation.
            </h1>
            <p className="mt-4 max-w-[46ch] text-[13px] leading-relaxed text-slate-400">
              Role-aware access to passive telemetry, detection workspaces, evaluated models, alert evidence and
              reports. Sessions are signed and CSRF-protected.
            </p>
            <div className="mt-7 overflow-hidden rounded-2xl border border-white/[0.07] bg-ink-900/45 p-2">
              <GlobeView
                arcs={heroArcs}
                nodes={heroNodes}
                height={360}
                interactive={false}
                autoRotate
                demo
                className="!rounded-xl"
              />
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Badge tone="accent" dot>
                Passive observation
              </Badge>
              <Badge tone="slate">Synthetic demo data</Badge>
              <Badge tone="slate">No active remediation</Badge>
            </div>
          </div>
          <p className="mt-8 text-[10.5px] leading-relaxed text-slate-600">
            Access is restricted to authorised operators. Authentication and session events are recorded in the audit
            log.
          </p>
        </div>

        <div className="mx-auto w-full max-w-[440px]">
          <div className="mb-6 flex items-center justify-between lg:hidden">
            <Link to="/" aria-label="Back to landing page">
              <SentinelLogo />
            </Link>
            <Link to="/" className="text-[11.5px] text-slate-500 hover:text-slate-300">
              Back
            </Link>
          </div>

          <div className="rounded-2xl border border-white/[0.08] bg-ink-800/80 p-5 shadow-panel backdrop-blur-xl sm:p-7">
            <div className="flex items-center gap-2 text-[11px] text-accent-soft">
              <LockKeyhole className="h-3.5 w-3.5" />
              Secure sign-in
            </div>
            <h2 className="mt-2 text-[22px] font-semibold tracking-[-0.02em] text-slate-50">Welcome back</h2>
            <p className="mt-1.5 text-[12px] leading-relaxed text-slate-500">
              Use a demonstration account below, or sign in with your assigned credentials.
            </p>

            <form className="mt-6 space-y-4" onSubmit={submit}>
              <label className="block">
                <span className="label mb-1.5 block">Email address</span>
                <input
                  type="email"
                  required
                  autoComplete="username"
                  className="field"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="analyst@company.example"
                />
              </label>
              <label className="block">
                <span className="label mb-1.5 block">Password</span>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    autoComplete="current-password"
                    className="field pr-10"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="At least 12 characters"
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-slate-500 hover:text-slate-300"
                    onClick={() => setShowPassword((value) => !value)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </label>
              <div className="flex items-center justify-between gap-3">
                <label className="flex items-center gap-2 text-[11.5px] text-slate-400">
                  <input
                    type="checkbox"
                    checked={remember}
                    onChange={(event) => setRemember(event.target.checked)}
                    className="h-3.5 w-3.5 rounded border-white/20 bg-transparent accent-[#36D9D0]"
                  />
                  Keep me signed in
                </label>
                <span className="text-[10.5px] text-slate-600">Sessions expire automatically</span>
              </div>

              {message ? (
                <div className="rounded-lg border border-signal-rose/25 bg-signal-rose/[0.06] px-3 py-2 text-[11.5px] leading-relaxed text-rose-200/90" role="alert">
                  {message}
                </div>
              ) : null}

              <button type="submit" className="btn-primary h-10 w-full" disabled={busy || demoBusy}>
                {busy ? <Spinner className="text-accent-soft" label="Signing in" /> : <ShieldCheck className="h-4 w-4" />}
                {busy ? "Verifying credentials…" : "Sign in"}
              </button>
            </form>

            <div className="my-5 flex items-center gap-3 text-[10px] uppercase tracking-[0.16em] text-slate-600">
              <span className="h-px flex-1 bg-white/[0.07]" />
              or
              <span className="h-px flex-1 bg-white/[0.07]" />
            </div>

            <button type="button" className="btn-secondary h-10 w-full" onClick={startDemo} disabled={busy || demoBusy}>
              {demoBusy ? <Spinner label="Starting demo" /> : null}
              {demoBusy ? "Preparing demo session…" : "Enter demo as SOC Analyst"}
            </button>

            <div className="mt-5 rounded-xl border border-white/[0.06] bg-ink-900/60 p-3">
              <div className="flex items-center justify-between">
                <p className="label">Demonstration accounts</p>
                <span className="font-mono text-[9.5px] text-slate-600">password: {DEMO_PASSWORD}</span>
              </div>
              <ul className="mt-2 space-y-0.5">
                {demoAccounts.map((account) => (
                  <li key={account.email}>
                    <button
                      type="button"
                      onClick={() => {
                        setEmail(account.email);
                        setPassword(DEMO_PASSWORD);
                      }}
                      className="flex w-full items-center justify-between gap-3 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-white/[0.04]"
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-[11.5px] text-slate-300">{account.name}</span>
                        <span className="block truncate font-mono text-[10px] text-slate-600">{account.email}</span>
                      </span>
                      <span className="shrink-0 text-[10px] text-slate-500">{account.role}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <p className="mt-4 text-center text-[10.5px] leading-relaxed text-slate-600">
            Demo accounts are synthetic and contain labelled scenario data only. They are disabled when demo mode is
            turned off by an administrator.
          </p>
          <p className="mt-3 text-center text-[11px] text-slate-500 lg:hidden">
            <Link to="/" className="hover:text-slate-300">
              ← Back to overview
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
