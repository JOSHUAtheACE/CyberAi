import { ArrowLeft, Compass } from "lucide-react";
import { Link } from "react-router-dom";
import { SentinelLogo } from "@/components/layout/Logo";

export function NotFound() {
  return (
    <div className="flex min-h-screen flex-col bg-ink-950">
      <header className="flex h-[64px] items-center px-5 sm:px-8">
        <Link to="/" aria-label="SENTINEL AI home">
          <SentinelLogo />
        </Link>
      </header>
      <main className="flex flex-1 items-center justify-center px-5 pb-20">
        <div className="max-w-md text-center">
          <div className="mx-auto mb-5 flex h-12 w-12 items-center justify-center rounded-xl border border-white/[0.08] bg-white/[0.025] text-slate-500">
            <Compass className="h-5 w-5" />
          </div>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-600">404 · route not found</p>
          <h1 className="mt-2 text-[24px] font-semibold tracking-[-0.02em] text-slate-100">This path is not part of the workspace</h1>
          <p className="mt-2 text-[12.5px] leading-relaxed text-slate-500">
            The link may be outdated, or the resource may have been removed. Internal navigation stays inside the
            signed-in environment.
          </p>
          <div className="mt-6 flex items-center justify-center gap-2">
            <Link to="/app/overview" className="btn-primary h-9">
              <ArrowLeft className="h-3.5 w-3.5" />
              Return to overview
            </Link>
            <Link to="/" className="btn-secondary h-9">
              Landing page
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}
