import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useAuth } from "@/context/AuthContext";
import type { Workspace } from "@/lib/types";

export type RangeKey = "1h" | "6h" | "24h" | "7d" | "30d";

interface WorkspaceContextValue {
  workspace: Workspace | null;
  workspaces: Workspace[];
  workspaceSlug: string;
  setWorkspaceSlug: (slug: string) => void;
  range: RangeKey;
  setRange: (range: RangeKey) => void;
  environment: string;
  isDemo: boolean;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

const RANGE_STORAGE = "sentinel.range";
const WORKSPACE_STORAGE = "sentinel.workspace";

function readRange(): RangeKey {
  const stored = sessionStorage.getItem(RANGE_STORAGE) as RangeKey | null;
  return stored && ["1h", "6h", "24h", "7d", "30d"].includes(stored) ? stored : "24h";
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const workspaces = session?.workspaces ?? [];
  const [workspaceSlug, setWorkspaceSlugState] = useState<string>(() => {
    return sessionStorage.getItem(WORKSPACE_STORAGE) ?? "demo";
  });
  const [range, setRangeState] = useState<RangeKey>(readRange);

  useEffect(() => {
    if (!workspaces.length) return;
    if (!workspaces.some((workspace) => workspace.slug === workspaceSlug)) {
      const fallback = workspaces.find((workspace) => workspace.slug === "demo") ?? workspaces[0];
      setWorkspaceSlugState(fallback.slug);
    }
  }, [workspaces, workspaceSlug]);

  const setWorkspaceSlug = useCallback((slug: string) => {
    setWorkspaceSlugState(slug);
    sessionStorage.setItem(WORKSPACE_STORAGE, slug);
  }, []);

  const setRange = useCallback((next: RangeKey) => {
    setRangeState(next);
    sessionStorage.setItem(RANGE_STORAGE, next);
  }, []);

  const workspace = useMemo(
    () => workspaces.find((item) => item.slug === workspaceSlug) ?? workspaces[0] ?? null,
    [workspaces, workspaceSlug],
  );

  const value = useMemo<WorkspaceContextValue>(
    () => ({
      workspace,
      workspaces,
      workspaceSlug: workspace?.slug ?? workspaceSlug,
      setWorkspaceSlug,
      range,
      setRange,
      environment: workspace?.environment ?? "OFFLINE",
      isDemo: workspace?.environment === "DEMO" || workspace?.environment === "REPLAY",
    }),
    [workspace, workspaces, workspaceSlug, setWorkspaceSlug, range, setRange],
  );

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const context = useContext(WorkspaceContext);
  if (!context) throw new Error("useWorkspace must be used within WorkspaceProvider");
  return context;
}
