import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "@/lib/api";
import type { SessionInfo, Workspace } from "@/lib/types";

interface AuthContextValue {
  session: SessionInfo | null;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string, remember: boolean) => Promise<void>;
  demoLogin: () => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  workspaces: Workspace[];
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.get<SessionInfo>("/auth/me");
      setSession(data);
      setError(null);
    } catch {
      setSession(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const onUnauthorized = () => setSession(null);
    window.addEventListener("sentinel:unauthorized", onUnauthorized);
    return () => window.removeEventListener("sentinel:unauthorized", onUnauthorized);
  }, []);

  const login = useCallback(async (email: string, password: string, remember: boolean) => {
    setError(null);
    try {
      await api.post("/auth/login", { email, password, remember });
      await refresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Sign-in failed.";
      setError(message);
      throw err;
    }
  }, [refresh]);

  const demoLogin = useCallback(async () => {
    setError(null);
    try {
      await api.post("/auth/demo-login");
      await refresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Demo sign-in is unavailable.";
      setError(message);
      throw err;
    }
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // session may already be invalid
    }
    setSession(null);
    sessionStorage.removeItem("sentinel.workspace");
  }, []);

  const hasPermission = useCallback(
    (permission: string) => Boolean(session?.user.role.permissions.includes(permission)),
    [session],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      loading,
      error,
      login,
      demoLogin,
      logout,
      refresh,
      hasPermission,
      workspaces: session?.workspaces ?? [],
    }),
    [session, loading, error, login, demoLogin, logout, refresh, hasPermission],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
