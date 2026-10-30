import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import {
  Activity,
  Database,
  KeyRound,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  UserCog,
  Users,
} from "lucide-react";
import { useState } from "react";
import { Pagination, SummaryStrip } from "@/components/app";
import {
  Badge,
  EmptyState,
  ErrorState,
  Modal,
  Panel,
  PageHeader,
  SectionTitle,
  Skeleton,
  Stat,
  Tabs,
  Toggle,
} from "@/components/ui";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { api } from "@/lib/api";
import { cn, formatDateTime, formatNumber, relativeTime } from "@/lib/format";
import type {
  AdminOverview,
  AdminUser,
  AuditResponse,
  PlatformSettings,
  RolesResponse,
} from "@/lib/types";

type TabKey = "overview" | "users" | "roles" | "audit" | "settings";

interface NewUserState {
  name: string;
  email: string;
  role_code: string;
  password: string;
}

const ROLE_TONE: Record<string, "accent" | "blue" | "violet" | "amber" | "slate"> = {
  security_admin: "accent",
  soc_analyst: "blue",
  network_engineer: "violet",
  ml_engineer: "amber",
  auditor: "slate",
};

function UsersPanel({ roles }: { roles: RolesResponse | undefined }) {
  const { session } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<AdminUser | null>(null);
  const [draft, setDraft] = useState<NewUserState>({ name: "", email: "", role_code: "soc_analyst", password: "" });
  const [editDraft, setEditDraft] = useState({ name: "", role_code: "", is_active: true, password: "" });

  const usersQuery = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => api.get<{ items: AdminUser[]; total: number }>("/admin/users"),
  });

  const createUser = useMutation({
    mutationFn: () => api.post<AdminUser>("/admin/users", draft),
    onSuccess: (user) => {
      toast("success", "User created", `${user.email} can now sign in with the assigned role.`);
      setCreateOpen(false);
      setDraft({ name: "", email: "", role_code: "soc_analyst", password: "" });
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      queryClient.invalidateQueries({ queryKey: ["admin-overview"] });
      queryClient.invalidateQueries({ queryKey: ["admin-roles"] });
    },
    onError: (error: Error) => toast("error", "User could not be created", error.message),
  });

  const updateUser = useMutation({
    mutationFn: () =>
      api.patch<AdminUser>(`/admin/users/${editing?.id}`, {
        name: editDraft.name || undefined,
        role_code: editDraft.role_code || undefined,
        is_active: editDraft.is_active,
        password: editDraft.password || undefined,
      }),
    onSuccess: (user) => {
      toast("success", "User updated", `${user.email} was updated.`);
      setEditing(null);
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      queryClient.invalidateQueries({ queryKey: ["admin-roles"] });
      queryClient.invalidateQueries({ queryKey: ["admin-overview"] });
    },
    onError: (error: Error) => toast("error", "User could not be updated", error.message),
  });

  const openEdit = (user: AdminUser) => {
    setEditing(user);
    setEditDraft({ name: user.name, role_code: user.role.code, is_active: user.is_active, password: "" });
  };

  const roleOptions = roles?.roles ?? [];

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
        <div>
          <h3 className="text-[13px] font-semibold text-slate-200">Accounts</h3>
          <p className="mt-0.5 text-[11px] text-slate-500">
            Role permissions are enforced on every API request. Passwords are stored as scrypt hashes.
          </p>
        </div>
        <button type="button" className="btn-primary px-3 py-1.5" onClick={() => setCreateOpen(true)}>
          <Plus className="h-3.5 w-3.5" /> New user
        </button>
      </div>
      {usersQuery.isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 5 }).map((_, index) => (
            <Skeleton key={index} className="h-10 w-full" />
          ))}
        </div>
      ) : usersQuery.isError ? (
        <div className="p-4">
          <ErrorState message={(usersQuery.error as Error).message} retry={() => usersQuery.refetch()} />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="table-base min-w-[780px]">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>State</th>
                <th>Last sign-in</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {usersQuery.data?.items.map((user) => (
                <tr key={user.id}>
                  <td>
                    <span className="text-[12px] text-slate-200">{user.name}</span>
                    {user.id === session?.user.id ? (
                      <Badge tone="accent" className="ml-2">
                        you
                      </Badge>
                    ) : null}
                  </td>
                  <td className="font-mono text-[11px] text-slate-400">{user.email}</td>
                  <td>
                    <Badge tone={ROLE_TONE[user.role.code] ?? "slate"}>{user.role.name}</Badge>
                    {user.is_demo ? <Badge tone="slate" className="ml-1.5">demo</Badge> : null}
                  </td>
                  <td>
                    <span
                      className={cn(
                        "inline-flex items-center gap-1.5 text-[11px]",
                        user.is_active ? "text-signal-mint" : "text-slate-500",
                      )}
                    >
                      <span className={cn("h-1.5 w-1.5 rounded-full", user.is_active ? "bg-signal-mint" : "bg-slate-600")} />
                      {user.is_active ? "active" : "disabled"}
                    </span>
                  </td>
                  <td>
                    <span className="text-[11px] text-slate-400" title={formatDateTime(user.last_login_at)}>
                      {user.last_login_at ? relativeTime(user.last_login_at) : "never"}
                    </span>
                  </td>
                  <td className="text-right">
                    <button type="button" className="btn-ghost px-2 py-1 text-[11px]" onClick={() => openEdit(user)}>
                      <UserCog className="h-3 w-3" /> Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create a user"
        description="The password must be at least 12 characters. Share it through an approved channel."
        footer={
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-ghost px-3 py-1.5" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn-primary px-3 py-1.5"
              disabled={createUser.isPending || draft.name.length < 2 || !draft.email || draft.password.length < 12}
              onClick={() => createUser.mutate()}
            >
              {createUser.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
              Create user
            </button>
          </div>
        }
      >
        <div className="space-y-3">
          <label className="block">
            <span className="label mb-1.5 block">Full name</span>
            <input
              value={draft.name}
              onChange={(event) => setDraft({ ...draft, name: event.target.value })}
              maxLength={160}
              className="input w-full"
            />
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Email</span>
            <input
              type="email"
              value={draft.email}
              onChange={(event) => setDraft({ ...draft, email: event.target.value })}
              className="input w-full"
              autoComplete="off"
            />
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Role</span>
            <select
              value={draft.role_code}
              onChange={(event) => setDraft({ ...draft, role_code: event.target.value })}
              className="input w-full"
            >
              {roleOptions.map((role) => (
                <option key={role.code} value={role.code}>
                  {role.name}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Initial password</span>
            <input
              type="password"
              value={draft.password}
              onChange={(event) => setDraft({ ...draft, password: event.target.value })}
              minLength={12}
              className="input w-full"
              autoComplete="new-password"
            />
            <span className="mt-1 block text-[10.5px] text-slate-500">
              {draft.password.length}/12 characters minimum
            </span>
          </label>
        </div>
      </Modal>

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={editing ? `Edit ${editing.name}` : "Edit user"}
        description="Role changes apply to the next request; active sessions keep the permissions checked server-side."
        footer={
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-ghost px-3 py-1.5" onClick={() => setEditing(null)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn-primary px-3 py-1.5"
              disabled={updateUser.isPending}
              onClick={() => updateUser.mutate()}
            >
              {updateUser.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserCog className="h-3.5 w-3.5" />}
              Save changes
            </button>
          </div>
        }
      >
        {editing ? (
          <div className="space-y-3">
            <label className="block">
              <span className="label mb-1.5 block">Full name</span>
              <input
                value={editDraft.name}
                onChange={(event) => setEditDraft({ ...editDraft, name: event.target.value })}
                maxLength={160}
                className="input w-full"
              />
            </label>
            <label className="block">
              <span className="label mb-1.5 block">Role</span>
              <select
                value={editDraft.role_code}
                onChange={(event) => setEditDraft({ ...editDraft, role_code: event.target.value })}
                className="input w-full"
                disabled={editing.id === session?.user.id}
              >
                {roleOptions.map((role) => (
                  <option key={role.code} value={role.code}>
                    {role.name}
                  </option>
                ))}
              </select>
              {editing.id === session?.user.id ? (
                <span className="mt-1 block text-[10.5px] text-slate-500">You cannot change your own role.</span>
              ) : null}
            </label>
            <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2.5">
              <div>
                <p className="text-[12px] text-slate-300">Account active</p>
                <p className="mt-0.5 text-[10.5px] text-slate-500">Disabled accounts cannot sign in or use existing sessions.</p>
              </div>
              <Toggle
                checked={editDraft.is_active}
                onChange={(value) => setEditDraft({ ...editDraft, is_active: value })}
                disabled={editing.id === session?.user.id}
                label="Account active"
              />
            </div>
            <label className="block">
              <span className="label mb-1.5 block">Reset password (optional)</span>
              <input
                type="password"
                value={editDraft.password}
                onChange={(event) => setEditDraft({ ...editDraft, password: event.target.value })}
                className="input w-full"
                placeholder="Leave blank to keep the current password"
                autoComplete="new-password"
              />
            </label>
          </div>
        ) : null}
      </Modal>
    </Panel>
  );
}

function RolesPanel({ rolesQuery }: { rolesQuery: UseQueryResult<RolesResponse> }) {
  if (rolesQuery.isLoading) {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-48 w-full" />
        ))}
      </div>
    );
  }
  if (rolesQuery.isError) {
    return <ErrorState message={(rolesQuery.error as Error).message} retry={() => rolesQuery.refetch()} />;
  }
  const data = rolesQuery.data;
  if (!data) return null;
  const labels = new Map(data.permissions.map((permission) => [permission.code, permission.label]));
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        {data.roles.map((role) => (
          <Panel key={role.code} className="p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-[13px] font-semibold text-slate-100">{role.name}</h3>
                  <Badge tone={ROLE_TONE[role.code] ?? "slate"}>{role.users} users</Badge>
                </div>
                <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">{role.description}</p>
              </div>
              <ShieldCheck className="h-4 w-4 shrink-0 text-slate-600" />
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {role.permissions.map((permission) => (
                <span
                  key={permission}
                  title={labels.get(permission) ?? permission}
                  className="rounded border border-white/[0.07] bg-white/[0.02] px-1.5 py-0.5 font-mono text-[9.5px] text-slate-400"
                >
                  {permission}
                </span>
              ))}
            </div>
          </Panel>
        ))}
      </div>
      <Panel className="p-4">
        <SectionTitle
          eyebrow="Permission catalog"
          title="Server-enforced permissions"
          subtitle="Every endpoint declares the permission it requires. The browser only hides controls it knows will be refused."
        />
        <div className="mt-3 grid gap-x-6 gap-y-1.5 sm:grid-cols-2 lg:grid-cols-3">
          {data.permissions.map((permission) => (
            <div key={permission.code} className="flex items-baseline justify-between gap-3 border-b border-white/[0.04] py-1">
              <span className="font-mono text-[10.5px] text-slate-400">{permission.code}</span>
              <span className="text-right text-[10.5px] text-slate-600">{permission.label}</span>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[10.5px] text-slate-600">{data.note}</p>
      </Panel>
    </div>
  );
}

function AuditPanel() {
  const [q, setQ] = useState("");
  const [action, setAction] = useState("");
  const [page, setPage] = useState(1);

  const auditQuery = useQuery({
    queryKey: ["admin-audit", q, action, page],
    queryFn: () =>
      api.get<AuditResponse>("/admin/audit", {
        q: q || undefined,
        action: action || undefined,
        page,
        page_size: 30,
      }),
    refetchInterval: 30_000,
  });

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
        <div>
          <h3 className="text-[13px] font-semibold text-slate-200">Audit trail</h3>
          <p className="mt-0.5 text-[11px] text-slate-500">
            Immutable record of authentication, investigation, configuration and export actions.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
            <input
              value={q}
              onChange={(event) => {
                setQ(event.target.value);
                setPage(1);
              }}
              placeholder="Search actor, action or resource"
              className="input w-64 py-1.5 pl-8 text-[11.5px]"
              aria-label="Search audit log"
            />
          </div>
          <select
            value={action}
            onChange={(event) => {
              setAction(event.target.value);
              setPage(1);
            }}
            className="input w-52 py-1.5 text-[11.5px]"
            aria-label="Filter by action"
          >
            <option value="">All actions</option>
            {(auditQuery.data?.actions ?? []).map((item) => (
              <option key={item.value} value={item.value}>
                {item.value} ({item.count})
              </option>
            ))}
          </select>
        </div>
      </div>
      {auditQuery.isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 8 }).map((_, index) => (
            <Skeleton key={index} className="h-10 w-full" />
          ))}
        </div>
      ) : auditQuery.isError ? (
        <div className="p-4">
          <ErrorState message={(auditQuery.error as Error).message} retry={() => auditQuery.refetch()} />
        </div>
      ) : !auditQuery.data?.items.length ? (
        <EmptyState
          title="No audit records match"
          description="Adjust the search or action filter. Audit records are written only for real actions performed in this deployment."
          icon={<Activity className="h-4 w-4" />}
          compact
        />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="table-base min-w-[960px]">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Source IP</th>
                  <th>Metadata</th>
                </tr>
              </thead>
              <tbody>
                {auditQuery.data.items.map((event) => (
                  <tr key={event.id}>
                    <td>
                      <span className="font-mono text-[10.5px] text-slate-400">{formatDateTime(event.ts)}Z</span>
                    </td>
                    <td className="font-mono text-[11px] text-slate-300">{event.actor ?? "system"}</td>
                    <td>
                      <Badge tone="slate">{event.action}</Badge>
                    </td>
                    <td>
                      <span className="font-mono text-[10.5px] text-slate-400">
                        {event.resource_type ?? "—"}
                        {event.resource_id ? `:${event.resource_id}` : ""}
                      </span>
                    </td>
                    <td className="font-mono text-[10.5px] text-slate-500">{event.ip_address ?? "—"}</td>
                    <td className="max-w-[280px]">
                      {event.meta ? (
                        <details>
                          <summary className="cursor-pointer text-[10.5px] text-slate-500 hover:text-slate-300">
                            view
                          </summary>
                          <pre className="mt-1 overflow-x-auto rounded bg-ink-950/70 p-2 font-mono text-[9.5px] leading-relaxed text-slate-400">
                            {JSON.stringify(event.meta, null, 1)}
                          </pre>
                        </details>
                      ) : (
                        <span className="text-[10.5px] text-slate-600">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={auditQuery.data.page}
            pageSize={auditQuery.data.page_size}
            total={auditQuery.data.total}
            onChange={setPage}
          />
        </>
      )}
    </Panel>
  );
}

function SettingsPanel() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const canManage = hasPermission("users.manage");

  const settingsQuery = useQuery({
    queryKey: ["admin-settings"],
    queryFn: () => api.get<PlatformSettings>("/admin/settings"),
  });

  const toggleDemo = useMutation({
    mutationFn: (enabled: boolean) => api.patch<PlatformSettings>("/admin/settings", { demo_mode: enabled }),
    onSuccess: (data) => {
      toast(
        "success",
        data.runtime.demo_mode.enabled ? "Demo mode enabled" : "Demo mode disabled",
        "The change applies to new sign-ins and demo workspace availability.",
      );
      queryClient.invalidateQueries({ queryKey: ["admin-settings"] });
      queryClient.invalidateQueries({ queryKey: ["admin-overview"] });
    },
    onError: (error: Error) => toast("error", "Setting could not be updated", error.message),
  });

  if (settingsQuery.isLoading) return <Skeleton className="h-64 w-full" />;
  if (settingsQuery.isError) {
    return <ErrorState message={(settingsQuery.error as Error).message} retry={() => settingsQuery.refetch()} />;
  }
  const data = settingsQuery.data;
  if (!data) return null;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel className="p-4">
        <SectionTitle
          eyebrow="Runtime"
          title="Demo mode"
          subtitle="Controls whether the synthetic demo workspace and demo sign-in are available. Demo data remains permanently labelled."
        />
        <div className="mt-4 flex items-center justify-between rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-3">
          <div>
            <p className="text-[12px] text-slate-300">
              {data.runtime.demo_mode.enabled ? "Enabled" : "Disabled"}
            </p>
            <p className="mt-0.5 text-[10.5px] text-slate-500">
              {data.runtime.demo_mode.updated_at
                ? `Last changed ${relativeTime(data.runtime.demo_mode.updated_at)}`
                : "Not changed since deployment"}
            </p>
          </div>
          <Toggle
            checked={data.runtime.demo_mode.enabled}
            onChange={(value) => toggleDemo.mutate(value)}
            disabled={!canManage || toggleDemo.isPending}
            label="Demo mode"
          />
        </div>
        {!canManage ? (
          <p className="mt-2 text-[10.5px] text-slate-500">
            Changing runtime settings requires the <span className="font-mono">users.manage</span> permission.
          </p>
        ) : null}
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          <Stat label="Upload limit" value={`${data.limits.upload_mb} MB`} hint="per capture or dataset" />
          <Stat label="Preview records" value={data.limits.max_preview_records} hint="returned before upload" />
          <Stat label="Collector batch" value={formatNumber(data.limits.collector_records_per_request)} hint="records per request" />
          <Stat label="Retention" value={`${data.limits.retention_days} days`} hint="stored telemetry window" />
        </div>
      </Panel>

      <Panel className="p-4">
        <SectionTitle eyebrow="Workspaces" title="Environment separation" subtitle="Demo, replay and live telemetry are stored and queried separately." />
        <div className="mt-4 space-y-2">
          {data.workspaces.map((workspace) => (
            <div key={workspace.id} className="rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-[12px] font-medium text-slate-200">{workspace.name}</p>
                  <p className="font-mono text-[10px] text-slate-500">{workspace.slug}</p>
                </div>
                <Badge tone={workspace.environment === "LIVE" ? "rose" : workspace.environment === "DEMO" ? "violet" : workspace.environment === "REPLAY" ? "blue" : "slate"}>
                  {workspace.environment}
                </Badge>
              </div>
              {workspace.description ? (
                <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">{workspace.description}</p>
              ) : null}
              {workspace.internal_cidrs?.length ? (
                <p className="mt-1 font-mono text-[9.5px] text-slate-600">
                  internal CIDRs · {workspace.internal_cidrs.join(", ")}
                </p>
              ) : null}
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-lg border border-white/[0.06] bg-ink-900/40 px-3 py-2">
          <p className="label mb-1 flex items-center gap-1.5">
            <Lock className="h-3 w-3" /> Deployment policy
          </p>
          <ul className="space-y-1">
            {data.notes.map((note) => (
              <li key={note} className="text-[10.5px] leading-relaxed text-slate-500">
                · {note}
              </li>
            ))}
          </ul>
        </div>
      </Panel>
    </div>
  );
}

export function Admin() {
  const { hasPermission } = useAuth();
  const [tab, setTab] = useState<TabKey>("overview");
  const canManageUsers = hasPermission("users.manage");
  const canViewAudit = hasPermission("audit.view");

  const overviewQuery = useQuery({
    queryKey: ["admin-overview"],
    queryFn: () => api.get<AdminOverview>("/admin/overview"),
    refetchInterval: 45_000,
  });

  const rolesQuery = useQuery<RolesResponse>({
    queryKey: ["admin-roles"],
    queryFn: () => api.get<RolesResponse>("/admin/roles"),
    enabled: canManageUsers,
  });

  const tabs = [
    { value: "overview" as const, label: "Overview" },
    ...(canManageUsers ? [{ value: "users" as const, label: "Users" }] : []),
    ...(canManageUsers ? [{ value: "roles" as const, label: "Roles & permissions" }] : []),
    ...(canViewAudit ? [{ value: "audit" as const, label: "Audit log" }] : []),
    { value: "settings" as const, label: "Settings" },
  ];

  const overview = overviewQuery.data;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Administration"
        title="Access, audit and platform policy"
        description="Role-based access control is enforced server-side. This console manages accounts, reviews the audit trail and controls runtime policy; it never performs network remediation."
        actions={
          <button
            type="button"
            className="btn-ghost px-2.5 py-1.5"
            onClick={() => overviewQuery.refetch()}
            disabled={overviewQuery.isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", overviewQuery.isFetching && "animate-spin")} />
            Refresh
          </button>
        }
      />

      {overviewQuery.isError ? (
        <ErrorState message={(overviewQuery.error as Error).message} retry={() => overviewQuery.refetch()} />
      ) : null}

      {overview ? (
        <SummaryStrip
          items={[
            { label: "Users", value: overview.users.total },
            { label: "Active", value: overview.users.active, tone: "accent" },
            { label: "Disabled", value: overview.users.disabled, tone: overview.users.disabled ? "danger" : "default" },
            { label: "Flows stored", value: formatNumber(overview.records.flows) },
            { label: "Alerts stored", value: formatNumber(overview.records.alerts) },
            { label: "Audit events", value: formatNumber(overview.audit_events) },
          ]}
        />
      ) : null}

      <Tabs tabs={tabs} value={tab} onChange={(value) => setTab(value as TabKey)} />

      {tab === "overview" ? (
        overviewQuery.isLoading ? (
          <div className="grid gap-4 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-40 w-full" />
            ))}
          </div>
        ) : overview ? (
          <div className="grid gap-4 lg:grid-cols-3">
            <Panel className="p-4 lg:col-span-2">
              <SectionTitle eyebrow="System events" title="Recent activity" subtitle="Operational events recorded by the platform, newest first." />
              {overview.recent_events.length ? (
                <ul className="mt-3 divide-y divide-white/[0.05]">
                  {overview.recent_events.map((event) => (
                    <li key={event.id} className="flex items-start gap-3 py-2">
                      <span
                        className={cn(
                          "mt-1 h-1.5 w-1.5 shrink-0 rounded-full",
                          event.level === "error" ? "bg-signal-rose" : event.level === "warning" ? "bg-signal-amber" : "bg-signal-mint",
                        )}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="text-[11.5px] leading-relaxed text-slate-300">{event.message}</p>
                        <p className="mt-0.5 font-mono text-[9.5px] uppercase tracking-[0.06em] text-slate-600">
                          {event.category} · {formatDateTime(event.ts)}Z
                        </p>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-3 text-[11.5px] text-slate-500">No system events recorded yet.</p>
              )}
            </Panel>
            <div className="space-y-4">
              <Panel className="p-4">
                <SectionTitle eyebrow="Records" title="Stored data" />
                <div className="mt-3 grid grid-cols-2 gap-3">
                  <Stat label="Flows" value={formatNumber(overview.records.flows)} icon={<Database className="h-3.5 w-3.5" />} />
                  <Stat label="Alerts" value={formatNumber(overview.records.alerts)} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
                  <Stat label="Reports" value={formatNumber(overview.records.reports)} />
                  <Stat label="Replay sessions" value={formatNumber(overview.records.replay_sessions)} />
                </div>
              </Panel>
              <Panel className="p-4">
                <SectionTitle eyebrow="Accounts" title="Access overview" />
                <div className="mt-3 grid grid-cols-2 gap-3">
                  <Stat label="Active" value={overview.users.active} icon={<Users className="h-3.5 w-3.5" />} />
                  <Stat label="Disabled" value={overview.users.disabled} tone={overview.users.disabled ? "danger" : "default"} />
                </div>
                <p className="mt-3 flex items-start gap-1.5 text-[10.5px] leading-relaxed text-slate-500">
                  <KeyRound className="mt-0.5 h-3 w-3 shrink-0" />
                  Passwords use scrypt with a per-user salt. Sessions are signed server-side and validated on every request.
                </p>
              </Panel>
            </div>
          </div>
        ) : null
      ) : null}

      {tab === "users" && canManageUsers ? <UsersPanel roles={rolesQuery.data} /> : null}
      {tab === "roles" && canManageUsers ? <RolesPanel rolesQuery={rolesQuery} /> : null}
      {tab === "audit" && canViewAudit ? <AuditPanel /> : null}
      {tab === "settings" ? <SettingsPanel /> : null}
    </div>
  );
}
