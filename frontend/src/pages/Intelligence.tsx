import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  CheckCircle2,
  Database,
  Globe2,
  KeyRound,
  Loader2,
  Lock,
  RefreshCw,
  Search,
  ShieldOff,
  Upload,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Pagination, SummaryStrip } from "@/components/app";
import {
  Badge,
  EmptyState,
  ErrorState,
  InfoHint,
  Panel,
  PageHeader,
  SectionTitle,
  Skeleton,
  Tabs,
  Toggle,
} from "@/components/ui";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { api } from "@/lib/api";
import { cn, formatDateTime, formatNumber, plural, relativeTime, titleCase } from "@/lib/format";
import type {
  IntelIndicator,
  IntelProvidersResponse,
  Paginated,
  Provider,
} from "@/lib/types";

type TabKey = "providers" | "indicators" | "enrichment" | "offline";

interface LookupResult {
  indicator: string;
  provider: string;
  cached?: boolean;
  found?: boolean;
  verdict?: string | null;
  confidence?: number | null;
  attribution?: string | null;
  source_url?: string | null;
  licence?: string | null;
  retrieved_at?: string | null;
  valid_until?: string | null;
  result?: Record<string, unknown> | null;
  summary?: string | null;
}

interface LookupResponse {
  indicator: string;
  results: LookupResult[];
  errors: { provider: string; error: string }[];
  context_notice: string;
}

interface EnrichmentRow {
  id: number;
  provider: string;
  indicator: string;
  status: string;
  cached: boolean;
  alert_id: number | null;
  error: string | null;
  retrieved_at: string;
  summary: string | null;
  verdict: string | null;
}

interface TestResponse {
  ok: boolean;
  latency_ms: number;
  message: string;
  result?: Record<string, unknown>;
}

interface SnapshotResponse {
  imported: number;
  rejected: number;
  source: string | null;
  licence: string | null;
  retrieved_at: string;
}

const CATEGORY_TONE: Record<string, "blue" | "violet" | "amber" | "mint" | "slate"> = {
  threat_intelligence: "blue",
  reputation: "violet",
  abuse: "amber",
  scanner: "mint",
  geoip: "slate",
  offline: "slate",
};

function rateLimitLabel(value: Provider["rate_limit"]): string {
  if (!value) return "not declared";
  if (typeof value === "string") return value;
  return typeof value.requests_per_minute === "number"
    ? `${value.requests_per_minute}/min`
    : "declared";
}

function rateLimitHint(value: Provider["rate_limit"]): string | undefined {
  return typeof value === "object" && value ? value.tracking : undefined;
}

function providerTone(provider: Provider) {
  if (provider.status === "READY") return "mint" as const;
  if (provider.status === "ERROR") return "rose" as const;
  if (!provider.configured) return "slate" as const;
  return "amber" as const;
}

function ProviderCard({
  provider,
  canManage,
  pending,
  testState,
  onToggle,
  onTest,
}: {
  provider: Provider;
  canManage: boolean;
  pending: boolean;
  testState?: { ok: boolean; message: string };
  onToggle: (enabled: boolean) => void;
  onTest: () => void;
}) {
  const externalBlocked = !provider.external_requests_allowed;
  const toggleDisabled = !canManage || !provider.configured || pending || (externalBlocked && !provider.enabled);
  return (
    <Panel className="flex flex-col p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-[13.5px] font-semibold tracking-tight text-slate-100">{provider.display_name}</h3>
            <Badge tone={CATEGORY_TONE[provider.category] ?? "slate"}>{titleCase(provider.category)}</Badge>
          </div>
          <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">
            {provider.notes ?? "Server-side lookups only. No telemetry is transmitted."}
          </p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-2">
          <Badge tone={providerTone(provider)} dot>
            {provider.status.replace(/_/g, " ")}
          </Badge>
          {canManage ? (
            <Toggle
              checked={provider.enabled}
              onChange={onToggle}
              disabled={toggleDisabled}
              label={`${provider.enabled ? "Disable" : "Enable"} ${provider.display_name}`}
            />
          ) : (
            <span className="text-[10px] uppercase tracking-[0.08em] text-slate-600">
              {provider.enabled ? "enabled" : "disabled"}
            </span>
          )}
        </div>
      </div>

      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 border-t border-white/[0.06] pt-3 text-[11px]">
        <div className="col-span-2">
          <dt className="label mb-1 flex items-center gap-1.5">
            <KeyRound className="h-3 w-3" /> Server credentials
            <InfoHint text="Credential values are never sent to the browser. This view reports only whether each environment variable is present." />
          </dt>
          <dd className="flex flex-wrap gap-1.5">
            {provider.credential_env.length ? (
              provider.credential_env.map((name) => (
                <span
                  key={name}
                  className={cn(
                    "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px]",
                    provider.credentials_present[name]
                      ? "border-signal-mint/25 bg-signal-mint/[0.06] text-signal-mint"
                      : "border-white/[0.07] bg-white/[0.02] text-slate-500",
                  )}
                >
                  {name}
                  <span className="text-[9px] uppercase tracking-[0.06em] opacity-80">
                    {provider.credentials_present[name] ? "present" : "missing"}
                  </span>
                </span>
              ))
            ) : (
              <span className="font-mono text-[10px] text-slate-500">no credentials required</span>
            )}
          </dd>
        </div>
        <div>
          <dt className="label mb-0.5">Rate limit</dt>
          <dd className="text-slate-400" title={rateLimitHint(provider.rate_limit)}>
            {rateLimitLabel(provider.rate_limit)}
          </dd>
        </div>
        <div>
          <dt className="label mb-0.5">Last success</dt>
          <dd className="font-mono text-[10.5px] text-slate-400">
            {provider.last_success_at ? relativeTime(provider.last_success_at) : "never"}
          </dd>
        </div>
      </dl>

      {provider.last_error ? (
        <p className="mt-2 rounded-md border border-signal-rose/20 bg-signal-rose/[0.05] px-2.5 py-1.5 text-[10.5px] leading-relaxed text-signal-rose/90">
          {provider.last_error}
        </p>
      ) : null}
      {testState ? (
        <p
          className={cn(
            "mt-2 rounded-md border px-2.5 py-1.5 text-[10.5px] leading-relaxed",
            testState.ok
              ? "border-signal-mint/20 bg-signal-mint/[0.05] text-signal-mint"
              : "border-signal-rose/20 bg-signal-rose/[0.05] text-signal-rose/90",
          )}
        >
          {testState.message}
        </p>
      ) : null}

      {externalBlocked && provider.provider !== "offline_snapshot" ? (
        <p className="mt-2 flex items-start gap-1.5 text-[10.5px] leading-relaxed text-slate-500">
          <Lock className="mt-0.5 h-3 w-3 shrink-0" />
          External enrichment is globally disabled by deployment policy. Lookups will be refused.
        </p>
      ) : null}

      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-3">
        {canManage ? (
          <button
            type="button"
            className="btn-ghost px-2.5 py-1 text-[11px]"
            onClick={onTest}
            disabled={!provider.configured || !provider.external_requests_allowed || pending}
          >
            {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            Test connection
          </button>
        ) : null}
        {provider.docs_url ? (
          <a
            href={provider.docs_url}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-[11px] text-slate-500 transition-colors hover:text-slate-300"
          >
            Documentation <ArrowUpRight className="h-3 w-3" />
          </a>
        ) : null}
        <span className="ml-auto font-mono text-[9.5px] uppercase tracking-[0.06em] text-slate-600">
          {provider.attribution ?? "attribution not declared"}
        </span>
      </div>
    </Panel>
  );
}

function LookupPanel({ providers, canLookup }: { providers: Provider[]; canLookup: boolean }) {
  const { toast } = useToast();
  const [indicator, setIndicator] = useState("");
  const [provider, setProvider] = useState("");
  const [response, setResponse] = useState<LookupResponse | null>(null);

  const enabled = useMemo(() => providers.filter((item) => item.enabled), [providers]);

  const lookup = useMutation({
    mutationFn: () =>
      api.post<LookupResponse>("/intel/lookup", {
        indicator: indicator.trim(),
        provider: provider || undefined,
      }),
    onSuccess: (data) => {
      setResponse(data);
      if (!data.results.length) toast("info", "No matching indicators", "No provider returned a result.");
    },
    onError: (error: Error) => toast("error", "Lookup refused", error.message),
  });

  return (
    <Panel className="p-4 sm:p-5">
      <SectionTitle
        eyebrow="Read-only lookup"
        title="Query an indicator"
        subtitle="Only public IP addresses and bare hostnames are eligible. Internal, private and reserved addresses are rejected before any request leaves the platform."
      />
      <form
        className="mt-4 flex flex-col gap-2 sm:flex-row"
        onSubmit={(event) => {
          event.preventDefault();
          if (!indicator.trim()) return;
          lookup.mutate();
        }}
      >
        <input
          value={indicator}
          onChange={(event) => setIndicator(event.target.value)}
          maxLength={255}
          placeholder="198.51.100.24 or example-domain.test"
          className="input flex-1"
          aria-label="Indicator to look up"
          spellCheck={false}
        />
        <select
          value={provider}
          onChange={(event) => setProvider(event.target.value)}
          className="input sm:w-52"
          aria-label="Provider"
        >
          <option value="">All enabled providers</option>
          {enabled.map((item) => (
            <option key={item.provider} value={item.provider}>
              {item.display_name}
            </option>
          ))}
        </select>
        <button type="submit" className="btn-primary px-4" disabled={!canLookup || !indicator.trim() || lookup.isPending}>
          {lookup.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
          Look up
        </button>
      </form>
      {!enabled.length ? (
        <p className="mt-2 text-[11px] text-slate-500">
          No provider is currently enabled. Enable a configured provider above, or import an offline snapshot below.
        </p>
      ) : null}

      {response ? (
        <div className="mt-4 space-y-2">
          <p className="text-[11px] leading-relaxed text-slate-500">{response.context_notice}</p>
          {response.results.map((result, index) => (
            <div key={`${result.provider}-${index}`} className="rounded-lg border border-white/[0.07] bg-ink-900/50 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[11.5px] text-slate-200">{result.indicator}</span>
                <Badge tone="slate">{result.provider.replace(/_/g, " ")}</Badge>
                {result.cached ? <Badge tone="blue">cached</Badge> : null}
                {result.found === false ? <Badge tone="mint">not listed</Badge> : null}
                {result.verdict ? <Badge tone="amber">{result.verdict}</Badge> : null}
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
                {result.summary ??
                  "Provider returned contextual metadata. A listing is evidence for investigation, not proof of compromise."}
              </p>
              <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-slate-500">
                {result.confidence !== undefined && result.confidence !== null ? (
                  <span>confidence {result.confidence}</span>
                ) : null}
                {result.licence ? <span>licence {result.licence}</span> : null}
                {result.retrieved_at ? <span>retrieved {formatDateTime(result.retrieved_at)}Z</span> : null}
                {result.valid_until ? <span>valid until {formatDateTime(result.valid_until)}Z</span> : null}
                {result.source_url ? (
                  <a href={result.source_url} target="_blank" rel="noreferrer noopener" className="text-accent-soft hover:underline">
                    source
                  </a>
                ) : null}
              </div>
            </div>
          ))}
          {response.errors.length ? (
            <div className="rounded-lg border border-signal-amber/20 bg-signal-amber/[0.04] px-3 py-2">
              {response.errors.map((item, index) => (
                <p key={index} className="text-[11px] leading-relaxed text-signal-amber/90">
                  {item.provider}: {item.error}
                </p>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </Panel>
  );
}

function OfflineImport({ canManage }: { canManage: boolean }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [source, setSource] = useState("");
  const [licence, setLicence] = useState("");
  const [entries, setEntries] = useState("");
  const [result, setResult] = useState<SnapshotResponse | null>(null);

  const importSnapshot = useMutation({
    mutationFn: () => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(entries);
      } catch {
        throw new Error("Entries must be a JSON array of indicator objects.");
      }
      if (!Array.isArray(parsed) || !parsed.length) {
        throw new Error("Entries must be a non-empty JSON array.");
      }
      return api.post<SnapshotResponse>("/intel/snapshot", {
        metadata: { source: source.trim() || "offline", licence: licence.trim() || undefined },
        entries: parsed,
      });
    },
    onSuccess: (data) => {
      setResult(data);
      setEntries("");
      toast(
        "success",
        "Snapshot imported",
        `${data.imported} ${plural(data.imported, "indicator")} added, ${data.rejected} rejected.`,
      );
      queryClient.invalidateQueries({ queryKey: ["intel-indicators"] });
      queryClient.invalidateQueries({ queryKey: ["intel-enrichment"] });
      queryClient.invalidateQueries({ queryKey: ["intel-providers"] });
    },
    onError: (error: Error) => toast("error", "Import failed", error.message),
  });

  return (
    <Panel className="p-4 sm:p-5">
      <SectionTitle
        eyebrow="Air-gapped support"
        title="Import an offline indicator snapshot"
        subtitle="Locally vetted indicators are stored under the offline_snapshot provider. Nothing is transmitted externally; entries are only queried inside this deployment."
      />
      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        <input
          value={source}
          onChange={(event) => setSource(event.target.value)}
          maxLength={120}
          placeholder="Source name, e.g. internal CTI feed"
          className="input"
          aria-label="Snapshot source"
        />
        <input
          value={licence}
          onChange={(event) => setLicence(event.target.value)}
          maxLength={160}
          placeholder="Licence or handling note"
          className="input"
          aria-label="Snapshot licence"
        />
      </div>
      <textarea
        value={entries}
        onChange={(event) => setEntries(event.target.value)}
        rows={8}
        spellCheck={false}
        placeholder='[{"indicator":"203.0.113.10","type":"ip","verdict":"c2","confidence":80}]'
        className="input mt-2 w-full resize-y font-mono text-[11px] leading-relaxed"
        aria-label="Snapshot entries JSON"
      />
      <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
        <p className="text-[10.5px] text-slate-500">
          Up to 10,000 entries per import. Each entry requires an <span className="font-mono">indicator</span>; other fields are optional.
        </p>
        <button
          type="button"
          className="btn-primary px-3 py-1.5"
          disabled={!canManage || !entries.trim() || importSnapshot.isPending}
          onClick={() => importSnapshot.mutate()}
        >
          {importSnapshot.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
          Import snapshot
        </button>
      </div>
      {!canManage ? (
        <p className="mt-2 text-[11px] text-slate-500">
          Importing indicators requires the <span className="font-mono">intel.manage</span> permission.
        </p>
      ) : null}
      {result ? (
        <div className="mt-3 rounded-lg border border-signal-mint/20 bg-signal-mint/[0.04] px-3 py-2 text-[11px] text-signal-mint">
          Imported {result.imported} · rejected {result.rejected} · source {result.source ?? "offline"} ·{" "}
          {formatDateTime(result.retrieved_at)}Z
        </div>
      ) : null}
    </Panel>
  );
}

export function Intelligence() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<TabKey>("providers");
  const [testStates, setTestStates] = useState<Record<string, { ok: boolean; message: string }>>({});
  const [pendingProvider, setPendingProvider] = useState<string | null>(null);
  const [indicatorQ, setIndicatorQ] = useState("");
  const [indicatorProvider, setIndicatorProvider] = useState("");
  const [indicatorPage, setIndicatorPage] = useState(1);
  const [enrichmentPage, setEnrichmentPage] = useState(1);

  const canManage = hasPermission("intel.manage");

  const providersQuery = useQuery({
    queryKey: ["intel-providers"],
    queryFn: () => api.get<IntelProvidersResponse>("/intel/providers"),
    refetchInterval: 60_000,
  });

  const indicatorsQuery = useQuery({
    queryKey: ["intel-indicators", indicatorQ, indicatorProvider, indicatorPage],
    queryFn: () =>
      api.get<Paginated<IntelIndicator>>("/intel/indicators", {
        q: indicatorQ || undefined,
        provider: indicatorProvider || undefined,
        page: indicatorPage,
        page_size: 20,
      }),
    enabled: tab === "indicators",
  });

  const enrichmentQuery = useQuery({
    queryKey: ["intel-enrichment", enrichmentPage],
    queryFn: () =>
      api.get<Paginated<EnrichmentRow>>("/intel/enrichment", { page: enrichmentPage, page_size: 15 }),
    enabled: tab === "enrichment",
  });

  const toggleProvider = useMutation({
    mutationFn: (vars: { provider: string; enabled: boolean }) => {
      setPendingProvider(vars.provider);
      return api.patch<Provider>(`/intel/providers/${vars.provider}`, { enabled: vars.enabled });
    },
    onSuccess: (updated) => {
      toast(
        "success",
        updated.enabled ? "Provider enabled" : "Provider disabled",
        `${updated.display_name} is now ${updated.status.toLowerCase().replace(/_/g, " ")}.`,
      );
      queryClient.invalidateQueries({ queryKey: ["intel-providers"] });
    },
    onError: (error: Error) => toast("error", "Provider could not be updated", error.message),
    onSettled: () => setPendingProvider(null),
  });

  const testProvider = useMutation({
    mutationFn: (provider: string) => {
      setPendingProvider(provider);
      return api.post<TestResponse>(`/intel/providers/${provider}/test`);
    },
    onSuccess: (result, provider) => {
      setTestStates((current) => ({
        ...current,
        [provider]: { ok: true, message: `${result.message} (${result.latency_ms} ms)` },
      }));
      queryClient.invalidateQueries({ queryKey: ["intel-providers"] });
    },
    onError: (error: Error, provider) => {
      setTestStates((current) => ({ ...current, [provider]: { ok: false, message: error.message } }));
    },
    onSettled: () => setPendingProvider(null),
  });

  const data = providersQuery.data;
  const providers = data?.providers ?? [];
  const readyProviders = providers.filter((item) => item.status === "READY").length;
  const configuredProviders = providers.filter((item) => item.configured).length;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Threat intelligence"
        title="External context, under explicit control"
        description="Read-only enrichment of public indicators. Disabled by default; credentials stay server-side and are never exposed to the browser or written to logs."
        actions={
          <div className="flex items-center gap-2">
            <Badge tone={data?.external_enrichment_allowed ? "mint" : "slate"} dot>
              {data?.external_enrichment_allowed ? "external enrichment allowed" : "external enrichment disabled"}
            </Badge>
            <button
              type="button"
              className="btn-ghost px-2.5 py-1.5"
              onClick={() => providersQuery.refetch()}
              disabled={providersQuery.isFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", providersQuery.isFetching && "animate-spin")} />
              Refresh
            </button>
          </div>
        }
      />

      {providersQuery.isError ? (
        <ErrorState message={(providersQuery.error as Error).message} retry={() => providersQuery.refetch()} />
      ) : (
        <>
          <SummaryStrip
            items={[
              { label: "Providers", value: providers.length },
              { label: "Configured", value: configuredProviders, tone: configuredProviders ? "accent" : "danger" },
              { label: "Ready", value: readyProviders, tone: readyProviders ? "accent" : "danger" },
              { label: "Cached indicators", value: formatNumber(data?.cache.indicators ?? 0) },
              { label: "Enrichment records", value: formatNumber(data?.cache.enrichment_results ?? 0) },
              { label: "Cache TTL", value: `${data?.cache.ttl_hours ?? 24}h` },
            ]}
          />

          {data && !data.external_enrichment_allowed ? (
            <Panel className="border-signal-amber/20 bg-signal-amber/[0.04] p-4">
              <div className="flex items-start gap-3">
                <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-signal-amber" />
                <div>
                  <p className="text-[12.5px] font-medium text-signal-amber">{data.policy.headline}</p>
                  <ul className="mt-2 space-y-1 text-[11.5px] leading-relaxed text-slate-400">
                    {data.policy.rules.map((rule) => (
                      <li key={rule} className="flex gap-2">
                        <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                        {rule}
                      </li>
                    ))}
                  </ul>
                  <p className="mt-2 font-mono text-[10.5px] text-slate-500">{data.policy.enable_via}</p>
                </div>
              </div>
            </Panel>
          ) : null}

          <Tabs
            tabs={[
              { value: "providers", label: "Providers", count: providers.length },
              { value: "indicators", label: "Indicator cache" },
              { value: "enrichment", label: "Enrichment log" },
              { value: "offline", label: "Offline import" },
            ]}
            value={tab}
            onChange={(value) => setTab(value as TabKey)}
          />

          {tab === "providers" ? (
            <div className="space-y-5">
              <div className="grid gap-4 xl:grid-cols-2">
                {providersQuery.isLoading
                  ? Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-56 w-full" />)
                  : providers.map((provider) => (
                      <ProviderCard
                        key={provider.provider}
                        provider={provider}
                        canManage={canManage}
                        pending={pendingProvider === provider.provider}
                        testState={testStates[provider.provider]}
                        onToggle={(enabled) => toggleProvider.mutate({ provider: provider.provider, enabled })}
                        onTest={() => testProvider.mutate(provider.provider)}
                      />
                    ))}
              </div>
              <div className="grid gap-4 xl:grid-cols-2">
                <LookupPanel providers={providers} canLookup={hasPermission("intel.view")} />
                <Panel className="p-4 sm:p-5">
                  <SectionTitle
                    eyebrow="Data handling"
                    title="What never leaves this platform"
                    subtitle="Every external lookup is a narrow, read-only request for one public indicator."
                  />
                  <ul className="mt-4 space-y-2 text-[11.5px] leading-relaxed text-slate-400">
                    {[
                      "Packet captures, flow records and analyst notes are never transmitted.",
                      "Internal hostnames, private and reserved addresses are rejected before the request.",
                      "Results are cached locally for auditability and rate-limit protection.",
                      "A provider listing is contextual evidence, not proof of compromise or attribution.",
                      "Disabling a provider takes effect immediately for new lookups.",
                    ].map((item) => (
                      <li key={item} className="flex gap-2">
                        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-600" />
                        {item}
                      </li>
                    ))}
                  </ul>
                  <div className="mt-4 flex flex-wrap gap-3 border-t border-white/[0.06] pt-3 text-[10.5px] text-slate-500">
                    <span className="inline-flex items-center gap-1.5">
                      <Database className="h-3 w-3" /> TTL {data?.cache.ttl_hours ?? 24}h
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <Globe2 className="h-3 w-3" /> public indicators only
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <Lock className="h-3 w-3" /> values never exposed
                    </span>
                  </div>
                </Panel>
              </div>
            </div>
          ) : null}

          {tab === "indicators" ? (
            <Panel className="overflow-hidden">
              <div className="flex flex-wrap items-end justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
                <div>
                  <h3 className="text-[13px] font-semibold text-slate-200">Stored indicators</h3>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Indicators retrieved from providers or imported offline. Values are cached for {data?.cache.ttl_hours ?? 24} hours.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    value={indicatorQ}
                    onChange={(event) => {
                      setIndicatorQ(event.target.value);
                      setIndicatorPage(1);
                    }}
                    placeholder="Search indicator or verdict"
                    className="input w-56 py-1.5 text-[11.5px]"
                    aria-label="Search indicators"
                  />
                  <select
                    value={indicatorProvider}
                    onChange={(event) => {
                      setIndicatorProvider(event.target.value);
                      setIndicatorPage(1);
                    }}
                    className="input w-44 py-1.5 text-[11.5px]"
                    aria-label="Filter by provider"
                  >
                    <option value="">All providers</option>
                    {providers.map((item) => (
                      <option key={item.provider} value={item.provider}>
                        {item.display_name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              {indicatorsQuery.isLoading ? (
                <div className="space-y-2 p-4">
                  {Array.from({ length: 6 }).map((_, index) => (
                    <Skeleton key={index} className="h-10 w-full" />
                  ))}
                </div>
              ) : indicatorsQuery.isError ? (
                <div className="p-4">
                  <ErrorState message={(indicatorsQuery.error as Error).message} retry={() => indicatorsQuery.refetch()} />
                </div>
              ) : !indicatorsQuery.data?.items.length ? (
                <EmptyState
                  title="No cached indicators"
                  description="Indicators appear after a provider lookup or an offline snapshot import. Nothing is fabricated to fill this table."
                  icon={<Database className="h-4 w-4" />}
                  compact
                />
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="table-base min-w-[880px]">
                      <thead>
                        <tr>
                          <th>Indicator</th>
                          <th>Type</th>
                          <th>Provider</th>
                          <th>Verdict</th>
                          <th>Confidence</th>
                          <th>Retrieved</th>
                          <th>Licence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {indicatorsQuery.data.items.map((row) => (
                          <tr key={row.id}>
                            <td className="font-mono text-[11.5px] text-slate-200">{row.indicator}</td>
                            <td className="text-[11.5px] uppercase tracking-[0.06em] text-slate-500">{row.type}</td>
                            <td>
                              <Badge tone="slate">{row.provider.replace(/_/g, " ")}</Badge>
                            </td>
                            <td className="text-[11.5px] text-slate-300">{row.verdict}</td>
                            <td className="font-mono text-[11.5px] tabular-nums text-slate-400">
                              {row.confidence ?? "—"}
                            </td>
                            <td>
                              <span className="text-[11px] text-slate-400" title={formatDateTime(row.retrieved_at)}>
                                {relativeTime(row.retrieved_at)}
                              </span>
                            </td>
                            <td className="text-[11px] text-slate-500">{row.licence ?? "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <Pagination
                    page={indicatorsQuery.data.page}
                    pageSize={indicatorsQuery.data.page_size}
                    total={indicatorsQuery.data.total}
                    onChange={setIndicatorPage}
                  />
                </>
              )}
            </Panel>
          ) : null}

          {tab === "enrichment" ? (
            <Panel className="overflow-hidden">
              <div className="border-b border-white/[0.06] px-4 py-3">
                <h3 className="text-[13px] font-semibold text-slate-200">Enrichment history</h3>
                <p className="mt-0.5 text-[11px] text-slate-500">
                  Every provider request is recorded for audit. Errors are retained rather than hidden.
                </p>
              </div>
              {enrichmentQuery.isLoading ? (
                <div className="space-y-2 p-4">
                  {Array.from({ length: 6 }).map((_, index) => (
                    <Skeleton key={index} className="h-10 w-full" />
                  ))}
                </div>
              ) : enrichmentQuery.isError ? (
                <div className="p-4">
                  <ErrorState message={(enrichmentQuery.error as Error).message} retry={() => enrichmentQuery.refetch()} />
                </div>
              ) : !enrichmentQuery.data?.items.length ? (
                <EmptyState
                  title="No enrichment requests yet"
                  description="No external provider has been queried in this deployment. The log stays empty until an approved lookup is made."
                  icon={<Globe2 className="h-4 w-4" />}
                  compact
                />
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="table-base min-w-[900px]">
                      <thead>
                        <tr>
                          <th>Indicator</th>
                          <th>Provider</th>
                          <th>Status</th>
                          <th>Source</th>
                          <th>Summary</th>
                          <th>Alert</th>
                          <th>Retrieved</th>
                        </tr>
                      </thead>
                      <tbody>
                        {enrichmentQuery.data.items.map((row) => (
                          <tr key={row.id}>
                            <td className="font-mono text-[11.5px] text-slate-200">{row.indicator}</td>
                            <td>
                              <Badge tone="slate">{row.provider.replace(/_/g, " ")}</Badge>
                            </td>
                            <td>
                              <Badge tone={row.status === "OK" || row.status === "TEST_OK" ? "mint" : "rose"}>
                                {row.status}
                              </Badge>
                            </td>
                            <td>
                              <Badge tone={row.cached ? "blue" : "slate"}>{row.cached ? "cache" : "live"}</Badge>
                            </td>
                            <td className="max-w-[280px]">
                              <p className="truncate text-[11.5px] text-slate-300" title={row.summary ?? row.error ?? ""}>
                                {row.summary ?? row.verdict ?? row.error ?? "—"}
                              </p>
                            </td>
                            <td>
                              {row.alert_id ? (
                                <Link to={`/app/alerts/${row.alert_id}`} className="font-mono text-[11px] text-accent-soft hover:underline">
                                  #{row.alert_id}
                                </Link>
                              ) : (
                                <span className="text-[11px] text-slate-600">—</span>
                              )}
                            </td>
                            <td>
                              <span className="text-[11px] text-slate-400" title={formatDateTime(row.retrieved_at)}>
                                {relativeTime(row.retrieved_at)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <Pagination
                    page={enrichmentQuery.data.page}
                    pageSize={enrichmentQuery.data.page_size}
                    total={enrichmentQuery.data.total}
                    onChange={setEnrichmentPage}
                  />
                </>
              )}
            </Panel>
          ) : null}

          {tab === "offline" ? <OfflineImport canManage={canManage} /> : null}
        </>
      )}
    </div>
  );
}
