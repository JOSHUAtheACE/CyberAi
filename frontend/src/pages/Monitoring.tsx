import { useQuery } from "@tanstack/react-query";
import {
  ArrowRightLeft,
  Download,
  Network,
  Search,
  ShieldAlert,
  Waypoints,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ChartPanel, Pagination, SummaryStrip } from "@/components/app";
import { EChart } from "@/components/charts/EChart";
import { TopologyGraph } from "@/components/topology/TopologyGraph";
import {
  Badge,
  EmptyState,
  ErrorState,
  InfoHint,
  Modal,
  PageHeader,
  PageLoader,
  Panel,
  SectionTitle,
  SeverityBadge,
  Spinner,
  StatusBadge,
  Tabs,
} from "@/components/ui";
import { useWorkspace } from "@/context/WorkspaceContext";
import { api } from "@/lib/api";
import { lineOption, paletteCycle, shortBucket } from "@/lib/charts";
import { cn, formatBytes, formatDateTime, formatDuration, formatNumber, relativeTime } from "@/lib/format";
import type { Flow, HostProfile, TopologyNode, TopologyResponse } from "@/lib/types";

type Tab = "flows" | "topology";

const PROTOCOLS = ["TCP", "UDP", "ICMP", "GRE", "ESP", "OTHER"];
const DIRECTIONS = ["inbound", "outbound", "internal", "external"];

export function Monitoring() {
  const { workspaceSlug, range, isDemo } = useWorkspace();
  const [tab, setTab] = useState<Tab>("flows");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("");
  const [direction, setDirection] = useState("");
  const [suspicious, setSuspicious] = useState(false);
  const [page, setPage] = useState(1);
  const [hostIp, setHostIp] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);

  const flows = useQuery({
    queryKey: ["flows", workspaceSlug, range, query, protocol, direction, suspicious, page],
    queryFn: () =>
      api.get<{
        items: Flow[];
        total: number;
        page: number;
        page_size: number;
        period: { label: string; start: string; end: string };
        workspace: { slug: string; environment: string };
        classification_note: string;
      }>("/monitoring/flows", {
        workspace: workspaceSlug,
        range,
        q: query || undefined,
        protocol: protocol || undefined,
        direction: direction || undefined,
        suspicious,
        page,
        page_size: 25,
      }),
    enabled: tab === "flows",
  });

  const topology = useQuery({
    queryKey: ["topology", workspaceSlug, range],
    queryFn: () => api.get<TopologyResponse>("/dashboard/topology", { workspace: workspaceSlug, range }),
    enabled: tab === "topology",
  });

  const host = useQuery({
    queryKey: ["host", workspaceSlug, range, hostIp],
    queryFn: () => api.get<HostProfile>(`/monitoring/hosts/${encodeURIComponent(hostIp ?? "")}`, { workspace: workspaceSlug, range }),
    enabled: Boolean(hostIp),
  });

  const hostTimeline = useMemo(() => {
    const points = host.data?.timeline ?? [];
    return lineOption({
      labels: points.map((point) => shortBucket(point.bucket)),
      series: [
        { name: "Sent MiB", data: points.map((point) => point.sent_mib), color: paletteCycle[1], area: true },
        { name: "Received MiB", data: points.map((point) => point.received_mib), color: paletteCycle[0], area: true },
      ],
    });
  }, [host.data]);

  const submitSearch = () => {
    setQuery(search.trim());
    setPage(1);
  };

  return (
    <div>
      <PageHeader
        eyebrow="Network monitoring"
        title="Traffic & topology"
        description={`Flow-level visibility derived from stored passive observations. ${isDemo ? "This workspace contains synthetic scenario telemetry and is labelled accordingly." : "No active probing or host interaction takes place."}`}
        actions={
          <Tabs
            tabs={[
              { value: "flows", label: "Flow explorer", count: flows.data?.total },
              { value: "topology", label: "Topology" },
            ]}
            value={tab}
            onChange={setTab}
          />
        }
      />

      {tab === "flows" ? (
        <>
          <div className="flex flex-wrap items-center gap-2 rounded-xl border border-white/[0.06] bg-ink-900/50 p-2.5">
            <form
              className="flex min-w-[220px] flex-1 items-center gap-2 rounded-lg border border-white/[0.08] bg-ink-950/50 px-2.5"
              onSubmit={(event) => {
                event.preventDefault();
                submitSearch();
              }}
            >
              <Search className="h-3.5 w-3.5 text-slate-500" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search IP, reference, DNS name or SNI"
                aria-label="Search flows"
                className="h-8 w-full bg-transparent text-[12px] text-slate-200 placeholder:text-slate-600 focus:outline-none"
              />
              {query ? (
                <button
                  type="button"
                  className="text-[10px] text-slate-500 hover:text-slate-300"
                  onClick={() => {
                    setSearch("");
                    setQuery("");
                    setPage(1);
                  }}
                >
                  Clear
                </button>
              ) : null}
            </form>
            <select
              aria-label="Protocol filter"
              value={protocol}
              onChange={(event) => {
                setProtocol(event.target.value);
                setPage(1);
              }}
              className="h-8 rounded-lg border border-white/[0.08] bg-ink-950/50 px-2 text-[11.5px] text-slate-300 focus:outline-none"
            >
              <option value="">All protocols</option>
              {PROTOCOLS.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
            <select
              aria-label="Direction filter"
              value={direction}
              onChange={(event) => {
                setDirection(event.target.value);
                setPage(1);
              }}
              className="h-8 rounded-lg border border-white/[0.08] bg-ink-950/50 px-2 text-[11.5px] text-slate-300 focus:outline-none"
            >
              <option value="">All directions</option>
              {DIRECTIONS.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => {
                setSuspicious((value) => !value);
                setPage(1);
              }}
              aria-pressed={suspicious}
              className={cn(
                "inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-[11.5px] transition-colors",
                suspicious
                  ? "border-signal-rose/30 bg-signal-rose/[0.08] text-rose-200"
                  : "border-white/[0.08] bg-ink-950/50 text-slate-400 hover:text-slate-200",
              )}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Alert-linked only
            </button>
            <button type="button" className="btn-ghost h-8 px-2" onClick={() => flows.refetch()} aria-label="Refresh flows">
              <Download className={cn("h-3.5 w-3.5", flows.isFetching ? "animate-pulse" : "")} />
            </button>
          </div>

          <div className="mt-3">
            <SummaryStrip
              items={[
                { label: "Matching flows", value: formatNumber(flows.data?.total ?? 0) },
                { label: "Window", value: flows.data?.period.label ?? range },
                { label: "Environment", value: flows.data?.workspace.environment ?? "—" },
                { label: "Page", value: `${flows.data?.page ?? 1} / ${Math.max(1, Math.ceil((flows.data?.total ?? 0) / 25))}` },
              ]}
            />
          </div>

          <Panel className="mt-3 overflow-hidden">
            {flows.isLoading ? (
              <div className="flex h-64 items-center justify-center">
                <Spinner label="Loading flows" />
              </div>
            ) : flows.isError ? (
              <div className="p-4">
                <ErrorState
                  message={flows.error instanceof Error ? flows.error.message : "Flows could not be loaded."}
                  retry={() => flows.refetch()}
                />
              </div>
            ) : flows.data?.items.length ? (
              <>
                <div className="overflow-x-auto">
                  <table className="table-base min-w-[1040px]">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th className="w-6" aria-label="Direction" />
                        <th>Destination</th>
                        <th>Protocol</th>
                        <th>Volume</th>
                        <th>Packets</th>
                        <th>Duration</th>
                        <th>Context</th>
                        <th>Geo</th>
                      </tr>
                    </thead>
                    <tbody>
                      {flows.data.items.map((flow) => (
                        <tr key={flow.id}>
                          <td>
                            <span className="font-mono text-[10.5px] text-slate-400">{formatDateTime(flow.ts)}</span>
                            <p className="font-mono text-[9.5px] text-slate-600">{flow.reference}</p>
                          </td>
                          <td>
                            <button
                              type="button"
                              className="font-mono text-[11.5px] text-slate-300 hover:text-accent-soft hover:underline"
                              onClick={() => setHostIp(flow.src_ip)}
                            >
                              {flow.src_ip}
                              <span className="text-slate-600">:{flow.src_port}</span>
                            </button>
                          </td>
                          <td className="px-0 text-slate-600">
                            <ArrowRightLeft className="h-3 w-3" />
                          </td>
                          <td>
                            <button
                              type="button"
                              className="font-mono text-[11.5px] text-slate-300 hover:text-accent-soft hover:underline"
                              onClick={() => setHostIp(flow.dst_ip)}
                            >
                              {flow.dst_ip}
                              <span className="text-slate-600">:{flow.dst_port}</span>
                            </button>
                            {flow.direction ? (
                              <p className="text-[9.5px] uppercase tracking-[0.06em] text-slate-600">{flow.direction}</p>
                            ) : null}
                          </td>
                          <td>
                            <Badge tone={flow.protocol === "UDP" ? "blue" : flow.protocol === "TCP" ? "slate" : "neutral"}>
                              {flow.protocol}
                            </Badge>
                            {flow.app_proto ? <p className="mt-0.5 text-[9.5px] text-slate-600">{flow.app_proto}</p> : null}
                          </td>
                          <td>
                            <span className="font-mono text-[11px] text-slate-300">{formatBytes(flow.bytes_total)}</span>
                            <p className="font-mono text-[9.5px] text-slate-600">
                              ↑{formatBytes(flow.bytes_out)} ↓{formatBytes(flow.bytes_in)}
                            </p>
                          </td>
                          <td className="font-mono text-[11px] text-slate-400">{formatNumber(flow.packets)}</td>
                          <td className="font-mono text-[11px] text-slate-400">{formatDuration(flow.duration_ms)}</td>
                          <td>
                            {flow.dns_query ? (
                              <p className="max-w-[190px] truncate font-mono text-[10.5px] text-slate-400" title={flow.dns_query}>
                                {flow.dns_query}
                              </p>
                            ) : null}
                            {flow.tls_sni ? (
                              <p className="max-w-[190px] truncate font-mono text-[10.5px] text-slate-500" title={flow.tls_sni}>
                                {flow.tls_sni}
                              </p>
                            ) : null}
                            {flow.tls_ja3 ? (
                              <p className="font-mono text-[9.5px] text-slate-600">ja3 {flow.tls_ja3.slice(0, 12)}…</p>
                            ) : null}
                            {!flow.dns_query && !flow.tls_sni && !flow.tls_ja3 ? <span className="text-slate-600">—</span> : null}
                          </td>
                          <td>
                            <span className="text-[10.5px] text-slate-400">
                              {flow.src_country ? `${flow.src_city ?? "—"}, ${flow.src_country}` : "—"}
                            </span>
                            <p className="text-[9.5px] text-slate-600">
                              → {flow.dst_country ? `${flow.dst_city ?? "—"}, ${flow.dst_country}` : "internal / unknown"}
                            </p>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pagination page={flows.data.page} pageSize={flows.data.page_size} total={flows.data.total} onChange={setPage} />
              </>
            ) : (
              <EmptyState
                title="No flows match these filters"
                description="Flow rows are stored records only. Loosen the filters or widen the time range."
                icon={<Network className="h-4 w-4" />}
              />
            )}
            {flows.data ? (
              <p className="border-t border-white/[0.05] px-4 py-2.5 text-[10.5px] leading-relaxed text-slate-600">
                {flows.data.classification_note}
              </p>
            ) : null}
          </Panel>
        </>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <SummaryStrip
              items={[
                { label: "Nodes", value: formatNumber(topology.data?.meta.displayed_nodes ?? 0) },
                { label: "Edges", value: formatNumber(topology.data?.meta.displayed_edges ?? 0) },
                { label: "Truncated", value: topology.data?.meta.truncated ? "yes" : "no", tone: topology.data?.meta.truncated ? "danger" : "default" },
                { label: "Derived from", value: topology.data?.meta.derived_from ?? "stored flows" },
              ]}
            />
            <span className="flex items-center gap-1.5 text-[10.5px] text-slate-600">
              {topology.data?.range.label}
              <InfoHint text="Nodes are internal assets or external endpoints observed in stored flows. Threat-linked nodes carry alert severity, not an inferred reputation." />
            </span>
          </div>

          {topology.isLoading ? (
            <PageLoader label="Building topology from stored flows" />
          ) : topology.isError ? (
            <ErrorState
              message={topology.error instanceof Error ? topology.error.message : "Topology could not be built."}
              retry={() => topology.refetch()}
            />
          ) : topology.data?.has_data ? (
            <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
              <TopologyGraph
                nodes={topology.data.nodes}
                edges={topology.data.edges}
                selectedId={selectedNode?.id ?? null}
                onSelect={(node) => setSelectedNode(node)}
                height={620}
              />
              <div className="space-y-4">
                {selectedNode ? (
                  <Panel className="p-4">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="label">Selected node</p>
                        <p className="mt-1 font-mono text-[13px] text-slate-100">{selectedNode.label}</p>
                      </div>
                      <Badge tone={selectedNode.internal ? "blue" : "slate"}>{selectedNode.internal ? "internal" : "external"}</Badge>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <p className="label mb-0.5">Flows</p>
                        <p className="font-mono text-slate-300">{formatNumber(selectedNode.flows)}</p>
                      </div>
                      <div>
                        <p className="label mb-0.5">Volume</p>
                        <p className="font-mono text-slate-300">{formatBytes(selectedNode.bytes)}</p>
                      </div>
                      <div>
                        <p className="label mb-0.5">Protocols</p>
                        <p className="text-slate-300">{selectedNode.protocols.join(", ") || "—"}</p>
                      </div>
                      <div>
                        <p className="label mb-0.5">Alerts</p>
                        <p className="font-mono text-slate-300">{formatNumber(selectedNode.alerts)}</p>
                      </div>
                    </div>
                    {selectedNode.threat ? (
                      <div className="mt-3 flex items-center justify-between rounded-md border border-signal-rose/20 bg-signal-rose/[0.05] px-2.5 py-2">
                        <span className="text-[10.5px] text-rose-200/80">Threat-linked observation</span>
                        <SeverityBadge severity={selectedNode.severity} />
                      </div>
                    ) : null}
                    {selectedNode.threat_classes.length ? (
                      <p className="mt-2 text-[10.5px] text-slate-500">{selectedNode.threat_classes.join(" · ")}</p>
                    ) : null}
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button type="button" className="btn-secondary px-2.5 py-1.5 text-[11px]" onClick={() => setHostIp(selectedNode.label)}>
                        Open host profile
                      </button>
                      <Link to={`/app/alerts?q=${encodeURIComponent(selectedNode.label)}`} className="btn-ghost px-2.5 py-1.5 text-[11px]">
                        Alerts mentioning host
                      </Link>
                    </div>
                  </Panel>
                ) : (
                  <Panel className="p-4">
                    <div className="flex items-center gap-2 text-[11.5px] text-slate-300">
                      <Waypoints className="h-3.5 w-3.5 text-accent" />
                      Select a node
                    </div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">
                      Click any node to inspect observed volume, protocols and alert linkage. Drag nodes, scroll to zoom,
                      or refit the graph with the controls.
                    </p>
                  </Panel>
                )}
                <Panel className="p-4">
                  <p className="label mb-2">Construction</p>
                  <ul className="space-y-1.5 text-[10.5px] leading-relaxed text-slate-500">
                    <li>Edges aggregate stored flows between endpoint pairs.</li>
                    <li>Private addresses are classified against the workspace internal CIDRs.</li>
                    <li>Suspicious edges connect endpoints named in an alert.</li>
                    <li>No DNS resolution or probing is performed to build the graph.</li>
                  </ul>
                </Panel>
              </div>
            </div>
          ) : (
            <EmptyState
              title="No topology for this window"
              description="The graph only renders when stored flows contain at least one endpoint pair. Ingest telemetry or widen the range."
              icon={<Waypoints className="h-4 w-4" />}
            />
          )}
        </>
      )}

      <Modal
        open={Boolean(hostIp)}
        onClose={() => setHostIp(null)}
        title={hostIp ? `Host profile · ${hostIp}` : "Host profile"}
        description="Built only from stored passive observations in this workspace."
        width="max-w-3xl"
      >
        {host.isLoading ? (
          <div className="flex h-48 items-center justify-center">
            <Spinner label="Loading host profile" />
          </div>
        ) : host.isError ? (
          <ErrorState
            message={host.error instanceof Error ? host.error.message : "Host profile unavailable."}
            retry={() => host.refetch()}
          />
        ) : host.data ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={host.data.role.includes("internal") ? "blue" : "slate"}>{host.data.role}</Badge>
              {host.data.geo.country ? (
                <Badge tone="neutral">
                  {[host.data.geo.city, host.data.geo.country].filter(Boolean).join(", ")}
                </Badge>
              ) : null}
              <span className="font-mono text-[10px] text-slate-600">{host.data.period.label}</span>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {[
                ["Observations", formatNumber(host.data.totals.observations)],
                ["Outbound", formatNumber(host.data.totals.outbound_flows)],
                ["Inbound", formatNumber(host.data.totals.inbound_flows)],
                ["Volume", formatBytes(host.data.totals.bytes)],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-white/[0.06] bg-ink-900/60 px-3 py-2">
                  <p className="label mb-1">{label}</p>
                  <p className="font-mono text-[13px] text-slate-200">{value}</p>
                </div>
              ))}
            </div>
            <div className="rounded-lg border border-white/[0.06] bg-ink-900/40 p-2">
              <EChart option={hostTimeline} height={180} ariaLabel="Host traffic timeline" />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div>
                <p className="label mb-1.5">Top peers</p>
                <ul className="space-y-1 text-[10.5px]">
                  {host.data.top_peers.map((peer) => (
                    <li key={peer.ip} className="flex justify-between gap-2">
                      <span className="font-mono text-slate-400">{peer.ip}</span>
                      <span className="font-mono text-slate-600">{peer.flows}</span>
                    </li>
                  ))}
                  {!host.data.top_peers.length ? <li className="text-slate-600">—</li> : null}
                </ul>
              </div>
              <div>
                <p className="label mb-1.5">Destination ports</p>
                <ul className="space-y-1 text-[10.5px]">
                  {host.data.top_destination_ports.map((port) => (
                    <li key={port.port} className="flex justify-between gap-2">
                      <span className="font-mono text-slate-400">:{port.port}</span>
                      <span className="font-mono text-slate-600">{port.flows}</span>
                    </li>
                  ))}
                  {!host.data.top_destination_ports.length ? <li className="text-slate-600">—</li> : null}
                </ul>
              </div>
              <div>
                <p className="label mb-1.5">Protocols</p>
                <ul className="space-y-1 text-[10.5px]">
                  {host.data.protocols.map((item) => (
                    <li key={item.protocol} className="flex justify-between gap-2">
                      <span className="text-slate-400">{item.protocol}</span>
                      <span className="font-mono text-slate-600">{item.flows}</span>
                    </li>
                  ))}
                  {!host.data.protocols.length ? <li className="text-slate-600">—</li> : null}
                </ul>
              </div>
            </div>
            {host.data.alerts.length ? (
              <div>
                <p className="label mb-1.5">Alerts referencing this host</p>
                <ul className="space-y-1.5">
                  {host.data.alerts.map((alert) => (
                    <li key={alert.id} className="flex items-center gap-2 rounded-md border border-white/[0.06] bg-ink-900/60 px-2.5 py-1.5">
                      <SeverityBadge severity={alert.severity} />
                      <Link to={`/app/alerts/${alert.id}`} className="font-mono text-[10.5px] text-accent-soft hover:underline">
                        {alert.alert_code}
                      </Link>
                      <span className="truncate text-[10.5px] text-slate-500">{alert.threat_class.replace(/_/g, " ")}</span>
                      <span className="ml-auto shrink-0 text-[10px] text-slate-600">{relativeTime(alert.first_seen)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-[10.5px] text-slate-600">No alerts currently reference this host in the selected window.</p>
            )}
            <p className="text-[10.5px] leading-relaxed text-slate-600">{host.data.notice}</p>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
