"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Filter,
  Globe,
  Lock,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  IndicatorDetailOut,
  PaginatedIndicatorsOut,
  ThreatIndicatorLookupRequest,
  ThreatIntelStatsOut,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth } from "@/components/providers";
import { formatDateTime, formatRelativeTime } from "@/lib/format";

export default function ThreatIntelligencePage() {
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState("");
  const [iocTypeFilter, setIocTypeFilter] = useState<string>("");
  const [reputationFilter, setReputationFilter] = useState<string>("");
  const [page, setPage] = useState(1);

  // Quick lookup form state
  const [lookupType, setLookupType] = useState<string>("ip");
  const [lookupValue, setLookupValue] = useState("");
  const [forceRefresh, setForceRefresh] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  // Inspector drawer state
  const [selectedIndicator, setSelectedIndicator] = useState<IndicatorDetailOut | null>(null);

  // 1. Threat Intel Stats Query
  const statsQuery = useQuery({
    queryKey: ["threat-intel-stats"],
    queryFn: () => apiRequest<ThreatIntelStatsOut>("/api/v1/enrichment/stats"),
    refetchInterval: 30_000,
  });

  // 2. Indicators List Query
  const indicatorsQuery = useQuery({
    queryKey: ["threat-indicators", searchTerm, iocTypeFilter, reputationFilter, page],
    queryFn: () => {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: "25",
      });
      if (searchTerm.trim()) params.set("search", searchTerm.trim());
      if (iocTypeFilter) params.set("ioc_type", iocTypeFilter);
      if (reputationFilter) params.set("reputation", reputationFilter);
      return apiRequest<PaginatedIndicatorsOut>(`/api/v1/enrichment/indicators?${params.toString()}`);
    },
  });

  // 3. On-Demand Lookup Mutation
  const lookupMutation = useMutation({
    mutationFn: (req: ThreatIndicatorLookupRequest) =>
      apiRequest<IndicatorDetailOut>("/api/v1/enrichment/lookup", {
        method: "POST",
        body: JSON.stringify(req),
      }),
    onSuccess: (data) => {
      setLookupError(null);
      setSelectedIndicator(data);
      void queryClient.invalidateQueries({ queryKey: ["threat-indicators"] });
      void queryClient.invalidateQueries({ queryKey: ["threat-intel-stats"] });
    },
    onError: (err: any) => {
      setLookupError(err?.message || "Threat intelligence lookup failed.");
    },
  });

  const handleLookupSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupValue.trim()) return;
    lookupMutation.mutate({
      ioc_type: lookupType as any,
      value: lookupValue.trim(),
      force_refresh: forceRefresh,
    });
  };

  const stats = statsQuery.data;
  const indicators = indicatorsQuery.data?.items || [];
  const totalIndicators = indicatorsQuery.data?.total || 0;

  const canRunEnrichment = hasPermission("enrichment:run");

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <Globe className="h-6 w-6 text-primary" />
            Threat Intelligence & IOC Enrichment
          </h1>
          <p className="text-sm text-muted-foreground">
            Multi-source adversary indicator correlation with VirusTotal, AbuseIPDB, AlienVault OTX, and RFC 1918 internal IP leak protection.
          </p>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-xs font-medium uppercase tracking-wider">Total Indicators</span>
            <Globe className="h-4 w-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-foreground">
            {statsQuery.isLoading ? "..." : stats?.total_indicators ?? 0}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">Global observed IOCs</div>
        </div>

        <div className="rounded-lg border border-red-500/30 bg-red-950/10 p-4">
          <div className="flex items-center justify-between text-red-400">
            <span className="text-xs font-medium uppercase tracking-wider">Malicious</span>
            <AlertOctagon className="h-4 w-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-red-400">
            {statsQuery.isLoading ? "..." : stats?.malicious_count ?? 0}
          </div>
          <div className="mt-1 text-xs text-red-500/80">Confirmed adversary infrastructure</div>
        </div>

        <div className="rounded-lg border border-amber-500/30 bg-amber-950/10 p-4">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-xs font-medium uppercase tracking-wider">Suspicious</span>
            <AlertTriangle className="h-4 w-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400">
            {statsQuery.isLoading ? "..." : stats?.suspicious_count ?? 0}
          </div>
          <div className="mt-1 text-xs text-amber-500/80">Anomalous probe & scan activity</div>
        </div>

        <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 p-4">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-xs font-medium uppercase tracking-wider">Benign</span>
            <ShieldCheck className="h-4 w-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400">
            {statsQuery.isLoading ? "..." : stats?.benign_count ?? 0}
          </div>
          <div className="mt-1 text-xs text-emerald-500/80">Clean infrastructure & public DNS</div>
        </div>

        <div className="rounded-lg border border-blue-500/30 bg-blue-950/10 p-4 col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between text-blue-400">
            <span className="text-xs font-medium uppercase tracking-wider">Internal Assets</span>
            <Lock className="h-4 w-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-blue-400">
            {statsQuery.isLoading ? "..." : stats?.internal_count ?? 0}
          </div>
          <div className="mt-1 text-xs text-blue-400/80">Protected RFC 1918 / Intranet</div>
        </div>
      </div>

      {/* On-Demand Indicator Lookup Box */}
      {canRunEnrichment && (
        <div className="rounded-lg border border-border bg-card p-5 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
              <Search className="h-4 w-4 text-primary" />
              On-Demand Threat Intelligence Lookup
            </h2>
            <span className="text-xs text-muted-foreground flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-emerald-400" />
              RFC 1918 Leak Prevention Active
            </span>
          </div>

          <form onSubmit={handleLookupSubmit} className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <select
              value={lookupType}
              onChange={(e) => setLookupType(e.target.value)}
              className="h-10 rounded-md border border-input bg-background px-3 py-1 text-sm font-medium shadow-sm focus:outline-none focus:ring-1 focus:ring-ring sm:w-36"
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain Name</option>
              <option value="sha256">SHA-256 Hash</option>
              <option value="md5">MD5 Hash</option>
              <option value="url">URL</option>
            </select>

            <div className="relative flex-1">
              <input
                type="text"
                placeholder={
                  lookupType === "ip"
                    ? "e.g. 185.220.101.5 or 10.20.40.31"
                    : lookupType === "domain"
                    ? "e.g. bad-actor-c2.net"
                    : lookupType === "sha256"
                    ? "e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                    : "Enter indicator value..."
                }
                value={lookupValue}
                onChange={(e) => setLookupValue(e.target.value)}
                className="h-10 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm font-mono placeholder:font-sans focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </div>

            <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none whitespace-nowrap">
              <input
                type="checkbox"
                checked={forceRefresh}
                onChange={(e) => setForceRefresh(e.target.checked)}
                className="rounded border-input text-primary focus:ring-ring"
              />
              Bypass Cache
            </label>

            <button
              type="submit"
              disabled={lookupMutation.isPending || !lookupValue.trim()}
              className="inline-flex h-10 items-center justify-center rounded-md bg-primary px-5 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 disabled:opacity-50"
            >
              {lookupMutation.isPending ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  Querying Providers...
                </>
              ) : (
                "Enrich Indicator"
              )}
            </button>
          </form>

          {lookupError && (
            <div className="mt-3 rounded-md bg-destructive/10 border border-destructive/20 p-2.5 text-xs text-destructive flex items-center justify-between">
              <span>{lookupError}</span>
              <button onClick={() => setLookupError(null)} className="text-destructive/70 hover:text-destructive">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* Indicator Search & Filters */}
      <div className="rounded-lg border border-border bg-card">
        <div className="flex flex-col gap-3 border-b border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative flex-1 sm:max-w-xs">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search indicators..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              className="h-9 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 text-muted-foreground" />
              <select
                value={iocTypeFilter}
                onChange={(e) => {
                  setIocTypeFilter(e.target.value);
                  setPage(1);
                }}
                className="h-8 rounded-md border border-input bg-background px-2.5 text-xs font-medium"
              >
                <option value="">All IOC Types</option>
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="sha256">SHA-256</option>
                <option value="md5">MD5</option>
                <option value="url">URL</option>
              </select>
            </div>

            <select
              value={reputationFilter}
              onChange={(e) => {
                setReputationFilter(e.target.value);
                setPage(1);
              }}
              className="h-8 rounded-md border border-input bg-background px-2.5 text-xs font-medium"
            >
              <option value="">All Reputations</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="benign">Benign</option>
              <option value="internal">Internal</option>
              <option value="unknown">Unknown</option>
            </select>
          </div>
        </div>

        {/* Indicators Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-4 py-3 font-semibold">Indicator Value</th>
                <th className="px-4 py-3 font-semibold">Type</th>
                <th className="px-4 py-3 font-semibold">Reputation</th>
                <th className="px-4 py-3 font-semibold">Confidence</th>
                <th className="px-4 py-3 font-semibold">Enrichment Sources</th>
                <th className="px-4 py-3 font-semibold">Last Seen</th>
                <th className="px-4 py-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {indicatorsQuery.isLoading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                    <RefreshCw className="mx-auto h-5 w-5 animate-spin mb-2" />
                    Loading threat indicators...
                  </td>
                </tr>
              ) : indicators.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                    No threat indicators found matching current filters.
                  </td>
                </tr>
              ) : (
                indicators.map((ind) => {
                  const repBadge = getReputationBadge(ind.reputation);
                  return (
                    <tr
                      key={ind.id}
                      onClick={() => setSelectedIndicator(ind)}
                      className="cursor-pointer transition-colors hover:bg-muted/30"
                    >
                      <td className="px-4 py-3 font-mono text-xs font-semibold text-foreground max-w-xs truncate">
                        {ind.value}
                        {ind.is_simulated && (
                          <span className="ml-2 rounded bg-amber-500/10 px-1 py-0.5 text-[10px] text-amber-400">
                            SIMULATED
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-muted px-2 py-0.5 text-xs uppercase font-mono text-muted-foreground">
                          {ind.ioc_type}
                        </span>
                      </td>
                      <td className="px-4 py-3">{repBadge}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden">
                            <div
                              className={`h-full ${
                                ind.reputation === "malicious"
                                  ? "bg-red-500"
                                  : ind.reputation === "suspicious"
                                  ? "bg-amber-500"
                                  : ind.reputation === "internal"
                                  ? "bg-blue-500"
                                  : "bg-emerald-500"
                              }`}
                              style={{ width: `${ind.confidence}%` }}
                            />
                          </div>
                          <span className="text-xs text-muted-foreground">{ind.confidence}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {ind.enrichments && ind.enrichments.length > 0 ? (
                            ind.enrichments.map((e) => (
                              <span
                                key={e.id}
                                className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                                  e.is_mock
                                    ? "bg-muted text-muted-foreground border border-border"
                                    : "bg-primary/10 text-primary border border-primary/20"
                                }`}
                                title={`${e.provider}: ${e.summary}`}
                              >
                                {e.provider}
                                {e.is_mock && " (mock)"}
                              </span>
                            ))
                          ) : (
                            <span className="text-xs text-muted-foreground italic">Pending</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {formatRelativeTime(ind.last_seen_at)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedIndicator(ind);
                          }}
                          className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                          title="View Inspector"
                        >
                          <Search className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between border-t border-border px-4 py-3 text-xs text-muted-foreground">
          <div>
            Showing {indicators.length} of {totalIndicators} indicators
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="rounded border border-border px-2.5 py-1 text-xs hover:bg-muted disabled:opacity-50"
            >
              Previous
            </button>
            <span>Page {page}</span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={indicators.length < 25}
              className="rounded border border-border px-2.5 py-1 text-xs hover:bg-muted disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Slide-over Indicator Inspector Drawer */}
      {selectedIndicator && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="h-full w-full max-w-xl border-l border-border bg-card p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div className="space-y-6">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-border pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-muted px-2 py-0.5 text-xs uppercase font-mono font-bold text-muted-foreground">
                      {selectedIndicator.ioc_type}
                    </span>
                    {getReputationBadge(selectedIndicator.reputation)}
                    {selectedIndicator.is_internal && (
                      <span className="rounded bg-blue-500/20 px-2 py-0.5 text-xs text-blue-400 font-medium">
                        RFC 1918 Private
                      </span>
                    )}
                  </div>
                  <h3 className="mt-2 text-lg font-mono font-bold text-foreground break-all">
                    {selectedIndicator.value}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedIndicator(null)}
                  className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Summary Stats */}
              <div className="grid grid-cols-2 gap-4 rounded-lg border border-border bg-muted/20 p-4">
                <div>
                  <div className="text-xs text-muted-foreground">Confidence Score</div>
                  <div className="mt-1 text-xl font-bold text-foreground">{selectedIndicator.confidence}%</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">First Seen</div>
                  <div className="mt-1 text-sm font-medium text-foreground">
                    {formatDateTime(selectedIndicator.first_seen_at)}
                  </div>
                </div>
              </div>

              {/* Provider Enrichment Details */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Provider Intelligence Breakdown ({selectedIndicator.enrichments?.length || 0})
                </h4>

                {selectedIndicator.enrichments && selectedIndicator.enrichments.length > 0 ? (
                  selectedIndicator.enrichments.map((e) => (
                    <div key={e.id} className="rounded-lg border border-border bg-background p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-sm text-foreground capitalize">{e.provider}</span>
                          {e.is_mock && (
                            <span className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-400 border border-amber-500/20">
                              SIMULATED MOCK
                            </span>
                          )}
                        </div>
                        {getReputationBadge(e.reputation)}
                      </div>

                      <p className="text-xs text-foreground/90">{e.summary}</p>

                      {e.malicious_count !== null && e.total_engines !== null && (
                        <div className="flex items-center gap-4 text-xs text-muted-foreground pt-1">
                          <span>
                            Detections:{" "}
                            <strong className="text-foreground">
                              {e.malicious_count} / {e.total_engines}
                            </strong>
                          </span>
                          <span>Confidence: {e.confidence_score}%</span>
                        </div>
                      )}

                      {e.source_references && e.source_references.length > 0 && (
                        <div className="pt-2 border-t border-border flex flex-wrap gap-2">
                          {e.source_references.map((ref, idx) => (
                            <a
                              key={idx}
                              href={ref}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline"
                            >
                              External Reference <ExternalLink className="h-3 w-3" />
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-muted-foreground italic">No provider lookups recorded yet.</p>
                )}
              </div>
            </div>

            {/* Footer */}
            <div className="pt-6 border-t border-border flex justify-between items-center text-xs text-muted-foreground">
              <span>ID: {selectedIndicator.id}</span>
              <button
                onClick={() => setSelectedIndicator(null)}
                className="rounded-md border border-border px-4 py-2 font-medium hover:bg-muted"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function getReputationBadge(rep: string) {
  switch (rep) {
    case "malicious":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-red-500/10 px-2 py-0.5 text-xs font-semibold text-red-400 border border-red-500/20">
          <AlertOctagon className="h-3 w-3" />
          Malicious
        </span>
      );
    case "suspicious":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 text-xs font-semibold text-amber-400 border border-amber-500/20">
          <AlertTriangle className="h-3 w-3" />
          Suspicious
        </span>
      );
    case "benign":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-500/20">
          <CheckCircle2 className="h-3 w-3" />
          Benign
        </span>
      );
    case "internal":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-blue-500/10 px-2 py-0.5 text-xs font-semibold text-blue-400 border border-blue-500/20">
          <Lock className="h-3 w-3" />
          Internal RFC 1918
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded bg-muted px-2 py-0.5 text-xs font-semibold text-muted-foreground">
          Unknown
        </span>
      );
  }
}
