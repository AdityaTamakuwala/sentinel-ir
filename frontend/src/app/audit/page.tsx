"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  CheckCircle2,
  Download,
  Eye,
  Filter,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  AuditChainVerificationOut,
  AuditLogItemOut,
  PaginatedAuditLogsOut,
  SentinelApiError,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth, useToast } from "@/components/providers";
import { RoleBadge } from "@/components/ui/badges";
import { Modal } from "@/components/ui/modal";
import { formatDateTime } from "@/lib/format";

export default function AuditCompliancePage() {
  const { hasPermission } = useAuth();
  const { pushToast } = useToast();

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState("");
  const [selectedEntry, setSelectedEntry] = useState<AuditLogItemOut | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [chainResult, setChainResult] = useState<AuditChainVerificationOut | null>(null);

  const canRead = hasPermission("audit:read");
  const canExport = hasPermission("audit:export");

  const auditQuery = useQuery({
    queryKey: ["audit-logs", page, search, actorFilter, actionFilter, outcomeFilter],
    enabled: canRead,
    queryFn: () =>
      apiRequest<PaginatedAuditLogsOut>("/api/v1/audit", {
        params: {
          page,
          page_size: 25,
          search: search || undefined,
          actor_username: actorFilter || undefined,
          action: actionFilter || undefined,
          outcome: outcomeFilter || undefined,
        },
      }),
  });

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await apiRequest<AuditChainVerificationOut>("/api/v1/audit/verify");
      setChainResult(res);
      pushToast({
        title: res.valid
          ? "Cryptographic Hash Chain Verified"
          : "Audit Chain Integrity Failure Detected",
        description: res.valid
          ? `Verified ${res.checked_count} append-only audit entries.`
          : res.reason || `Chain broken at sequence #${res.broken_at_seq}`,
        variant: res.valid ? "success" : "error",
      });
    } catch (err) {
      const msg = err instanceof SentinelApiError ? err.message : "Verification request failed";
      pushToast({ title: "Verification Error", description: msg, variant: "error" });
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = async (format: "json" | "csv") => {
    try {
      const blob = await apiRequest<Blob>("/api/v1/audit/export", {
        params: { format, limit: 1000 },
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentinel-ir-audit-logs.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      pushToast({
        title: `Audit Log Export (${format.toUpperCase()})`,
        description: "Tamper-evident export downloaded and recorded in the audit ledger.",
        variant: "success",
      });
      void auditQuery.refetch();
    } catch (err) {
      const msg = err instanceof SentinelApiError ? err.message : "Export failed";
      pushToast({ title: "Audit Export Failed", description: msg, variant: "error" });
    }
  };

  if (!canRead) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-200">
        <div className="flex items-center gap-2 font-semibold text-red-300 mb-1">
          <ShieldAlert className="w-4 h-4" />
          Restricted Governance Ledger
        </div>
        Your current role does not hold the <code className="font-mono">audit:read</code> permission.
        Audit ledger inspection requires SOC Manager or Platform Administrator privileges.
      </div>
    );
  }

  const total = auditQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / 25));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-sky-400" />
            Tamper-Evident Audit & Compliance Ledger
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Append-only PostgreSQL ledger protected by database triggers, revoked{" "}
            <code className="font-mono">UPDATE/DELETE</code> privileges, and sequential SHA-256 hash chaining.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void handleVerifyChain()}
            disabled={verifying}
            className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/25 disabled:opacity-50"
          >
            <ShieldCheck className={`w-4 h-4 ${verifying ? "animate-pulse" : ""}`} />
            {verifying ? "Verifying Chain..." : "Verify SHA-256 Chain"}
          </button>

          {canExport && (
            <>
              <button
                type="button"
                onClick={() => void handleExport("csv")}
                className="inline-flex items-center gap-1.5 rounded-md border border-soc-border bg-soc-elevated px-3 py-1.5 text-xs font-medium text-soc-text hover:border-sky-500/40"
              >
                <Download className="w-3.5 h-3.5 text-sky-400" />
                Export CSV
              </button>
              <button
                type="button"
                onClick={() => void handleExport("json")}
                className="inline-flex items-center gap-1.5 rounded-md border border-soc-border bg-soc-elevated px-3 py-1.5 text-xs font-medium text-soc-text hover:border-sky-500/40"
              >
                <Download className="w-3.5 h-3.5 text-sky-400" />
                Export JSON
              </button>
            </>
          )}

          <button
            type="button"
            onClick={() => void auditQuery.refetch()}
            className="inline-flex items-center gap-1.5 rounded-md border border-soc-border bg-soc-surface px-3 py-1.5 text-xs text-soc-muted hover:text-soc-text"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${auditQuery.isFetching ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Chain Integrity Result Banner */}
      {chainResult && (
        <div
          className={`rounded-lg border p-4 text-xs flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 ${
            chainResult.valid
              ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-200"
              : "border-red-500/40 bg-red-500/15 text-red-200"
          }`}
        >
          <div className="flex items-start gap-2.5">
            {chainResult.valid ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            )}
            <div>
              <p className="font-semibold">
                {chainResult.valid
                  ? `Cryptographic Integrity Verified (${chainResult.checked_count} sequential entries)`
                  : `Hash Chain Integrity Violation at seq #${chainResult.broken_at_seq}`}
              </p>
              <p className="text-[11px] opacity-85 mt-0.5 font-mono break-all">
                {chainResult.valid
                  ? `Head SHA-256: ${chainResult.head_hash || "GENESIS"}`
                  : chainResult.reason}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
        <div className="flex items-center gap-2 text-xs font-medium text-soc-muted mb-3">
          <Filter className="w-3.5 h-3.5 text-sky-400" />
          Filter Ledger Entries
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <input
            type="search"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search action, target ID, correlation ID..."
            aria-label="Search audit entries"
            className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-sky-500"
          />
          <input
            type="text"
            value={actorFilter}
            onChange={(e) => {
              setActorFilter(e.target.value);
              setPage(1);
            }}
            placeholder="Filter actor username..."
            aria-label="Filter by actor username"
            className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-sky-500"
          />
          <input
            type="text"
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setPage(1);
            }}
            placeholder="Action prefix (e.g. auth., incident.)"
            aria-label="Filter by action"
            className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-sky-500"
          />
          <select
            value={outcomeFilter}
            onChange={(e) => {
              setOutcomeFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by outcome"
            className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text focus:outline-none focus:border-sky-500"
          >
            <option value="">All Outcomes</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="denied">Denied</option>
          </select>
        </div>
      </div>

      {/* Audit Table */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border bg-soc-elevated/60 text-[11px] uppercase tracking-wider text-soc-muted">
              <tr>
                <th className="px-4 py-3 font-semibold">Seq</th>
                <th className="px-4 py-3 font-semibold">Timestamp</th>
                <th className="px-4 py-3 font-semibold">Actor</th>
                <th className="px-4 py-3 font-semibold">Action</th>
                <th className="px-4 py-3 font-semibold">Target</th>
                <th className="px-4 py-3 font-semibold">Outcome</th>
                <th className="px-4 py-3 font-semibold">Entry Hash</th>
                <th className="px-4 py-3 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {auditQuery.isLoading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-10 text-center text-soc-muted">
                    Loading cryptographic audit ledger...
                  </td>
                </tr>
              ) : auditQuery.data?.items.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-10 text-center text-soc-muted">
                    No audit records match the active filter criteria.
                  </td>
                </tr>
              ) : (
                auditQuery.data?.items.map((item) => (
                  <tr key={item.id} className="hover:bg-soc-elevated/40 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-sky-300">#{item.seq}</td>
                    <td className="px-4 py-2.5 font-mono whitespace-nowrap text-soc-muted">
                      {formatDateTime(item.occurred_at)}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-medium text-soc-text">
                          {item.actor_username}
                        </span>
                        {item.actor_role && <RoleBadge role={item.actor_role} />}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-soc-text">{item.action}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-soc-muted">{item.target_type}</span>
                      {item.target_id && (
                        <span className="block font-mono text-[11px] text-soc-text truncate max-w-[180px]">
                          {item.target_id}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${
                          item.outcome === "success"
                            ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                            : "bg-red-500/15 text-red-300 border-red-500/30"
                        }`}
                      >
                        {item.outcome}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-soc-muted">
                      {item.entry_hash.slice(0, 14)}…
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => setSelectedEntry(item)}
                        className="inline-flex items-center gap-1 rounded border border-soc-border bg-soc-bg px-2 py-1 text-[11px] text-soc-muted hover:text-soc-text hover:border-sky-500/40"
                      >
                        <Eye className="w-3 h-3" />
                        Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between border-t border-soc-border px-4 py-3 text-xs text-soc-muted">
          <span>
            Showing page {page} of {totalPages} ({total} total ledger entries)
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="rounded border border-soc-border px-2.5 py-1 disabled:opacity-40 hover:bg-soc-elevated"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="rounded border border-soc-border px-2.5 py-1 disabled:opacity-40 hover:bg-soc-elevated"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Entry Inspection Modal */}
      <Modal
        open={Boolean(selectedEntry)}
        title={selectedEntry ? `Audit Ledger Entry #${selectedEntry.seq}` : "Audit Entry"}
        description={selectedEntry?.action}
        onClose={() => setSelectedEntry(null)}
        maxWidthClass="max-w-2xl"
      >
        {selectedEntry && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 rounded-md border border-soc-border bg-soc-bg p-3">
              <div>
                <span className="text-soc-muted block">Actor</span>
                <span className="font-mono font-medium">
                  {selectedEntry.actor_username} ({selectedEntry.actor_role || "system"})
                </span>
              </div>
              <div>
                <span className="text-soc-muted block">Occurred At</span>
                <span className="font-mono">{formatDateTime(selectedEntry.occurred_at)}</span>
              </div>
              <div>
                <span className="text-soc-muted block">Source IP</span>
                <span className="font-mono">{selectedEntry.source_ip || "—"}</span>
              </div>
              <div>
                <span className="text-soc-muted block">Correlation ID</span>
                <span className="font-mono break-all">{selectedEntry.correlation_id}</span>
              </div>
            </div>

            <div className="rounded-md border border-soc-border bg-soc-bg p-3 space-y-2 font-mono text-[11px]">
              <div>
                <span className="text-soc-muted block">Previous Hash (prev_hash)</span>
                <span className="break-all text-soc-text">{selectedEntry.prev_hash}</span>
              </div>
              <div>
                <span className="text-soc-muted block">Entry Hash (SHA-256)</span>
                <span className="break-all text-emerald-300">{selectedEntry.entry_hash}</span>
              </div>
            </div>

            <div>
              <span className="text-soc-muted block mb-1.5 font-medium">Structured Event Details</span>
              <pre className="rounded-md border border-soc-border bg-soc-bg p-3 font-mono text-[11px] overflow-x-auto text-soc-text">
                {JSON.stringify(selectedEntry.details_json, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

