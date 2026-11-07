"use client";

import React, { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  FileSearch,
  Plus,
  RefreshCw,
  Upload,
} from "lucide-react";
import {
  PaginatedAlertsOut,
  SentinelApiError,
  apiRequest,
} from "@/lib/api/generated";
import {
  AlertTriageBadge,
  SeverityBadge,
  SimulatedBadge,
} from "@/components/ui/badges";
import { Modal } from "@/components/ui/modal";
import { useAuth, useToast } from "@/components/providers";
import { formatDateTime } from "@/lib/format";

function AlertInboxContent() {
  const searchParams = useSearchParams();
  const initialSearch = searchParams.get("search") || "";

  const [search, setSearch] = useState(initialSearch);
  const [severity, setSeverity] = useState("");
  const [triageStatus, setTriageStatus] = useState("");
  const [page, setPage] = useState(1);
  const [manualModalOpen, setManualModalOpen] = useState(false);
  const [jsonModalOpen, setJsonModalOpen] = useState(false);

  const { hasPermission } = useAuth();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["alerts", page, severity, triageStatus, search],
    queryFn: () =>
      apiRequest<PaginatedAlertsOut>("/api/v1/alerts", {
        params: {
          page,
          page_size: 25,
          severity: severity || undefined,
          triage_status: triageStatus || undefined,
          search: search || undefined,
        },
      }),
  });

  // Manual alert form state
  const [ruleId, setRuleId] = useState("MANUAL-1001");
  const [ruleDesc, setRuleDesc] = useState("");
  const [category, setCategory] = useState("authentication");
  const [manualSev, setManualSev] = useState<"low" | "medium" | "high" | "critical">("high");
  const [srcIp, setSrcIp] = useState("");
  const [hostname, setHostname] = useState("");
  const [username, setUsername] = useState("");

  const createManualMutation = useMutation({
    mutationFn: () =>
      apiRequest("/api/v1/alerts", {
        method: "POST",
        body: {
          source_system: "manual",
          rule_id: ruleId,
          rule_description: ruleDesc,
          event_category: category,
          severity: manualSev,
          src_ip: srcIp || null,
          hostname: hostname || null,
          username: username || null,
        },
      }),
    onSuccess: () => {
      pushToast({
        title: "Manual alert ingested",
        description: "Normalized and fingerprinted into the Alert Inbox.",
        variant: "success",
      });
      setManualModalOpen(false);
      setRuleDesc("");
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["command-center"] });
    },
    onError: (err) => {
      pushToast({
        title: "Failed to ingest alert",
        description: err instanceof SentinelApiError ? err.message : "Unexpected error",
        variant: "error",
      });
    },
  });

  const [jsonBatchText, setJsonBatchText] = useState("");
  const importJsonMutation = useMutation({
    mutationFn: () => {
      const parsed = JSON.parse(jsonBatchText);
      const alertsArray = Array.isArray(parsed) ? parsed : [parsed];
      return apiRequest("/api/v1/alerts/import/json", {
        method: "POST",
        body: { alerts: alertsArray, format: "wazuh" },
      });
    },
    onSuccess: () => {
      pushToast({
        title: "Wazuh JSON alert(s) imported",
        description: "Parsed ATT&CK metadata and applied deduplication window.",
        variant: "success",
      });
      setJsonModalOpen(false);
      setJsonBatchText("");
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
    onError: (err) => {
      pushToast({
        title: "Invalid JSON or import error",
        description: err instanceof Error ? err.message : "Failed to parse Wazuh JSON",
        variant: "error",
      });
    },
  });

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Alert Inbox</h1>
          <p className="text-xs text-soc-muted mt-0.5">
            Normalized detection stream from Wazuh SIEM webhooks, JSON imports, and SOC simulations
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {hasPermission("alerts:create") && (
            <>
              <button
                type="button"
                onClick={() => setManualModalOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-md bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white"
              >
                <Plus className="w-3.5 h-3.5" />
                Ingest Manual Alert
              </button>
              <button
                type="button"
                onClick={() => setJsonModalOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-md border border-soc-border bg-soc-surface hover:bg-soc-elevated px-3 py-1.5 text-xs font-medium"
              >
                <Upload className="w-3.5 h-3.5" />
                Import Wazuh JSON
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() => void refetch()}
            className="inline-flex items-center gap-1.5 rounded-md border border-soc-border bg-soc-surface hover:bg-soc-elevated px-3 py-1.5 text-xs font-medium"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 rounded-lg border border-soc-border bg-soc-surface p-3">
        <input
          type="search"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          placeholder="Filter rule, host, user, IP, domain..."
          aria-label="Search alerts"
          className="sm:col-span-2 rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text"
        />
        <select
          aria-label="Filter by severity"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
          className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          aria-label="Filter by triage status"
          value={triageStatus}
          onChange={(e) => {
            setTriageStatus(e.target.value);
            setPage(1);
          }}
          className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text"
        >
          <option value="">All Triage States</option>
          <option value="new">New (Unreviewed)</option>
          <option value="in_review">In Review</option>
          <option value="escalated">Escalated</option>
          <option value="incident_created">Case Linked</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {/* Alerts Table */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-soc-border text-[11px] uppercase tracking-wider text-soc-muted bg-soc-elevated/40">
              <th className="py-2.5 px-4">Severity</th>
              <th className="py-2.5 px-4">Rule &amp; Detection</th>
              <th className="py-2.5 px-4">Host / Principal</th>
              <th className="py-2.5 px-4">Source Indicator</th>
              <th className="py-2.5 px-4">Status</th>
              <th className="py-2.5 px-4">Last Seen</th>
              <th className="py-2.5 px-4 text-right">Workbench</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border text-xs">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-soc-muted">
                  Loading detection alerts...
                </td>
              </tr>
            ) : !data || data.items.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-10 text-center text-soc-muted">
                  No alerts match the current filters.
                </td>
              </tr>
            ) : (
              data.items.map((alert) => (
                <tr key={alert.id} className="hover:bg-soc-elevated/50 transition-colors">
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={alert.severity} />
                      {alert.occurrence_count > 1 && (
                        <span
                          title="Deduplicated alert occurrences within fingerprint window"
                          className="px-1.5 py-0.5 rounded bg-soc-elevated border border-soc-border font-mono text-[10px] text-soc-muted"
                        >
                          x{alert.occurrence_count}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 max-w-md">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-sky-400">
                        [{alert.source_system}:{alert.rule_id}]
                      </span>
                      {alert.is_simulated && <SimulatedBadge />}
                    </div>
                    <Link
                      href={`/alerts/${alert.id}`}
                      className="font-medium text-soc-text hover:text-sky-400 block mt-0.5"
                    >
                      {alert.rule_description}
                    </Link>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px]">
                    <div>{alert.hostname || "—"}</div>
                    <div className="text-soc-muted">{alert.username ? `user:${alert.username}` : ""}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px]">
                    {alert.src_ip || alert.domain || (alert.file_hash ? `${alert.file_hash.slice(0, 12)}…` : "—")}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex flex-col gap-1 items-start">
                      <AlertTriageBadge status={alert.triage_status} />
                      {alert.linked_incident_human_id && (
                        <Link
                          href={`/incidents/${alert.linked_incident_human_id}`}
                          className="font-mono text-[11px] text-emerald-400 hover:underline"
                        >
                          → {alert.linked_incident_human_id}
                        </Link>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-soc-muted">
                    {formatDateTime(alert.last_seen_at)}
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <Link
                      href={`/alerts/${alert.id}/triage`}
                      className="inline-flex items-center gap-1 rounded border border-sky-500/35 bg-sky-500/10 hover:bg-sky-500/20 px-2.5 py-1 text-xs font-medium text-sky-300"
                    >
                      <FileSearch className="w-3.5 h-3.5" />
                      Triage
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Manual Alert Modal */}
      <Modal
        open={manualModalOpen}
        title="Ingest Manual Security Alert"
        description="Enters the same normalization, asset matching, and fingerprint deduplication pipeline as SIEM webhooks."
        onClose={() => setManualModalOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            createManualMutation.mutate();
          }}
          className="space-y-3 text-xs"
        >
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-soc-muted mb-1">Rule ID</label>
              <input
                required
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Initial Severity</label>
              <select
                value={manualSev}
                onChange={(e) => setManualSev(e.target.value as any)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-soc-muted mb-1">Alert Description</label>
            <input
              required
              minLength={4}
              value={ruleDesc}
              onChange={(e) => setRuleDesc(e.target.value)}
              placeholder="e.g., Suspicious outbound SSH connection from database server"
              className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-soc-muted mb-1">Category</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5"
              >
                <option value="authentication">Authentication</option>
                <option value="malware">Malware</option>
                <option value="execution">Execution</option>
                <option value="privilege_escalation">Privilege Escalation</option>
                <option value="network">Network</option>
                <option value="dns">DNS</option>
              </select>
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Source IP</label>
              <input
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                placeholder="198.51.100.25"
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Hostname</label>
              <input
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="prod-bastion-01"
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-soc-muted mb-1">Affected Username (optional)</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="svc_deploy"
              className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5 font-mono"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-soc-border">
            <button
              type="button"
              onClick={() => setManualModalOpen(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted hover:text-soc-text"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createManualMutation.isPending}
              className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white disabled:opacity-50"
            >
              {createManualMutation.isPending ? "Ingesting..." : "Ingest Alert"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Wazuh JSON Import Modal */}
      <Modal
        open={jsonModalOpen}
        title="Import Wazuh Alert JSON"
        description="Paste a single Wazuh alert JSON object or an array of Wazuh alert objects."
        onClose={() => setJsonModalOpen(false)}
        maxWidthClass="max-w-2xl"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            importJsonMutation.mutate();
          }}
          className="space-y-3 text-xs"
        >
          <textarea
            required
            rows={10}
            value={jsonBatchText}
            onChange={(e) => setJsonBatchText(e.target.value)}
            placeholder='{"rule":{"id":"5712","level":10,"description":"sshd: brute force"},"agent":{"name":"prod-bastion-01"},"data":{"srcip":"198.51.100.42","dstuser":"svc_deploy"}}'
            className="w-full rounded border border-soc-border bg-soc-bg p-3 font-mono text-xs"
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setJsonModalOpen(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={importJsonMutation.isPending}
              className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white"
            >
              {importJsonMutation.isPending ? "Importing..." : "Import JSON"}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

export default function AlertInboxPage() {
  return (
    <Suspense fallback={<div className="text-xs text-soc-muted">Loading Alert Inbox...</div>}>
      <AlertInboxContent />
    </Suspense>
  );
}

