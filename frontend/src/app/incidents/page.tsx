"use client";

import React, { Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderPlus, RefreshCw } from "lucide-react";
import {
  IncidentDetailOut,
  PaginatedIncidentsOut,
  SentinelApiError,
  apiRequest,
} from "@/lib/api/generated";
import {
  IncidentStatusBadge,
  SeverityBadge,
  SimulatedBadge,
  SlaBadge,
} from "@/components/ui/badges";
import { Modal } from "@/components/ui/modal";
import { useAuth, useToast } from "@/components/providers";
import { formatDateTime } from "@/lib/format";

function IncidentsListContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();
  const { pushToast } = useToast();

  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") || "");
  const [severityFilter, setSeverityFilter] = useState(searchParams.get("severity") || "");
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("general");
  const [baseSeverity, setBaseSeverity] = useState<"low" | "medium" | "high" | "critical">("high");

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["incidents", statusFilter, severityFilter, search],
    queryFn: () =>
      apiRequest<PaginatedIncidentsOut>("/api/v1/incidents", {
        params: {
          page: 1,
          page_size: 30,
          status: statusFilter || undefined,
          severity: severityFilter || undefined,
          search: search || undefined,
        },
      }),
  });

  const createMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentDetailOut>("/api/v1/incidents", {
        method: "POST",
        body: {
          title,
          description,
          category,
          base_severity: baseSeverity,
          alert_ids: [],
        },
      }),
    onSuccess: (inc) => {
      pushToast({
        title: `Incident ${inc.human_id} created`,
        variant: "success",
      });
      setCreateOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      router.push(`/incidents/${inc.human_id}`);
    },
    onError: (err) => {
      pushToast({
        title: "Failed to create incident",
        description: err instanceof SentinelApiError ? err.message : "Unexpected error",
        variant: "error",
      });
    },
  });

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Incident Management</h1>
          <p className="text-xs text-soc-muted mt-0.5">
            Full security incident case lifecycle: NEW → TRIAGED → INVESTIGATING → CONTAINMENT →
            ERADICATION → RECOVERY → RESOLVED → CLOSED
          </p>
        </div>

        <div className="flex items-center gap-2">
          {hasPermission("incidents:create") && (
            <button
              type="button"
              onClick={() => setCreateOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-md bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white"
            >
              <FolderPlus className="w-3.5 h-3.5" />
              New Incident
            </button>
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
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search INC-2026-0001, title, category..."
          aria-label="Search incidents"
          className="sm:col-span-2 rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs"
        />
        <select
          aria-label="Filter by lifecycle status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs"
        >
          <option value="">All Lifecycle States</option>
          {[
            "NEW",
            "TRIAGED",
            "INVESTIGATING",
            "CONTAINMENT",
            "ERADICATION",
            "RECOVERY",
            "RESOLVED",
            "CLOSED",
          ].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by severity"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Cases Table */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-soc-border text-[11px] uppercase tracking-wider text-soc-muted bg-soc-elevated/40">
              <th className="py-2.5 px-4">Case ID</th>
              <th className="py-2.5 px-4">Title &amp; Category</th>
              <th className="py-2.5 px-4">Severity / Risk</th>
              <th className="py-2.5 px-4">Lifecycle State</th>
              <th className="py-2.5 px-4">Owner</th>
              <th className="py-2.5 px-4">SLA</th>
              <th className="py-2.5 px-4">Created</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border text-xs">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-soc-muted">
                  Loading security incidents...
                </td>
              </tr>
            ) : !data || data.items.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-10 text-center text-soc-muted">
                  No incidents match the selected filters.
                </td>
              </tr>
            ) : (
              data.items.map((inc) => (
                <tr key={inc.id} className="hover:bg-soc-elevated/50 transition-colors">
                  <td className="py-3 px-4 whitespace-nowrap">
                    <Link
                      href={`/incidents/${inc.human_id}`}
                      className="font-mono font-semibold text-sky-400 hover:underline"
                    >
                      {inc.human_id}
                    </Link>
                  </td>
                  <td className="py-3 px-4 max-w-md">
                    <Link
                      href={`/incidents/${inc.human_id}`}
                      className="font-medium text-soc-text hover:text-sky-400 block"
                    >
                      {inc.title}
                    </Link>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[11px] font-mono text-soc-muted">
                        {inc.category} • {inc.alert_count} alert(s)
                      </span>
                      {inc.is_simulated && <SimulatedBadge />}
                    </div>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={inc.severity} />
                      <span className="font-mono text-[11px] text-soc-muted">
                        {inc.risk_score}/100
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <IncidentStatusBadge status={inc.status} />
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px]">
                    {inc.assigned_to_username ? `@${inc.assigned_to_username}` : "Unassigned"}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <SlaBadge status={inc.sla_status} />
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-soc-muted">
                    {formatDateTime(inc.created_at)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Create Incident Modal */}
      <Modal
        open={createOpen}
        title="Open Security Incident"
        description="Declare a new SOC case directly (or promote from the Alert Triage Workbench)."
        onClose={() => setCreateOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            createMutation.mutate();
          }}
          className="space-y-3 text-xs"
        >
          <div>
            <label className="block text-soc-muted mb-1">Incident Title</label>
            <input
              required
              minLength={4}
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Suspicious Lateral Movement Toward Domain Controller"
              className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-soc-muted mb-1">Category</label>
              <input
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Initial Base Severity</label>
              <select
                value={baseSeverity}
                onChange={(e) => setBaseSeverity(e.target.value as any)}
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
            <label className="block text-soc-muted mb-1">Description &amp; Scope</label>
            <textarea
              required
              minLength={4}
              rows={4}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded border border-soc-border bg-soc-bg p-2.5"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setCreateOpen(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white"
            >
              {createMutation.isPending ? "Creating..." : "Create Incident"}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense fallback={<div className="text-xs text-soc-muted">Loading Incidents...</div>}>
      <IncidentsListContent />
    </Suspense>
  );
}

