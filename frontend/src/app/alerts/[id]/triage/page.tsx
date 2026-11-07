"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  CheckCircle,
  Copy,
  FolderPlus,
  Link2,
  ShieldX,
  UserCheck,
} from "lucide-react";
import {
  AlertDetailOut,
  IncidentDetailOut,
  PaginatedIncidentsOut,
  SentinelApiError,
  UserSummaryOut,
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

export default function AlertTriageWorkbenchPage() {
  const params = useParams<{ id: string }>();
  const alertId = params.id;
  const router = useRouter();
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const { hasPermission } = useAuth();

  const [fpModalOpen, setFpModalOpen] = useState(false);
  const [fpReason, setFpReason] = useState("");
  const [createCaseModalOpen, setCreateCaseModalOpen] = useState(false);
  const [linkCaseModalOpen, setLinkCaseModalOpen] = useState(false);
  const [noteInput, setNoteInput] = useState("");
  const [duplicateConflict, setDuplicateConflict] = useState<{
    incidentId: string;
    humanId: string;
  } | null>(null);

  const { data: alert, isLoading } = useQuery({
    queryKey: ["alert", alertId],
    queryFn: () => apiRequest<AlertDetailOut>(`/api/v1/alerts/${alertId}`),
  });

  const { data: analysts } = useQuery({
    queryKey: ["users"],
    queryFn: () => apiRequest<UserSummaryOut[]>("/api/v1/users"),
  });

  const { data: openIncidents } = useQuery({
    queryKey: ["incidents-open-list"],
    queryFn: () =>
      apiRequest<PaginatedIncidentsOut>("/api/v1/incidents", {
        params: { page: 1, page_size: 25 },
      }),
    enabled: linkCaseModalOpen,
  });

  const [caseTitle, setCaseTitle] = useState("");
  const [caseDesc, setCaseDesc] = useState("");
  const [targetIncidentId, setTargetIncidentId] = useState("");

  const triageMutation = useMutation({
    mutationFn: (body: any) =>
      apiRequest<AlertDetailOut>(`/api/v1/alerts/${alertId}/triage`, {
        method: "PATCH",
        body,
      }),
    onSuccess: (_res, vars) => {
      pushToast({
        title: `Triage action recorded: ${vars.action}`,
        description: "Written to tamper-evident audit trail.",
        variant: "success",
      });
      setFpModalOpen(false);
      setFpReason("");
      setNoteInput("");
      void queryClient.invalidateQueries({ queryKey: ["alert", alertId] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["command-center"] });
    },
    onError: (err) => {
      pushToast({
        title: "Triage action failed",
        description: err instanceof SentinelApiError ? err.message : "Request failed",
        variant: "error",
      });
    },
  });

  const createIncidentMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentDetailOut>("/api/v1/incidents", {
        method: "POST",
        headers: { "Idempotency-Key": `alert-promote-${alertId}` },
        body: {
          title: caseTitle || alert?.rule_description || "Investigate Security Alert",
          description:
            caseDesc ||
            `Promoted from ${alert?.source_system} rule ${alert?.rule_id} on host ${
              alert?.hostname || "unknown"
            }.`,
          category: alert?.event_category || "general",
          base_severity: (alert?.severity as any) || "medium",
          alert_ids: [alertId],
        },
      }),
    onSuccess: (inc) => {
      pushToast({
        title: `Incident ${inc.human_id} created`,
        description: "Entities, indicators, and ATT&CK techniques mapped.",
        variant: "success",
      });
      setCreateCaseModalOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      router.push(`/incidents/${inc.human_id}`);
    },
    onError: (err) => {
      if (
        err instanceof SentinelApiError &&
        err.code === "ALERT_ALREADY_LINKED_TO_OPEN_INCIDENT" &&
        err.details
      ) {
        setDuplicateConflict({
          incidentId: err.details.existing_incident_id,
          humanId: err.details.existing_human_id,
        });
        return;
      }
      pushToast({
        title: "Could not create incident",
        description: err instanceof SentinelApiError ? err.message : "Unexpected error",
        variant: "error",
      });
    },
  });

  const linkExistingMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentDetailOut>(`/api/v1/incidents/${targetIncidentId}/alerts`, {
        method: "POST",
        body: { alert_id: alertId },
      }),
    onSuccess: (inc) => {
      pushToast({
        title: `Alert linked to ${inc.human_id}`,
        variant: "success",
      });
      setLinkCaseModalOpen(false);
      router.push(`/incidents/${inc.human_id}`);
    },
    onError: (err) => {
      pushToast({
        title: "Failed to link alert",
        description: err instanceof SentinelApiError ? err.message : "Error",
        variant: "error",
      });
    },
  });

  if (isLoading || !alert) {
    return <div className="text-xs text-soc-muted">Loading Alert Triage Workbench...</div>;
  }

  return (
    <div className="space-y-5">
      {/* Workbench Header */}
      <div className="rounded-lg border border-soc-border bg-soc-surface p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-sky-400">
              Alert Triage Workbench
            </span>
            <SeverityBadge severity={alert.severity} />
            <AlertTriageBadge status={alert.triage_status} />
            {alert.is_simulated && <SimulatedBadge />}
          </div>
          <h1 className="text-lg font-semibold">{alert.rule_description}</h1>
          <p className="text-xs text-soc-muted mt-0.5 font-mono">
            Source: {alert.source_system}:{alert.rule_id} • Host: {alert.hostname || "N/A"} • Src IP:{" "}
            {alert.src_ip || "N/A"} • User: {alert.username || "N/A"}
          </p>
        </div>

        {/* Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2">
          {hasPermission("alerts:triage") && (
            <>
              <button
                type="button"
                onClick={() => triageMutation.mutate({ action: "mark_reviewed" })}
                className="inline-flex items-center gap-1.5 rounded border border-soc-border bg-soc-bg hover:bg-soc-elevated px-3 py-1.5 text-xs font-medium"
              >
                <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />
                Mark Reviewed
              </button>

              <button
                type="button"
                onClick={() => triageMutation.mutate({ action: "escalate" })}
                className="inline-flex items-center gap-1.5 rounded border border-orange-500/35 bg-orange-500/10 hover:bg-orange-500/20 px-3 py-1.5 text-xs font-medium text-orange-300"
              >
                <ArrowUpRight className="w-3.5 h-3.5" />
                Escalate L2
              </button>

              <button
                type="button"
                onClick={() => setFpModalOpen(true)}
                className="inline-flex items-center gap-1.5 rounded border border-soc-border bg-soc-bg hover:bg-soc-elevated px-3 py-1.5 text-xs font-medium text-soc-muted hover:text-soc-text"
              >
                <ShieldX className="w-3.5 h-3.5" />
                False Positive
              </button>
            </>
          )}

          {alert.linked_incident_human_id ? (
            <Link
              href={`/incidents/${alert.linked_incident_human_id}`}
              className="inline-flex items-center gap-1.5 rounded bg-emerald-600 hover:bg-emerald-500 px-3.5 py-1.5 text-xs font-medium text-white"
            >
              View Linked Case ({alert.linked_incident_human_id})
            </Link>
          ) : (
            hasPermission("incidents:create") && (
              <>
                <button
                  type="button"
                  onClick={() => {
                    setCaseTitle(alert.rule_description);
                    setCaseDesc(
                      `Investigation initiated from ${alert.source_system} rule ${alert.rule_id}.\nAffected Host: ${
                        alert.hostname || "N/A"
                      }\nSource IP: ${alert.src_ip || "N/A"}\nPrincipal: ${alert.username || "N/A"}`
                    );
                    setDuplicateConflict(null);
                    setCreateCaseModalOpen(true);
                  }}
                  className="inline-flex items-center gap-1.5 rounded bg-sky-600 hover:bg-sky-500 px-3.5 py-1.5 text-xs font-medium text-white"
                >
                  <FolderPlus className="w-3.5 h-3.5" />
                  Create Incident
                </button>
                {hasPermission("incidents:update") && (
                  <button
                    type="button"
                    onClick={() => setLinkCaseModalOpen(true)}
                    className="inline-flex items-center gap-1.5 rounded border border-soc-border bg-soc-bg hover:bg-soc-elevated px-3 py-1.5 text-xs font-medium"
                  >
                    <Link2 className="w-3.5 h-3.5" />
                    Link Existing
                  </button>
                )}
              </>
            )
          )}
        </div>
      </div>

      {/* Main Split Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Recommended Playbook Steps, Assignment & Triage Notes */}
        <div className="lg:col-span-5 space-y-4">
          {/* Assignment Card */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-2.5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-soc-muted flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-sky-400" />
              Triage Ownership
            </h2>
            <div className="flex items-center gap-2">
              <select
                aria-label="Assign alert to analyst"
                value={alert.assigned_to_id || ""}
                onChange={(e) =>
                  triageMutation.mutate({
                    action: "assign",
                    assigned_to_id: e.target.value || null,
                  })
                }
                className="flex-1 rounded border border-soc-border bg-soc-bg px-2.5 py-1.5 text-xs"
              >
                <option value="">— Unassigned —</option>
                {(analysts || []).map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.full_name} (@{u.username} • {u.role.toUpperCase()})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Recommended Triage Checklist */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
            <h2 className="text-sm font-semibold mb-2.5">Recommended Triage Steps</h2>
            <ol className="space-y-2 text-xs text-soc-muted list-decimal list-inside">
              {alert.recommended_steps.map((step, idx) => (
                <li key={idx} className="leading-relaxed text-soc-text/90">
                  {step}
                </li>
              ))}
            </ol>
          </div>

          {/* Analyst Triage Notes */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
            <h2 className="text-sm font-semibold">Analyst Triage Notes</h2>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!noteInput.trim()) return;
                triageMutation.mutate({ action: "add_note", note: noteInput });
              }}
              className="space-y-2"
            >
              <textarea
                rows={3}
                value={noteInput}
                onChange={(e) => setNoteInput(e.target.value)}
                placeholder="Document initial observations, indicator context, or host verification..."
                className="w-full rounded border border-soc-border bg-soc-bg p-2.5 text-xs"
              />
              <button
                type="submit"
                disabled={triageMutation.isPending || !noteInput.trim()}
                className="rounded bg-soc-elevated hover:bg-sky-600 hover:text-white border border-soc-border px-3 py-1.5 text-xs font-medium disabled:opacity-50 transition-colors"
              >
                Save Timestamped Note
              </button>
            </form>

            {(alert.notes ?? []).length > 0 && (
              <div className="space-y-2 pt-2 border-t border-soc-border">
                {(alert.notes ?? []).map((n: any) => (
                  <div key={n.id} className="rounded border border-soc-border bg-soc-bg/60 p-2.5 text-xs">
                    <div className="flex items-center justify-between text-[11px] text-soc-muted mb-1">
                      <span className="font-mono text-sky-400">@{n.author_username}</span>
                      <span>{formatDateTime(n.created_at)}</span>
                    </div>
                    <p className="whitespace-pre-wrap">{n.content}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Related Alerts */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-2.5">
            <h2 className="text-sm font-semibold">
              Correlated Alerts ({(alert.related_alerts ?? []).length})
            </h2>
            {(alert.related_alerts ?? []).length === 0 ? (
              <p className="text-xs text-soc-muted">
                No other alerts share this host, source IP, or username.
              </p>
            ) : (
              <div className="space-y-2">
                {(alert.related_alerts ?? []).map((rel) => (
                  <Link
                    key={rel.id}
                    href={`/alerts/${rel.id}/triage`}
                    className="block rounded border border-soc-border bg-soc-bg/60 hover:bg-soc-elevated p-2.5 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <SeverityBadge severity={rel.severity} />
                      <span className="text-[10px] text-soc-muted">
                        {formatDateTime(rel.event_timestamp)}
                      </span>
                    </div>
                    <p className="font-medium truncate">{rel.rule_description}</p>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Raw Event JSON & Deduplicated Occurrences */}
        <div className="lg:col-span-7 space-y-4">
          <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
            <div className="flex items-center justify-between border-b border-soc-border px-4 py-2.5 bg-soc-elevated/40">
              <span className="text-xs font-semibold">Original Raw Detection Payload</span>
              <button
                type="button"
                onClick={() =>
                  void navigator.clipboard.writeText(JSON.stringify(alert.raw_payload, null, 2))
                }
                className="inline-flex items-center gap-1 text-xs text-soc-muted hover:text-soc-text"
              >
                <Copy className="w-3.5 h-3.5" />
                Copy
              </button>
            </div>
            <pre className="p-4 text-xs font-mono text-sky-200/90 overflow-x-auto max-h-[420px]">
              <code>{JSON.stringify(alert.raw_payload, null, 2)}</code>
            </pre>
          </div>

          <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
            <h2 className="text-sm font-semibold mb-2.5">
              Occurrence Timeline ({alert.occurrence_count} total)
            </h2>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {(alert.occurrences ?? []).map((occ, idx, arr) => (
                <div
                  key={occ.id}
                  className="flex items-center justify-between rounded border border-soc-border bg-soc-bg/60 px-3 py-2 text-xs font-mono"
                >
                  <span>Occurrence #{arr.length - idx}</span>
                  <span className="text-soc-muted">{formatDateTime(occ.occurred_at)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* False Positive Modal (Mandatory Reason) */}
      <Modal
        open={fpModalOpen}
        title="Close Alert as False Positive"
        description="A documented operational reason is mandatory and permanently recorded in the audit log."
        onClose={() => setFpModalOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            triageMutation.mutate({ action: "mark_false_positive", reason: fpReason });
          }}
          className="space-y-3 text-xs"
        >
          <div>
            <label className="block text-soc-muted mb-1">
              False Positive Justification (min 5 characters)
            </label>
            <textarea
              required
              minLength={5}
              rows={4}
              value={fpReason}
              onChange={(e) => setFpReason(e.target.value)}
              placeholder="e.g., Authorized vulnerability scan from internal Nessus scanner window CHG-4819."
              className="w-full rounded border border-soc-border bg-soc-bg p-2.5"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setFpModalOpen(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={triageMutation.isPending || fpReason.trim().length < 5}
              className="rounded bg-amber-600 hover:bg-amber-500 px-4 py-1.5 font-medium text-white disabled:opacity-50"
            >
              Confirm False Positive
            </button>
          </div>
        </form>
      </Modal>

      {/* Create Incident Modal */}
      <Modal
        open={createCaseModalOpen}
        title="Promote Alert to Security Incident"
        description="Creates a formal case with explainable risk scoring, SLA deadlines, extracted IOCs, and suggested ATT&CK techniques."
        onClose={() => setCreateCaseModalOpen(false)}
      >
        {duplicateConflict ? (
          <div className="space-y-4 text-xs">
            <div className="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-amber-200">
              This alert is already linked to open incident{" "}
              <strong className="font-mono">{duplicateConflict.humanId}</strong>. Duplicate open
              incidents from the same alert are prevented.
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setCreateCaseModalOpen(false)}
                className="rounded border border-soc-border px-3 py-1.5"
              >
                Close
              </button>
              <Link
                href={`/incidents/${duplicateConflict.humanId}`}
                className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white"
              >
                Open {duplicateConflict.humanId}
              </Link>
            </div>
          </div>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              createIncidentMutation.mutate();
            }}
            className="space-y-3 text-xs"
          >
            <div>
              <label className="block text-soc-muted mb-1">Incident Title</label>
              <input
                required
                minLength={4}
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Initial Case Summary</label>
              <textarea
                required
                rows={4}
                value={caseDesc}
                onChange={(e) => setCaseDesc(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg p-2.5"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setCreateCaseModalOpen(false)}
                className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createIncidentMutation.isPending}
                className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white"
              >
                {createIncidentMutation.isPending ? "Creating Case..." : "Create Incident"}
              </button>
            </div>
          </form>
        )}
      </Modal>

      {/* Link to Existing Incident Modal */}
      <Modal
        open={linkCaseModalOpen}
        title="Link Alert to Existing Incident"
        onClose={() => setLinkCaseModalOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!targetIncidentId) return;
            linkExistingMutation.mutate();
          }}
          className="space-y-3 text-xs"
        >
          <label className="block text-soc-muted">Select Target Incident</label>
          <select
            required
            value={targetIncidentId}
            onChange={(e) => setTargetIncidentId(e.target.value)}
            className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-2"
          >
            <option value="">— Choose an Incident —</option>
            {(openIncidents?.items || []).map((inc) => (
              <option key={inc.id} value={inc.id}>
                {inc.human_id} [{inc.status}] — {inc.title}
              </option>
            ))}
          </select>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setLinkCaseModalOpen(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!targetIncidentId || linkExistingMutation.isPending}
              className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white disabled:opacity-50"
            >
              Link Alert
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
