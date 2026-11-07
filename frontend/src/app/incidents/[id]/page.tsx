"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Clock,
  Edit3,
  FileArchive,
  Globe,
  History,
  Network,
  Plus,
  RefreshCw,
  ShieldAlert,
  Sliders,
  X,
} from "lucide-react";
import {
  IncidentDetailOut,
  SentinelApiError,
  UserSummaryOut,
  apiRequest,
} from "@/lib/api/generated";
import {
  IncidentStatusBadge,
  MockIntelBadge,
  SeverityBadge,
  SimulatedBadge,
  SlaBadge,
} from "@/components/ui/badges";
import { EntityRelationshipGraph } from "@/components/investigation/entity-graph";
import { Modal } from "@/components/ui/modal";
import { useAuth, useToast } from "@/components/providers";
import { formatDateTime } from "@/lib/format";

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const incidentRef = params.id;
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();
  const { pushToast } = useToast();

  const [transitionModal, setTransitionModal] = useState<string | null>(null);
  const [transitionReason, setTransitionReason] = useState("");
  const [closureCategory, setClosureCategory] = useState("true_positive_mitigated");
  const [closureJustification, setClosureJustification] = useState("");

  const [overrideModal, setOverrideModal] = useState(false);
  const [overrideSev, setOverrideSev] = useState<"low" | "medium" | "high" | "critical">("critical");
  const [overrideJustification, setOverrideJustification] = useState("");

  const [noteContent, setNoteContent] = useState("");
  const [editingNote, setEditingNote] = useState<{ id: string; content: string } | null>(null);
  const [historyNote, setHistoryNote] = useState<any | null>(null);

  const [mitreModal, setMitreModal] = useState(false);
  const [mitreTechId, setMitreTechId] = useState("");
  const [mitreRationale, setMitreRationale] = useState("");

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", incidentRef],
    queryFn: () => apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incidentRef}`),
  });

  const { data: analysts } = useQuery({
    queryKey: ["users"],
    queryFn: () => apiRequest<UserSummaryOut[]>("/api/v1/users"),
  });

  const transitionMutation = useMutation({
    mutationFn: (targetStatus: string) =>
      apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incident!.id}/transition`, {
        method: "POST",
        body: {
          target_status: targetStatus,
          expected_version: incident!.version,
          reason: transitionReason || null,
          closure_category: targetStatus === "CLOSED" ? closureCategory : null,
          closure_justification: targetStatus === "CLOSED" ? closureJustification : null,
        },
      }),
    onSuccess: (updated) => {
      pushToast({
        title: `Transitioned to ${updated.status}`,
        description: `Case ${updated.human_id} updated (v${updated.version}).`,
        variant: "success",
      });
      setTransitionModal(null);
      setTransitionReason("");
      setClosureJustification("");
      queryClient.setQueryData(["incident", incidentRef], updated);
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["command-center"] });
    },
    onError: (err) => {
      pushToast({
        title: "Lifecycle transition rejected",
        description: err instanceof SentinelApiError ? err.message : "Error",
        variant: "error",
      });
    },
  });

  const assignMutation = useMutation({
    mutationFn: (assignedToId: string | null) =>
      apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incident!.id}/assign`, {
        method: "POST",
        body: {
          assigned_to_id: assignedToId,
          expected_version: incident!.version,
        },
      }),
    onSuccess: (updated) => {
      pushToast({ title: "Incident ownership updated", variant: "success" });
      queryClient.setQueryData(["incident", incidentRef], updated);
    },
    onError: (err) => {
      pushToast({
        title: "Assignment failed",
        description: err instanceof SentinelApiError ? err.message : "Error",
        variant: "error",
      });
    },
  });

  const overrideMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incident!.id}/risk-override`, {
        method: "POST",
        body: {
          override_severity: overrideSev,
          justification: overrideJustification,
          expected_version: incident!.version,
        },
      }),
    onSuccess: (updated) => {
      pushToast({ title: "Severity override recorded & audited", variant: "success" });
      setOverrideModal(false);
      setOverrideJustification("");
      queryClient.setQueryData(["incident", incidentRef], updated);
    },
    onError: (err) => {
      pushToast({
        title: "Override failed",
        description: err instanceof SentinelApiError ? err.message : "Error",
        variant: "error",
      });
    },
  });

  const addNoteMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incident!.id}/notes`, {
        method: "POST",
        body: { content: noteContent },
      }),
    onSuccess: (updated) => {
      pushToast({ title: "Investigation note added", variant: "success" });
      setNoteContent("");
      queryClient.setQueryData(["incident", incidentRef], updated);
    },
  });

  const editNoteMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentDetailOut>(
        `/api/v1/incidents/${incident!.id}/notes/${editingNote!.id}`,
        {
          method: "PATCH",
          body: { content: editingNote!.content },
        }
      ),
    onSuccess: (updated) => {
      pushToast({ title: "Note revision saved (history preserved)", variant: "success" });
      setEditingNote(null);
      queryClient.setQueryData(["incident", incidentRef], updated);
    },
  });

  const mapMitreMutation = useMutation({
    mutationFn: () =>
      apiRequest(`/api/v1/incidents/${incident!.id}/mitre`, {
        method: "POST",
        body: { technique_id: mitreTechId, rationale: mitreRationale, source: "analyst" },
      }),
    onSuccess: () => {
      pushToast({ title: "MITRE technique mapped", variant: "success" });
      setMitreModal(false);
      setMitreTechId("");
      setMitreRationale("");
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentRef] });
    },
    onError: (err: any) => {
      pushToast({ title: "Mapping failed", description: err?.message, variant: "error" });
    },
  });

  const confirmMitreMutation = useMutation({
    mutationFn: ({ techniqueId, confirm }: { techniqueId: string; confirm: boolean }) =>
      apiRequest(`/api/v1/incidents/${incident!.id}/mitre/${techniqueId}/confirm`, {
        method: "POST",
        body: { confirm, notes: confirm ? "Confirmed by analyst" : "Rejected by analyst" },
      }),
    onSuccess: (_, vars) => {
      pushToast({
        title: vars.confirm ? "Technique confirmed" : "Technique rejected",
        variant: "success",
      });
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentRef] });
    },
    onError: (err: any) => {
      pushToast({ title: "Action failed", description: err?.message, variant: "error" });
    },
  });

  const enrichAllMutation = useMutation({
    mutationFn: () =>
      apiRequest(`/api/v1/enrichment/incidents/${incident!.id}/enrich`, {
        method: "POST",
      }),
    onSuccess: () => {
      pushToast({ title: "Incident indicators enriched across threat providers", variant: "success" });
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentRef] });
    },
    onError: (err: any) => {
      pushToast({ title: "Enrichment failed", description: err?.message, variant: "error" });
    },
  });

  if (isLoading || !incident) {
    return <div className="text-xs text-soc-muted">Loading Incident Case...</div>;
  }

  const rb = incident.risk_breakdown || {};

  return (
    <div className="space-y-6">
      {/* Top Case Banner */}
      <div className="rounded-lg border border-soc-border bg-soc-surface p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-bold text-sky-400">
                {incident.human_id}
              </span>
              <IncidentStatusBadge status={incident.status} />
              <SeverityBadge severity={incident.severity} />
              <SlaBadge status={incident.sla_status} />
              {incident.is_simulated && <SimulatedBadge />}
              <span className="text-[11px] font-mono text-soc-muted">v{incident.version}</span>
            </div>
            <h1 className="text-xl font-semibold text-soc-text">{incident.title}</h1>
            <p className="text-xs text-soc-muted whitespace-pre-line">{incident.description}</p>
          </div>

          {/* Allowed State Machine Transitions */}
          {hasPermission("incidents:update") && incident.allowed_transitions.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              {incident.allowed_transitions.map((nextState) => (
                <button
                  key={nextState}
                  type="button"
                  onClick={() => {
                    if (
                      nextState === "CLOSED" ||
                      (incident.status === "RESOLVED" && nextState === "INVESTIGATING") ||
                      (incident.status === "CLOSED" && nextState === "INVESTIGATING")
                    ) {
                      setTransitionModal(nextState);
                    } else {
                      transitionMutation.mutate(nextState);
                    }
                  }}
                  className="rounded-md border border-sky-500/35 bg-sky-500/15 hover:bg-sky-500/25 px-3 py-1.5 text-xs font-mono font-semibold text-sky-300 transition-colors"
                >
                  → {nextState}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Ownership & SLA Bar */}
        <div className="pt-3 border-t border-soc-border flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-soc-muted">Assigned Analyst:</span>
            {hasPermission("incidents:assign") ? (
              <select
                aria-label="Assign incident owner"
                value={incident.assigned_to_id || ""}
                onChange={(e) => assignMutation.mutate(e.target.value || null)}
                className="rounded border border-soc-border bg-soc-bg px-2.5 py-1 text-xs"
              >
                <option value="">Unassigned</option>
                {(analysts || []).map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.full_name} (@{u.username})
                  </option>
                ))}
              </select>
            ) : (
              <span className="font-mono">
                {incident.assigned_to_username ? `@${incident.assigned_to_username}` : "Unassigned"}
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-4 text-soc-muted font-mono text-[11px]">
            <span>Opened: {formatDateTime(incident.created_at)}</span>
            <span>SLA Target: {formatDateTime(incident.sla_resolve_due_at)}</span>
            <div className="flex items-center gap-2 ml-auto">
              <Link
                href={`/incidents/${incident.human_id}/workbench`}
                className="inline-flex items-center gap-1 rounded border border-soc-border bg-soc-bg hover:border-sky-500/40 px-2.5 py-1 text-xs text-soc-text"
              >
                <Network className="w-3.5 h-3.5 text-sky-400" />
                Workbench
              </Link>
              <Link
                href={`/incidents/${incident.human_id}/evidence`}
                className="inline-flex items-center gap-1 rounded border border-soc-border bg-soc-bg hover:border-sky-500/40 px-2.5 py-1 text-xs text-soc-text"
              >
                <FileArchive className="w-3.5 h-3.5 text-sky-400" />
                Evidence ({incident.evidence_items.length})
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Entity Topology Graph */}
      <EntityRelationshipGraph incident={incident} />

      {/* Main 3-Column Investigation Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Left: Risk Breakdown, Linked Alerts, Assets, Indicators, MITRE */}
        <div className="xl:col-span-4 space-y-4">
          {/* Explainable Risk Score Card */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-sky-400" />
                Explainable Risk Score
              </h2>
              <span className="font-mono text-base font-bold text-sky-400">
                {incident.risk_score}/100
              </span>
            </div>

            <div className="space-y-1 text-xs font-mono text-soc-muted border-t border-soc-border pt-2.5">
              <div className="flex justify-between">
                <span>Base Severity Weight</span>
                <span className="text-soc-text">+{rb.base_severity_weight ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Asset Criticality Weight</span>
                <span className="text-soc-text">+{rb.asset_criticality_weight ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Threat Intel Confidence</span>
                <span className="text-soc-text">+{rb.threat_intel_points ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Correlated Alerts Bonus</span>
                <span className="text-soc-text">+{rb.correlated_alerts_bonus ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Privileged Principal Bonus</span>
                <span className="text-soc-text">+{rb.privileged_account_bonus ?? 0}</span>
              </div>
            </div>

            {incident.risk_override_reason && (
              <div className="rounded border border-amber-500/35 bg-amber-500/10 p-2.5 text-xs">
                <span className="font-semibold text-amber-300 block">
                  Analyst Override ({incident.risk_override_severity?.toUpperCase()}):
                </span>
                {incident.risk_override_reason}
              </div>
            )}

            {hasPermission("incidents:update") && (
              <button
                type="button"
                onClick={() => {
                  setOverrideSev(incident.severity as any);
                  setOverrideModal(true);
                }}
                className="w-full inline-flex items-center justify-center gap-1.5 rounded border border-soc-border bg-soc-bg hover:bg-soc-elevated py-1.5 text-xs text-soc-muted hover:text-soc-text"
              >
                <Sliders className="w-3.5 h-3.5" />
                Override Severity (Audited)
              </button>
            )}
          </div>

          {/* Linked Alerts */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-2.5">
            <h2 className="text-sm font-semibold">
              Correlated Alerts ({incident.linked_alerts.length})
            </h2>
            {incident.linked_alerts.length === 0 ? (
              <p className="text-xs text-soc-muted">No alerts linked yet.</p>
            ) : (
              incident.linked_alerts.map((a: any) => (
                <Link
                  key={a.id}
                  href={`/alerts/${a.id}`}
                  className="block rounded border border-soc-border bg-soc-bg/60 hover:bg-soc-elevated p-2.5 text-xs"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-sky-400">
                      {a.source_system}:{a.rule_id}
                    </span>
                    <SeverityBadge severity={a.severity} />
                  </div>
                  <p className="font-medium">{a.rule_description}</p>
                </Link>
              ))
            )}
          </div>

          {/* MITRE ATT&CK Mappings */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">
                MITRE ATT&amp;CK Techniques ({incident.mitre_techniques.length})
              </h2>
              {hasPermission("mitre:map") && (
                <button
                  onClick={() => setMitreModal(true)}
                  className="inline-flex items-center gap-1 rounded border border-soc-border px-2 py-0.5 text-[11px] text-soc-muted hover:text-white hover:bg-soc-elevated"
                >
                  <Plus className="h-3 w-3" /> Map Technique
                </button>
              )}
            </div>
            {incident.mitre_techniques.length === 0 ? (
              <p className="text-xs text-soc-muted">No ATT&amp;CK techniques mapped.</p>
            ) : (
              incident.mitre_techniques.map((t: any) => (
                <div
                  key={t.mapping_id || t.technique_id}
                  className="rounded border border-soc-border bg-soc-bg/60 p-2.5 text-xs space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-semibold text-sky-400">
                      {t.technique_id} — {t.name}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${
                        t.status === "confirmed"
                          ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/35"
                          : "bg-amber-500/15 text-amber-300 border border-amber-500/35"
                      }`}
                    >
                      {t.status}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-soc-muted">
                    <span>
                      Source: <span className="font-mono">{t.source}</span>
                    </span>
                    {t.status === "suggested" && hasPermission("mitre:confirm") && (
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => confirmMitreMutation.mutate({ techniqueId: t.technique_id, confirm: true })}
                          disabled={confirmMitreMutation.isPending}
                          className="rounded bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 px-1.5 py-0.5 text-[10px] font-medium flex items-center gap-1"
                        >
                          <Check className="h-2.5 w-2.5" /> Confirm
                        </button>
                        <button
                          onClick={() => confirmMitreMutation.mutate({ techniqueId: t.technique_id, confirm: false })}
                          disabled={confirmMitreMutation.isPending}
                          className="rounded bg-red-500/20 text-red-300 hover:bg-red-500/30 px-1.5 py-0.5 text-[10px] font-medium flex items-center gap-1"
                        >
                          <X className="h-2.5 w-2.5" /> Reject
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Extracted Indicators */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">
                Associated Indicators ({incident.indicators.length})
              </h2>
              {hasPermission("enrichment:run") && incident.indicators.length > 0 && (
                <button
                  onClick={() => enrichAllMutation.mutate()}
                  disabled={enrichAllMutation.isPending}
                  className="inline-flex items-center gap-1 rounded border border-soc-border px-2 py-0.5 text-[11px] text-soc-muted hover:text-white hover:bg-soc-elevated"
                >
                  <RefreshCw className={`h-3 w-3 ${enrichAllMutation.isPending ? "animate-spin" : ""}`} />
                  Enrich All
                </button>
              )}
            </div>
            {incident.indicators.length === 0 ? (
              <p className="text-xs text-soc-muted">No indicators extracted.</p>
            ) : (
              incident.indicators.map((ind: any) => (
                <div
                  key={ind.id}
                  className="rounded border border-soc-border bg-soc-bg/60 p-2.5 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono break-all">
                      [{ind.ioc_type.toUpperCase()}] {ind.value}
                    </span>
                    <span className="text-[10px] font-mono uppercase text-soc-muted">
                      {ind.is_internal ? "INTERNAL" : ind.reputation}
                    </span>
                  </div>
                  {ind.enrichments?.map((er: any, idx: number) => (
                    <div key={idx} className="flex items-center justify-between text-[11px] text-soc-muted pt-1 border-t border-soc-border">
                      <span>
                        {er.provider}: {er.summary}
                      </span>
                      {er.is_mock && <MockIntelBadge />}
                    </div>
                  ))}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Center/Right: Chronological Investigation Timeline & Revisioned Notes */}
        <div className="xl:col-span-8 space-y-5">
          {/* Investigation Notes (Immutable Revision History) */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
            <h2 className="text-sm font-semibold">
              Analyst Investigation Notes ({incident.notes.length})
            </h2>
            {hasPermission("notes:write") && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!noteContent.trim()) return;
                  addNoteMutation.mutate();
                }}
                className="space-y-2"
              >
                <textarea
                  rows={3}
                  value={noteContent}
                  onChange={(e) => setNoteContent(e.target.value)}
                  placeholder="Record forensic findings, containment verification, or analyst handoff notes..."
                  className="w-full rounded border border-soc-border bg-soc-bg p-2.5 text-xs"
                />
                <button
                  type="submit"
                  disabled={!noteContent.trim() || addNoteMutation.isPending}
                  className="rounded bg-sky-600 hover:bg-sky-500 px-3.5 py-1.5 text-xs font-medium text-white disabled:opacity-50"
                >
                  Append Investigation Note
                </button>
              </form>
            )}

            <div className="space-y-2.5">
              {incident.notes.map((n: any) => (
                <div
                  key={n.id}
                  className="rounded border border-soc-border bg-soc-bg/60 p-3 text-xs space-y-1.5"
                >
                  <div className="flex items-center justify-between text-[11px] text-soc-muted">
                    <span className="font-mono text-sky-400">
                      @{n.author_username} • rev {n.revision_count}
                    </span>
                    <div className="flex items-center gap-2">
                      <span>{formatDateTime(n.updated_at)}</span>
                      {n.revision_count > 1 && (
                        <button
                          type="button"
                          onClick={() => setHistoryNote(n)}
                          className="inline-flex items-center gap-1 text-amber-300 hover:underline"
                        >
                          <History className="w-3 h-3" />
                          History
                        </button>
                      )}
                      {hasPermission("notes:write") && (
                        <button
                          type="button"
                          onClick={() => setEditingNote({ id: n.id, content: n.content })}
                          className="inline-flex items-center gap-1 text-soc-muted hover:text-soc-text"
                        >
                          <Edit3 className="w-3 h-3" />
                          Edit
                        </button>
                      )}
                    </div>
                  </div>
                  <p className="whitespace-pre-wrap leading-relaxed">{n.content}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Append-Only Chronological Investigation Timeline */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
            <h2 className="text-sm font-semibold flex items-center gap-1.5 mb-4">
              <Clock className="w-4 h-4 text-sky-400" />
              Chronological Case Timeline ({incident.timeline.length} events)
            </h2>
            <div className="relative border-l-2 border-soc-border ml-2.5 space-y-4 pl-5">
              {incident.timeline.map((ev) => (
                <div key={ev.id} className="relative">
                  <span className="absolute -left-[25px] top-1.5 w-2.5 h-2.5 rounded-full bg-sky-500 ring-4 ring-soc-surface" />
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-soc-muted">
                    <span className="font-mono uppercase text-sky-400">{ev.event_type}</span>
                    <span>{formatDateTime(ev.occurred_at)}</span>
                  </div>
                  <p className="text-xs font-semibold text-soc-text mt-0.5">{ev.title}</p>
                  {ev.description && (
                    <p className="text-xs text-soc-muted mt-0.5">{ev.description}</p>
                  )}
                  <span className="text-[10px] font-mono text-soc-muted">
                    Actor: {ev.actor_label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Closure / Reopen Modal */}
      <Modal
        open={Boolean(transitionModal)}
        title={`Transition Incident to ${transitionModal}`}
        onClose={() => setTransitionModal(null)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (transitionModal) transitionMutation.mutate(transitionModal);
          }}
          className="space-y-3 text-xs"
        >
          {transitionModal === "CLOSED" ? (
            <>
              <div>
                <label className="block text-soc-muted mb-1">Closure Category</label>
                <select
                  value={closureCategory}
                  onChange={(e) => setClosureCategory(e.target.value)}
                  className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5"
                >
                  <option value="true_positive_mitigated">True Positive — Contained &amp; Mitigated</option>
                  <option value="benign_positive_authorized">Benign Positive — Authorized Activity</option>
                  <option value="false_positive">False Positive After Investigation</option>
                  <option value="duplicate_merged">Duplicate / Merged Case</option>
                </select>
              </div>
              <div>
                <label className="block text-soc-muted mb-1">
                  Closure Justification (minimum 10 characters)
                </label>
                <textarea
                  required
                  minLength={10}
                  rows={4}
                  value={closureJustification}
                  onChange={(e) => setClosureJustification(e.target.value)}
                  placeholder="Summarize containment verification, credential rotation, and residual risk..."
                  className="w-full rounded border border-soc-border bg-soc-bg p-2.5"
                />
              </div>
            </>
          ) : (
            <div>
              <label className="block text-soc-muted mb-1">
                Mandatory Reopen Reason (minimum 5 characters)
              </label>
              <textarea
                required
                minLength={5}
                rows={4}
                value={transitionReason}
                onChange={(e) => setTransitionReason(e.target.value)}
                placeholder="Document new indicator recurrence or scope expansion requiring reopening..."
                className="w-full rounded border border-soc-border bg-soc-bg p-2.5"
              />
            </div>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setTransitionModal(null)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={transitionMutation.isPending}
              className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white"
            >
              Confirm {transitionModal}
            </button>
          </div>
        </form>
      </Modal>

      {/* Risk Override Modal */}
      <Modal
        open={overrideModal}
        title="Override Calculated Incident Severity"
        description="Requires written justification and writes an immutable entry to the timeline and audit trail."
        onClose={() => setOverrideModal(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            overrideMutation.mutate();
          }}
          className="space-y-3 text-xs"
        >
          <div>
            <label className="block text-soc-muted mb-1">Override Severity</label>
            <select
              value={overrideSev}
              onChange={(e) => setOverrideSev(e.target.value as any)}
              className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-1.5"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div>
            <label className="block text-soc-muted mb-1">Justification (min 10 chars)</label>
            <textarea
              required
              minLength={10}
              rows={3}
              value={overrideJustification}
              onChange={(e) => setOverrideJustification(e.target.value)}
              className="w-full rounded border border-soc-border bg-soc-bg p-2.5"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setOverrideModal(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={overrideMutation.isPending}
              className="rounded bg-amber-600 hover:bg-amber-500 px-4 py-1.5 font-medium text-white"
            >
              Apply Override
            </button>
          </div>
        </form>
      </Modal>

      {/* Edit Note Modal */}
      <Modal
        open={Boolean(editingNote)}
        title="Revise Investigation Note"
        description="Previous revisions are preserved in immutable note history."
        onClose={() => setEditingNote(null)}
      >
        {editingNote && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              editNoteMutation.mutate();
            }}
            className="space-y-3 text-xs"
          >
            <textarea
              required
              rows={5}
              value={editingNote.content}
              onChange={(e) => setEditingNote({ ...editingNote, content: e.target.value })}
              className="w-full rounded border border-soc-border bg-soc-bg p-2.5"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setEditingNote(null)}
                className="rounded border border-soc-border px-3 py-1.5 text-soc-muted"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={editNoteMutation.isPending}
                className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white"
              >
                Save New Revision
              </button>
            </div>
          </form>
        )}
      </Modal>

      {/* MITRE Technique Mapping Modal */}
      <Modal
        open={mitreModal}
        title="Map MITRE ATT&CK Technique"
        onClose={() => setMitreModal(false)}
      >
        <div className="space-y-4 text-xs">
          <div>
            <label className="text-soc-muted block mb-1">Technique ID (e.g. T1059.001 or T1078)</label>
            <input
              type="text"
              placeholder="T1059.001"
              value={mitreTechId}
              onChange={(e) => setMitreTechId(e.target.value)}
              className="w-full rounded border border-soc-border bg-soc-bg px-3 py-1.5 font-mono text-xs"
            />
          </div>
          <div>
            <label className="text-soc-muted block mb-1">Analyst Rationale / Evidence</label>
            <textarea
              rows={3}
              placeholder="Observed encoded PowerShell command line execution..."
              value={mitreRationale}
              onChange={(e) => setMitreRationale(e.target.value)}
              className="w-full rounded border border-soc-border bg-soc-bg p-2.5 text-xs"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2 border-t border-soc-border">
            <button
              type="button"
              onClick={() => setMitreModal(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted hover:text-white"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => mapMitreMutation.mutate()}
              disabled={!mitreTechId.trim() || mapMitreMutation.isPending}
              className="rounded bg-sky-600 hover:bg-sky-500 px-4 py-1.5 font-medium text-white disabled:opacity-50"
            >
              Map Technique
            </button>
          </div>
        </div>
      </Modal>

      {/* Note Revision History Modal */}
      <Modal
        open={Boolean(historyNote)}
        title="Investigation Note Revision History"
        onClose={() => setHistoryNote(null)}
      >
        {historyNote && (
          <div className="space-y-3 text-xs">
            {(historyNote.revisions || []).map((rev: any) => (
              <div key={rev.revision_number} className="rounded border border-soc-border bg-soc-bg p-3">
                <div className="flex justify-between text-[11px] text-soc-muted mb-1 font-mono">
                  <span>
                    Revision #{rev.revision_number} by @{rev.edited_by}
                  </span>
                  <span>{formatDateTime(rev.created_at)}</span>
                </div>
                <p className="whitespace-pre-wrap">{rev.content}</p>
              </div>
            ))}
          </div>
        )}
      </Modal>
    </div>
  );
}

