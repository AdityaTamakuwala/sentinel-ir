"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  FileArchive,
  Network,
  RefreshCw,
  Send,
  ShieldAlert,
} from "lucide-react";
import {
  IncidentDetailOut,
  SentinelApiError,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth, useToast } from "@/components/providers";
import { EntityRelationshipGraph } from "@/components/investigation/entity-graph";
import {
  IncidentStatusBadge,
  MockIntelBadge,
  SeverityBadge,
  SimulatedBadge,
  SlaBadge,
} from "@/components/ui/badges";
import { formatBytes, formatDateTime } from "@/lib/format";

export default function ScopedIncidentWorkbenchPage() {
  const params = useParams<{ id: string }>();
  const incidentRef = params.id;
  const { hasPermission } = useAuth();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();

  const [quickNote, setQuickNote] = useState("");

  const canViewIncidents = hasPermission("incidents:view");
  const canWriteNotes = hasPermission("notes:write");

  const incidentQuery = useQuery({
    queryKey: ["incident-scoped-workbench", incidentRef],
    enabled: Boolean(incidentRef) && canViewIncidents,
    queryFn: () => apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incidentRef}`),
  });

  const addNoteMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incidentQuery.data!.id}/notes`, {
        method: "POST",
        body: { content: quickNote.trim() },
      }),
    onSuccess: (updated) => {
      pushToast({
        title: "Workbench Note Preserved",
        description: `Appended note to ${updated.human_id}.`,
        variant: "success",
      });
      setQuickNote("");
      queryClient.setQueryData(["incident-scoped-workbench", incidentRef], updated);
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentRef] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : "Failed to append note";
      pushToast({ title: "Note Error", description: msg, variant: "error" });
    },
  });

  if (!canViewIncidents) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-200">
        <div className="flex items-center gap-2 font-semibold text-red-300 mb-1">
          <ShieldAlert className="w-4 h-4" />
          Restricted Investigation Workbench
        </div>
        Your current role does not have <code className="font-mono">incidents:view</code> permission.
      </div>
    );
  }

  const incident = incidentQuery.data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Link
              href={`/incidents/${incidentRef}`}
              className="inline-flex items-center gap-1 text-xs text-sky-400 hover:underline"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Back to Case {incidentRef}
            </Link>
          </div>
          <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-sky-400" />
            Investigation Workbench — {incidentRef}
          </h1>
        </div>

        <button
          type="button"
          onClick={() => void incidentQuery.refetch()}
          className="inline-flex items-center gap-1.5 rounded-md border border-soc-border bg-soc-surface px-3 py-1.5 text-xs text-soc-muted hover:text-soc-text"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${incidentQuery.isFetching ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {incidentQuery.isLoading ? (
        <div className="p-12 text-center text-xs text-soc-muted">
          Loading investigation topology...
        </div>
      ) : !incident ? (
        <div className="rounded-lg border border-soc-border bg-soc-surface p-8 text-center text-xs text-soc-muted">
          Incident case not found.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Active Incident Case Header Banner */}
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-bold text-sky-400">{incident.human_id}</span>
                <IncidentStatusBadge status={incident.status} />
                <SeverityBadge severity={incident.severity} />
                <SlaBadge status={incident.sla_status} />
                {incident.is_simulated && <SimulatedBadge />}
                <span className="text-[11px] font-mono text-soc-muted">v{incident.version}</span>
              </div>
              <h2 className="text-base font-semibold text-soc-text">{incident.title}</h2>
              <div className="flex flex-wrap items-center gap-3 text-xs text-soc-muted font-mono">
                <span>Owner: {incident.assigned_to_username ? `@${incident.assigned_to_username}` : "Unassigned"}</span>
                <span>•</span>
                <span>Category: {incident.category}</span>
                <span>•</span>
                <span>Opened: {formatDateTime(incident.created_at)}</span>
              </div>
            </div>
          </div>

          {/* Interactive Topology Graph */}
          <EntityRelationshipGraph incident={incident} />

          {/* 2-Column Bottom Investigation Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left: Notes & Evidence */}
            <div className="lg:col-span-6 space-y-6">
              {/* Quick Investigation Note */}
              <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
                <h3 className="text-sm font-semibold flex items-center justify-between">
                  <span>Analyst Findings &amp; Notes</span>
                  <span className="text-xs font-mono text-soc-muted">
                    {incident.notes.length} notes recorded
                  </span>
                </h3>

                {canWriteNotes && (
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (quickNote.trim()) addNoteMutation.mutate();
                    }}
                    className="space-y-2"
                  >
                    <textarea
                      rows={2}
                      value={quickNote}
                      onChange={(e) => setQuickNote(e.target.value)}
                      placeholder="Append timestamped forensic finding or containment observation..."
                      className="w-full rounded border border-soc-border bg-soc-bg p-2.5 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-sky-500"
                    />
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        disabled={!quickNote.trim() || addNoteMutation.isPending}
                        className="inline-flex items-center gap-1.5 rounded bg-sky-500 px-3 py-1 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
                      >
                        <Send className="w-3 h-3" />
                        Append Note
                      </button>
                    </div>
                  </form>
                )}

                <div className="space-y-2.5 max-h-72 overflow-y-auto">
                  {incident.notes.map((n: any) => (
                    <div
                      key={n.id}
                      className="rounded border border-soc-border bg-soc-bg/60 p-2.5 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between text-[11px] text-soc-muted font-mono">
                        <span className="text-sky-400">@{n.author_username}</span>
                        <span>{formatDateTime(n.created_at)}</span>
                      </div>
                      <p className="whitespace-pre-wrap">{n.content}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Linked Evidence Artifacts */}
              <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold flex items-center gap-1.5">
                    <FileArchive className="w-4 h-4 text-sky-400" />
                    Case Evidence ({incident.evidence_items.length})
                  </h3>
                  <Link
                    href="/evidence"
                    className="text-xs text-sky-400 hover:underline font-mono"
                  >
                    View Repository →
                  </Link>
                </div>

                {incident.evidence_items.length === 0 ? (
                  <p className="text-xs text-soc-muted">No evidence artifacts uploaded yet.</p>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {incident.evidence_items.map((ev: any) => (
                      <div
                        key={ev.id}
                        className="rounded border border-soc-border bg-soc-bg/60 p-2.5 text-xs flex items-center justify-between gap-3"
                      >
                        <div className="min-w-0">
                          <p className="font-medium truncate text-soc-text">{ev.title}</p>
                          <p className="text-[11px] font-mono text-soc-muted truncate">
                            {ev.original_filename} ({formatBytes(ev.size_bytes)}) · SHA-256: {ev.sha256_hash?.slice(0, 14)}…
                          </p>
                        </div>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase shrink-0 border ${
                            ev.status === "active"
                              ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                              : "bg-red-500/15 text-red-300 border-red-500/30"
                          }`}
                        >
                          {ev.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Right: Indicators & ATT&CK Matrix */}
            <div className="lg:col-span-6 space-y-6">
              {/* Threat Indicators */}
              <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
                <h3 className="text-sm font-semibold">
                  Extracted Threat Indicators ({incident.indicators.length})
                </h3>
                {incident.indicators.length === 0 ? (
                  <p className="text-xs text-soc-muted">No indicators extracted from alerts.</p>
                ) : (
                  <div className="space-y-2 max-h-72 overflow-y-auto">
                    {incident.indicators.map((ind: any) => (
                      <div
                        key={ind.id}
                        className="rounded border border-soc-border bg-soc-bg/60 p-2.5 text-xs space-y-1.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono font-medium text-soc-text break-all">
                            [{ind.ioc_type.toUpperCase()}] {ind.value}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${
                              ind.is_internal
                                ? "bg-slate-500/20 text-slate-300"
                                : ind.reputation === "malicious"
                                ? "bg-red-500/15 text-red-400 border border-red-500/35"
                                : "bg-sky-500/15 text-sky-300"
                            }`}
                          >
                            {ind.is_internal ? "INTERNAL" : ind.reputation}
                          </span>
                        </div>
                        {ind.enrichments?.map((er: any, idx: number) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between text-[11px] text-soc-muted pt-1 border-t border-soc-border"
                          >
                            <span>
                              {er.provider}: {er.summary}
                            </span>
                            {er.is_mock && <MockIntelBadge />}
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* MITRE Techniques */}
              <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
                <h3 className="text-sm font-semibold">
                  Mapped MITRE ATT&amp;CK Techniques ({incident.mitre_techniques.length})
                </h3>
                {incident.mitre_techniques.length === 0 ? (
                  <p className="text-xs text-soc-muted">No techniques mapped.</p>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {incident.mitre_techniques.map((t: any) => (
                      <div
                        key={t.mapping_id}
                        className="rounded border border-soc-border bg-soc-bg/60 p-2.5 text-xs flex items-center justify-between gap-2"
                      >
                        <div>
                          <p className="font-mono font-semibold text-sky-400">
                            {t.technique_id} — {t.name}
                          </p>
                          <p className="text-[11px] text-soc-muted">
                            Tactics: {t.tactics.join(", ") || "General"} · Source: {t.source}
                          </p>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${
                            t.status === "confirmed"
                              ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/35"
                              : "bg-amber-500/15 text-amber-300 border-amber-500/35"
                          }`}
                        >
                          {t.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

