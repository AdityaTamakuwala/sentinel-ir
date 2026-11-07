"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Check, Copy, FileSearch, Server } from "lucide-react";
import { AlertDetailOut, apiRequest } from "@/lib/api/generated";
import {
  AlertTriageBadge,
  MockIntelBadge,
  SeverityBadge,
  SimulatedBadge,
} from "@/components/ui/badges";
import { formatDateTime } from "@/lib/format";

export default function AlertDetailPage() {
  const params = useParams<{ id: string }>();
  const alertId = params.id;
  const [copied, setCopied] = useState(false);

  const { data: alert, isLoading } = useQuery({
    queryKey: ["alert", alertId],
    queryFn: () => apiRequest<AlertDetailOut>(`/api/v1/alerts/${alertId}`),
  });

  if (isLoading) {
    return <div className="text-xs text-soc-muted">Loading alert telemetry...</div>;
  }

  if (!alert) {
    return (
      <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-300">
        Alert record not found.
      </div>
    );
  }

  const rawJsonFormatted = JSON.stringify(alert.raw_payload, null, 2);

  const copyRawJson = async () => {
    await navigator.clipboard.writeText(rawJsonFormatted);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-soc-border pb-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <SeverityBadge severity={alert.severity} />
            <AlertTriageBadge status={alert.triage_status} />
            {alert.is_simulated && <SimulatedBadge />}
            <span className="font-mono text-xs text-soc-muted">
              Rule {alert.source_system}:{alert.rule_id}
            </span>
          </div>
          <h1 className="text-lg font-semibold text-soc-text">{alert.rule_description}</h1>
        </div>

        <div className="flex items-center gap-2">
          {alert.linked_incident_human_id && (
            <Link
              href={`/incidents/${alert.linked_incident_human_id}`}
              className="rounded-md border border-emerald-500/40 bg-emerald-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-emerald-300"
            >
              Case {alert.linked_incident_human_id}
            </Link>
          )}
          <Link
            href={`/alerts/${alert.id}/triage`}
            className="inline-flex items-center gap-1.5 rounded-md bg-sky-600 hover:bg-sky-500 px-3.5 py-2 text-xs font-medium text-white"
          >
            <FileSearch className="w-4 h-4" />
            Open in Triage Workbench
          </Link>
        </div>
      </div>

      {/* Metadata & Entity Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-lg border border-soc-border bg-soc-surface p-4 space-y-4">
          <h2 className="text-sm font-semibold">Normalized Event Telemetry</h2>
          <dl className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
            <Field label="Event Timestamp (UTC)" value={formatDateTime(alert.event_timestamp)} />
            <Field label="Ingested Timestamp" value={formatDateTime(alert.ingested_at)} />
            <Field label="Category" value={alert.event_category} mono />
            <Field label="Source IP" value={alert.src_ip || "—"} mono />
            <Field label="Destination IP" value={alert.dst_ip || "—"} mono />
            <Field label="Hostname" value={alert.hostname || "—"} mono />
            <Field label="Username" value={alert.username || "—"} mono />
            <Field label="Domain" value={alert.domain || "—"} mono />
            <Field
              label="Occurrences (Deduplicated)"
              value={`${alert.occurrence_count} (Fingerprint ${alert.fingerprint.slice(0, 12)}…)`}
              mono
            />
          </dl>

          {alert.file_hash && (
            <div className="pt-2 border-t border-soc-border">
              <span className="text-[11px] text-soc-muted block">SHA-256 File Hash</span>
              <code className="text-xs font-mono text-amber-300 break-all">{alert.file_hash}</code>
            </div>
          )}

          {alert.false_positive_reason && (
            <div className="rounded border border-slate-500/30 bg-slate-500/10 p-3 text-xs">
              <span className="font-semibold block mb-0.5">False Positive Justification:</span>
              {alert.false_positive_reason}
            </div>
          )}
        </div>

        {/* Asset & MITRE Panel */}
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-4">
          <div>
            <h2 className="text-sm font-semibold flex items-center gap-1.5 mb-2">
              <Server className="w-4 h-4 text-sky-400" />
              Associated Enterprise Asset
            </h2>
            {alert.asset ? (
              <div className="rounded border border-soc-border bg-soc-bg/60 p-3 text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold">{alert.asset.hostname}</span>
                  <SeverityBadge severity={alert.asset.criticality} />
                </div>
                <p className="text-soc-muted">
                  {alert.asset.os_name || alert.asset.asset_type} • {alert.asset.ip_address}
                </p>
                <p className="text-soc-muted">
                  Owner: {alert.asset.owner || "Unassigned"} ({alert.asset.department || "IT"})
                </p>
              </div>
            ) : (
              <p className="text-xs text-soc-muted">No registered CMDB asset matched.</p>
            )}
          </div>

          <div className="pt-3 border-t border-soc-border">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-soc-muted mb-2">
              Mapped MITRE ATT&amp;CK Metadata
            </h3>
            {alert.mitre_mappings_raw.length === 0 ? (
              <p className="text-xs text-soc-muted">No rule-level ATT&amp;CK tags attached.</p>
            ) : (
              <div className="space-y-1.5">
                {alert.mitre_mappings_raw.map((m: any, idx: number) => (
                  <div
                    key={`${m.id}-${idx}`}
                    className="rounded border border-soc-border bg-soc-bg/60 px-2.5 py-1.5 text-xs flex items-center justify-between"
                  >
                    <div>
                      <span className="font-mono text-sky-400 font-semibold mr-2">{m.id}</span>
                      <span>{m.name}</span>
                    </div>
                    <span className="text-[10px] font-mono uppercase text-soc-muted">
                      {m.source || "alert_metadata"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Threat Intelligence Summary if present */}
      {alert.enrichment_summary && alert.enrichment_summary.length > 0 && (
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3">
          <h2 className="text-sm font-semibold">Indicator Threat Intelligence Context</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {alert.enrichment_summary.map((item: any) => (
              <div
                key={item.indicator_id}
                className="rounded border border-soc-border bg-soc-bg/60 p-3 text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold">
                    [{item.ioc_type.toUpperCase()}] {item.value}
                  </span>
                  <span className="uppercase font-mono text-[11px]">{item.reputation}</span>
                </div>
                {item.results.map((r: any, i: number) => (
                  <div key={i} className="border-t border-soc-border pt-1.5 flex items-center justify-between gap-2">
                    <span className="text-soc-muted">
                      <strong className="text-soc-text">{r.provider}</strong>: {r.summary}
                    </span>
                    {r.is_mock && <MockIntelBadge />}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Immutable Raw Payload JSON Viewer (safely text-rendered, never innerHTML) */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-soc-border px-4 py-2.5 bg-soc-elevated/40">
          <span className="text-xs font-semibold">
            Immutable Original Raw Event JSON ({(alert.occurrences ?? []).length} retained occurrence
            {(alert.occurrences ?? []).length === 1 ? "" : "s"})
          </span>
          <button
            type="button"
            onClick={() => void copyRawJson()}
            className="inline-flex items-center gap-1.5 rounded border border-soc-border bg-soc-bg px-2.5 py-1 text-xs text-soc-muted hover:text-soc-text"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? "Copied" : "Copy JSON"}
          </button>
        </div>
        <pre className="p-4 text-xs font-mono text-sky-200/90 overflow-x-auto max-h-96 leading-relaxed">
          <code>{rawJsonFormatted}</code>
        </pre>
      </div>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-[11px] text-soc-muted">{label}</dt>
      <dd className={`mt-0.5 text-soc-text break-words ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}
