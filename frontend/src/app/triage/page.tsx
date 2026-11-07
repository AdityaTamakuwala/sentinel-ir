"use client";

import React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, FileSearch } from "lucide-react";
import { PaginatedAlertsOut, apiRequest } from "@/lib/api/generated";
import {
  AlertTriageBadge,
  SeverityBadge,
  SimulatedBadge,
} from "@/components/ui/badges";
import { formatRelativeTime } from "@/lib/format";

export default function TriageQueueIndexPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["triage-priority-queue"],
    queryFn: () =>
      apiRequest<PaginatedAlertsOut>("/api/v1/alerts", {
        params: { page: 1, page_size: 30 },
      }),
  });

  const actionable = (data?.items || []).filter((a) =>
    ["new", "in_review", "escalated"].includes(a.triage_status)
  );

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Alert Triage Workbench Queue</h1>
        <p className="text-xs text-soc-muted mt-0.5">
          Prioritized queue of unreviewed, active, and escalated alerts awaiting analyst decision
        </p>
      </div>

      {isLoading ? (
        <div className="text-xs text-soc-muted">Loading triage queue...</div>
      ) : actionable.length === 0 ? (
        <div className="rounded-lg border border-soc-border bg-soc-surface p-10 text-center space-y-2">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
          <p className="text-sm font-medium">Triage queue clear</p>
          <p className="text-xs text-soc-muted">
            All ingested alerts have been converted to incidents or dispositioned.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {actionable.map((alert) => (
            <Link
              key={alert.id}
              href={`/alerts/${alert.id}/triage`}
              className="rounded-lg border border-soc-border bg-soc-surface hover:border-sky-500/40 p-4 flex flex-col justify-between gap-3 transition-colors"
            >
              <div>
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <AlertTriageBadge status={alert.triage_status} />
                    {alert.is_simulated && <SimulatedBadge />}
                  </div>
                  <span className="text-[11px] text-soc-muted">
                    {formatRelativeTime(alert.last_seen_at)}
                  </span>
                </div>
                <h2 className="text-sm font-semibold text-soc-text">{alert.rule_description}</h2>
                <p className="text-xs font-mono text-soc-muted mt-1">
                  {alert.source_system}:{alert.rule_id} • Host: {alert.hostname || "N/A"} • Src:{" "}
                  {alert.src_ip || alert.domain || "N/A"}
                </p>
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-soc-border text-xs text-sky-400 font-medium">
                <span className="inline-flex items-center gap-1.5">
                  <FileSearch className="w-3.5 h-3.5" />
                  Launch Triage Workbench
                </span>
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

