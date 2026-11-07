import React from "react";

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const s = (severity || "medium").toLowerCase();
  const styles: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/35",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/35",
    medium: "bg-amber-500/15 text-amber-300 border-amber-500/35",
    low: "bg-sky-500/15 text-sky-300 border-sky-500/35",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider border ${
        styles[s] || styles.medium
      }`}
    >
      {s}
    </span>
  );
}

export function IncidentStatusBadge({ status }: { status?: string | null }) {
  const st = (status || "NEW").toUpperCase();
  const styles: Record<string, string> = {
    NEW: "bg-sky-500/15 text-sky-300 border-sky-500/30",
    TRIAGED: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30",
    INVESTIGATING: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
    CONTAINMENT: "bg-orange-500/15 text-orange-300 border-orange-500/30",
    ERADICATION: "bg-amber-500/15 text-amber-300 border-amber-500/30",
    RECOVERY: "bg-teal-500/15 text-teal-300 border-teal-500/30",
    RESOLVED: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    CLOSED: "bg-slate-500/20 text-slate-300 border-slate-500/35",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${
        styles[st] || styles.NEW
      }`}
    >
      {st}
    </span>
  );
}

export function AlertTriageBadge({ status }: { status?: string | null }) {
  const st = (status || "new").toLowerCase();
  const labels: Record<string, string> = {
    new: "NEW",
    in_review: "IN REVIEW",
    escalated: "ESCALATED",
    incident_created: "CASE LINKED",
    false_positive: "FALSE POSITIVE",
  };
  const styles: Record<string, string> = {
    new: "bg-sky-500/15 text-sky-300 border-sky-500/30",
    in_review: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
    escalated: "bg-orange-500/15 text-orange-300 border-orange-500/30",
    incident_created: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    false_positive: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wide border ${
        styles[st] || styles.new
      }`}
    >
      {labels[st] || st.toUpperCase()}
    </span>
  );
}

export function SlaBadge({ status }: { status?: string | null }) {
  const s = (status || "on_track").toLowerCase();
  const map: Record<string, { label: string; cls: string }> = {
    on_track: {
      label: "SLA ON TRACK",
      cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    },
    at_risk: {
      label: "SLA AT RISK (>75%)",
      cls: "bg-amber-500/15 text-amber-300 border-amber-500/35",
    },
    breached: {
      label: "SLA BREACHED",
      cls: "bg-red-500/15 text-red-400 border-red-500/35",
    },
  };
  const item = map[s] || map.on_track;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider border ${item.cls}`}
    >
      {item.label}
    </span>
  );
}

export function SimulatedBadge() {
  return (
    <span
      title="Record generated through SENTINEL IR Simulation Engine using RFC 5737 documentation indicators"
      className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider bg-purple-500/15 text-purple-300 border border-purple-500/35"
    >
      SIMULATED
    </span>
  );
}

export function MockIntelBadge() {
  return (
    <span
      title="Deterministic Mock Threat Intelligence Provider (no external live API key configured)"
      className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider bg-amber-500/15 text-amber-300 border border-amber-500/35"
    >
      MOCK / SIMULATED
    </span>
  );
}

export function RoleBadge({ role }: { role: string }) {
  const labels: Record<string, string> = {
    soc_l1: "SOC L1",
    soc_l2: "SOC L2",
    soc_manager: "SOC MANAGER",
    admin: "ADMIN",
  };
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider bg-sky-500/15 text-sky-300 border border-sky-500/30">
      {labels[role] || role.toUpperCase()}
    </span>
  );
}

