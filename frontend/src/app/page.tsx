"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Clock,
  HelpCircle,
  RefreshCw,
  Shield,
  ShieldAlert,
  Timer,
  X,
} from "lucide-react";
import { apiRequest } from "@/lib/api/generated";
import {
  IncidentStatusBadge,
  RoleBadge,
  SeverityBadge,
  SimulatedBadge,
  SlaBadge,
} from "@/components/ui/badges";
import { formatMinutesDuration, formatRelativeTime } from "@/lib/format";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#38bdf8",
};

export default function CommandCenterPage() {
  const [windowDays, setWindowDays] = useState<number>(30);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [showGuide, setShowGuide] = useState<boolean>(true);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["command-center", windowDays, severityFilter],
    queryFn: () =>
      apiRequest<any>("/api/v1/analytics/command-center", {
        params: {
          window_days: windowDays,
          severity: severityFilter || undefined,
        },
      }),
    refetchInterval: 30_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-8 w-64 bg-soc-surface rounded animate-pulse" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 rounded-lg border border-soc-border bg-soc-surface animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-300">
        Failed to load SOC Command Centre telemetry.{" "}
        <button onClick={() => void refetch()} className="underline font-medium ml-2">
          Retry
        </button>
      </div>
    );
  }

  const { kpis, sla_summary, sla_watchlist, severity_distribution, alert_source_distribution, trends, analyst_workload, recent_activity } = data;

  return (
    <div className="space-y-6">
      {/* Header & Operational Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">SOC Command Centre</h1>
          <p className="text-xs text-soc-muted mt-0.5">
            Live database-driven incident posture, SLA compliance, and triage telemetry
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Time window"
            value={windowDays}
            onChange={(e) => setWindowDays(Number(e.target.value))}
            className="rounded-md border border-soc-border bg-soc-surface px-3 py-1.5 text-xs text-soc-text"
          >
            <option value={1}>Last 24 Hours</option>
            <option value={7}>Last 7 Days</option>
            <option value={30}>Last 30 Days</option>
            <option value={90}>Last 90 Days</option>
          </select>

          <select
            aria-label="Severity filter"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-md border border-soc-border bg-soc-surface px-3 py-1.5 text-xs text-soc-text"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
          </select>

          <button
            type="button"
            onClick={() => setShowGuide((prev) => !prev)}
            className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${
              showGuide
                ? "border-sky-500/50 bg-sky-500/15 text-sky-300"
                : "border-soc-border bg-soc-surface hover:bg-soc-elevated text-soc-muted"
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            SOC Guide
          </button>

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

      {/* First-Time Analyst Orientation Card */}
      {showGuide && (
        <div className="relative rounded-xl border border-sky-500/30 bg-gradient-to-r from-sky-950/40 via-soc-surface to-soc-surface p-4 sm:p-5">
          <button
            onClick={() => setShowGuide(false)}
            className="absolute top-3 right-3 text-soc-muted hover:text-soc-text p-1"
            title="Dismiss Guide"
          >
            <X className="w-4 h-4" />
          </button>

          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20 shrink-0 mt-0.5">
              <Shield className="w-5 h-5" />
            </div>
            <div className="space-y-3 pr-6 w-full">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  First Time in SENTINEL IR? Here is the 4-Step SOC Workflow
                </h3>
                <p className="text-xs text-soc-muted mt-1">
                  This platform coordinates the entire security incident response lifecycle. Follow these four stages to triage, investigate, contain, and report on threats:
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <Link
                  href="/alerts"
                  className="rounded-lg border border-soc-border bg-soc-bg/60 hover:border-sky-500/40 p-3 transition-colors group block"
                >
                  <div className="flex items-center justify-between text-xs font-semibold text-sky-300 mb-1">
                    <span>1. Triage Alarms</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p className="text-[11px] text-soc-muted">
                    Incoming SIEM alerts. Inspect headers, filter false positives, and promote real attacks to Incidents.
                  </p>
                </Link>

                <Link
                  href="/incidents"
                  className="rounded-lg border border-soc-border bg-soc-bg/60 hover:border-amber-500/40 p-3 transition-colors group block"
                >
                  <div className="flex items-center justify-between text-xs font-semibold text-amber-300 mb-1">
                    <span>2. Investigate Cases</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p className="text-[11px] text-soc-muted">
                    Enrich malicious IPs/hashes, map MITRE ATT&CK techniques, and preserve forensic evidence with SHA-256.
                  </p>
                </Link>

                <Link
                  href="/playbooks"
                  className="rounded-lg border border-soc-border bg-soc-bg/60 hover:border-emerald-500/40 p-3 transition-colors group block"
                >
                  <div className="flex items-center justify-between text-xs font-semibold text-emerald-300 mb-1">
                    <span>3. SOAR Containment</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p className="text-[11px] text-soc-muted">
                    Execute automated playbooks. High-impact containment actions require manager 4-eyes approval.
                  </p>
                </Link>

                <Link
                  href="/simulations"
                  className="rounded-lg border border-soc-border bg-soc-bg/60 hover:border-purple-500/40 p-3 transition-colors group block"
                >
                  <div className="flex items-center justify-between text-xs font-semibold text-purple-300 mb-1">
                    <span>4. Attack Simulations</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p className="text-[11px] text-soc-muted">
                    Launch 7 real attack drills (Brute Force, Ransomware, Exfiltration) to see live telemetry flow in.
                  </p>
                </Link>
              </div>

              <div className="text-[11px] text-soc-muted/80 flex items-center gap-1.5 pt-1">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                <span>
                  <strong>Data telemetry note:</strong> Metrics reflect real PostgreSQL queries. The system is initialized with baseline demo incidents and 637 MITRE techniques; launching a simulation injects live events.
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-3">
        <KpiCard
          label="Total Alerts"
          value={kpis.total_alerts}
          sub={`${kpis.unreviewed_alerts} unreviewed`}
          icon={<AlertTriangle className="w-4 h-4 text-sky-400" />}
          href="/alerts"
        />
        <KpiCard
          label="Open Incidents"
          value={kpis.open_incidents}
          sub={`${kpis.under_investigation} investigating`}
          icon={<ShieldAlert className="w-4 h-4 text-cyan-400" />}
          href="/incidents"
        />
        <KpiCard
          label="Critical Cases"
          value={kpis.critical_incidents}
          sub="15m Ack / 4h SLA"
          icon={<AlertOctagon className="w-4 h-4 text-red-400" />}
          valueClass={kpis.critical_incidents > 0 ? "text-red-400" : undefined}
          href="/incidents?severity=critical"
        />
        <KpiCard
          label="High Priority"
          value={kpis.high_priority_incidents}
          sub="1h Ack / 8h SLA"
          icon={<AlertTriangle className="w-4 h-4 text-orange-400" />}
          valueClass={kpis.high_priority_incidents > 0 ? "text-orange-400" : undefined}
          href="/incidents?severity=high"
        />
        <KpiCard
          label="Awaiting Action"
          value={kpis.awaiting_analyst_action}
          sub="Unassigned or NEW"
          icon={<Clock className="w-4 h-4 text-amber-400" />}
        />
        <KpiCard
          label="Resolved"
          value={kpis.resolved_incidents}
          sub={`In ${windowDays}d window`}
          icon={<CheckCircle2 className="w-4 h-4 text-emerald-400" />}
        />
        <KpiCard
          label="Mean Time to Ack"
          value={formatMinutesDuration(kpis.mtta_minutes)}
          sub="MTTA"
          tooltip="MTTA = mean of (first analyst acknowledgement or assignment timestamp minus incident creation timestamp)."
          icon={<Timer className="w-4 h-4 text-sky-400" />}
        />
        <KpiCard
          label="Mean Time to Resolve"
          value={formatMinutesDuration(kpis.mttr_minutes)}
          sub="MTTR"
          tooltip="MTTR = mean of (resolved timestamp minus incident creation timestamp) for incidents resolved in the selected window."
          icon={<Activity className="w-4 h-4 text-emerald-400" />}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-lg border border-soc-border bg-soc-surface p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">Alert &amp; Incident Volume Trend (UTC)</h2>
            <span className="text-[11px] text-soc-muted font-mono">
              DB Total: {kpis.total_alerts_all_time} alerts / {kpis.total_incidents_all_time} cases
            </span>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d45" />
                <XAxis dataKey="date" tick={{ fill: "#8b9bb4", fontSize: 11 }} />
                <YAxis allowDecimals={false} tick={{ fill: "#8b9bb4", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0e1624",
                    borderColor: "#1e2d45",
                    fontSize: "12px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  name="Alerts Ingested"
                  stroke="#0ea5e9"
                  fill="#0ea5e9"
                  fillOpacity={0.18}
                />
                <Area
                  type="monotone"
                  dataKey="incidents"
                  name="Incidents Created"
                  stroke="#f97316"
                  fill="#f97316"
                  fillOpacity={0.22}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-lg border border-soc-border bg-soc-surface p-4 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold mb-3">Incident Severity &amp; Source Split</h2>
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severity_distribution}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d45" />
                  <XAxis dataKey="severity" tick={{ fill: "#8b9bb4", fontSize: 11 }} />
                  <YAxis allowDecimals={false} tick={{ fill: "#8b9bb4", fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0e1624",
                      borderColor: "#1e2d45",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" name="Incidents" radius={[4, 4, 0, 0]}>
                    {severity_distribution.map((entry: any) => (
                      <Cell
                        key={entry.severity}
                        fill={SEVERITY_COLORS[entry.severity] || "#38bdf8"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="mt-3 pt-3 border-t border-soc-border space-y-1.5">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-soc-muted">
              Alert Sources
            </p>
            {alert_source_distribution.length === 0 ? (
              <p className="text-xs text-soc-muted">No alerts in selected window.</p>
            ) : (
              alert_source_distribution.map((src: any) => (
                <div key={src.source} className="flex items-center justify-between text-xs">
                  <span className="font-mono uppercase text-soc-muted">{src.source}</span>
                  <span className="font-semibold">{src.count}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* SLA Watchlist, Analyst Workload & Live Incident Feed */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* SLA Watchlist */}
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">Active Incident SLA Status</h2>
            <div className="flex items-center gap-2 text-[11px] font-mono">
              <span className="text-emerald-400">{sla_summary.on_track} OK</span>
              <span className="text-amber-300">{sla_summary.at_risk} Risk</span>
              <span className="text-red-400">{sla_summary.breached} Breach</span>
            </div>
          </div>
          {sla_watchlist.length === 0 ? (
            <p className="text-xs text-soc-muted py-6 text-center">
              No active open incidents in queue.
            </p>
          ) : (
            <div className="space-y-3">
              {sla_watchlist.map((item: any) => (
                <Link
                  key={item.incident_id}
                  href={`/incidents/${item.human_id}`}
                  className="block rounded border border-soc-border bg-soc-bg/60 hover:bg-soc-elevated p-3 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-sky-400">
                        {item.human_id}
                      </span>
                      <SeverityBadge severity={item.severity} />
                      {item.is_simulated && <SimulatedBadge />}
                    </div>
                    <SlaBadge status={item.sla_status} />
                  </div>
                  <p className="text-xs text-soc-text truncate">{item.title}</p>
                  <div className="mt-2 flex items-center justify-between text-[11px] text-soc-muted">
                    <IncidentStatusBadge status={item.status} />
                    <span>{Math.min(Math.round(item.elapsed_ratio * 100), 100)}% window elapsed</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Analyst Workload */}
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">SOC Shift &amp; Analyst Workload</h2>
            <Link href="/analysts" className="text-xs text-sky-400 hover:underline">
              Manage Roster
            </Link>
          </div>
          <div className="space-y-2.5">
            {analyst_workload.map((a: any) => (
              <div
                key={a.user_id}
                className="flex items-center justify-between rounded border border-soc-border bg-soc-bg/60 px-3 py-2.5"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium truncate">{a.full_name}</span>
                    <RoleBadge role={a.role} />
                  </div>
                  <span className="text-[11px] font-mono text-soc-muted">@{a.username}</span>
                </div>
                <div className="flex items-center gap-3 text-right shrink-0">
                  <div>
                    <span className="block text-xs font-semibold">{a.open_incidents}</span>
                    <span className="block text-[10px] text-soc-muted">Cases</span>
                  </div>
                  <div>
                    <span className="block text-xs font-semibold">{a.active_alerts}</span>
                    <span className="block text-[10px] text-soc-muted">Alerts</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live Incident Activity Feed */}
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
          <h2 className="text-sm font-semibold mb-3">Live SOC Case Activity Feed</h2>
          {recent_activity.length === 0 ? (
            <p className="text-xs text-soc-muted py-6 text-center">No recent timeline activity.</p>
          ) : (
            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {recent_activity.map((ev: any) => (
                <div
                  key={ev.id}
                  className="border-l-2 border-sky-500/40 pl-3 py-0.5 space-y-0.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <Link
                      href={`/incidents/${ev.human_id}`}
                      className="text-xs font-mono font-semibold text-sky-400 hover:underline"
                    >
                      {ev.human_id}
                    </Link>
                    <span className="text-[10px] text-soc-muted">
                      {formatRelativeTime(ev.occurred_at)}
                    </span>
                  </div>
                  <p className="text-xs font-medium text-soc-text">{ev.title}</p>
                  <p className="text-[11px] text-soc-muted line-clamp-2">
                    {ev.actor_label} {ev.description ? `— ${ev.description}` : ""}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function KpiCard({
  label,
  value,
  sub,
  icon,
  tooltip,
  valueClass,
  href,
}: {
  label: string;
  value: string | number;
  sub: string;
  icon: React.ReactNode;
  tooltip?: string;
  valueClass?: string;
  href?: string;
}) {
  const inner = (
    <div className="rounded-lg border border-soc-border bg-soc-surface hover:border-sky-500/40 p-3.5 transition-colors h-full flex flex-col justify-between">
      <div className="flex items-center justify-between gap-1">
        <span className="text-[11px] font-medium text-soc-muted flex items-center gap-1">
          {label}
          {tooltip && (
            <span title={tooltip} className="cursor-help text-soc-muted hover:text-soc-text">
              <HelpCircle className="w-3 h-3" />
            </span>
          )}
        </span>
        {icon}
      </div>
      <div className="mt-2">
        <div className={`text-xl font-semibold tracking-tight font-mono ${valueClass || ""}`}>
          {value}
        </div>
        <div className="text-[11px] text-soc-muted mt-0.5 truncate">{sub}</div>
      </div>
    </div>
  );
  return href ? <Link href={href}>{inner}</Link> : inner;
}
