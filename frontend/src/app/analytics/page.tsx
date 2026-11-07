"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  BarChart3,
  CheckCircle2,
  Clock,
  Flame,
  Loader2,
  Shield,
  ShieldAlert,
  Zap,
} from "lucide-react";
import { apiRequest } from "@/lib/api/generated";

interface OverviewData {
  window_days: number;
  generated_at: string;
  kpis: {
    mttd_minutes: number;
    mtta_minutes: number;
    mttc_minutes: number;
    mttr_minutes: number;
    total_incidents: number;
    open_incidents: number;
    critical_open: number;
    high_open: number;
    total_alerts: number;
    unreviewed_alerts: number;
    sla_compliance_rate: number;
    playbook_success_rate: number;
    total_playbook_runs: number;
  };
  severity_distribution: Array<{ severity: string; count: number }>;
  status_distribution: Array<{ status: string; count: number }>;
  category_distribution: Array<{ category: string; count: number }>;
}

interface TrendsData {
  window_days: number;
  daily_trends: Array<{
    date: string;
    alerts: number;
    incidents: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
}

interface PerformanceData {
  window_days: number;
  playbooks: {
    total_executions: number;
    by_status: Record<string, number>;
  };
  response_actions: {
    total_actions: number;
    by_status: Record<string, number>;
    approvals: Record<string, number>;
  };
  mitre_techniques: {
    top_techniques: Array<{
      technique_id: string;
      name: string;
      count: number;
      tactics: string[];
    }>;
  };
  threat_intelligence: {
    total_indicators: number;
    reputations: Record<string, number>;
  };
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#F59E0B",
  low: "#3B82F6",
};

const REPUTATION_COLORS: Record<string, string> = {
  malicious: "#EF4444",
  suspicious: "#F59E0B",
  benign: "#10B981",
  internal: "#3B82F6",
  unknown: "#9CA3AF",
};

export default function AnalyticsPage() {
  const [windowDays, setWindowDays] = useState<number>(30);
  const [includeSimulated, setIncludeSimulated] = useState<boolean>(true);

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ["analytics-overview", windowDays, includeSimulated],
    queryFn: () =>
      apiRequest<OverviewData>(
        `/api/v1/analytics/overview?window_days=${windowDays}&include_simulated=${includeSimulated}`
      ),
  });

  const { data: trends, isLoading: trendsLoading } = useQuery({
    queryKey: ["analytics-trends", windowDays, includeSimulated],
    queryFn: () =>
      apiRequest<TrendsData>(
        `/api/v1/analytics/trends?window_days=${windowDays}&include_simulated=${includeSimulated}`
      ),
  });

  const { data: performance, isLoading: perfLoading } = useQuery({
    queryKey: ["analytics-performance", windowDays, includeSimulated],
    queryFn: () =>
      apiRequest<PerformanceData>(
        `/api/v1/analytics/performance?window_days=${windowDays}&include_simulated=${includeSimulated}`
      ),
  });

  const kpis = overview?.kpis;

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <BarChart3 className="h-6 w-6 text-primary" />
            SOC Command Analytics & Operational Performance
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Database-driven detection and response metrics, SLA compliance rates, MTTD/MTTA/MTTR durations,
            and ATT&CK technique frequencies.
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-xs font-semibold text-muted-foreground cursor-pointer bg-card border border-border rounded-lg px-3 py-2">
            <input
              type="checkbox"
              checked={includeSimulated}
              onChange={(e) => setIncludeSimulated(e.target.checked)}
              className="rounded"
            />
            Include Simulated Scenarios
          </label>

          <div className="flex rounded-lg border border-border bg-card p-1">
            {[7, 30, 90].map((days) => (
              <button
                key={days}
                onClick={() => setWindowDays(days)}
                className={`rounded px-3 py-1 text-xs font-bold transition-colors ${
                  windowDays === days
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {days}d
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      {overviewLoading ? (
        <div className="flex items-center justify-center p-12 text-muted-foreground">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading analytics metrics...
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
          <div className="rounded-xl border border-border bg-card p-4 space-y-1 shadow-sm">
            <div className="text-[11px] font-bold uppercase text-muted-foreground flex items-center gap-1">
              <Clock className="h-3 w-3" />
              MTTD (Detect)
            </div>
            <div className="text-2xl font-black text-foreground">
              {kpis?.mttd_minutes ?? 0}
              <span className="text-xs font-normal text-muted-foreground ml-1">min</span>
            </div>
            <div className="text-[10px] text-muted-foreground">Alert event to ingest</div>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-1 shadow-sm">
            <div className="text-[11px] font-bold uppercase text-muted-foreground flex items-center gap-1">
              <Clock className="h-3 w-3" />
              MTTA (Ack)
            </div>
            <div className="text-2xl font-black text-foreground">
              {kpis?.mtta_minutes ?? 0}
              <span className="text-xs font-normal text-muted-foreground ml-1">min</span>
            </div>
            <div className="text-[10px] text-muted-foreground">Time to acknowledge</div>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-1 shadow-sm">
            <div className="text-[11px] font-bold uppercase text-muted-foreground flex items-center gap-1">
              <Shield className="h-3 w-3 text-amber-500" />
              MTTC (Contain)
            </div>
            <div className="text-2xl font-black text-foreground">
              {kpis?.mttc_minutes ?? 0}
              <span className="text-xs font-normal text-muted-foreground ml-1">min</span>
            </div>
            <div className="text-[10px] text-muted-foreground">Containment response</div>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-1 shadow-sm">
            <div className="text-[11px] font-bold uppercase text-muted-foreground flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3 text-emerald-500" />
              MTTR (Resolve)
            </div>
            <div className="text-2xl font-black text-foreground">
              {kpis?.mttr_minutes ?? 0}
              <span className="text-xs font-normal text-muted-foreground ml-1">min</span>
            </div>
            <div className="text-[10px] text-muted-foreground">Full incident resolution</div>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-1 shadow-sm">
            <div className="text-[11px] font-bold uppercase text-muted-foreground flex items-center gap-1">
              <Activity className="h-3 w-3 text-emerald-500" />
              SLA Rate
            </div>
            <div className="text-2xl font-black text-emerald-500">
              {kpis?.sla_compliance_rate ?? 100}%
            </div>
            <div className="text-[10px] text-muted-foreground">Resolved within target</div>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-1 shadow-sm">
            <div className="text-[11px] font-bold uppercase text-muted-foreground flex items-center gap-1">
              <Flame className="h-3 w-3 text-red-500" />
              Open Cases
            </div>
            <div className="text-2xl font-black text-foreground">
              {kpis?.open_incidents ?? 0}
              <span className="text-xs font-bold text-red-500 ml-1.5">
                ({kpis?.critical_open ?? 0} crit)
              </span>
            </div>
            <div className="text-[10px] text-muted-foreground">Of {kpis?.total_incidents ?? 0} total</div>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-1 shadow-sm">
            <div className="text-[11px] font-bold uppercase text-muted-foreground flex items-center gap-1">
              <Zap className="h-3 w-3 text-blue-500" />
              SOAR Success
            </div>
            <div className="text-2xl font-black text-primary">
              {kpis?.playbook_success_rate ?? 100}%
            </div>
            <div className="text-[10px] text-muted-foreground">
              {kpis?.total_playbook_runs ?? 0} playbook runs
            </div>
          </div>
        </div>
      )}

      {/* Chart Section 1: Timeline Volume Trends */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-foreground">
              Incident & Alert Volume Trend ({windowDays} Days)
            </h2>
          </div>
          <div className="h-72 w-full">
            {trendsLoading ? (
              <div className="flex h-full items-center justify-center text-muted-foreground text-xs">
                <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading trend data...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trends?.daily_trends || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="date" stroke="#94A3B8" fontSize={10} tickLine={false} />
                  <YAxis stroke="#94A3B8" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0F172A",
                      borderColor: "#334155",
                      borderRadius: "6px",
                      fontSize: "11px",
                      color: "#F8FAFC",
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: "11px" }} />
                  <Area
                    type="monotone"
                    dataKey="alerts"
                    name="Alerts Ingested"
                    stroke="#3B82F6"
                    fill="#3B82F6"
                    fillOpacity={0.15}
                  />
                  <Area
                    type="monotone"
                    dataKey="incidents"
                    name="Incidents Created"
                    stroke="#F97316"
                    fill="#F97316"
                    fillOpacity={0.25}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Severity Distribution Donut */}
        <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm flex flex-col justify-between">
          <h2 className="text-sm font-bold uppercase tracking-wider text-foreground">
            Incident Severity Breakdown
          </h2>
          <div className="h-56 w-full flex items-center justify-center">
            {overviewLoading ? (
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={overview?.severity_distribution || []}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="count"
                    nameKey="severity"
                  >
                    {overview?.severity_distribution?.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={SEVERITY_COLORS[entry.severity] || "#94A3B8"}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0F172A",
                      borderColor: "#334155",
                      borderRadius: "6px",
                      fontSize: "11px",
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: "11px" }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs pt-2 border-t border-border">
            {overview?.severity_distribution?.map((item) => (
              <div key={item.severity} className="flex items-center justify-between">
                <span className="capitalize font-semibold text-muted-foreground">{item.severity}:</span>
                <span className="font-bold text-foreground">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Chart Section 2: MITRE ATT&CK & Top Threat Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top 10 MITRE ATT&CK Techniques */}
        <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-primary" />
            Top MITRE ATT&CK® Techniques Mapped
          </h2>
          <div className="h-72 w-full">
            {perfLoading ? (
              <div className="flex h-full items-center justify-center text-muted-foreground text-xs">
                <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading MITRE metrics...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={performance?.mitre_techniques?.top_techniques || []}
                  layout="vertical"
                  margin={{ top: 5, right: 20, left: 20, bottom: 5 }}
                >
                  <XAxis type="number" stroke="#94A3B8" fontSize={10} tickLine={false} />
                  <YAxis
                    type="category"
                    dataKey="technique_id"
                    stroke="#94A3B8"
                    fontSize={10}
                    tickLine={false}
                    width={70}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0F172A",
                      borderColor: "#334155",
                      borderRadius: "6px",
                      fontSize: "11px",
                    }}
                  />
                  <Bar dataKey="count" name="Frequency" fill="#6366F1" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Threat Intelligence Indicator Reputations */}
        <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
            <Zap className="h-4 w-4 text-primary" />
            Threat Intelligence Indicator Reputations
          </h2>
          <div className="h-72 w-full flex items-center justify-center">
            {perfLoading ? (
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={
                      performance?.threat_intelligence?.reputations
                        ? Object.entries(performance.threat_intelligence.reputations).map(
                            ([k, v]) => ({ reputation: k, count: v })
                          )
                        : []
                    }
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="count"
                    nameKey="reputation"
                  >
                    {Object.keys(performance?.threat_intelligence?.reputations || {}).map(
                      (rep, idx) => (
                        <Cell
                          key={`cell-${idx}`}
                          fill={REPUTATION_COLORS[rep] || "#94A3B8"}
                        />
                      )
                    )}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0F172A",
                      borderColor: "#334155",
                      borderRadius: "6px",
                      fontSize: "11px",
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: "11px" }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
