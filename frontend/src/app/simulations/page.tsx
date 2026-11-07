"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ChevronRight,
  Loader2,
  Play,
  RotateCcw,
  Zap,
} from "lucide-react";
import { apiRequest } from "@/lib/api/generated";

interface Scenario {
  slug: string;
  scenario_id: string;
  name: string;
  short_summary: string;
  description: string;
  category: string;
  severity: string;
  expected_mitre_techniques: string[];
  associated_playbook_slug: string;
  expected_response_actions: string[];
  expected_investigation_path: string[];
  alerts_count: number;
}

interface SimulationExecution {
  id: string;
  scenario_slug: string;
  scenario_name: string;
  status: string;
  mode: string;
  alerts_count: number;
  incident_id: string | null;
  playbook_execution_id: string | null;
  execution_log: Array<{ timestamp: string; level: string; step: string; message: string }>;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
  is_simulated: boolean;
}

export default function SimulationsPage() {
  const queryClient = useQueryClient();
  const [selectedScenario, setSelectedScenario] = useState<Scenario | null>(null);
  const [launchMode, setLaunchMode] = useState<"full_chain" | "alerts_only" | "incident_only">("full_chain");
  const [resetModalOpen, setResetModalOpen] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");

  const { data: scenarios = [], isLoading: scenariosLoading } = useQuery({
    queryKey: ["simulation-scenarios"],
    queryFn: () => apiRequest<Scenario[]>("/api/v1/simulations/scenarios"),
  });

  const { data: executions = [], isLoading: executionsLoading } = useQuery({
    queryKey: ["simulation-executions"],
    queryFn: () => apiRequest<SimulationExecution[]>("/api/v1/simulations/executions"),
    refetchInterval: 5000,
  });

  const launchMutation = useMutation({
    mutationFn: ({ slug, mode }: { slug: string; mode: string }) =>
      apiRequest<SimulationExecution>(`/api/v1/simulations/scenarios/${slug}/launch`, {
        method: "POST",
        body: JSON.stringify({ mode }),
      }),
    onSuccess: () => {
      setSelectedScenario(null);
      void queryClient.invalidateQueries({ queryKey: ["simulation-executions"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const resetMutation = useMutation({
    mutationFn: () => apiRequest("/api/v1/simulations/reset", { method: "POST" }),
    onSuccess: () => {
      setResetModalOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["simulation-executions"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
  });

  const categories = ["all", ...Array.from(new Set(scenarios.map((s) => s.category)))];
  const filteredScenarios =
    selectedCategory === "all"
      ? scenarios
      : scenarios.filter((s) => s.category === selectedCategory);

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">
              Simulation Launcher
            </h1>
            <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-xs font-semibold text-amber-500 border border-amber-500/20">
              <Zap className="h-3 w-3" />
              7 Reproducible Scenarios
            </span>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Launch multi-stage attack scenarios through the production ingestion pipeline to test triage,
            enrichment, MITRE mapping, and human four-eyes response playbooks.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setResetModalOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3.5 py-2 text-sm font-semibold text-destructive hover:bg-destructive/20 transition-colors"
          >
            <RotateCcw className="h-4 w-4" />
            Reset Simulated Data
          </button>
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`capitalize rounded-lg px-3 py-1.5 text-xs font-semibold whitespace-nowrap transition-colors ${
              selectedCategory === cat
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:bg-muted/80"
            }`}
          >
            {cat === "all" ? "All Scenarios (7)" : cat.replace("_", " ")}
          </button>
        ))}
      </div>

      {/* Scenarios Grid */}
      {scenariosLoading ? (
        <div className="flex items-center justify-center p-12 text-muted-foreground">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading scenario library...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredScenarios.map((sc) => (
            <div
              key={sc.slug}
              className="flex flex-col justify-between rounded-xl border border-border bg-card p-5 hover:border-primary/50 transition-all shadow-sm"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-muted-foreground">
                    {sc.scenario_id}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                        sc.severity === "critical"
                          ? "bg-red-500/10 text-red-500 border border-red-500/20"
                          : sc.severity === "high"
                          ? "bg-orange-500/10 text-orange-500 border border-orange-500/20"
                          : "bg-amber-500/10 text-amber-500 border border-amber-500/20"
                      }`}
                    >
                      {sc.severity}
                    </span>
                    <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-muted text-muted-foreground">
                      {sc.category.replace("_", " ")}
                    </span>
                  </div>
                </div>

                <div>
                  <h3 className="text-base font-bold text-foreground leading-snug">
                    {sc.name}
                  </h3>
                  <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                    {sc.short_summary}
                  </p>
                </div>

                {/* MITRE Tags */}
                <div>
                  <div className="text-[10px] uppercase font-semibold text-muted-foreground mb-1">
                    MITRE ATT&CK Techniques:
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {sc.expected_mitre_techniques.map((tech) => (
                      <span
                        key={tech}
                        className="font-mono text-[10px] bg-secondary/80 text-secondary-foreground px-1.5 py-0.5 rounded"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Associated Playbook & Response */}
                <div className="rounded-lg bg-muted/50 p-2.5 text-xs space-y-1">
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span>Associated Playbook:</span>
                    <span className="font-mono font-bold text-foreground">
                      {sc.associated_playbook_slug}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span>Approval Containment:</span>
                    <span className="font-medium text-foreground">
                      {sc.expected_response_actions.join(", ")}
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-5 pt-4 border-t border-border flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  {sc.alerts_count} alert{sc.alerts_count > 1 ? "s" : ""}
                </span>
                <button
                  onClick={() => setSelectedScenario(sc)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground hover:bg-primary/90 transition-colors"
                >
                  <Play className="h-3 w-3 fill-current" />
                  Launch Scenario
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Execution History */}
      <div className="rounded-xl border border-border bg-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-foreground">Simulation History & Progress</h2>
            <p className="text-xs text-muted-foreground">
              Real-time audit trail of scenario executions and linked incidents.
            </p>
          </div>
        </div>

        {executionsLoading ? (
          <div className="p-8 text-center text-muted-foreground text-sm">
            <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2" />
            Loading executions...
          </div>
        ) : executions.length === 0 ? (
          <div className="p-8 text-center text-muted-foreground text-sm border border-dashed border-border rounded-lg">
            No scenario executions recorded yet. Click &quot;Launch Scenario&quot; above to start your first drill.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted/50 text-muted-foreground uppercase font-semibold border-b border-border">
                <tr>
                  <th className="py-2.5 px-3">Scenario</th>
                  <th className="py-2.5 px-3">Mode</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Alerts</th>
                  <th className="py-2.5 px-3">Linked Incident</th>
                  <th className="py-2.5 px-3">Playbook Execution</th>
                  <th className="py-2.5 px-3">Started At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {executions.map((ex) => (
                  <tr key={ex.id} className="hover:bg-muted/30 transition-colors">
                    <td className="py-3 px-3 font-medium text-foreground">
                      {ex.scenario_name}
                      <div className="text-[10px] text-muted-foreground font-mono">{ex.scenario_slug}</div>
                    </td>
                    <td className="py-3 px-3 font-mono uppercase text-[10px]">
                      {ex.mode.replace("_", " ")}
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          ex.status === "COMPLETED"
                            ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20"
                            : ex.status === "RUNNING"
                            ? "bg-blue-500/10 text-blue-500 border border-blue-500/20 animate-pulse"
                            : "bg-red-500/10 text-red-500 border border-red-500/20"
                        }`}
                      >
                        {ex.status}
                      </span>
                    </td>
                    <td className="py-3 px-3">{ex.alerts_count}</td>
                    <td className="py-3 px-3">
                      {ex.incident_id ? (
                        <Link
                          href={`/incidents/${ex.incident_id}`}
                          className="font-mono text-primary hover:underline font-bold inline-flex items-center gap-1"
                        >
                          View Incident <ChevronRight className="h-3 w-3" />
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      {ex.playbook_execution_id ? (
                        <Link
                          href={`/responses`}
                          className="font-mono text-primary hover:underline inline-flex items-center gap-1"
                        >
                          Check Approval Queue <ChevronRight className="h-3 w-3" />
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-muted-foreground">
                      {new Date(ex.started_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Launch Scenario Modal */}
      {selectedScenario && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-xl rounded-xl border border-border bg-card p-6 shadow-2xl space-y-5 animate-in fade-in-0 zoom-in-95">
            <div className="flex items-start justify-between border-b border-border pb-4">
              <div>
                <span className="text-xs font-mono text-amber-500 font-bold uppercase tracking-wider">
                  {selectedScenario.scenario_id}
                </span>
                <h3 className="text-lg font-bold text-foreground mt-1">
                  Launch: {selectedScenario.name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedScenario(null)}
                className="text-muted-foreground hover:text-foreground text-sm font-semibold"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed">
              {selectedScenario.description}
            </p>

            <div className="space-y-3">
              <label className="text-xs font-bold uppercase text-foreground">
                Execution Pipeline Mode:
              </label>
              <div className="grid grid-cols-1 gap-2.5">
                {[
                  {
                    id: "full_chain",
                    title: "Full Kill-Chain Response (Recommended)",
                    desc: "Ingests alerts -> Creates Incident -> Enriches IOCs -> Maps MITRE -> Triggers Playbook -> Queues Four-Eyes Human Approval.",
                  },
                  {
                    id: "incident_only",
                    title: "Incident & Threat Intelligence Only",
                    desc: "Ingests alerts and creates Incident with IOCs and MITRE mappings without auto-triggering SOAR playbooks.",
                  },
                  {
                    id: "alerts_only",
                    title: "Raw Alert Ingestion Only",
                    desc: "Injects raw alerts into the Alert Inbox to practice manual triage and analyst investigation workflows.",
                  },
                ].map((opt) => (
                  <label
                    key={opt.id}
                    className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-all ${
                      launchMode === opt.id
                        ? "border-primary bg-primary/5 ring-1 ring-primary"
                        : "border-border hover:bg-muted/50"
                    }`}
                  >
                    <input
                      type="radio"
                      name="launchMode"
                      value={opt.id}
                      checked={launchMode === opt.id}
                      onChange={() => setLaunchMode(opt.id as any)}
                      className="mt-0.5"
                    />
                    <div>
                      <div className="text-xs font-bold text-foreground">{opt.title}</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5">{opt.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-4 border-t border-border">
              <button
                type="button"
                onClick={() => setSelectedScenario(null)}
                className="rounded-lg px-4 py-2 text-xs font-semibold text-muted-foreground hover:text-foreground"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={launchMutation.isPending}
                onClick={() =>
                  launchMutation.mutate({
                    slug: selectedScenario.slug,
                    mode: launchMode,
                  })
                }
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground hover:bg-primary/90 disabled:opacity-50 shadow"
              >
                {launchMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Executing Pipeline...
                  </>
                ) : (
                  <>
                    <Play className="h-3.5 w-3.5 fill-current" />
                    Execute Scenario
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset Confirmation Modal */}
      {resetModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-destructive/30 bg-card p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-destructive">
              <AlertTriangle className="h-6 w-6" />
              <h3 className="text-base font-bold">Reset Simulated Scenario Data?</h3>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              This action will strictly purge all simulation-flagged records (where{" "}
              <code className="text-foreground font-mono">is_simulated = true</code>), including simulated
              alerts, incidents, evidence, and response actions. Real operational incidents are protected.
            </p>
            <div className="flex items-center justify-end gap-3 pt-3">
              <button
                type="button"
                onClick={() => setResetModalOpen(false)}
                className="rounded-lg px-3.5 py-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={resetMutation.isPending}
                onClick={() => resetMutation.mutate()}
                className="inline-flex items-center gap-2 rounded-lg bg-destructive px-3.5 py-1.5 text-xs font-semibold text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                {resetMutation.isPending ? "Purging..." : "Confirm Purge"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
