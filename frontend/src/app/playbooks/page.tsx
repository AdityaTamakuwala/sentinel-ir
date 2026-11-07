"use client";

import { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Clock,
  Filter,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  Terminal,
  X,
  XCircle,
} from "lucide-react";
import {
  PlaybookExecuteRequest,
  PlaybookExecutionOut,
  PlaybookOut,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth } from "@/components/providers";
import { formatRelativeTime } from "@/lib/format";

export default function PlaybooksPage() {
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();

  const [activeTab, setActiveTab] = useState<"library" | "executions">("library");
  const [searchTerm, setSearchTerm] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  // Trigger modal state
  const [triggerPlaybook, setTriggerPlaybook] = useState<PlaybookOut | null>(null);
  const [isDryRun, setIsDryRun] = useState(false);
  const [targetIncidentId, setTargetIncidentId] = useState("");
  const [parameterInputs, setParameterInputs] = useState<Record<string, string>>({});
  const [triggerError, setTriggerError] = useState<string | null>(null);

  // Trace drawer state
  const [selectedExecution, setSelectedExecution] = useState<PlaybookExecutionOut | null>(null);

  // 1. Playbooks List Query
  const playbooksQuery = useQuery({
    queryKey: ["playbooks"],
    queryFn: async () => {
      return await apiRequest<PlaybookOut[]>("/api/v1/playbooks");
    },
  });

  // 2. Executions List Query
  const executionsQuery = useQuery({
    queryKey: ["playbook-executions"],
    queryFn: async () => {
      return await apiRequest<PlaybookExecutionOut[]>("/api/v1/playbooks/executions?limit=50");
    },
    refetchInterval: 5000,
  });

  // 3. Sync Playbooks Mutation
  const syncMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest<{ status: string; synced_count: number }>("/api/v1/playbooks/sync", {
        method: "POST",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    },
  });

  // 4. Execute Playbook Mutation
  const executeMutation = useMutation({
    mutationFn: async ({ slug, req }: { slug: string; req: PlaybookExecuteRequest }) => {
      return await apiRequest<PlaybookExecutionOut>(`/api/v1/playbooks/${slug}/execute`, {
        method: "POST",
        body: req,
      });
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["playbook-executions"] });
      setTriggerPlaybook(null);
      setParameterInputs({});
      setTargetIncidentId("");
      setTriggerError(null);
      setActiveTab("executions");
      setSelectedExecution(data);
    },
    onError: (err: any) => {
      setTriggerError(err.message || "Failed to trigger playbook execution");
    },
  });

  // 5. Cancel Execution Mutation
  const cancelMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiRequest<PlaybookExecutionOut>(`/api/v1/playbooks/executions/${id}/cancel`, {
        method: "POST",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["playbook-executions"] });
    },
  });

  const playbooks = playbooksQuery.data || [];
  const executions = executionsQuery.data || [];

  const filteredPlaybooks = playbooks.filter((pb) => {
    const matchesSearch =
      pb.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      pb.slug.toLowerCase().includes(searchTerm.toLowerCase()) ||
      pb.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory =
      categoryFilter === "all" || pb.slug.toLowerCase().includes(categoryFilter);
    return matchesSearch && matchesCategory;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "COMPLETED":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3.5 h-3.5" />
            COMPLETED
          </span>
        );
      case "WAITING_APPROVAL":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse">
            <Clock className="w-3.5 h-3.5" />
            WAITING APPROVAL
          </span>
        );
      case "RUNNING":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            RUNNING
          </span>
        );
      case "FAILED":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3.5 h-3.5" />
            FAILED
          </span>
        );
      case "CANCELLED":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
            CANCELLED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-300 border border-slate-500/20">
            {status}
          </span>
        );
    }
  };

  const getCategoryColor = (slug: string) => {
    if (slug.includes("phish")) return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    if (slug.includes("malware")) return "bg-rose-500/10 text-rose-400 border-rose-500/20";
    if (slug.includes("brute") || slug.includes("credential"))
      return "bg-amber-500/10 text-amber-400 border-amber-500/20";
    if (slug.includes("unauthorized")) return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
    if (slug.includes("ransomware")) return "bg-red-500/10 text-red-400 border-red-500/20";
    return "bg-blue-500/10 text-blue-400 border-blue-500/20";
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              SOAR ORCHESTRATION
            </span>
            <span className="text-xs text-slate-400 font-mono">TIER 1 AUTOMATION</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white mt-1">
            Declarative Playbook Engine
          </h1>
          <p className="text-sm text-slate-400">
            Manage automated SOC investigation workflows, execute safe dry-runs, and monitor human-approved checkpoints.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {hasPermission("playbooks:manage") && (
            <button
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
              className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-700 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncMutation.isPending ? "animate-spin" : ""}`} />
              Sync YAML Definitions
            </button>
          )}

          <Link
            href="/responses"
            className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 transition shadow-lg shadow-cyan-900/20"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Approval Queue
          </Link>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab("library")}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
            activeTab === "library"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-slate-400 hover:text-slate-300"
          }`}
        >
          <BookOpen className="w-4 h-4" />
          Playbook Library
          <span className="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {playbooks.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("executions")}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
            activeTab === "executions"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-slate-400 hover:text-slate-300"
          }`}
        >
          <Terminal className="w-4 h-4" />
          Execution Monitor
          <span className="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {executions.length}
          </span>
        </button>
      </div>

      {/* TAB 1: PLAYBOOK LIBRARY */}
      {activeTab === "library" && (
        <div className="space-y-6">
          {/* Search & Filter Bar */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search playbooks by name, slug, or purpose..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-4 py-2 text-sm bg-slate-900 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-slate-500" />
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-3 py-2 text-sm bg-slate-900 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Categories</option>
                <option value="phish">Phishing</option>
                <option value="malware">Malware</option>
                <option value="credential">Credential Compromise</option>
                <option value="unauthorized">Unauthorized Access</option>
                <option value="ransomware">Ransomware</option>
                <option value="exfiltration">Data Exfiltration</option>
              </select>
            </div>
          </div>

          {/* Playbooks Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {filteredPlaybooks.map((pb) => (
              <div
                key={pb.id}
                className="flex flex-col justify-between p-5 rounded-xl bg-slate-900/80 border border-slate-800/80 hover:border-slate-700 transition"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span
                      className={`px-2.5 py-0.5 text-xs font-semibold rounded-full border ${getCategoryColor(
                        pb.slug
                      )}`}
                    >
                      {pb.slug.toUpperCase()}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">v{pb.current_version}</span>
                  </div>

                  <h3 className="text-base font-semibold text-white mb-2">{pb.name}</h3>
                  <p className="text-xs text-slate-400 line-clamp-3 mb-4">{pb.description}</p>
                </div>

                <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{pb.step_count} Steps</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <Link
                      href={`/playbooks/${pb.slug}`}
                      className="px-2.5 py-1.5 rounded text-slate-300 hover:text-white hover:bg-slate-800 transition inline-flex items-center gap-1"
                    >
                      Details
                      <ArrowRight className="w-3 h-3" />
                    </Link>

                    {hasPermission("playbooks:execute") && (
                      <button
                        onClick={() => {
                          setTriggerPlaybook(pb);
                          setTriggerError(null);
                        }}
                        className="px-3 py-1.5 rounded bg-cyan-600/90 hover:bg-cyan-500 text-white font-medium inline-flex items-center gap-1.5 transition"
                      >
                        <Play className="w-3 h-3 fill-current" />
                        Run
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: EXECUTION MONITOR */}
      {activeTab === "executions" && (
        <div className="space-y-4">
          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-950/60 text-xs uppercase text-slate-400 border-b border-slate-800 font-mono">
                  <tr>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Playbook</th>
                    <th className="py-3 px-4">Mode</th>
                    <th className="py-3 px-4">Current Step</th>
                    <th className="py-3 px-4">Triggered By</th>
                    <th className="py-3 px-4">Started</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {executions.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="text-center py-8 text-slate-500 text-xs">
                        No playbook executions recorded yet.
                      </td>
                    </tr>
                  ) : (
                    executions.map((exec) => (
                      <tr key={exec.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          {getStatusBadge(exec.status)}
                        </td>
                        <td className="py-3.5 px-4 font-medium text-white whitespace-nowrap">
                          {exec.playbook_name}
                          <span className="block text-xs font-mono text-slate-400">
                            {exec.playbook_slug}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          {exec.is_dry_run ? (
                            <span className="px-2 py-0.5 text-xs rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono">
                              DRY-RUN
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 text-xs rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                              LIVE
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300 font-mono text-xs whitespace-nowrap">
                          {exec.current_step_id || `Step ${exec.current_step_index + 1}`}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300 whitespace-nowrap text-xs">
                          {exec.triggered_by_username || exec.triggered_by}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 text-xs whitespace-nowrap">
                          {formatRelativeTime(exec.created_at)}
                        </td>
                        <td className="py-3.5 px-4 text-right whitespace-nowrap space-x-2">
                          <button
                            onClick={() => setSelectedExecution(exec)}
                            className="px-2.5 py-1 text-xs rounded bg-slate-800 text-slate-200 hover:bg-slate-700 transition"
                          >
                            Trace
                          </button>
                          {(exec.status === "RUNNING" || exec.status === "WAITING_APPROVAL") && (
                            <button
                              onClick={() => cancelMutation.mutate(exec.id)}
                              className="px-2.5 py-1 text-xs rounded bg-rose-950 text-rose-300 border border-rose-800 hover:bg-rose-900 transition"
                            >
                              Cancel
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TRIGGER PLAYBOOK MODAL */}
      {triggerPlaybook && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400">TRIGGER WORKFLOW</span>
                <h3 className="text-lg font-bold text-white">{triggerPlaybook.name}</h3>
              </div>
              <button
                onClick={() => setTriggerPlaybook(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-400">{triggerPlaybook.description}</p>

            {triggerError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{triggerError}</span>
              </div>
            )}

            {/* Dry Run Toggle */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div>
                <label className="text-sm font-medium text-slate-200">Dry-Run Simulation</label>
                <p className="text-xs text-slate-400">
                  Simulate all actions without halting for approvals or mutating records.
                </p>
              </div>
              <input
                type="checkbox"
                checked={isDryRun}
                onChange={(e) => setIsDryRun(e.target.checked)}
                className="w-4 h-4 accent-cyan-500 rounded"
              />
            </div>

            {/* Optional Incident ID */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Link Incident UUID (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
                value={targetIncidentId}
                onChange={(e) => setTargetIncidentId(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Common Parameters */}
            <div className="space-y-3 pt-2 border-t border-slate-800">
              <span className="text-xs font-semibold text-slate-400">Execution Parameters</span>

              {triggerPlaybook.slug.includes("phish") && (
                <>
                  <input
                    type="text"
                    placeholder="Affected User (e.g. jdoe)"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, affected_user: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <input
                    type="text"
                    placeholder="Sender Email (e.g. attacker@malicious.com)"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, sender_email: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <input
                    type="text"
                    placeholder="Suspicious URL"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, suspicious_url: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </>
              )}

              {triggerPlaybook.slug.includes("malware") && (
                <>
                  <input
                    type="text"
                    placeholder="Target Hostname (e.g. SEC-WKSTN-01)"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, target_hostname: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <input
                    type="text"
                    placeholder="Process Name (e.g. mimikatz.exe)"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, process_name: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <input
                    type="text"
                    placeholder="SHA-256 File Hash"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, file_hash: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </>
              )}

              {triggerPlaybook.slug.includes("brute") && (
                <>
                  <input
                    type="text"
                    placeholder="Source IP Address"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, source_ip: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                  <input
                    type="text"
                    placeholder="Target Username"
                    onChange={(e) =>
                      setParameterInputs((p) => ({ ...p, target_username: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
              <button
                onClick={() => setTriggerPlaybook(null)}
                className="px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  executeMutation.mutate({
                    slug: triggerPlaybook.slug,
                    req: {
                      incident_id: targetIncidentId || undefined,
                      is_dry_run: isDryRun,
                      parameters: parameterInputs,
                    },
                  })
                }
                disabled={executeMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-1.5"
              >
                {executeMutation.isPending ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5 fill-current" />
                )}
                Launch Execution
              </button>
            </div>
          </div>
        </div>
      )}

      {/* EXECUTION STEP TRACE DRAWER */}
      {selectedExecution && (
        <div className="fixed inset-0 z-50 bg-black/80 flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full flex flex-col p-6 space-y-4 overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <span className="text-xs font-mono text-cyan-400">EXECUTION STEP TRACE</span>
                <h3 className="text-lg font-bold text-white">{selectedExecution.playbook_name}</h3>
                <span className="text-xs text-slate-500 font-mono">{selectedExecution.id}</span>
              </div>
              <button
                onClick={() => setSelectedExecution(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex items-center gap-3">
              {getStatusBadge(selectedExecution.status)}
              {selectedExecution.is_dry_run && (
                <span className="px-2 py-0.5 text-xs rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  DRY-RUN SIMULATION
                </span>
              )}
            </div>

            {selectedExecution.error_message && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
                {selectedExecution.error_message}
              </div>
            )}

            <div className="space-y-4">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Executed Steps ({selectedExecution.steps?.length || 0})
              </h4>

              {(selectedExecution.steps || []).map((step, idx) => (
                <div
                  key={step.id}
                  className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">
                      {idx + 1}. {step.step_name}
                    </span>
                    <span className="font-mono text-slate-500">{step.step_type}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    {getStatusBadge(step.status)}
                    {step.duration_ms !== null && step.duration_ms !== undefined && (
                      <span className="text-slate-500 text-[11px] font-mono">
                        {step.duration_ms}ms
                      </span>
                    )}
                  </div>

                  {step.outputs_json && Object.keys(step.outputs_json).length > 0 && (
                    <div className="mt-2">
                      <span className="text-[11px] text-slate-500">Outputs:</span>
                      <pre className="p-2 mt-1 rounded bg-slate-900 border border-slate-800/80 font-mono text-[11px] text-cyan-300 overflow-x-auto">
                        {JSON.stringify(step.outputs_json, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
