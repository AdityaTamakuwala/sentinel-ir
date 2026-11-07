"use client";

import { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Lock,
  Search,
  ShieldCheck,
  User,
  X,
  XCircle,
} from "lucide-react";
import {
  ResponseActionOut,
  ResponseApprovalRequest,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth } from "@/components/providers";
import { formatRelativeTime } from "@/lib/format";

export default function ResponseApprovalsPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const [statusFilter, setStatusFilter] = useState<string>("PENDING_APPROVAL");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");

  // Modal state
  const [decisionAction, setDecisionAction] = useState<ResponseActionOut | null>(null);
  const [decisionComment, setDecisionComment] = useState("");
  const [decisionError, setDecisionError] = useState<string | null>(null);

  // 1. Response Actions Query
  const actionsQuery = useQuery({
    queryKey: ["response-actions", statusFilter, riskFilter],
    queryFn: async () => {
      let url = "/api/v1/responses/actions?limit=100";
      if (statusFilter !== "all") {
        url += `&status=${statusFilter}`;
      }
      if (riskFilter !== "all") {
        url += `&risk_impact=${riskFilter}`;
      }
      return await apiRequest<ResponseActionOut[]>(url);
    },
    refetchInterval: 5000,
  });

  // 2. Approve Action Mutation
  const approveMutation = useMutation({
    mutationFn: async ({ id, req }: { id: string; req: ResponseApprovalRequest }) => {
      return await apiRequest<ResponseActionOut>(`/api/v1/responses/actions/${id}/approve`, {
        method: "POST",
        body: req,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["response-actions"] });
      setDecisionAction(null);
      setDecisionComment("");
      setDecisionError(null);
    },
    onError: (err: any) => {
      setDecisionError(err.message || "Failed to approve response action");
    },
  });

  // 3. Reject Action Mutation
  const rejectMutation = useMutation({
    mutationFn: async ({ id, req }: { id: string; req: ResponseApprovalRequest }) => {
      return await apiRequest<ResponseActionOut>(`/api/v1/responses/actions/${id}/reject`, {
        method: "POST",
        body: req,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["response-actions"] });
      setDecisionAction(null);
      setDecisionComment("");
      setDecisionError(null);
    },
    onError: (err: any) => {
      setDecisionError(err.message || "Failed to reject response action");
    },
  });

  const actions = actionsQuery.data || [];

  // Metrics calculation
  const totalPending = actions.filter((a) => a.status === "PENDING_APPROVAL").length;
  const highRiskPending = actions.filter(
    (a) => a.status === "PENDING_APPROVAL" && (a.risk_impact === "high" || a.risk_impact === "critical")
  ).length;

  const filteredActions = actions.filter((a) => {
    const matchesSearch =
      a.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.action_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (a.target_indicator && a.target_indicator.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (a.target_hostname && a.target_hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (a.target_username && a.target_username.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesSearch;
  });

  const getRiskBadge = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "critical":
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-red-500/10 text-red-400 border border-red-500/20">
            CRITICAL
          </span>
        );
      case "high":
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-orange-500/10 text-orange-400 border border-orange-500/20">
            HIGH
          </span>
        );
      case "medium":
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
            LOW
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "PENDING_APPROVAL":
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse inline-flex items-center gap-1">
            <Clock className="w-3 h-3" />
            PENDING APPROVAL
          </span>
        );
      case "APPROVED":
      case "COMPLETED":
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 inline-flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            COMPLETED
          </span>
        );
      case "REJECTED":
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 inline-flex items-center gap-1">
            <XCircle className="w-3 h-3" />
            REJECTED
          </span>
        );
      case "EXPIRED":
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-slate-500/10 text-slate-400 border border-slate-500/20 inline-flex items-center gap-1">
            <Clock className="w-3 h-3" />
            EXPIRED
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-slate-500/10 text-slate-300 border border-slate-500/20">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
              FOUR-EYES GOVERNANCE
            </span>
            <span className="text-xs text-slate-400 font-mono">SOAR CONTAINMENT GATE</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white mt-1">
            Human Approval Queue
          </h1>
          <p className="text-sm text-slate-400">
            Review proposed active-response actions. Self-approval is strictly prohibited by backend four-eyes policy.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href="/playbooks"
            className="px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 transition"
          >
            Playbooks Monitor
          </Link>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-xs font-medium text-slate-400">Pending Approvals</span>
          <p className="text-2xl font-bold text-amber-400 mt-1">{totalPending}</p>
        </div>
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-xs font-medium text-slate-400">High/Critical Risk Pending</span>
          <p className="text-2xl font-bold text-rose-400 mt-1">{highRiskPending}</p>
        </div>
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-xs font-medium text-slate-400">Total Filtered</span>
          <p className="text-2xl font-bold text-white mt-1">{filteredActions.length}</p>
        </div>
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-xs font-medium text-slate-400">Adapter Mode</span>
          <p className="text-sm font-semibold text-emerald-400 mt-2 font-mono">SAFE SIMULATION</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search actions by target host, IP, user, or title..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm bg-slate-900 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 text-sm bg-slate-900 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="PENDING_APPROVAL">Pending Approval</option>
            <option value="COMPLETED">Completed / Approved</option>
            <option value="REJECTED">Rejected</option>
            <option value="EXPIRED">Expired</option>
            <option value="all">All Statuses</option>
          </select>

          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="px-3 py-2 text-sm bg-slate-900 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Risk Levels</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      {/* Actions Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950/60 text-xs uppercase text-slate-400 border-b border-slate-800 font-mono">
              <tr>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Action Title</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Target Entity</th>
                <th className="py-3 px-4">Requested By</th>
                <th className="py-3 px-4">Expires</th>
                <th className="py-3 px-4 text-right">Four-Eyes Decision</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredActions.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-slate-500 text-xs">
                    No response actions matching current filters.
                  </td>
                </tr>
              ) : (
                filteredActions.map((act) => {
                  const isRequester = user?.id === act.requested_by_id;

                  return (
                    <tr key={act.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {getStatusBadge(act.status)}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="font-semibold text-white block">{act.title}</span>
                        <span className="font-mono text-xs text-slate-400">{act.action_type}</span>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">{getRiskBadge(act.risk_impact)}</td>
                      <td className="py-3.5 px-4 font-mono text-xs text-cyan-300 whitespace-nowrap">
                        {act.target_indicator ||
                          act.target_hostname ||
                          act.target_username ||
                          "Fleet"}
                      </td>
                      <td className="py-3.5 px-4 text-xs text-slate-300 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-slate-500" />
                          <span>{act.requested_by_username}</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 text-xs text-slate-400 whitespace-nowrap">
                        {formatRelativeTime(act.expires_at)}
                      </td>
                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        {act.status === "PENDING_APPROVAL" ? (
                          isRequester ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded bg-slate-800 text-slate-400 border border-slate-700">
                              <Lock className="w-3 h-3 text-amber-500" />
                              Self-Requested (Disabled)
                            </span>
                          ) : (
                            <button
                              onClick={() => {
                                setDecisionAction(act);
                                setDecisionComment("");
                                setDecisionError(null);
                              }}
                              className="px-3 py-1.5 text-xs font-semibold rounded bg-cyan-600 hover:bg-cyan-500 text-white transition inline-flex items-center gap-1.5"
                            >
                              <ShieldCheck className="w-3.5 h-3.5" />
                              Review & Decide
                            </button>
                          )
                        ) : (
                          <span className="text-xs text-slate-500 font-mono">
                            {act.approved_by_username ? `By ${act.approved_by_username}` : "Closed"}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* DECISION MODAL */}
      {decisionAction && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <span className="text-xs font-mono text-amber-400">HUMAN CONTAINMENT REVIEW</span>
                <h3 className="text-lg font-bold text-white">{decisionAction.title}</h3>
              </div>
              <button
                onClick={() => setDecisionAction(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {decisionError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{decisionError}</span>
              </div>
            )}

            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Action Type:</span>
                <span className="font-mono text-slate-200">{decisionAction.action_type}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Risk Impact:</span>
                <span>{getRiskBadge(decisionAction.risk_impact)}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Target Entity:</span>
                <span className="font-mono text-cyan-300">
                  {decisionAction.target_indicator ||
                    decisionAction.target_hostname ||
                    decisionAction.target_username}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Requested By:</span>
                <span className="text-slate-200">{decisionAction.requested_by_username}</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
              <span className="text-slate-400 block font-medium">Justification:</span>
              <p className="text-slate-300 italic">{decisionAction.justification}</p>
            </div>

            {/* Simulated Command Preview */}
            <div className="space-y-1 text-xs">
              <span className="text-slate-400 font-medium">Simulated Adapter Execution:</span>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80 font-mono text-emerald-400 text-[11px]">
                {decisionAction.action_type.includes("isolate")
                  ? `wazuh-control isolate-host --agent-name ${decisionAction.target_hostname || "HOST"}`
                  : decisionAction.action_type.includes("block_ip")
                  ? `pan-os-cli security-rule create --action drop --source-ip ${decisionAction.target_indicator || "IP"}`
                  : decisionAction.action_type.includes("disable")
                  ? `dsquery user -samid '${decisionAction.target_username || "USER"}' | dsmod user -disabled yes`
                  : `sentinel-response execute --action ${decisionAction.action_type}`}
              </div>
            </div>

            {/* Four-Eyes Notice */}
            <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-800/50 text-[11px] text-cyan-300 flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Four-eyes audit compliance active. Your decision and username will be permanently
                inscribed into the cryptographically verifiable audit chain.
              </span>
            </div>

            {/* Comment Input */}
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-300">
                Decision Rationale / Comment (Required, min 3 chars):
              </label>
              <textarea
                rows={3}
                placeholder="Provide operational justification for approving or rejecting this containment action..."
                value={decisionComment}
                onChange={(e) => setDecisionComment(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
              <button
                onClick={() => setDecisionAction(null)}
                className="px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  rejectMutation.mutate({
                    id: decisionAction.id,
                    req: { decision: "rejected", comment: decisionComment },
                  })
                }
                disabled={decisionComment.trim().length < 3 || rejectMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white transition flex items-center gap-1.5"
              >
                Reject Action
              </button>
              <button
                onClick={() =>
                  approveMutation.mutate({
                    id: decisionAction.id,
                    req: { decision: "approved", comment: decisionComment },
                  })
                }
                disabled={decisionComment.trim().length < 3 || approveMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition flex items-center gap-1.5"
              >
                Approve Containment
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
