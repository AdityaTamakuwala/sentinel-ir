"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Archive,
  CheckCircle2,
  Download,
  Eye,
  FileArchive,
  FileSearch,
  Filter,
  History,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Upload,
  XCircle,
} from "lucide-react";
import {
  EvidenceDetailOut,
  EvidenceIntegrityVerifyOut,
  IncidentListItemOut,
  PaginatedEvidenceOut,
  PaginatedIncidentsOut,
  SentinelApiError,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth, useToast } from "@/components/providers";
import { SimulatedBadge } from "@/components/ui/badges";
import { Modal } from "@/components/ui/modal";
import { formatBytes, formatDateTime } from "@/lib/format";

export default function EvidenceRepositoryPage() {
  const { hasPermission } = useAuth();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [incidentFilter, setIncidentFilter] = useState<string>("");

  // Modals
  const [uploadOpen, setUploadOpen] = useState(false);
  const [versionModalTarget, setVersionModalTarget] = useState<EvidenceDetailOut | null>(null);
  const [custodyTarget, setCustodyTarget] = useState<EvidenceDetailOut | null>(null);
  const [withdrawTarget, setWithdrawTarget] = useState<EvidenceDetailOut | null>(null);
  const [verifyResult, setVerifyResult] = useState<EvidenceIntegrityVerifyOut | null>(null);

  // Upload Form state
  const [uploadIncidentId, setUploadIncidentId] = useState("");
  const [uploadTitle, setUploadTitle] = useState("");
  const [uploadDesc, setUploadDesc] = useState("");
  const [uploadType, setUploadType] = useState("file");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadNotes, setUploadNotes] = useState("");
  const [withdrawReason, setWithdrawReason] = useState("");

  const canRead = hasPermission("evidence:read");
  const canUpload = hasPermission("evidence:upload");
  const canWithdraw = hasPermission("evidence:withdraw");

  const evidenceQuery = useQuery({
    queryKey: ["evidence", page, search, statusFilter, incidentFilter],
    enabled: canRead,
    queryFn: () =>
      apiRequest<PaginatedEvidenceOut>("/api/v1/evidence", {
        params: {
          page,
          page_size: 20,
          search: search || undefined,
          status: statusFilter || undefined,
          incident_id: incidentFilter || undefined,
        },
      }),
  });

  const incidentsQuery = useQuery({
    queryKey: ["incidents-lookup"],
    enabled: canRead,
    queryFn: () =>
      apiRequest<PaginatedIncidentsOut>("/api/v1/incidents", {
        params: { page: 1, page_size: 50 },
      }),
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!uploadFile) throw new Error("Please select an evidence file.");
      if (!uploadIncidentId) throw new Error("Please select an associated incident.");

      const formData = new FormData();
      formData.append("incident_id", uploadIncidentId);
      formData.append("title", uploadTitle);
      formData.append("description", uploadDesc);
      formData.append("evidence_type", uploadType);
      formData.append("file", uploadFile);

      return apiRequest<EvidenceDetailOut>("/api/v1/evidence", {
        method: "POST",
        body: formData,
      });
    },
    onSuccess: (created) => {
      pushToast({
        title: "Forensic Evidence Preserved",
        description: `Preserved '${created.title}' (SHA-256: ${created.sha256_hash.slice(0, 12)}…).`,
        variant: "success",
      });
      setUploadOpen(false);
      setUploadTitle("");
      setUploadDesc("");
      setUploadFile(null);
      void queryClient.invalidateQueries({ queryKey: ["evidence"] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : (err as Error).message;
      pushToast({ title: "Evidence Upload Failed", description: msg, variant: "error" });
    },
  });

  const newVersionMutation = useMutation({
    mutationFn: async () => {
      if (!versionModalTarget || !uploadFile) throw new Error("Missing file or target.");
      const formData = new FormData();
      formData.append("file", uploadFile);
      if (uploadNotes) formData.append("notes", uploadNotes);

      return apiRequest<EvidenceDetailOut>(`/api/v1/evidence/${versionModalTarget.id}/versions`, {
        method: "POST",
        body: formData,
      });
    },
    onSuccess: (updated) => {
      pushToast({
        title: `Preserved Version ${updated.current_version}`,
        description: `Appended immutable version ${updated.current_version} for '${updated.title}'.`,
        variant: "success",
      });
      setVersionModalTarget(null);
      setUploadFile(null);
      setUploadNotes("");
      void queryClient.invalidateQueries({ queryKey: ["evidence"] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : (err as Error).message;
      pushToast({ title: "Version Upload Failed", description: msg, variant: "error" });
    },
  });

  const verifyMutation = useMutation({
    mutationFn: (evidenceId: string) =>
      apiRequest<EvidenceIntegrityVerifyOut>(`/api/v1/evidence/${evidenceId}/verify`, {
        method: "POST",
      }),
    onSuccess: (res) => {
      setVerifyResult(res);
      pushToast({
        title: res.valid ? "Cryptographic Match Verified" : "Integrity Mismatch Detected",
        description: res.detail,
        variant: res.valid ? "success" : "error",
      });
      void queryClient.invalidateQueries({ queryKey: ["evidence"] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : "Verification request failed";
      pushToast({ title: "Verification Error", description: msg, variant: "error" });
    },
  });

  const withdrawMutation = useMutation({
    mutationFn: (evidenceId: string) =>
      apiRequest<EvidenceDetailOut>(`/api/v1/evidence/${evidenceId}/withdraw`, {
        method: "POST",
        body: { reason: withdrawReason },
      }),
    onSuccess: (updated) => {
      pushToast({
        title: "Evidence Withdrawn",
        description: `Artifact '${updated.title}' soft-withdrawn with documented reason.`,
        variant: "info",
      });
      setWithdrawTarget(null);
      setWithdrawReason("");
      void queryClient.invalidateQueries({ queryKey: ["evidence"] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : "Withdrawal failed";
      pushToast({ title: "Withdraw Error", description: msg, variant: "error" });
    },
  });

  const handleDownload = async (evidenceId: string, filename: string) => {
    try {
      const blob = await apiRequest<Blob>(`/api/v1/evidence/${evidenceId}/download`);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      pushToast({
        title: "Evidence Downloaded",
        description: "Served strictly with attachment and nosniff protection. Recorded in chain of custody.",
        variant: "info",
      });
      void queryClient.invalidateQueries({ queryKey: ["evidence"] });
    } catch (err) {
      const msg = err instanceof SentinelApiError ? err.message : "Download failed";
      pushToast({ title: "Download Failed", description: msg, variant: "error" });
    }
  };

  if (!canRead) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-200">
        <div className="flex items-center gap-2 font-semibold text-red-300 mb-1">
          <ShieldAlert className="w-4 h-4" />
          Restricted Evidence Vault
        </div>
        Your current role does not hold the <code className="font-mono">evidence:read</code> permission.
      </div>
    );
  }

  const total = evidenceQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / 20));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <FileArchive className="w-5 h-5 text-sky-400" />
            Forensic Evidence Repository &amp; Chain of Custody
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Tamper-protected artifact storage with streaming SHA-256 calculation, magic-byte allowlist,
            immutable version history, and full audit custody logs.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {canUpload && (
            <button
              type="button"
              onClick={() => setUploadOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 transition-colors"
            >
              <Upload className="w-4 h-4" />
              Preserve Evidence Artifact
            </button>
          )}

          <button
            type="button"
            onClick={() => void evidenceQuery.refetch()}
            className="inline-flex items-center gap-1.5 rounded-md border border-soc-border bg-soc-surface px-3 py-1.5 text-xs text-soc-muted hover:text-soc-text"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${evidenceQuery.isFetching ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
        <div className="flex items-center gap-2 text-xs font-medium text-soc-muted mb-3">
          <Filter className="w-3.5 h-3.5 text-sky-400" />
          Filter Artifacts
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <input
            type="search"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search by title, original filename, or keyword..."
            aria-label="Search evidence"
            className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-sky-500"
          />
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by status"
            className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text focus:outline-none focus:border-sky-500"
          >
            <option value="">All Statuses (Active &amp; Withdrawn)</option>
            <option value="active">Active Evidence</option>
            <option value="withdrawn">Withdrawn Evidence</option>
          </select>
          <select
            value={incidentFilter}
            onChange={(e) => {
              setIncidentFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by incident"
            className="rounded-md border border-soc-border bg-soc-bg px-3 py-1.5 text-xs text-soc-text focus:outline-none focus:border-sky-500"
          >
            <option value="">All Incident Cases</option>
            {incidentsQuery.data?.items.map((inc: IncidentListItemOut) => (
              <option key={inc.id} value={inc.id}>
                {inc.human_id} — {inc.title.slice(0, 40)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border bg-soc-elevated/60 text-[11px] uppercase tracking-wider text-soc-muted">
              <tr>
                <th className="px-4 py-3 font-semibold">Artifact / Case</th>
                <th className="px-4 py-3 font-semibold">Type</th>
                <th className="px-4 py-3 font-semibold">Version</th>
                <th className="px-4 py-3 font-semibold">File Details</th>
                <th className="px-4 py-3 font-semibold">SHA-256 Digest</th>
                <th className="px-4 py-3 font-semibold">Status</th>
                <th className="px-4 py-3 font-semibold text-right">Forensic Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {evidenceQuery.isLoading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-soc-muted">
                    Loading evidence artifacts from secure storage...
                  </td>
                </tr>
              ) : evidenceQuery.data?.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-soc-muted">
                    No evidence items match the filter criteria.
                  </td>
                </tr>
              ) : (
                evidenceQuery.data?.items.map((ev) => (
                  <tr key={ev.id} className="hover:bg-soc-elevated/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-medium text-soc-text flex items-center gap-2">
                        <span>{ev.title}</span>
                        {ev.is_simulated && <SimulatedBadge />}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5 text-[11px] text-soc-muted">
                        <Link
                          href={`/incidents/${ev.incident_human_id || ev.incident_id}`}
                          className="font-mono text-sky-400 hover:underline"
                        >
                          {ev.incident_human_id || "Linked Case"}
                        </Link>
                        <span>• preserved by @{ev.uploaded_by_username}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-soc-bg border border-soc-border text-soc-muted">
                        {ev.evidence_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-sky-300">
                      v{ev.current_version}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-mono text-soc-text truncate max-w-[200px]" title={ev.original_filename}>
                        {ev.original_filename}
                      </div>
                      <div className="text-[11px] text-soc-muted font-mono">
                        {formatBytes(ev.size_bytes)} · {ev.detected_mime_type}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <code
                        className="font-mono text-[11px] text-emerald-300/90 select-all cursor-pointer hover:underline"
                        title={ev.sha256_hash}
                        onClick={() => {
                          void navigator.clipboard.writeText(ev.sha256_hash);
                          pushToast({ title: "Copied SHA-256", description: ev.sha256_hash, variant: "info" });
                        }}
                      >
                        {ev.sha256_hash.slice(0, 16)}…
                      </code>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${
                          ev.status === "active"
                            ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                            : "bg-red-500/15 text-red-300 border-red-500/30"
                        }`}
                      >
                        {ev.status === "active" ? (
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <XCircle className="w-3 h-3 text-red-400" />
                        )}
                        {ev.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          title="Verify cryptographic SHA-256 integrity against disk"
                          onClick={() => verifyMutation.mutate(ev.id)}
                          disabled={verifyMutation.isPending}
                          className="p-1 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-emerald-400 hover:border-emerald-500/40"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                        </button>

                        <button
                          type="button"
                          title="Secure Download (Attachment &amp; NoSniff enforced)"
                          onClick={() => void handleDownload(ev.id, ev.original_filename)}
                          className="p-1 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-sky-400 hover:border-sky-500/40"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </button>

                        <button
                          type="button"
                          title="View Chain of Custody Log"
                          onClick={() => setCustodyTarget(ev)}
                          className="p-1 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-soc-text hover:border-sky-500/40"
                        >
                          <History className="w-3.5 h-3.5" />
                        </button>

                        {canUpload && ev.status === "active" && (
                          <button
                            type="button"
                            title="Preserve New Version"
                            onClick={() => {
                              setVersionModalTarget(ev);
                              setUploadFile(null);
                              setUploadNotes("");
                            }}
                            className="p-1 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-sky-400"
                          >
                            <Plus className="w-3.5 h-3.5" />
                          </button>
                        )}

                        {canWithdraw && ev.status === "active" && (
                          <button
                            type="button"
                            title="Withdraw Evidence"
                            onClick={() => {
                              setWithdrawTarget(ev);
                              setWithdrawReason("");
                            }}
                            className="p-1 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-red-400"
                          >
                            <Archive className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between border-t border-soc-border px-4 py-3 text-xs text-soc-muted">
          <span>
            Showing page {page} of {totalPages} ({total} preserved artifacts)
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="rounded border border-soc-border px-2.5 py-1 disabled:opacity-40 hover:bg-soc-elevated"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="rounded border border-soc-border px-2.5 py-1 disabled:opacity-40 hover:bg-soc-elevated"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Preserve Evidence Modal */}
      <Modal
        open={uploadOpen}
        title="Preserve Forensic Evidence Artifact"
        description="Artifacts are validated against magic-byte allowlists and stored with immutable SHA-256 digests."
        onClose={() => setUploadOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            uploadMutation.mutate();
          }}
          className="space-y-3.5 text-xs"
        >
          <div>
            <label className="block text-soc-muted mb-1">Associated Incident Case</label>
            <select
              required
              value={uploadIncidentId}
              onChange={(e) => setUploadIncidentId(e.target.value)}
              className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-2 text-soc-text"
            >
              <option value="">Select an Incident...</option>
              {incidentsQuery.data?.items.map((inc) => (
                <option key={inc.id} value={inc.id}>
                  {inc.human_id} — {inc.title.slice(0, 50)} ({inc.status})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-soc-muted mb-1">Evidence Title</label>
            <input
              required
              value={uploadTitle}
              onChange={(e) => setUploadTitle(e.target.value)}
              placeholder="e.g. Memory Dump Excerpt / auth.log Snapshot"
              className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-soc-text"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-soc-muted mb-1">Evidence Category</label>
              <select
                value={uploadType}
                onChange={(e) => setUploadType(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2.5 py-2 text-soc-text"
              >
                <option value="file">File Artifact</option>
                <option value="log_excerpt">Log Excerpt</option>
                <option value="json_artifact">Structured JSON</option>
                <option value="screenshot">Screenshot / Image</option>
                <option value="ioc_record">IOC Record</option>
              </select>
            </div>

            <div>
              <label className="block text-soc-muted mb-1">File Artifact (Max 25MB)</label>
              <input
                required
                type="file"
                onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2 py-1.5 text-xs text-soc-muted file:mr-2 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:bg-sky-500/20 file:text-sky-300"
              />
            </div>
          </div>

          <div>
            <label className="block text-soc-muted mb-1">Description &amp; Chain Context</label>
            <textarea
              rows={3}
              value={uploadDesc}
              onChange={(e) => setUploadDesc(e.target.value)}
              placeholder="Source system, forensic acquisition command, and retention rationale..."
              className="w-full rounded border border-soc-border bg-soc-bg p-2.5 text-soc-text"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setUploadOpen(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted hover:text-soc-text"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={uploadMutation.isPending || !uploadFile}
              className="rounded bg-sky-500 px-4 py-1.5 font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {uploadMutation.isPending ? "Hashing & Vaulting..." : "Preserve Artifact"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Upload New Version Modal */}
      <Modal
        open={Boolean(versionModalTarget)}
        title={versionModalTarget ? `Preserve New Version for '${versionModalTarget.title}'` : "New Version"}
        description="Preserving version N+1 retains all prior immutable versions in the chain of custody."
        onClose={() => setVersionModalTarget(null)}
      >
        {versionModalTarget && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              newVersionMutation.mutate();
            }}
            className="space-y-3.5 text-xs"
          >
            <div>
              <label className="block text-soc-muted mb-1">Updated Artifact File</label>
              <input
                required
                type="file"
                onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                className="w-full rounded border border-soc-border bg-soc-bg px-2 py-1.5 text-xs text-soc-muted file:mr-2 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:bg-sky-500/20 file:text-sky-300"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Version Notes</label>
              <textarea
                rows={3}
                value={uploadNotes}
                onChange={(e) => setUploadNotes(e.target.value)}
                placeholder="Document why this revised artifact version was uploaded..."
                className="w-full rounded border border-soc-border bg-soc-bg p-2.5 text-soc-text"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setVersionModalTarget(null)}
                className="rounded border border-soc-border px-3 py-1.5 text-soc-muted hover:text-soc-text"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={newVersionMutation.isPending || !uploadFile}
                className="rounded bg-sky-500 px-4 py-1.5 font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
              >
                {newVersionMutation.isPending ? "Preserving..." : `Preserve v${versionModalTarget.current_version + 1}`}
              </button>
            </div>
          </form>
        )}
      </Modal>

      {/* Custody Log Modal */}
      <Modal
        open={Boolean(custodyTarget)}
        title={custodyTarget ? `Chain of Custody — ${custodyTarget.title}` : "Chain of Custody"}
        description="Immutable custody entries recorded upon upload, download, integrity check, and withdrawal."
        onClose={() => setCustodyTarget(null)}
        maxWidthClass="max-w-2xl"
      >
        {custodyTarget && (
          <div className="space-y-3 text-xs">
            <div className="rounded border border-soc-border bg-soc-bg p-3 space-y-1">
              <span className="font-semibold text-soc-text">{custodyTarget.original_filename}</span>
              <p className="font-mono text-[11px] text-emerald-300 break-all select-all">
                SHA-256: {custodyTarget.sha256_hash}
              </p>
            </div>

            <div className="divide-y divide-soc-border rounded border border-soc-border bg-soc-bg max-h-72 overflow-y-auto">
              {(custodyTarget.custody_logs || []).map((c) => (
                <div key={c.id} className="p-3 space-y-1">
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-sky-400 uppercase font-semibold">{c.action}</span>
                    <span className="text-soc-muted">{formatDateTime(c.created_at)}</span>
                  </div>
                  <div className="flex items-center justify-between text-soc-muted text-[11px]">
                    <span>Actor: @{c.actor_label} {c.version_number ? `(v${c.version_number})` : ""}</span>
                    <span>IP: {c.ip_address || "internal"}</span>
                  </div>
                  <div className="font-mono text-[10px] text-soc-muted break-all">
                    Recorded SHA-256: {c.sha256_recorded}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </Modal>

      {/* Withdraw Modal */}
      <Modal
        open={Boolean(withdrawTarget)}
        title={withdrawTarget ? `Withdraw Evidence: ${withdrawTarget.title}` : "Withdraw Evidence"}
        description="Withdrawn evidence remains preserved on disk with an immutable audit record and justification."
        onClose={() => setWithdrawTarget(null)}
      >
        {withdrawTarget && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              withdrawMutation.mutate(withdrawTarget.id);
            }}
            className="space-y-3 text-xs"
          >
            <div>
              <label className="block text-soc-muted mb-1">
                Withdrawal Reason (minimum 5 characters)
              </label>
              <textarea
                required
                minLength={5}
                rows={3}
                value={withdrawReason}
                onChange={(e) => setWithdrawReason(e.target.value)}
                placeholder="Document why this artifact is being withdrawn from active case evidence..."
                className="w-full rounded border border-soc-border bg-soc-bg p-2.5 text-soc-text"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setWithdrawTarget(null)}
                className="rounded border border-soc-border px-3 py-1.5 text-soc-muted hover:text-soc-text"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={withdrawMutation.isPending || withdrawReason.trim().length < 5}
                className="rounded bg-red-600 hover:bg-red-500 px-4 py-1.5 font-medium text-white disabled:opacity-50"
              >
                {withdrawMutation.isPending ? "Withdrawing..." : "Confirm Withdrawal"}
              </button>
            </div>
          </form>
        )}
      </Modal>

      {/* Verify Result Modal */}
      <Modal
        open={Boolean(verifyResult)}
        title="Cryptographic Integrity Check"
        onClose={() => setVerifyResult(null)}
      >
        {verifyResult && (
          <div className="space-y-3 text-xs">
            <div
              className={`rounded border p-3 flex items-start gap-2.5 ${
                verifyResult.valid
                  ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-200"
                  : "border-red-500/40 bg-red-500/15 text-red-200"
              }`}
            >
              {verifyResult.valid ? (
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              )}
              <div>
                <p className="font-semibold">{verifyResult.detail}</p>
                <p className="text-[11px] opacity-85 mt-0.5">
                  Verified artifact version v{verifyResult.version_number} ({formatBytes(verifyResult.size_bytes)}).
                </p>
              </div>
            </div>

            <div className="rounded border border-soc-border bg-soc-bg p-3 space-y-2 font-mono text-[11px]">
              <div>
                <span className="text-soc-muted block">Expected Stored Hash (SHA-256)</span>
                <span className="break-all text-soc-text">{verifyResult.expected_sha256}</span>
              </div>
              <div>
                <span className="text-soc-muted block">Recomputed File Hash (SHA-256)</span>
                <span className="break-all text-emerald-300">
                  {verifyResult.computed_sha256 || "FILE MISSING"}
                </span>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

