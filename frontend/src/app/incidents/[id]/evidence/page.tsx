"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Archive,
  ArrowLeft,
  CheckCircle2,
  Download,
  FileArchive,
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
  IncidentDetailOut,
  PaginatedEvidenceOut,
  SentinelApiError,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth, useToast } from "@/components/providers";
import { SimulatedBadge } from "@/components/ui/badges";
import { Modal } from "@/components/ui/modal";
import { formatBytes, formatDateTime } from "@/lib/format";

export default function ScopedIncidentEvidencePage() {
  const params = useParams<{ id: string }>();
  const incidentRef = params.id;
  const { hasPermission } = useAuth();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();

  const [uploadOpen, setUploadOpen] = useState(false);
  const [versionModalTarget, setVersionModalTarget] = useState<EvidenceDetailOut | null>(null);
  const [custodyTarget, setCustodyTarget] = useState<EvidenceDetailOut | null>(null);
  const [withdrawTarget, setWithdrawTarget] = useState<EvidenceDetailOut | null>(null);
  const [verifyResult, setVerifyResult] = useState<EvidenceIntegrityVerifyOut | null>(null);

  const [uploadTitle, setUploadTitle] = useState("");
  const [uploadDesc, setUploadDesc] = useState("");
  const [uploadType, setUploadType] = useState("file");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadNotes, setUploadNotes] = useState("");
  const [withdrawReason, setWithdrawReason] = useState("");

  const canRead = hasPermission("evidence:read");
  const canUpload = hasPermission("evidence:upload");
  const canWithdraw = hasPermission("evidence:withdraw");

  const incidentQuery = useQuery({
    queryKey: ["incident-evidence-parent", incidentRef],
    enabled: Boolean(incidentRef) && canRead,
    queryFn: () => apiRequest<IncidentDetailOut>(`/api/v1/incidents/${incidentRef}`),
  });

  const incidentId = incidentQuery.data?.id;

  const evidenceQuery = useQuery({
    queryKey: ["incident-evidence-items", incidentId],
    enabled: Boolean(incidentId) && canRead,
    queryFn: () =>
      apiRequest<PaginatedEvidenceOut>("/api/v1/evidence", {
        params: { incident_id: incidentId, page: 1, page_size: 50 },
      }),
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!uploadFile || !incidentId) throw new Error("Missing file or incident.");
      const formData = new FormData();
      formData.append("incident_id", incidentId);
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
      void queryClient.invalidateQueries({ queryKey: ["incident-evidence-items", incidentId] });
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentRef] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : (err as Error).message;
      pushToast({ title: "Upload Failed", description: msg, variant: "error" });
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
      void queryClient.invalidateQueries({ queryKey: ["incident-evidence-items", incidentId] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : "Verification request failed";
      pushToast({ title: "Verification Error", description: msg, variant: "error" });
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
        description: "Served with strict attachment & nosniff headers. Logged to custody ledger.",
        variant: "info",
      });
      void queryClient.invalidateQueries({ queryKey: ["incident-evidence-items", incidentId] });
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
        Your current role does not have <code className="font-mono">evidence:read</code> permission.
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
            <FileArchive className="w-5 h-5 text-sky-400" />
            Case Evidence Vault — {incident?.human_id || incidentRef}
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {canUpload && (
            <button
              type="button"
              onClick={() => setUploadOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 transition-colors"
            >
              <Upload className="w-4 h-4" />
              Preserve Artifact for {incident?.human_id || "Case"}
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

      {/* Evidence Table */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border bg-soc-elevated/60 text-[11px] uppercase tracking-wider text-soc-muted">
              <tr>
                <th className="px-4 py-3 font-semibold">Title</th>
                <th className="px-4 py-3 font-semibold">Type</th>
                <th className="px-4 py-3 font-semibold">Version</th>
                <th className="px-4 py-3 font-semibold">File &amp; Size</th>
                <th className="px-4 py-3 font-semibold">SHA-256 Digest</th>
                <th className="px-4 py-3 font-semibold">Status</th>
                <th className="px-4 py-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {evidenceQuery.isLoading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-soc-muted">
                    Loading evidence artifacts...
                  </td>
                </tr>
              ) : (evidenceQuery.data?.items ?? []).length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-soc-muted">
                    No forensic evidence preserved for this incident case yet.
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
                      <div className="text-[11px] text-soc-muted mt-0.5">
                        Preserved by @{ev.uploaded_by_username} on {formatDateTime(ev.created_at)}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-soc-bg border border-soc-border text-soc-muted">
                        {ev.evidence_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-sky-300">v{ev.current_version}</td>
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
                          title="Secure Download"
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
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Preserve Modal */}
      <Modal
        open={uploadOpen}
        title={`Preserve Forensic Evidence — ${incident?.human_id || incidentRef}`}
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

      {/* Custody Log Modal */}
      <Modal
        open={Boolean(custodyTarget)}
        title={custodyTarget ? `Chain of Custody — ${custodyTarget.title}` : "Chain of Custody"}
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
                </div>
              ))}
            </div>
          </div>
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

