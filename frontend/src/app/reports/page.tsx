"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Download,
  FileCode,
  FileText,
  Loader2,
  Plus,
  ShieldAlert,
} from "lucide-react";
import { apiRequest } from "@/lib/api/generated";

interface IncidentReportItem {
  id: string;
  incident_id: string;
  incident_version_snapshot: number;
  report_format: string;
  tlp_classification: string;
  storage_key: string | null;
  sha256_hash: string | null;
  generated_by_id: string | null;
  is_simulated: boolean;
  created_at: string;
}

interface IncidentOption {
  id: string;
  human_id: string;
  title: string;
  severity: string;
  status: string;
}

export default function ReportsPage() {
  const queryClient = useQueryClient();
  const [generateModalOpen, setGenerateModalOpen] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");
  const [reportFormat, setReportFormat] = useState<"pdf" | "json" | "stix">("pdf");
  const [tlpClassification, setTlpClassification] = useState<string>("TLP:AMBER");

  const { data: reports = [], isLoading: reportsLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => apiRequest<IncidentReportItem[]>("/api/v1/reports"),
  });

  const { data: incidentsData } = useQuery({
    queryKey: ["incidents-select"],
    queryFn: () => apiRequest<{ items: IncidentOption[] }>("/api/v1/incidents?limit=50"),
    enabled: generateModalOpen,
  });

  const generateMutation = useMutation({
    mutationFn: () =>
      apiRequest<IncidentReportItem>(`/api/v1/reports/incidents/${selectedIncidentId}/generate`, {
        method: "POST",
        body: JSON.stringify({
          report_format: reportFormat,
          tlp_classification: tlpClassification,
        }),
      }),
    onSuccess: (newReport) => {
      setGenerateModalOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["reports"] });
      // Trigger download
      window.open(`/api/v1/reports/${newReport.id}/download`, "_blank");
    },
  });

  const getTlpBadgeColor = (tlp: string) => {
    switch (tlp.toUpperCase()) {
      case "TLP:RED":
        return "bg-red-500/10 text-red-500 border-red-500/20";
      case "TLP:AMBER":
      case "TLP:AMBER+STRICT":
        return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case "TLP:GREEN":
        return "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
      default:
        return "bg-muted text-muted-foreground border-border";
    }
  };

  const getFormatBadge = (fmt: string) => {
    switch (fmt.toLowerCase()) {
      case "pdf":
        return { label: "PDF Export", icon: FileText, color: "text-red-500" };
      case "stix":
        return { label: "STIX 2.1 Bundle", icon: ShieldAlert, color: "text-indigo-500" };
      default:
        return { label: "JSON Bundle", icon: FileCode, color: "text-blue-500" };
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            Incident Reporting Engine
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Generate and export cryptographically verifiable incident reports in WeasyPrint PDF,
            canonical JSON, and OASIS STIX 2.1 threat intelligence bundles.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setGenerateModalOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-sm font-semibold text-primary-foreground hover:bg-primary/90 transition-colors shadow"
          >
            <Plus className="h-4 w-4" />
            Generate Incident Report
          </button>
        </div>
      </div>

      {/* Reports Table Card */}
      <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        <div className="p-5 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-bold text-foreground">Exported Incident Reports Library</h2>
          <span className="text-xs text-muted-foreground">
            {reports.length} report{reports.length === 1 ? "" : "s"} generated
          </span>
        </div>

        {reportsLoading ? (
          <div className="p-12 text-center text-muted-foreground">
            <Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />
            Loading reports...
          </div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground space-y-3">
            <FileText className="h-10 w-10 mx-auto text-muted-foreground/50" />
            <p className="text-sm">No incident reports generated yet.</p>
            <button
              onClick={() => setGenerateModalOpen(true)}
              className="text-xs font-semibold text-primary hover:underline"
            >
              Generate your first report
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted/50 text-muted-foreground uppercase font-semibold border-b border-border">
                <tr>
                  <th className="py-3 px-4">Format</th>
                  <th className="py-3 px-4">Incident Link</th>
                  <th className="py-3 px-4">TLP Classification</th>
                  <th className="py-3 px-4">SHA-256 Digest</th>
                  <th className="py-3 px-4">Simulated</th>
                  <th className="py-3 px-4">Generated At</th>
                  <th className="py-3 px-4 text-right">Download</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {reports.map((rep) => {
                  const fmt = getFormatBadge(rep.report_format);
                  const Icon = fmt.icon;
                  return (
                    <tr key={rep.id} className="hover:bg-muted/30 transition-colors">
                      <td className="py-3 px-4">
                        <span className="inline-flex items-center gap-1.5 font-semibold text-foreground">
                          <Icon className={`h-4 w-4 ${fmt.color}`} />
                          {fmt.label}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <Link
                          href={`/incidents/${rep.incident_id}`}
                          className="font-mono text-primary font-bold hover:underline"
                        >
                          View Incident
                        </Link>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getTlpBadgeColor(
                            rep.tlp_classification
                          )}`}
                        >
                          {rep.tlp_classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-muted-foreground">
                        {rep.sha256_hash ? (
                          <span title={rep.sha256_hash}>
                            {rep.sha256_hash.slice(0, 16)}...{rep.sha256_hash.slice(-8)}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {rep.is_simulated ? (
                          <span className="text-[10px] font-bold text-amber-500 uppercase bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                            Drill
                          </span>
                        ) : (
                          <span className="text-[10px] text-muted-foreground uppercase">Live</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-muted-foreground">
                        {new Date(rep.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <a
                          href={`/api/v1/reports/${rep.id}/download`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 rounded bg-secondary px-2.5 py-1 text-xs font-semibold text-secondary-foreground hover:bg-secondary/80 transition-colors"
                        >
                          <Download className="h-3 w-3" />
                          Download
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Generate Report Modal */}
      {generateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-border bg-card p-6 shadow-2xl space-y-5 animate-in fade-in-0 zoom-in-95">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-lg font-bold text-foreground flex items-center gap-2">
                <FileText className="h-5 w-5 text-primary" />
                Generate Incident Report
              </h3>
              <button
                onClick={() => setGenerateModalOpen(false)}
                className="text-muted-foreground hover:text-foreground text-sm font-semibold"
              >
                ✕
              </button>
            </div>

            {/* Incident Selection */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-foreground">Select Incident:</label>
              <select
                value={selectedIncidentId}
                onChange={(e) => setSelectedIncidentId(e.target.value)}
                className="w-full rounded-lg border border-input bg-background px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="">-- Choose Incident to Export --</option>
                {incidentsData?.items?.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    [{inc.human_id}] {inc.title} ({inc.severity.toUpperCase()} - {inc.status})
                  </option>
                ))}
              </select>
            </div>

            {/* Export Format */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-foreground">Export Format:</label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: "pdf", label: "PDF Document", desc: "WeasyPrint branded" },
                  { id: "json", label: "JSON Bundle", desc: "Schema-validated" },
                  { id: "stix", label: "STIX 2.1", desc: "OASIS compliant" },
                ].map((fmt) => (
                  <button
                    key={fmt.id}
                    type="button"
                    onClick={() => setReportFormat(fmt.id as any)}
                    className={`rounded-lg border p-3 text-left transition-all ${
                      reportFormat === fmt.id
                        ? "border-primary bg-primary/5 ring-1 ring-primary"
                        : "border-border hover:bg-muted/50"
                    }`}
                  >
                    <div className="text-xs font-bold text-foreground">{fmt.label}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">{fmt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* TLP Classification */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-foreground">TLP Classification:</label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"].map((tlp) => (
                  <button
                    key={tlp}
                    type="button"
                    onClick={() => setTlpClassification(tlp)}
                    className={`rounded-lg border px-2.5 py-1.5 text-center text-xs font-bold uppercase transition-all ${
                      tlpClassification === tlp
                        ? `${getTlpBadgeColor(tlp)} ring-1 ring-primary`
                        : "border-border text-muted-foreground hover:bg-muted/50"
                    }`}
                  >
                    {tlp}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-4 border-t border-border">
              <button
                type="button"
                onClick={() => setGenerateModalOpen(false)}
                className="rounded-lg px-4 py-2 text-xs font-semibold text-muted-foreground hover:text-foreground"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!selectedIncidentId || generateMutation.isPending}
                onClick={() => generateMutation.mutate()}
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground hover:bg-primary/90 disabled:opacity-50 shadow"
              >
                {generateMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Generating Report...
                  </>
                ) : (
                  <>
                    <Download className="h-3.5 w-3.5" />
                    Generate & Download
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
