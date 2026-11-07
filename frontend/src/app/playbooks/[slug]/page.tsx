"use client";

import { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  CheckCircle2,
  Code2,
  Copy,
  Layers,
  Play,
  ShieldAlert,
} from "lucide-react";
import { PlaybookDetailOut, apiRequest } from "@/lib/api/generated";

export default function PlaybookDetailPage() {
  const params = useParams();
  const slug = params.slug as string;

  const [activeTab, setActiveTab] = useState<"pipeline" | "yaml">("pipeline");
  const [copied, setCopied] = useState(false);

  const playbookQuery = useQuery({
    queryKey: ["playbook-detail", slug],
    queryFn: async () => {
      return await apiRequest<PlaybookDetailOut>(`/api/v1/playbooks/${slug}`);
    },
    enabled: Boolean(slug),
  });

  const playbook = playbookQuery.data;

  if (playbookQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-slate-400">
        Loading playbook definition...
      </div>
    );
  }

  if (playbookQuery.isError || !playbook) {
    return (
      <div className="p-6 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
        Playbook &apos;{slug}&apos; not found or failed to load.
      </div>
    );
  }

  const steps = (playbook.definition_json?.steps as Array<any>) || [];

  const handleCopyYaml = () => {
    navigator.clipboard.writeText(playbook.definition_yaml || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Back button */}
      <div>
        <Link
          href="/playbooks"
          className="inline-flex items-center gap-2 text-xs font-medium text-slate-400 hover:text-white transition"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Playbooks Library
        </Link>
      </div>

      {/* Header Banner */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 text-xs font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                {playbook.slug.toUpperCase()}
              </span>
              <span className="text-xs text-slate-500 font-mono">
                VERSION {playbook.current_version}
              </span>
              <span className="px-2 py-0.5 text-xs rounded bg-slate-800 text-slate-300">
                {playbook.auto_trigger_mode.toUpperCase()}
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white">{playbook.name}</h1>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">{playbook.description}</p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Link
              href="/playbooks"
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Execute Playbook
            </Link>
          </div>
        </div>

        {/* Triggers Bar */}
        {playbook.trigger_config && Object.keys(playbook.trigger_config).length > 0 && (
          <div className="pt-3 border-t border-slate-800/80 flex flex-wrap gap-4 text-xs text-slate-400">
            <span className="font-semibold text-slate-300">Matching Criteria:</span>
            {playbook.trigger_config.alert_rule_ids && (
              <span>Rules: {playbook.trigger_config.alert_rule_ids.join(", ")}</span>
            )}
            {playbook.trigger_config.incident_category && (
              <span>Categories: {playbook.trigger_config.incident_category.join(", ")}</span>
            )}
            {playbook.trigger_config.min_severity && (
              <span>Min Severity: {playbook.trigger_config.min_severity}</span>
            )}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab("pipeline")}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
            activeTab === "pipeline"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-slate-400 hover:text-slate-300"
          }`}
        >
          <Layers className="w-4 h-4" />
          Workflow Pipeline ({steps.length} Steps)
        </button>

        <button
          onClick={() => setActiveTab("yaml")}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
            activeTab === "yaml"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-slate-400 hover:text-slate-300"
          }`}
        >
          <Code2 className="w-4 h-4" />
          Declarative YAML
        </button>
      </div>

      {/* TAB 1: WORKFLOW PIPELINE */}
      {activeTab === "pipeline" && (
        <div className="space-y-4">
          <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-slate-800">
            {steps.map((step, idx) => (
              <div key={step.id || idx} className="relative">
                {/* Node icon */}
                <div
                  className={`absolute -left-6 top-3 w-5 h-5 rounded-full border-2 flex items-center justify-center text-[10px] font-bold ${
                    step.require_approval
                      ? "bg-amber-950 border-amber-500 text-amber-300"
                      : "bg-cyan-950 border-cyan-500 text-cyan-300"
                  }`}
                >
                  {idx + 1}
                </div>

                {/* Step Card */}
                <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <h3 className="text-base font-semibold text-white">{step.name}</h3>
                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {step.type}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      {step.require_approval ? (
                        <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 inline-flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          HUMAN APPROVAL ({step.approval_level?.toUpperCase()})
                        </span>
                      ) : (
                        <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 inline-flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          AUTOMATED
                        </span>
                      )}

                      {step.risk_impact && (
                        <span
                          className={`px-2 py-0.5 text-xs font-semibold rounded border ${
                            step.risk_impact === "critical"
                              ? "bg-red-500/10 text-red-400 border-red-500/20"
                              : step.risk_impact === "high"
                              ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                              : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                          }`}
                        >
                          {step.risk_impact.toUpperCase()} RISK
                        </span>
                      )}
                    </div>
                  </div>

                  {step.condition && (
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80 text-xs font-mono text-purple-300">
                      Condition: {step.condition}
                    </div>
                  )}

                  {step.parameters && Object.keys(step.parameters).length > 0 && (
                    <div>
                      <span className="text-xs font-medium text-slate-400 block mb-1.5">
                        Parameters & Templated Expressions:
                      </span>
                      <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto">
                        {JSON.stringify(step.parameters, null, 2)}
                      </pre>
                    </div>
                  )}

                  <div className="flex items-center gap-4 text-xs text-slate-500 pt-2 border-t border-slate-800/60 font-mono">
                    <span>On Failure: {step.on_failure || "abort"}</span>
                    {step.retry_count > 0 && <span>Retries: {step.retry_count}</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: RAW YAML */}
      {activeTab === "yaml" && (
        <div className="space-y-3">
          <div className="flex justify-end">
            <button
              onClick={handleCopyYaml}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 transition"
            >
              <Copy className="w-3.5 h-3.5" />
              {copied ? "Copied!" : "Copy YAML"}
            </button>
          </div>
          <pre className="p-5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto leading-relaxed">
            {playbook.definition_yaml}
          </pre>
        </div>
      )}
    </div>
  );
}
