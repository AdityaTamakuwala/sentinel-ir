"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  CheckCircle2,
  Code,
  Globe,
  Loader2,
  Play,
  Shield,
  ShieldAlert,
} from "lucide-react";
import { apiRequest } from "@/lib/api/generated";

interface ScenarioDetail {
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
  synthetic_indicators: Array<{
    ioc_type: string;
    value: string;
    reputation: string;
    confidence: number;
    description: string;
  }>;
  alerts: Array<{
    title: string;
    description: string;
    source_system: string;
    rule_id: string;
    rule_description: string;
    event_category: string;
    severity: string;
    src_ip: string | null;
    dst_ip: string | null;
    hostname: string | null;
    username: string | null;
    file_hash: string | null;
    domain: string | null;
  }>;
  executive_summary_template: string;
}

export default function ScenarioDetailPage() {
  const params = useParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const slug = params?.id as string;
  const [launchMode, setLaunchMode] = useState<"full_chain" | "alerts_only" | "incident_only">("full_chain");

  const { data: scenario, isLoading } = useQuery({
    queryKey: ["scenario-detail", slug],
    queryFn: () => apiRequest<ScenarioDetail>(`/api/v1/simulations/scenarios/${slug}`),
    enabled: Boolean(slug),
  });

  const launchMutation = useMutation({
    mutationFn: () =>
      apiRequest<{ id: string; incident_id: string | null }>(
        `/api/v1/simulations/scenarios/${slug}/launch`,
        {
          method: "POST",
          body: JSON.stringify({ mode: launchMode }),
        }
      ),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["simulation-executions"] });
      if (res.incident_id) {
        router.push(`/incidents/${res.incident_id}`);
      } else {
        router.push("/simulations");
      }
    },
  });

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        <Loader2 className="h-6 w-6 animate-spin mr-2" />
        Loading scenario specifications...
      </div>
    );
  }

  if (!scenario) {
    return (
      <div className="p-8 text-center text-muted-foreground">
        Scenario not found. <Link href="/simulations" className="text-primary underline">Back to scenarios</Link>
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Navigation */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <Link
          href="/simulations"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Scenario Library
        </Link>
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-bold text-amber-500 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
            {scenario.scenario_id}
          </span>
          <span
            className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
              scenario.severity === "critical"
                ? "bg-red-500/10 text-red-500 border border-red-500/20"
                : "bg-orange-500/10 text-orange-500 border border-orange-500/20"
            }`}
          >
            {scenario.severity}
          </span>
        </div>
      </div>

      {/* Header Info */}
      <div className="space-y-3">
        <h1 className="text-3xl font-extrabold tracking-tight text-foreground">
          {scenario.name}
        </h1>
        <p className="text-sm text-muted-foreground leading-relaxed">
          {scenario.description}
        </p>
      </div>

      {/* Architecture & Investigation Steps */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 space-y-6">
          <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
            <h2 className="text-sm font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Standard Investigation & Containment Path
            </h2>
            <div className="space-y-2.5">
              {scenario.expected_investigation_path.map((step, idx) => (
                <div key={idx} className="flex items-start gap-2.5 text-xs text-muted-foreground">
                  <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0 mt-0.5" />
                  <span>{step}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Synthetic Indicators */}
          <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
            <h2 className="text-sm font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
              <Globe className="h-4 w-4 text-primary" />
              Synthetic Indicators of Compromise (RFC Safe)
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/50 text-muted-foreground uppercase font-semibold">
                  <tr>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Value</th>
                    <th className="py-2 px-3">Reputation</th>
                    <th className="py-2 px-3">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {scenario.synthetic_indicators.map((ind, i) => (
                    <tr key={i}>
                      <td className="py-2.5 px-3 font-bold uppercase">{ind.ioc_type}</td>
                      <td className="py-2.5 px-3 font-mono font-medium text-foreground">
                        {ind.value}
                        {ind.description && (
                          <div className="text-[10px] text-muted-foreground">{ind.description}</div>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-bold text-red-500 uppercase">{ind.reputation}</span>
                      </td>
                      <td className="py-2.5 px-3">{ind.confidence}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Alert Payloads */}
          <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
            <h2 className="text-sm font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
              <Code className="h-4 w-4 text-primary" />
              Ingested Alert Definitions ({scenario.alerts.length})
            </h2>
            <div className="space-y-3">
              {scenario.alerts.map((alt, i) => (
                <div key={i} className="rounded-lg border border-border bg-muted/30 p-3.5 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-foreground">{alt.title}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">
                      Rule {alt.rule_id} ({alt.source_system})
                    </span>
                  </div>
                  <p className="text-muted-foreground text-[11px]">{alt.description}</p>
                  <div className="flex flex-wrap gap-2 text-[10px] font-mono text-muted-foreground pt-1">
                    {alt.src_ip && <span>src: {alt.src_ip}</span>}
                    {alt.dst_ip && <span>dst: {alt.dst_ip}</span>}
                    {alt.hostname && <span>host: {alt.hostname}</span>}
                    {alt.username && <span>user: {alt.username}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Sidebar Launch Controls */}
        <div className="space-y-6">
          <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
            <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Launch Configuration
            </h3>

            <div className="space-y-2">
              <label className="text-[11px] font-medium text-muted-foreground">
                Execution Pipeline Mode:
              </label>
              <select
                value={launchMode}
                onChange={(e) => setLaunchMode(e.target.value as any)}
                className="w-full rounded-lg border border-input bg-background px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="full_chain">Full Kill-Chain Response</option>
                <option value="incident_only">Incident & Threat Intel Only</option>
                <option value="alerts_only">Raw Alert Ingestion Only</option>
              </select>
            </div>

            <div className="rounded-lg bg-muted/50 p-3 text-xs space-y-2">
              <div className="flex items-center justify-between text-muted-foreground">
                <span>Playbook:</span>
                <span className="font-mono font-bold text-foreground">
                  {scenario.associated_playbook_slug}
                </span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span>Four-Eyes Action:</span>
                <span className="font-semibold text-foreground">
                  {scenario.expected_response_actions.join(", ")}
                </span>
              </div>
            </div>

            <button
              onClick={() => launchMutation.mutate()}
              disabled={launchMutation.isPending}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-xs font-bold text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 shadow"
            >
              {launchMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Executing...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 fill-current" />
                  Launch Scenario Now
                </>
              )}
            </button>
          </div>

          {/* MITRE ATT&CK Mapping Card */}
          <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm">
            <h3 className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-1.5">
              <ShieldAlert className="h-4 w-4 text-primary" />
              MITRE ATT&CK® Techniques
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {scenario.expected_mitre_techniques.map((tech) => (
                <Link
                  key={tech}
                  href={`/mitre`}
                  className="font-mono text-xs bg-secondary hover:bg-secondary/70 text-secondary-foreground px-2 py-1 rounded transition-colors"
                >
                  {tech}
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
