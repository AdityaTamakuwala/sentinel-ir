"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ExternalLink,
  Layers,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { MitreMatrixOut, MitreTechniqueOut, apiRequest } from "@/lib/api/generated";

export default function MitreMatrixPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTactic, setSelectedTactic] = useState<string>("");
  const [hideSubtechniques, setHideSubtechniques] = useState(false);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechniqueOut | null>(null);

  // Fetch full Enterprise ATT&CK matrix with incident coverage counts
  const matrixQuery = useQuery({
    queryKey: ["mitre-matrix"],
    queryFn: () => apiRequest<MitreMatrixOut>("/api/v1/mitre/matrix"),
  });

  const matrix = matrixQuery.data;
  const tactics = matrix?.tactics || [];

  // Filter tactics and techniques
  const filteredTactics = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return tactics.map((tactic) => {
      if (selectedTactic && tactic.shortname !== selectedTactic) {
        return { ...tactic, techniques: [] };
      }
      const techs = tactic.techniques || [];
      const filteredTechs = techs.filter((tech) => {
        if (hideSubtechniques && tech.is_subtechnique) return false;
        if (!q) return true;
        return (
          tech.id.toLowerCase().includes(q) ||
          tech.name.toLowerCase().includes(q) ||
          (tech.description || "").toLowerCase().includes(q)
        );
      });
      return { ...tactic, techniques: filteredTechs };
    });
  }, [tactics, searchQuery, selectedTactic, hideSubtechniques]);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-primary" />
            MITRE ATT&CK Enterprise Matrix Navigator
          </h1>
          <p className="text-sm text-muted-foreground">
            Official ATT&CK v15.1 Enterprise STIX matrix across 14 adversary tactics with real-time incident coverage telemetry.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="rounded bg-muted px-2.5 py-1 font-mono font-medium text-foreground">
            {matrix?.total_techniques || 0} Techniques Loaded
          </span>
          <span className="rounded bg-primary/10 border border-primary/20 px-2.5 py-1 font-medium text-primary">
            {matrix?.total_mapped_incidents || 0} Mapped Cases
          </span>
        </div>
      </div>

      {/* Control Bar: Search & Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card p-3 shadow-sm">
        <div className="relative flex-1 sm:max-w-md">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by ID (e.g. T1059), name, or keyword..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-9 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={selectedTactic}
            onChange={(e) => setSelectedTactic(e.target.value)}
            className="h-9 rounded-md border border-input bg-background px-3 text-xs font-medium"
          >
            <option value="">All 14 Tactics</option>
            {tactics.map((t) => (
              <option key={t.shortname} value={t.shortname}>
                {t.name}
              </option>
            ))}
          </select>

          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
            <input
              type="checkbox"
              checked={hideSubtechniques}
              onChange={(e) => setHideSubtechniques(e.target.checked)}
              className="rounded border-input text-primary focus:ring-ring"
            />
            Collapse Sub-techniques
          </label>
        </div>
      </div>

      {/* Interactive Matrix Columns View */}
      {matrixQuery.isLoading ? (
        <div className="rounded-lg border border-border bg-card p-12 text-center text-muted-foreground">
          <RefreshCw className="mx-auto h-6 w-6 animate-spin mb-3 text-primary" />
          Loading official MITRE ATT&CK Enterprise Matrix...
        </div>
      ) : (
        <div className="overflow-x-auto pb-4">
          <div className="flex gap-3 min-w-[2800px] items-start">
            {filteredTactics.map((tactic) => (
              <div
                key={tactic.shortname}
                className="w-56 flex-shrink-0 rounded-lg border border-border bg-card flex flex-col max-h-[80vh]"
              >
                {/* Column Tactic Header */}
                <div className="border-b border-border bg-muted/30 p-3 sticky top-0 z-10 rounded-t-lg backdrop-blur-sm">
                  <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
                    <span>{tactic.tactic_id}</span>
                    <span className="rounded bg-muted px-1.5 py-0.2 text-[10px]">
                      {tactic.techniques.length}
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-foreground mt-1 tracking-tight">
                    {tactic.name}
                  </h3>
                </div>

                {/* Column Techniques List */}
                <div className="p-2 space-y-1.5 overflow-y-auto flex-1 divide-y divide-border/20">
                  {(tactic.techniques || []).length === 0 ? (
                    <div className="p-3 text-center text-xs text-muted-foreground italic">
                      No matching techniques
                    </div>
                  ) : (
                    (tactic.techniques || []).map((tech) => {
                      const count = tech.incident_count ?? 0;
                      const hasActiveCases = count > 0;
                      return (
                        <div
                          key={`${tactic.shortname}-${tech.id}`}
                          onClick={() => setSelectedTechnique(tech)}
                          className={`group cursor-pointer rounded-md p-2 text-xs transition-all hover:bg-muted/50 ${
                            hasActiveCases
                              ? "border border-red-500/40 bg-red-950/20 shadow-sm"
                              : tech.is_subtechnique
                              ? "bg-background/40 border border-border/40 ml-2"
                              : "bg-background border border-border/80"
                          }`}
                        >
                          <div className="flex items-center justify-between font-mono text-[10px] text-muted-foreground">
                            <span className="font-semibold group-hover:text-primary">
                              {tech.id}
                            </span>
                            {hasActiveCases && (
                              <span className="rounded bg-red-500/20 px-1 py-0.5 text-[9px] font-bold text-red-400">
                                {count} {count === 1 ? "Case" : "Cases"}
                              </span>
                            )}
                          </div>
                          <div className="mt-1 font-medium text-foreground group-hover:text-primary line-clamp-2 leading-tight">
                            {tech.name}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Slide-over Technique Inspection Drawer */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="h-full w-full max-w-xl border-l border-border bg-card p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div className="space-y-6">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-border pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-primary/10 border border-primary/20 px-2 py-0.5 text-xs font-mono font-bold text-primary">
                      {selectedTechnique.id}
                    </span>
                    {selectedTechnique.is_subtechnique && (
                      <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground flex items-center gap-1 font-mono">
                        <Layers className="h-3 w-3" /> Sub-technique
                      </span>
                    )}
                    {(selectedTechnique.incident_count ?? 0) > 0 && (
                      <span className="rounded bg-red-500/20 border border-red-500/30 px-2 py-0.5 text-xs font-bold text-red-400">
                        Active in {selectedTechnique.incident_count} Incident(s)
                      </span>
                    )}
                  </div>
                  <h3 className="mt-2 text-xl font-bold text-foreground">
                    {selectedTechnique.name}
                  </h3>
                  {selectedTechnique.parent_id && (
                    <div className="mt-1 text-xs text-muted-foreground">
                      Parent Technique: <span className="font-mono font-bold text-foreground">{selectedTechnique.parent_id}</span>
                    </div>
                  )}
                </div>
                <button
                  onClick={() => setSelectedTechnique(null)}
                  className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Tactics & Platforms */}
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs text-muted-foreground font-semibold uppercase">Tactics:</span>
                  {(selectedTechnique.tactics || []).map((tac) => (
                    <span
                      key={tac}
                      className="rounded bg-muted px-2 py-0.5 text-xs font-medium text-foreground uppercase"
                    >
                      {tac}
                    </span>
                  ))}
                </div>

                {(selectedTechnique.platforms || []).length > 0 && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-muted-foreground font-semibold uppercase">Platforms:</span>
                    {(selectedTechnique.platforms || []).map((plat) => (
                      <span
                        key={plat}
                        className="rounded border border-border px-2 py-0.5 text-[11px] text-muted-foreground"
                      >
                        {plat}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Adversary Behavior Description */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Adversary Behavior Description
                </h4>
                <div className="rounded-lg border border-border bg-muted/20 p-4 text-xs text-foreground/90 leading-relaxed whitespace-pre-line max-h-60 overflow-y-auto">
                  {selectedTechnique.description || "No official description provided."}
                </div>
              </div>

              {/* Detection Advice */}
              {selectedTechnique.detection && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Shield className="h-3.5 w-3.5 text-primary" />
                    Detection Advice & Engineering Guidance
                  </h4>
                  <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 text-xs text-foreground/90 leading-relaxed whitespace-pre-line max-h-48 overflow-y-auto">
                    {selectedTechnique.detection}
                  </div>
                </div>
              )}

              {/* External STIX Link */}
              {selectedTechnique.url && (
                <div className="pt-2">
                  <a
                    href={selectedTechnique.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline font-medium"
                  >
                    View on Official MITRE ATT&CK Website <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="pt-6 border-t border-border flex justify-between items-center text-xs text-muted-foreground">
              <span>STIX ID: {selectedTechnique.stix_id}</span>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="rounded-md border border-border px-4 py-2 font-medium hover:bg-muted"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
