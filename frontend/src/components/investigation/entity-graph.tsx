"use client";

import React, { useMemo, useState } from "react";
import { Network, Table2, ZoomIn, ZoomOut } from "lucide-react";
import { IncidentDetailOut } from "@/lib/api/generated";

interface GraphNode {
  id: string;
  label: string;
  sublabel: string;
  kind: "incident" | "alert" | "asset" | "user" | "indicator" | "related_incident";
  x: number;
  y: number;
  meta: Record<string, any>;
}

interface GraphEdge {
  from: string;
  to: string;
  relation: string;
}

const NODE_COLORS: Record<GraphNode["kind"], { stroke: string; fill: string; badge: string }> = {
  incident: { stroke: "#38bdf8", fill: "#0c4a6e", badge: "INCIDENT" },
  alert: { stroke: "#fb923c", fill: "#431407", badge: "ALERT" },
  asset: { stroke: "#34d399", fill: "#064e3b", badge: "ASSET" },
  user: { stroke: "#a78bfa", fill: "#2e1065", badge: "ACCOUNT" },
  indicator: { stroke: "#f87171", fill: "#450a0a", badge: "IOC" },
  related_incident: { stroke: "#fbbf24", fill: "#451a03", badge: "LINKED CASE" },
};

export function EntityRelationshipGraph({ incident }: { incident: IncidentDetailOut }) {
  const [mode, setMode] = useState<"graph" | "table">("graph");
  const [zoom, setZoom] = useState<number>(1);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { nodes, edges } = useMemo(() => {
    const cx = 420;
    const cy = 230;
    const builtNodes: GraphNode[] = [
      {
        id: `inc:${incident.id}`,
        label: incident.human_id,
        sublabel: incident.status,
        kind: "incident",
        x: cx,
        y: cy,
        meta: {
          title: incident.title,
          severity: incident.severity,
          risk_score: incident.risk_score,
        },
      },
    ];
    const builtEdges: GraphEdge[] = [];

    const ringItems: Array<Omit<GraphNode, "x" | "y"> & { relation: string }> = [];

    for (const a of incident.linked_alerts.slice(0, 8)) {
      ringItems.push({
        id: `alert:${a.id}`,
        label: `Rule ${a.rule_id}`,
        sublabel: String(a.severity || "").toUpperCase(),
        kind: "alert",
        relation: "triggered_by",
        meta: a,
      });
    }
    for (const asst of incident.affected_assets.slice(0, 6)) {
      ringItems.push({
        id: `asset:${asst.id}`,
        label: asst.hostname,
        sublabel: asst.ip_address || asst.criticality,
        kind: "asset",
        relation: "impacts_host",
        meta: asst,
      });
    }
    for (const usr of incident.affected_users.slice(0, 6)) {
      ringItems.push({
        id: `user:${usr.id}`,
        label: `@${usr.username}`,
        sublabel: usr.is_privileged ? "PRIVILEGED" : "STANDARD",
        kind: "user",
        relation: "involves_identity",
        meta: usr,
      });
    }
    for (const ioc of incident.indicators.slice(0, 8)) {
      ringItems.push({
        id: `ioc:${ioc.id}`,
        label: String(ioc.value).slice(0, 22),
        sublabel: `${String(ioc.ioc_type).toUpperCase()} · ${ioc.reputation}`,
        kind: "indicator",
        relation: ioc.is_internal ? "internal_ip" : "external_ioc",
        meta: ioc,
      });
    }
    for (const rel of incident.related_incidents.slice(0, 4)) {
      ringItems.push({
        id: `rel:${rel.target_incident_id}`,
        label: rel.target_human_id,
        sublabel: rel.link_type,
        kind: "related_incident",
        relation: rel.link_type,
        meta: rel,
      });
    }

    const total = Math.max(ringItems.length, 1);
    const rx = 290;
    const ry = 165;

    ringItems.forEach((item, idx) => {
      const angle = (2 * Math.PI * idx) / total - Math.PI / 2;
      const x = Math.round(cx + rx * Math.cos(angle));
      const y = Math.round(cy + ry * Math.sin(angle));
      builtNodes.push({
        id: item.id,
        label: item.label,
        sublabel: item.sublabel,
        kind: item.kind,
        x,
        y,
        meta: item.meta,
      });
      builtEdges.push({
        from: `inc:${incident.id}`,
        to: item.id,
        relation: item.relation,
      });
    });

    return { nodes: builtNodes, edges: builtEdges };
  }, [incident]);

  const selectedNode = nodes.find((n) => n.id === selectedId) || nodes[0];

  return (
    <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
      <div className="border-b border-soc-border px-4 py-3 flex flex-wrap items-center justify-between gap-3 bg-soc-elevated/40">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-sky-400" />
          <h2 className="text-sm font-semibold">Entity & Attack Surface Graph</h2>
          <span className="text-[11px] font-mono text-soc-muted">
            ({nodes.length} entities · {edges.length} edges)
          </span>
        </div>

        <div className="flex items-center gap-2">
          {mode === "graph" && (
            <div className="flex items-center gap-1 mr-2">
              <button
                type="button"
                aria-label="Zoom out graph"
                onClick={() => setZoom((z) => Math.max(0.75, Number((z - 0.15).toFixed(2))))}
                className="p-1 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-soc-text"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <span className="text-[11px] font-mono text-soc-muted w-11 text-center">
                {Math.round(zoom * 100)}%
              </span>
              <button
                type="button"
                aria-label="Zoom in graph"
                onClick={() => setZoom((z) => Math.min(1.5, Number((z + 0.15).toFixed(2))))}
                className="p-1 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-soc-text"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          <button
            type="button"
            onClick={() => setMode("graph")}
            className={`inline-flex items-center gap-1 rounded px-2.5 py-1 text-xs border ${
              mode === "graph"
                ? "border-sky-500/40 bg-sky-500/15 text-sky-300"
                : "border-soc-border bg-soc-bg text-soc-muted"
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            Interactive Topology
          </button>
          <button
            type="button"
            onClick={() => setMode("table")}
            className={`inline-flex items-center gap-1 rounded px-2.5 py-1 text-xs border ${
              mode === "table"
                ? "border-sky-500/40 bg-sky-500/15 text-sky-300"
                : "border-soc-border bg-soc-bg text-soc-muted"
            }`}
          >
            <Table2 className="w-3.5 h-3.5" />
            Structured Table
          </button>
        </div>
      </div>

      {mode === "graph" ? (
        <div className="grid grid-cols-1 lg:grid-cols-12">
          <div className="lg:col-span-8 border-b lg:border-b-0 lg:border-r border-soc-border bg-soc-bg/70 overflow-auto">
            <svg
              viewBox="0 0 840 460"
              className="w-full h-[380px]"
              style={{ transform: `scale(${zoom})`, transformOrigin: "center center" }}
              role="img"
              aria-label={`Entity relationship graph for ${incident.human_id}`}
            >
              {/* Edges */}
              {edges.map((edge) => {
                const src = nodes.find((n) => n.id === edge.from);
                const dst = nodes.find((n) => n.id === edge.to);
                if (!src || !dst) return null;
                const mx = (src.x + dst.x) / 2;
                const my = (src.y + dst.y) / 2;
                return (
                  <g key={`${edge.from}->${edge.to}`}>
                    <line
                      x1={src.x}
                      y1={src.y}
                      x2={dst.x}
                      y2={dst.y}
                      stroke="#334155"
                      strokeWidth={1.6}
                      strokeDasharray={edge.relation === "external_ioc" ? "4 3" : undefined}
                    />
                    <text
                      x={mx}
                      y={my - 4}
                      textAnchor="middle"
                      fill="#94a3b8"
                      fontSize="9"
                      fontFamily="monospace"
                    >
                      {edge.relation}
                    </text>
                  </g>
                );
              })}

              {/* Nodes */}
              {nodes.map((node) => {
                const palette = NODE_COLORS[node.kind];
                const isSelected = selectedNode?.id === node.id;
                const width = node.kind === "incident" ? 136 : 128;
                const height = node.kind === "incident" ? 50 : 44;
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x - width / 2}, ${node.y - height / 2})`}
                    onClick={() => setSelectedId(node.id)}
                    className="cursor-pointer"
                  >
                    <rect
                      width={width}
                      height={height}
                      rx={8}
                      fill={palette.fill}
                      stroke={palette.stroke}
                      strokeWidth={isSelected ? 2.6 : 1.4}
                    />
                    <text
                      x={width / 2}
                      y={18}
                      textAnchor="middle"
                      fill="#f8fafc"
                      fontSize="11"
                      fontWeight="600"
                      fontFamily="monospace"
                    >
                      {node.label}
                    </text>
                    <text
                      x={width / 2}
                      y={33}
                      textAnchor="middle"
                      fill="#cbd5e1"
                      fontSize="9.5"
                      fontFamily="monospace"
                    >
                      {node.sublabel}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Selected Node Inspector */}
          <div className="lg:col-span-4 p-4 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-sky-400">
                {NODE_COLORS[selectedNode.kind].badge}
              </span>
              <span className="font-mono text-soc-muted">{selectedNode.sublabel}</span>
            </div>
            <h3 className="text-sm font-semibold font-mono text-soc-text break-all">
              {selectedNode.label}
            </h3>
            <pre className="rounded border border-soc-border bg-soc-bg p-2.5 font-mono text-[11px] overflow-x-auto max-h-52 text-soc-text">
              {JSON.stringify(selectedNode.meta, null, 2)}
            </pre>
            <div className="pt-2 border-t border-soc-border flex flex-wrap gap-2 text-[10px] font-mono text-soc-muted">
              {Object.entries(NODE_COLORS).map(([k, v]) => (
                <span key={k} className="inline-flex items-center gap-1">
                  <span
                    className="w-2.5 h-2.5 rounded-sm inline-block"
                    style={{ backgroundColor: v.stroke }}
                  />
                  {v.badge}
                </span>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border bg-soc-elevated/50 text-[11px] uppercase text-soc-muted">
              <tr>
                <th className="px-4 py-2.5">Entity Type</th>
                <th className="px-4 py-2.5">Identifier</th>
                <th className="px-4 py-2.5">Relationship</th>
                <th className="px-4 py-2.5">Context / Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {edges.map((edge) => {
                const dst = nodes.find((n) => n.id === edge.to);
                if (!dst) return null;
                return (
                  <tr key={edge.to} className="hover:bg-soc-elevated/30">
                    <td className="px-4 py-2 font-mono text-sky-300">
                      {NODE_COLORS[dst.kind].badge}
                    </td>
                    <td className="px-4 py-2 font-mono text-soc-text">{dst.label}</td>
                    <td className="px-4 py-2 font-mono text-soc-muted">{edge.relation}</td>
                    <td className="px-4 py-2 text-soc-muted">{dst.sublabel}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

