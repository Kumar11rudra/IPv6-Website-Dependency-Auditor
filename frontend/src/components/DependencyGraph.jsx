import { useMemo, useState } from "react";
import ReactFlow, { Background, Controls, Handle, MarkerType, Position } from "reactflow";
import "reactflow/dist/style.css";

const COLOR_HEX = { green: "#157F3C", yellow: "#B45309", red: "#B91C1C", gray: "#94A3B8" };
const COLOR_BG = { green: "#E7F6EC", yellow: "#FEF3E2", red: "#FDECEC", gray: "#EEF1F4" };

/** Maps an already-decided backend verdict (IPv4_REACHABLE, TCP_FAILURE, NOT_TESTED, ...)
 * to one of the graph's four colors. This does not re-classify anything - it's a purely
 * presentational mapping of a verdict the backend already computed, same role as
 * StatusBadge's color mapping elsewhere in the app. */
function familyColor(verdict) {
  if (!verdict) return "gray";
  if (verdict.endsWith("_REACHABLE")) return "green";
  if (verdict.endsWith("_FAILURE")) return "red";
  return "gray"; // NOT_TESTED, NOT_APPLICABLE, BLOCKED, SCAN_FAILED
}

/** Simple two-tier layout: host nodes on top, their resources fanned out below.
 * No layout library needed for a hackathon-sized graph (a handful of hosts). */
function layout(nodes, edges) {
  const hosts = nodes.filter((n) => n.kind === "host");
  const byHost = {};
  for (const n of nodes) if (n.kind === "resource") (byHost[n.hostname] ||= []).push(n);

  const positioned = [];
  let hx = 0;
  const HOST_GAP = 260;
  for (const h of hosts) {
    const kids = byHost[h.label] || [];
    positioned.push({ id: h.id, x: hx + Math.max(kids.length - 1, 0) * 60, y: 0, node: h });
    kids.forEach((k, i) => positioned.push({ id: k.id, x: hx + i * 130, y: 160, node: k }));
    hx += Math.max(kids.length, 1) * 130 + HOST_GAP;
  }
  return positioned;
}

/** Host nodes get an explicit "4 | 6" chip pair so IPv4-works/IPv6-broken is readable
 * at a glance, without clicking into the detail panel. The outer border keeps using the
 * backend's own `color` field (which the legend already documents as IPv6 status), and
 * the chips add the IPv4 side for direct comparison. */
function HostNode({ data }) {
  const node = data.raw;
  const v4 = familyColor(node.ipv4_verdict);
  const v6 = familyColor(node.ipv6_verdict);
  const chip = (fam, color) => (
    <span
      title={`IPv${fam}: ${node[`ipv${fam}_verdict`] || "NOT_TESTED"}`}
      style={{
        background: COLOR_HEX[color], color: "#fff", borderRadius: 4, fontSize: 11,
        fontWeight: 700, padding: "2px 7px", fontFamily: "IBM Plex Mono, monospace",
      }}
    >
      {fam}
    </span>
  );
  return (
    <div style={{
      background: COLOR_BG[node.color] || "#fff", border: `2px solid ${COLOR_HEX[node.color] || "#DCE3EA"}`,
      borderRadius: 6, padding: "10px 12px", width: 220, fontFamily: "IBM Plex Mono, monospace",
      color: "#101828", cursor: "pointer", boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
    }}>
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 8, wordBreak: "break-all" }}>{node.label}</div>
      <div style={{ display: "flex", gap: 6 }}>{chip(4, v4)}{chip(6, v6)}</div>
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  );
}

const NODE_TYPES = { host: HostNode };

function toFlowNode({ id, x, y, node }) {
  if (node.kind === "host") {
    return { id, position: { x, y }, type: "host", sourcePosition: "bottom", targetPosition: "top",
            data: { label: node.label, raw: node } };
  }
  return {
    id, position: { x, y }, sourcePosition: "bottom", targetPosition: "top",
    data: { label: node.label, raw: node },
    style: {
      background: COLOR_BG[node.color] || "#fff", border: `2px solid ${COLOR_HEX[node.color] || "#DCE3EA"}`,
      borderRadius: 6, padding: 10, fontSize: 12, fontFamily: "IBM Plex Mono, monospace",
      width: 130, color: "#101828", cursor: "pointer", boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
    },
  };
}

export default function DependencyGraph({ graph, onSelect }) {
  const [selectedId, setSelectedId] = useState(null);
  const { flowNodes, flowEdges } = useMemo(() => {
    if (!graph) return { flowNodes: [], flowEdges: [] };
    const positions = layout(graph.nodes, graph.edges);
    const flowNodes = positions.map((p) => toFlowNode(p));
    const flowEdges = graph.edges.map((e) => ({
      id: e.id, source: e.source, target: e.target, type: "smoothstep",
      animated: false,
      style: { stroke: e.kind === "hosts" ? "#B7C2CC" : "#8CA0B3", strokeDasharray: e.inferred ? "4 3" : undefined },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#8CA0B3" },
    }));
    return { flowNodes, flowEdges };
  }, [graph]);

  if (!graph) return <div className="text-base text-muted p-6">Run a scan to see the dependency graph.</div>;
  if (graph.nodes.length === 0) return <div className="text-base text-muted p-6">No resources were discovered to graph.</div>;

  return (
    <div className="h-[580px] border border-border rounded-xl bg-surface shadow-xs overflow-hidden" style={{ display: "flex" }}>
      <div style={{ flex: 1 }}>
        <ReactFlow
          nodes={flowNodes} edges={flowEdges} nodeTypes={NODE_TYPES} fitView
          onNodeClick={(_, n) => { setSelectedId(n.id); onSelect(n.data.raw); }}
          nodesDraggable={false} nodesConnectable={false} elementsSelectable
        >
          <Background gap={16} color="#EEF1F4" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="w-64 border-l border-border p-4 text-sm flex flex-col gap-2.5 shrink-0 bg-bg/40">
        <div className="font-bold text-muted text-xs uppercase tracking-wider mb-1">Legend</div>
        {Object.entries(graph.legend).map(([color, label]) => (
          <div key={color} className="flex items-center gap-2.5">
            <span className="inline-block w-3.5 h-3.5 rounded" style={{ background: COLOR_HEX[color] }} />
            <span className="font-medium text-ink">{label}</span>
          </div>
        ))}
        <div className="border-t border-border mt-1 pt-2.5 text-muted leading-relaxed text-xs">
          Host nodes show two chips: <span className="font-mono font-bold">4</span> = IPv4,{" "}
          <span className="font-mono font-bold">6</span> = IPv6. Green chip + red chip on the same
          host means it works over IPv4 but fails over IPv6.
        </div>
      </div>
    </div>
  );
}
