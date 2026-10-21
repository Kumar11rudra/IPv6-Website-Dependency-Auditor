import { useMemo, useState } from "react";
import StatusBadge from "./StatusBadge";

const FILTERS = ["All", "IPv6 Ready", "IPv4-only", "Scripts", "Stylesheets", "Images", "Fonts", "Blocked"];

function probeFor(probes, hostname, family) {
  return probes.find((p) => p.hostname === hostname && p.family === family);
}

const UNTESTED_VERDICTS = new Set(["NOT_TESTED", "NOT_APPLICABLE", "BLOCKED", "SCAN_FAILED", undefined, null]);

/** ✓ only for a confirmed reachable verdict, ✗ only for a confirmed failure verdict,
 * "—" for anything not actually tested. Never render untested as failed. */
function cell(family, probe) {
  if (!probe || UNTESTED_VERDICTS.has(probe.verdict)) return "—";
  return probe.verdict === `IPv${family}_REACHABLE` ? "✓" : "✗";
}

function isBlocked(r, v4, v6) {
  return r.load_status === "BLOCKED" || v4?.verdict === "BLOCKED" || v6?.verdict === "BLOCKED";
}

function matchesFilter(filter, r, v4, v6) {
  if (filter === "All") return true;
  if (filter === "IPv6 Ready") return v6?.verdict === "IPv6_REACHABLE";
  // A confirmed IPv6 FAILURE, not merely "not tested" - those are different findings.
  if (filter === "IPv4-only") return v4?.verdict === "IPv4_REACHABLE" && !!v6?.failure_stage;
  if (filter === "Scripts") return r.resource_type === "script";
  if (filter === "Stylesheets") return r.resource_type === "stylesheet";
  if (filter === "Images") return r.resource_type === "image";
  if (filter === "Fonts") return r.resource_type === "font";
  if (filter === "Blocked") return isBlocked(r, v4, v6);
  const stage = filter.split(" ")[0].toUpperCase();
  return v6?.failure_stage === stage;
}

export default function ResourceTable({ resources, probes }) {
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("All");

  const rows = useMemo(() => resources.map((r) => {
    const v4 = probeFor(probes, r.hostname, 4);
    const v6 = probeFor(probes, r.hostname, 6);
    return { r, v4, v6 };
  }), [resources, probes]);

  const filtered = rows.filter(({ r, v4, v6 }) => {
    if (!matchesFilter(filter, r, v4, v6)) return false;
    if (!q) return true;
    const needle = q.toLowerCase();
    return r.url.toLowerCase().includes(needle) || r.hostname.toLowerCase().includes(needle);
  });

  if (resources.length === 0) {
    return <div className="text-base text-muted border border-border rounded-xl bg-surface p-6 shadow-xs leading-relaxed">No resources were discovered for this scan.</div>;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <input
          value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search URL or hostname…"
          className="border-2 border-border/80 rounded-lg px-3.5 py-2 text-base w-72 bg-surface focus:outline-none focus:border-accent shadow-xs transition-all font-mono"
        />
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              className={`text-sm px-3 py-1.5 rounded-lg border font-medium transition-all ${filter === f ? "bg-primary text-white border-primary shadow-xs" : "border-border text-muted hover:text-ink hover:bg-bg"}`}>
              {f}
            </button>
          ))}
        </div>
        <span className="text-sm font-medium text-muted ml-auto">{filtered.length} of {resources.length}</span>
      </div>

      <div className="border border-border rounded-xl shadow-xs overflow-auto max-h-[560px] bg-surface">
        <table className="w-full text-base">
          <thead className="sticky top-0 bg-bg/95 backdrop-blur-xs border-b border-border text-left text-xs uppercase tracking-wider text-muted font-semibold">
            <tr>
              <th className="px-4 py-3.5">Resource</th>
              <th className="px-4 py-3.5">Type</th>
              <th className="px-4 py-3.5">IPv4</th>
              <th className="px-4 py-3.5">IPv6</th>
              <th className="px-4 py-3.5">Status</th>
              <th className="px-4 py-3.5">Failure stage</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {filtered.map(({ r, v4, v6 }) => (
              <tr key={r.resource_id} className="hover:bg-bg/60 transition-colors">
                <td className="px-4 py-3.5 font-mono text-sm max-w-[400px] truncate" title={r.url}>
                  {r.url.replace(/^https?:\/\//, "")}
                </td>
                <td className="px-4 py-3.5 text-sm text-muted font-medium">{r.resource_type}</td>
                <td className="px-4 py-3.5 font-mono text-base font-bold">{cell(4, v4)}</td>
                <td className="px-4 py-3.5 font-mono text-base font-bold">{cell(6, v6)}</td>
                <td className="px-4 py-3.5"><StatusBadge value={r.load_status} /></td>
                <td className="px-4 py-3.5 text-sm text-muted font-medium">{v6?.failure_stage || "—"}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-muted text-base">No resources match this filter.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="text-sm text-muted flex items-center gap-3 pt-1">
        <span><strong className="font-mono text-base">✓</strong> confirmed reachable</span>
        <span>·</span>
        <span><strong className="font-mono text-base">✗</strong> confirmed failure</span>
        <span>·</span>
        <span><strong className="font-mono text-base">—</strong> not tested / not applicable for this host</span>
      </div>
    </div>
  );
}
