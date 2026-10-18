import StatusBadge from "./StatusBadge";

export default function FailuresView({ probes }) {
  const failures = probes.filter((p) => p.family === 6 && p.failure_stage);
  if (failures.length === 0) {
    return <div className="text-base text-muted p-6 border border-border rounded-xl bg-surface shadow-xs leading-relaxed">No IPv6 failures recorded for this scan.</div>;
  }
  return (
    <div className="border border-border rounded-xl shadow-xs overflow-auto max-h-[560px] bg-surface">
      <table className="w-full text-base">
        <thead className="sticky top-0 bg-bg/95 backdrop-blur-xs border-b border-border text-left text-xs uppercase tracking-wider text-muted font-semibold">
          <tr>
            <th className="px-4 py-3.5">Host</th>
            <th className="px-4 py-3.5">Port</th>
            <th className="px-4 py-3.5">Stage</th>
            <th className="px-4 py-3.5">Subtype</th>
            <th className="px-4 py-3.5">Detail</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {failures.map((p) => (
            <tr key={`${p.hostname}:${p.port}`} className="hover:bg-bg/60 transition-colors">
              <td className="px-4 py-3.5 font-mono text-sm font-semibold">{p.hostname}</td>
              <td className="px-4 py-3.5 font-mono text-sm text-muted">{p.port}</td>
              <td className="px-4 py-3.5"><StatusBadge value={p.failure_stage} /></td>
              <td className="px-4 py-3.5 text-sm font-medium text-muted">{p.failure_subtype || "—"}</td>
              <td className="px-4 py-3.5 text-sm text-muted max-w-[420px] truncate" title={p.error_detail}>{p.error_detail || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
