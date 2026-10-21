import StatusBadge from "./StatusBadge";

export default function FailuresView({ probes }) {
  const failures = probes.filter((p) => p.family === 6 && p.failure_stage);
  if (failures.length === 0) {
    return (
      <div className="p-8 sm:p-10 border border-emerald-200/80 rounded-2xl bg-emerald-50/50 shadow-xs flex flex-col items-center text-center gap-3">
        <div className="w-11 h-11 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center shadow-2xs">
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h4 className="text-base font-bold text-emerald-950">Zero IPv6 Failures Detected</h4>
        <p className="text-xs sm:text-sm text-emerald-800/80 max-w-md leading-relaxed">
          All discovered third-party resources and host dependencies successfully connect and respond over IPv6.
        </p>
      </div>
    );
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
