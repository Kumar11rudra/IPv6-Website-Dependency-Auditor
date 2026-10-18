export default function ReportsView({ scanId }) {
  if (!scanId) return <div className="text-base text-muted p-6 border border-border rounded-xl bg-surface shadow-xs leading-relaxed">Run a scan to export reports.</div>;
  return (
    <div className="border border-border rounded-xl bg-surface p-6 md:p-8 flex flex-col gap-4 max-w-lg shadow-xs">
      <div className="text-base text-muted leading-relaxed">
        Export raw measurements for this scan. Formats follow the PS-027 report structure
        (per-resource IPv4/IPv6 status, failure stage, HTTP code).
      </div>
      <div className="flex gap-3">
        <a href={`${import.meta.env.VITE_API_BASE || "http://localhost:8000"}/api/scan/${scanId}/report/json`}
          className="border border-border rounded-lg px-4 py-2 text-base font-medium hover:bg-bg shadow-xs transition-colors" target="_blank" rel="noreferrer">
          Download JSON
        </a>
        <a href={`${import.meta.env.VITE_API_BASE || "http://localhost:8000"}/api/scan/${scanId}/report/csv`}
          className="border border-border rounded-lg px-4 py-2 text-base font-medium hover:bg-bg shadow-xs transition-colors" target="_blank" rel="noreferrer">
          Download CSV
        </a>
      </div>
      <div className="text-sm text-muted leading-relaxed">
        Reports include per-resource IPv4/IPv6 verdicts, measurement context, and are safe to share: credentials, tokens, and session identifiers discovered in resource URLs are redacted before export.
      </div>
    </div>
  );
}
