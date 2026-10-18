import StatusBadge from "./StatusBadge";
import { api } from "../api/client";

const STATUS_LABEL = {
  QUEUED: "Queued", RUNNING: "Running", COMPLETED: "Completed",
};

export default function BatchView({ batch, sites, error, onStart, onViewSite, running }) {
  if (!batch) {
    return (
      <div className="border border-border rounded-xl bg-surface p-6 md:p-8 flex flex-col items-start gap-4 shadow-xs">
        <div className="text-base text-muted max-w-2xl leading-relaxed">
          Runs every site in the configured <code className="font-mono text-sm bg-bg px-2 py-0.5 rounded border border-border">sites.json</code> (plus the
          controlled IPv4-only test site, if configured) through the same scan pipeline as a single scan,
          with a bounded concurrency limit so one slow or unreachable site can't stall the rest.
        </div>
        <button onClick={() => onStart()} className="bg-primary hover:bg-primary-hover active:scale-[0.98] text-white text-base font-semibold px-6 py-3 rounded-lg shadow-sm transition-all">
          Run 30-Site Batch
        </button>
        {error && <div className="text-base text-status-red bg-status-red-bg px-4 py-2 rounded-lg border border-status-red/30">{error}</div>}
      </div>
    );
  }

  const progress = batch.summary || { completed: 0, total: batch.total, by_status: {} };

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-4 flex-wrap text-base">
        <span className="text-muted font-medium">Batch {batch.batch_id}</span>
        <span className="font-semibold text-ink">{STATUS_LABEL[batch.status] || batch.status}</span>
        <span className="font-mono text-muted font-medium">{progress.completed} / {progress.total} completed</span>
        {running && <span className="text-sm font-semibold text-accent animate-pulse">polling…</span>}
      </div>

      <div className="flex flex-wrap gap-2.5">
        {Object.entries(progress.by_status || {}).map(([status, count]) => (
          <span key={status} className="flex items-center gap-1.5 text-sm font-medium border border-border rounded-lg px-3 py-1.5 bg-surface shadow-xs">
            <StatusBadge value={status} /> <span className="font-mono font-semibold text-ink">{count}</span>
          </span>
        ))}
      </div>

      {error && <div className="text-base text-status-red bg-status-red-bg px-4 py-2.5 rounded-lg border border-status-red/30">{error}</div>}

      {batch.status === "COMPLETED" && (
        <div className="flex gap-3 text-base font-medium">
          <a href={api.batchJsonReportUrl(batch.batch_id)} className="border border-border rounded-lg px-4 py-2 bg-surface hover:bg-bg shadow-xs transition-colors" target="_blank" rel="noreferrer">
            Download batch JSON
          </a>
          <a href={api.batchCsvReportUrl(batch.batch_id)} className="border border-border rounded-lg px-4 py-2 bg-surface hover:bg-bg shadow-xs transition-colors" target="_blank" rel="noreferrer">
            Download batch CSV
          </a>
        </div>
      )}

      <div className="border border-border rounded-xl shadow-xs overflow-auto max-h-[540px] bg-surface">
        <table className="w-full text-base">
          <thead className="sticky top-0 bg-bg/95 backdrop-blur-xs border-b border-border text-left text-xs uppercase tracking-wider text-muted font-semibold">
            <tr>
              <th className="px-4 py-3.5">Site</th>
              <th className="px-4 py-3.5">URL</th>
              <th className="px-4 py-3.5">Status</th>
              <th className="px-4 py-3.5"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {sites.map((s) => (
              <tr key={s.scan_id} className="hover:bg-bg/60 transition-colors">
                <td className="px-4 py-3.5 font-medium text-ink">{s.name}</td>
                <td className="px-4 py-3.5 font-mono text-sm text-muted max-w-[320px] truncate" title={s.url}>
                  {s.url.replace(/^https?:\/\//, "")}
                </td>
                <td className="px-4 py-3.5"><StatusBadge value={s.status} /></td>
                <td className="px-4 py-3.5 text-right">
                  <button onClick={() => onViewSite(s.scan_id)} className="text-sm font-semibold text-accent hover:underline">
                    View
                  </button>
                </td>
              </tr>
            ))}
            {sites.length === 0 && (
              <tr><td colSpan={4} className="px-4 py-8 text-center text-muted text-base">Loading site list…</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
