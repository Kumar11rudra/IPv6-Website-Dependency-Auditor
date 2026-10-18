import StatusBadge from "./StatusBadge";

function Stage({ label, status }) {
  return (
    <div className="flex items-center justify-between text-base py-1.5">
      <span className="text-muted font-medium">{label}</span>
      <StatusBadge value={status} />
    </div>
  );
}

export default function NodeDetailPanel({ node, probes }) {
  if (!node) {
    return (
      <div className="border border-border rounded-xl bg-surface p-6 text-base text-muted h-full flex items-center justify-center text-center shadow-xs leading-relaxed min-h-[220px]">
        Click a node in the graph to see its DNS → TCP → TLS → HTTP breakdown.
      </div>
    );
  }
  if (node.kind === "host") {
    const v6 = probes.find((p) => p.hostname === node.label && p.family === 6);
    const v4 = probes.find((p) => p.hostname === node.label && p.family === 4);
    return (
      <div className="border border-border rounded-xl bg-surface p-5 shadow-xs flex flex-col gap-4">
        <div>
          <div className="text-xs uppercase font-bold text-muted tracking-wider mb-1">Host</div>
          <div className="font-mono text-base font-semibold text-ink break-all">{node.label}</div>
        </div>
        {[["IPv4", v4], ["IPv6", v6]].map(([fam, p]) => (
          <div key={fam} className="border-t border-border pt-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-bold text-ink">{fam}</span>
              <StatusBadge value={p?.verdict} />
            </div>
            <Stage label="DNS" status={p?.dns_status} />
            <Stage label="TCP" status={p?.tcp_status} />
            <Stage label="TLS" status={p?.tls_status} />
            <Stage label="HTTP" status={p?.http_stage_status} />
            {p?.http_code != null && <div className="text-sm font-medium text-muted mt-1.5">HTTP {p.http_code}</div>}
            {p?.error_detail && <div className="text-sm font-mono text-status-red mt-1.5 break-words bg-status-red-bg/50 p-2 rounded">{p.error_detail}</div>}
          </div>
        ))}
      </div>
    );
  }
  return (
    <div className="border border-border rounded-xl bg-surface p-5 shadow-xs flex flex-col gap-3">
      <div>
        <div className="text-xs uppercase font-bold text-muted tracking-wider mb-1">Resource</div>
        <div className="font-mono text-sm font-medium text-ink break-all">{node.url}</div>
      </div>
      <div className="flex gap-4 text-base">
        <div><span className="text-muted font-medium">Type: </span><span className="font-semibold">{node.resource_type}</span></div>
        <div><span className="text-muted font-medium">HTTP: </span><span className="font-semibold">{node.http_status ?? "—"}</span></div>
      </div>
      <div><StatusBadge value={node.load_status} /></div>
    </div>
  );
}
