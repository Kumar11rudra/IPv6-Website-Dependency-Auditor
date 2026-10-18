function Metric({ label, value, tone }) {
  const toneCls = tone ? `text-${tone}` : "text-ink";
  return (
    <div className="flex flex-col gap-1 border-r border-border px-5 py-4 last:border-r-0 flex-1 min-w-[130px]">
      <span className={`text-2xl md:text-3xl font-bold font-mono ${toneCls}`}>{value}</span>
      <span className="text-xs md:text-sm font-medium text-muted leading-snug">{label}</span>
    </div>
  );
}

export default function MetricStrip({ summary }) {
  if (!summary) return null;
  const bl = summary.by_load_status || {};
  const probeFam = summary.probes?.by_family?.ipv6 || {};
  const ipv6Broken = summary.probes?.ipv4_vs_ipv6?.IPV6_BROKEN ?? 0;
  return (
    <div className="flex flex-wrap border border-border bg-surface rounded-xl shadow-xs overflow-hidden">
      <Metric label="IPv4 OK, IPv6 broken" value={ipv6Broken} tone={ipv6Broken > 0 ? "status-red" : "status-green"} />
      <Metric label="Resources" value={summary.resources ?? 0} />
      <Metric label="Hosts" value={summary.hosts ?? 0} />
      <Metric label="Loaded" value={bl.LOADED ?? 0} tone="status-green" />
      <Metric label="DNS failures" value={probeFam.DNS_FAILURE ?? 0} />
      <Metric label="TCP failures" value={probeFam.TCP_FAILURE ?? 0} />
      <Metric label="TLS failures" value={probeFam.TLS_FAILURE ?? 0} />
      <Metric label="HTTP failures" value={probeFam.HTTP_FAILURE ?? 0} />
    </div>
  );
}
