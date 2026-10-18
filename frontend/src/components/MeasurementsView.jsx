function Row({ label, value }) {
  return (
    <div className="flex justify-between items-center border-b border-border py-2.5 text-base last:border-b-0 gap-4">
      <span className="text-muted font-medium">{label}</span>
      <span className="font-mono text-sm font-semibold text-ink text-right break-all">{value === null || value === undefined ? "Unknown" : String(value)}</span>
    </div>
  );
}

export default function MeasurementsView({ context }) {
  if (!context) return <div className="text-base text-muted p-6 border border-border rounded-xl bg-surface shadow-xs leading-relaxed">No measurement context recorded yet.</div>;
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
      <div className="border border-border rounded-xl bg-surface p-6 shadow-xs">
        <div className="text-xs font-bold text-muted mb-3 uppercase tracking-wider">Resolver</div>
        <Row label="Configured resolvers" value={Array.isArray(context.resolver_ips) ? context.resolver_ips.join(", ") : context.resolver_ips} />
        <Row label="Upstream (behind stub)" value={Array.isArray(context.resolver_upstream_ips) ? context.resolver_upstream_ips.join(", ") : context.resolver_upstream_ips} />
        <Row label="Local stub resolver" value={context.resolver_is_local_stub} />
        <Row label="Resolver egress IP" value={context.resolver_egress_ip} />
      </div>
      <div className="border border-border rounded-xl bg-surface p-6 shadow-xs">
        <div className="text-xs font-bold text-muted mb-3 uppercase tracking-wider">Scanner network</div>
        <Row label="IPv4 egress" value={context.ipv4_egress_ok} />
        <Row label="IPv6 egress" value={context.ipv6_egress_ok} />
        <Row label="Public IPv4" value={context.scanner_public_ipv4} />
        <Row label="Public IPv6" value={context.scanner_public_ipv6} />
      </div>
      <div className="border border-border rounded-xl bg-surface p-6 shadow-xs">
        <div className="text-xs font-bold text-muted mb-3 uppercase tracking-wider">Geolocation (approximate)</div>
        <Row label="Country" value={context.geo_country} />
        <Row label="Region" value={context.geo_region} />
        <Row label="City" value={context.geo_city} />
        <Row label="Network / org" value={context.geo_org} />
        <Row label="Source" value={context.geo_source} />
      </div>
      <div className="border border-border rounded-xl bg-surface p-6 shadow-xs">
        <div className="text-xs font-bold text-muted mb-3 uppercase tracking-wider">Warnings</div>
        {(context.warnings || []).length === 0
          ? <div className="text-base text-muted">None.</div>
          : <ul className="text-base list-disc pl-5 space-y-1.5 text-muted">{context.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>}
      </div>
    </div>
  );
}
