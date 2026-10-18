import StatusBadge from "./StatusBadge";

/** Turns an existing failure_stage/failure_subtype pair into one plain-English line,
 * using ONLY the verdict terminology the backend already returns - no new wording that
 * could drift from what the classifier actually decided. */
function explain(stage, subtype) {
  const stageText = {
    DNS: "at DNS resolution", TCP: "at the TCP connection", TLS: "during the TLS handshake", HTTP: "at the HTTP request",
  }[stage] || `at the ${stage} stage`;
  const subtypeText = {
    NO_RECORD: "no AAAA record is published", NXDOMAIN: "the name does not resolve",
    TIMEOUT: "the attempt timed out", REFUSED: "the connection was refused",
    RESET: "the connection was reset", UNREACHABLE: "the address is unreachable",
    CERT_VERIFY: "the certificate could not be verified", HANDSHAKE: "the handshake failed",
    SERVER_ERROR: "the server returned an error",
  }[subtype];
  return subtypeText ? `Fails ${stageText} (${subtypeText}).` : `Fails ${stageText}.`;
}

/** Groups by host:port (not by resource) since IPv4/IPv6 reachability is a property of
 * the host, not of any one resource on it - matches how probing actually works
 * (Phase 3: one probe per host:port, reused by every resource on that host). */
function groupBrokenHosts(probes) {
  const byHost = {};
  for (const p of probes) {
    if (p.family !== 6 || p.family_comparison !== "IPV6_BROKEN") continue;
    byHost[`${p.hostname}:${p.port}`] = p;
  }
  return Object.values(byHost).sort((a, b) => a.hostname.localeCompare(b.hostname));
}

export default function Ipv6BrokenHighlight({ probes, resources }) {
  const broken = groupBrokenHosts(probes);

  if (probes.length === 0) {
    return null;  // nothing probed yet - let the caller decide what empty-state to show
  }
  if (broken.length === 0) {
    return (
      <div className="border border-status-green/30 bg-status-green-bg rounded-xl p-5 text-base font-medium text-status-green shadow-xs leading-relaxed">
        No resources were found that work over IPv4 but fail over IPv6.
      </div>
    );
  }

  return (
    <div className="border border-status-red/30 rounded-xl bg-surface overflow-hidden shadow-xs">
      <div className="bg-status-red-bg px-5 py-3 border-b border-status-red/30">
        <span className="text-base font-semibold text-status-red">
          {broken.length} host{broken.length > 1 ? "s" : ""} work{broken.length > 1 ? "" : "s"} over IPv4 but fail{broken.length > 1 ? "" : "s"} over IPv6
        </span>
      </div>
      <div className="divide-y divide-border">
        {broken.map((p) => {
          const count = resources.filter((r) => r.hostname === p.hostname && r.port === p.port).length;
          return (
            <div key={`${p.hostname}:${p.port}`} className="px-5 py-4 flex items-start justify-between gap-4 hover:bg-bg/40 transition-colors">
              <div>
                <div className="font-mono text-base font-semibold text-ink">{p.hostname}</div>
                <div className="text-base text-muted mt-1 leading-normal">{explain(p.failure_stage, p.failure_subtype)}</div>
                <div className="text-sm font-medium text-muted mt-1.5">
                  {count} resource{count === 1 ? "" : "s"} on this host{count > 0 ? " affected" : ""}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1.5 shrink-0">
                <StatusBadge value="IPv4_REACHABLE" />
                <StatusBadge value={p.verdict} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
