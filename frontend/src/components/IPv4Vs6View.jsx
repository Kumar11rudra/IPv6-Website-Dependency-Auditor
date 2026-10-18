import StatusBadge from "./StatusBadge";

export default function IPv4Vs6View({ probes = [], resources = [] }) {
  const byHost = {};
  for (const p of probes) (byHost[`${p.hostname}:${p.port}`] ||= {})[p.family] = p;
  const rows = Object.entries(byHost);

  return (
    <div className="border border-border rounded-xl shadow-xs overflow-hidden bg-surface">
      <div className="overflow-x-auto max-h-[560px]">
        <table className="w-full text-base">
          <thead className="sticky top-0 bg-[#EAF3FD] border-b border-border text-left text-xs uppercase tracking-wider text-primary font-bold">
            <tr>
              <th className="px-5 py-3.5">Host:Port</th>
              <th className="px-4 py-3.5">DNS</th>
              <th className="px-4 py-3.5">Protocols</th>
              <th className="px-5 py-3.5">IPv4</th>
              <th className="px-5 py-3.5">IPv6</th>
              <th className="px-5 py-3.5">Comparison</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.map(([key, fam]) => {
              const hostname = fam[4]?.hostname || fam[6]?.hostname || key.split(":")[0];
              const res = resources.find((r) => r.hostname === hostname);

              // 1. DNS Status Pill
              const hasV4Dns =
                (fam[4]?.dns_addresses && fam[4].dns_addresses.length > 0) ||
                (res?.ipv4_addresses && res.ipv4_addresses.length > 0) ||
                fam[4]?.dns_status === "NO_ERROR";
              const hasV6Dns =
                (fam[6]?.dns_addresses && fam[6].dns_addresses.length > 0) ||
                (res?.ipv6_addresses && res.ipv6_addresses.length > 0) ||
                (fam[6]?.dns_status === "NO_ERROR" && fam[6]?.failure_stage !== "DNS");

              let dnsBadge = "None";
              let isDnsReady = false;
              if (hasV4Dns && hasV6Dns) {
                dnsBadge = "Dual-stack";
                isDnsReady = true;
              } else if (hasV4Dns) {
                dnsBadge = "A only";
                isDnsReady = true;
              } else if (hasV6Dns) {
                dnsBadge = "AAAA only";
                isDnsReady = true;
              }

              // 2. Protocols
              const protoList = [];
              const httpProto =
                res?.protocol ||
                (fam[4]?.probe_scheme === "https" || fam[6]?.probe_scheme === "https"
                  ? "h2"
                  : fam[4] || fam[6]
                  ? "http/1.1"
                  : null);
              if (httpProto) protoList.push(httpProto);
              const tls =
                fam[6]?.tls_version ||
                fam[4]?.tls_version ||
                (res?.url?.startsWith("https") ? "TLS 1.3" : null);
              if (tls) protoList.push(tls);

              return (
                <tr key={key} className="hover:bg-bg/60 transition-colors">
                  <td className="px-5 py-3.5 font-mono text-sm font-semibold text-ink">{key}</td>
                  <td className="px-4 py-3.5">
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold border ${
                        isDnsReady
                          ? "border-[#1A7A1A] text-[#1A7A1A] bg-[#EAF5EA]"
                          : "border-[#B32020] text-[#B32020] bg-[#FDDEDE]"
                      }`}
                    >
                      {dnsBadge}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 font-mono text-sm text-[#767676]">
                    {protoList.length > 0 ? (
                      <div className="flex items-center gap-2">
                        {protoList.map((p, idx) => (
                          <span key={idx}>{p}</span>
                        ))}
                      </div>
                    ) : (
                      <span>—</span>
                    )}
                  </td>
                  <td className="px-5 py-3.5"><StatusBadge value={fam[4]?.verdict} /></td>
                  <td className="px-5 py-3.5"><StatusBadge value={fam[6]?.verdict} /></td>
                  <td className="px-5 py-3.5"><StatusBadge value={fam[4]?.family_comparison || fam[6]?.family_comparison} /></td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-muted text-base">
                  No probed hosts recorded yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

