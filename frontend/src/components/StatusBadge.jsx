const STYLES = {
  // --- probe/resource verdicts (Phase 3/4) ---
  PASS: "bg-status-green-bg text-status-green border border-status-green/40",
  IPv4_REACHABLE: "bg-status-green-bg text-status-green border border-status-green/40",
  IPv6_REACHABLE: "bg-status-green-bg text-status-green border border-status-green/40",
  LOADED: "bg-status-green-bg text-status-green border border-status-green/40",
  READY: "bg-status-green-bg text-status-green border border-status-green/40",
  BOTH_OK: "bg-status-green-bg text-status-green border border-status-green/40",

  DNS_FAILURE: "bg-status-red-bg text-status-red border border-status-red/40",
  TCP_FAILURE: "bg-status-red-bg text-status-red border border-status-red/40",
  TLS_FAILURE: "bg-status-red-bg text-status-red border border-status-red/40",
  HTTP_FAILURE: "bg-status-red-bg text-status-red border border-status-red/40",
  FAILED: "bg-status-red-bg text-status-red border border-status-red/40",
  IPV6_BROKEN: "bg-status-red-bg text-status-red border border-status-red/40",
  BOTH_BROKEN: "bg-status-red-bg text-status-red border border-status-red/40",

  BLOCKED: "bg-status-amber-bg text-status-amber border border-status-amber/40",
  IPV4_BROKEN: "bg-status-amber-bg text-status-amber border border-status-amber/40",

  NOT_TESTED: "bg-status-gray-bg text-status-gray border border-border",
  NOT_APPLICABLE: "bg-status-gray-bg text-status-gray border border-border",
  NOT_REACHED: "bg-status-gray-bg text-status-gray border border-border",
  UNKNOWN: "bg-status-gray-bg text-status-gray border border-border",
  INCONCLUSIVE: "bg-status-gray-bg text-status-gray border border-border",

  COMPLETED: "bg-status-green-bg text-status-green border border-status-green/40",
  PARTIAL: "bg-status-amber-bg text-status-amber border border-status-amber/40",
  SCAN_FAILED: "bg-status-red-bg text-status-red border border-status-red/40",
  QUEUED: "bg-status-gray-bg text-status-gray border border-border",
  RUNNING: "bg-status-gray-bg text-status-gray border border-border",
};

export default function StatusBadge({ value, fallback = "gray" }) {
  const label = value === null || value === undefined || value === "" ? "Unknown" : String(value);
  const cls = STYLES[label] || (fallback === "gray" ? STYLES.NOT_TESTED : "bg-surface text-ink border border-border");
  return (
    <span className={`inline-flex items-center rounded-md px-2.5 py-0.5 text-xs font-semibold font-mono tracking-wide ${cls}`}>
      {label.replace(/_/g, " ")}
    </span>
  );
}
