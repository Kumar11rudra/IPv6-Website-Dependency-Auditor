export function getApiBase() {
  if (typeof window !== "undefined") {
    const custom = localStorage.getItem("auditor_api_base");
    if (custom) return custom.trim().replace(/\/+$/, "");
    // Docker / VPS deployment with reverse proxy on same host
    if (
      window.location.hostname !== "localhost" &&
      window.location.hostname !== "127.0.0.1" &&
      !window.location.hostname.endsWith("github.io")
    ) {
      return "";
    }
  }
  return (import.meta.env.VITE_API_BASE || "http://localhost:8000").replace(/\/+$/, "");
}

export function setApiBase(url) {
  if (typeof window !== "undefined") {
    if (url && url.trim()) {
      localStorage.setItem("auditor_api_base", url.trim().replace(/\/+$/, ""));
    } else {
      localStorage.removeItem("auditor_api_base");
    }
  }
}

async function req(path, opts) {
  const base = getApiBase();
  const res = await fetch(`${base}${path}`, {
    headers: { "content-type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = typeof body.detail === "object" ? body.detail.detail : body.detail;
    throw new Error(detail || `Request failed (${res.status})`);
  }
  return res.json();
}

export const api = {
  startScan: (url) => req("/api/scan", { method: "POST", body: JSON.stringify({ url }) }),
  getScan: (id) => req(`/api/scan/${id}`),
  getResources: (id) => req(`/api/scan/${id}/resources`),
  getProbes: (id) => req(`/api/scan/${id}/probes`),
  getGraph: (id) => req(`/api/scan/${id}/graph`),
  getContext: (id) => req(`/api/scan/${id}/context`),
  getScannerContext: () => req("/api/context"),
  jsonReportUrl: (id) => `${getApiBase()}/api/scan/${id}/report/json`,
  csvReportUrl: (id) => `${getApiBase()}/api/scan/${id}/report/csv`,

  startBatch: (sites, includeControlled) =>
    req("/api/batch-scan", { method: "POST", body: JSON.stringify({ sites: sites ?? null, include_controlled: includeControlled ?? true }) }),
  getBatch: (id) => req(`/api/batch-scan/${id}`),
  getBatchSites: (id) => req(`/api/batch-scan/${id}/sites`),
  batchJsonReportUrl: (id) => `${getApiBase()}/api/batch-scan/${id}/report/json`,
  batchCsvReportUrl: (id) => `${getApiBase()}/api/batch-scan/${id}/report/csv`,
};

export const TERMINAL_STATUSES = new Set(["COMPLETED", "PARTIAL", "BLOCKED", "SCAN_FAILED"]);
export const BATCH_TERMINAL_STATUSES = new Set(["COMPLETED"]);
