const BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

async function req(path, opts) {
  const res = await fetch(`${BASE}${path}`, {
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
  jsonReportUrl: (id) => `${BASE}/api/scan/${id}/report/json`,
  csvReportUrl: (id) => `${BASE}/api/scan/${id}/report/csv`,

  startBatch: (sites, includeControlled) =>
    req("/api/batch-scan", { method: "POST", body: JSON.stringify({ sites: sites ?? null, include_controlled: includeControlled ?? true }) }),
  getBatch: (id) => req(`/api/batch-scan/${id}`),
  getBatchSites: (id) => req(`/api/batch-scan/${id}/sites`),
  batchJsonReportUrl: (id) => `${BASE}/api/batch-scan/${id}/report/json`,
  batchCsvReportUrl: (id) => `${BASE}/api/batch-scan/${id}/report/csv`,
};

export const TERMINAL_STATUSES = new Set(["COMPLETED", "PARTIAL", "BLOCKED", "SCAN_FAILED"]);
export const BATCH_TERMINAL_STATUSES = new Set(["COMPLETED"]);
