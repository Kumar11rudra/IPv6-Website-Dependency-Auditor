import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Dashboard from "./Dashboard";
import { api, TERMINAL_STATUSES, BATCH_TERMINAL_STATUSES } from "../api/client";

vi.mock("../api/client", () => ({
  api: {
    startScan: vi.fn(), getScan: vi.fn(), getResources: vi.fn(), getProbes: vi.fn(),
    getGraph: vi.fn(), getContext: vi.fn(), getScannerContext: vi.fn(),
    jsonReportUrl: (id) => `/json/${id}`, csvReportUrl: (id) => `/csv/${id}`,
    startBatch: vi.fn(), getBatch: vi.fn(), getBatchSites: vi.fn(),
    batchJsonReportUrl: (id) => `/batch-json/${id}`, batchCsvReportUrl: (id) => `/batch-csv/${id}`,
  },
  TERMINAL_STATUSES: new Set(["COMPLETED", "PARTIAL", "BLOCKED", "SCAN_FAILED"]),
  BATCH_TERMINAL_STATUSES: new Set(["COMPLETED"]),
}));

const EMPTY_GRAPH = { nodes: [], edges: [], legend: { green: "x", yellow: "y", red: "z", gray: "w" } };

function scanShell(overrides) {
  return { scan_id: "s1", target_url: "https://x.test/", final_url: "https://x.test/", error: null,
          scanner_version: "t", batch_id: null, truncated: false, created_at: "t", started_at: "t",
          finished_at: "t", summary: { resources: 0, hosts: 0, by_load_status: {}, probes: { by_family: {}, ipv4_vs_ipv6: {} } },
          ...overrides };
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getResources.mockResolvedValue([]);
  api.getProbes.mockResolvedValue([]);
  api.getGraph.mockResolvedValue(EMPTY_GRAPH);
});
afterEach(() => vi.restoreAllMocks());

async function analyze(user, url = "https://x.test/") {
  await user.type(screen.getByPlaceholderText("https://example.com"), url);
  await user.click(screen.getByRole("button", { name: "Analyze" }));
}

describe("Dashboard - loading a scan", () => {
  it("shows Completed and renders the Overview tab once a scan finishes", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({ status: "COMPLETED" }));
    render(<Dashboard />);
    await analyze(user);
    await waitFor(() => expect(screen.getByText("Completed")).toBeInTheDocument());
    expect(screen.getByText(/use the tabs above/i)).toBeInTheDocument();
  });

  it("renders PARTIAL as 'Completed with warnings' plus the reason", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({ status: "PARTIAL", error: "scan deadline reached" }));
    render(<Dashboard />);
    await analyze(user);
    await waitFor(() => expect(screen.getByText("Completed with warnings")).toBeInTheDocument());
    expect(screen.getByText("(scan deadline reached)")).toBeInTheDocument();
  });

  it("renders SCAN_FAILED as 'Scan failed'", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({ status: "SCAN_FAILED", error: "TimeoutError" }));
    render(<Dashboard />);
    await analyze(user);
    await waitFor(() => expect(screen.getByText("Scan failed")).toBeInTheDocument());
  });

  it("renders BLOCKED with the SSRF rejection reason, exact terminology preserved", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({
      status: "BLOCKED", error: "169.254.169.254 resolves to non-public address 169.254.169.254",
    }));
    render(<Dashboard />);
    await analyze(user, "http://169.254.169.254/");
    await waitFor(() => expect(screen.getByText("Blocked")).toBeInTheDocument());
    expect(screen.getByText(/non-public address/)).toBeInTheDocument();
  });

  it("empty resources renders the explicit empty state, not a blank or crashed table", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({ status: "COMPLETED" }));
    api.getResources.mockResolvedValue([]);
    render(<Dashboard />);
    await analyze(user);
    await waitFor(() => expect(screen.getByText("Completed")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Resources" }));
    expect(screen.getByText(/no resources were discovered/i)).toBeInTheDocument();
  });
});

describe("Dashboard - IPv4/IPv6 verdict rendering end to end", () => {
  it("shows the IPv4-works/IPv6-broken highlight on Overview using real verdict terms", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({ status: "COMPLETED" }));
    api.getResources.mockResolvedValue([{ resource_id: "r1", url: "https://broken.test/a.js",
      hostname: "broken.test", port: 443, resource_type: "script", load_status: "LOADED", http_status: 200 }]);
    api.getProbes.mockResolvedValue([
      { hostname: "broken.test", port: 443, family: 4, verdict: "IPv4_REACHABLE" },
      { hostname: "broken.test", port: 443, family: 6, verdict: "TCP_FAILURE", failure_stage: "TCP",
       failure_subtype: "REFUSED", family_comparison: "IPV6_BROKEN" },
    ]);
    render(<Dashboard />);
    await analyze(user);
    await waitFor(() => expect(screen.getByText("Completed")).toBeInTheDocument());
    expect(screen.getByText("broken.test")).toBeInTheDocument();
    expect(screen.getByText(/fails at the tcp connection/i)).toBeInTheDocument();
    expect(screen.getByText("IPv4 REACHABLE")).toBeInTheDocument();  // exact verdict terminology, both sides shown
    expect(screen.getByText("TCP FAILURE")).toBeInTheDocument();
  });

  it("the resource table correctly distinguishes a confirmed IPv6 failure from NOT_TESTED", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({ status: "COMPLETED" }));
    api.getResources.mockResolvedValue([
      { resource_id: "r1", url: "https://a.test/x.js", hostname: "a.test", port: 443,
       resource_type: "script", load_status: "LOADED", http_status: 200 },
    ]);
    api.getProbes.mockResolvedValue([
      { hostname: "a.test", port: 443, family: 4, verdict: "IPv4_REACHABLE" },
      { hostname: "a.test", port: 443, family: 6, verdict: "NOT_TESTED" },
    ]);
    render(<Dashboard />);
    await analyze(user);
    await waitFor(() => expect(screen.getByText("Completed")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Resources" }));
    const texts = screen.getAllByRole("cell").map((c) => c.textContent);
    expect(texts).toContain("—");
    expect(texts).not.toContain("✗");
  });
});

describe("Dashboard - Unknown measurement context", () => {
  it("renders Unknown values in the Measurements tab without crashing", async () => {
    const user = userEvent.setup();
    api.startScan.mockResolvedValue(scanShell({ status: "COMPLETED" }));
    api.getContext.mockResolvedValue({
      resolver_ips: "Unknown", resolver_upstream_ips: "Unknown", resolver_is_local_stub: "Unknown",
      resolver_egress_ip: "Unknown", ipv4_egress_ok: "Unknown", ipv6_egress_ok: "Unknown",
      scanner_public_ipv4: "Unknown", scanner_public_ipv6: "Unknown", geo_country: "Unknown",
      geo_region: "Unknown", geo_city: "Unknown", geo_org: "Unknown", geo_source: "Unknown", warnings: [],
    });
    render(<Dashboard />);
    await analyze(user);
    await waitFor(() => expect(screen.getByText("Completed")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Measurements" }));
    await waitFor(() => expect(screen.getAllByText("Unknown").length).toBeGreaterThan(5));
  });
});

describe("Dashboard - batch progress", () => {
  it("runs a batch, shows live progress, then completed per-site statuses", async () => {
    const user = userEvent.setup();
    api.startBatch.mockResolvedValue({ batch_id: "b1", status: "QUEUED", total: 2, source: "custom",
      scanner_version: "t", error: null, created_at: "t", started_at: null, finished_at: null,
      completed: 0, summary: { completed: 0, total: 2, by_status: {} } });
    api.getBatchSites.mockResolvedValue([
      { site_index: 0, name: "Site A", url: "https://a.test/", scan_id: "sa", status: "QUEUED" },
      { site_index: 1, name: "Site B", url: "https://b.test/", scan_id: "sb", status: "QUEUED" },
    ]);
    api.getBatch.mockResolvedValueOnce({ batch_id: "b1", status: "RUNNING", total: 2, source: "custom",
      scanner_version: "t", error: null, created_at: "t", started_at: "t", finished_at: null,
      completed: 1, summary: { completed: 1, total: 2, by_status: { COMPLETED: 1 } } })
      .mockResolvedValue({ batch_id: "b1", status: "COMPLETED", total: 2, source: "custom",
        scanner_version: "t", error: null, created_at: "t", started_at: "t", finished_at: "t",
        completed: 2, summary: { completed: 2, total: 2, by_status: { COMPLETED: 2 } } });

    render(<Dashboard />);
    await user.click(screen.getByRole("button", { name: "30-Site Batch" }));
    await user.click(screen.getByRole("button", { name: /run 30-site batch/i }));

    await waitFor(() => expect(screen.getByText("Site A")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("1 / 2 completed")).toBeInTheDocument(), { timeout: 3000 });
    await waitFor(() => expect(screen.getByText("2 / 2 completed")).toBeInTheDocument(), { timeout: 3000 });
    expect(screen.getByText("Completed")).toBeInTheDocument();
  });

  it("clicking View on a batch site switches to Single Scan mode showing that site's data", async () => {
    const user = userEvent.setup();
    api.startBatch.mockResolvedValue({ batch_id: "b1", status: "COMPLETED", total: 1, source: "custom",
      scanner_version: "t", error: null, created_at: "t", started_at: "t", finished_at: "t",
      completed: 1, summary: { completed: 1, total: 1, by_status: { COMPLETED: 1 } } });
    api.getBatchSites.mockResolvedValue([
      { site_index: 0, name: "Site A", url: "https://a.test/", scan_id: "sa", status: "COMPLETED" },
    ]);
    api.getBatch.mockResolvedValue({ batch_id: "b1", status: "COMPLETED", total: 1, source: "custom",
      scanner_version: "t", error: null, created_at: "t", started_at: "t", finished_at: "t",
      completed: 1, summary: { completed: 1, total: 1, by_status: { COMPLETED: 1 } } });
    api.getScan.mockResolvedValue(scanShell({ scan_id: "sa", status: "COMPLETED" }));

    render(<Dashboard />);
    await user.click(screen.getByRole("button", { name: "30-Site Batch" }));
    await user.click(screen.getByRole("button", { name: /run 30-site batch/i }));
    await waitFor(() => expect(screen.getByText("Site A")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /view/i }));
    await waitFor(() => expect(screen.getByText("Scan sa")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Scan a URL" })).toHaveClass("text-primary");
  });
});
