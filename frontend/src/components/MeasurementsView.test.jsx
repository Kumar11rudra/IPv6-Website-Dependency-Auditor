import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import MeasurementsView from "./MeasurementsView";

describe("MeasurementsView", () => {
  it("shows an empty state before any context has been loaded", () => {
    render(<MeasurementsView context={null} />);
    expect(screen.getByText(/no measurement context recorded/i)).toBeInTheDocument();
  });

  it("renders 'Unknown' for genuinely missing values, exactly as the API sends them", () => {
    // Mirrors the API contract: ScanContext.display() already converts None -> "Unknown"
    // string server-side; this component must render that string, not re-derive it.
    const context = {
      resolver_ips: "Unknown", resolver_upstream_ips: "Unknown", resolver_is_local_stub: "Unknown",
      resolver_egress_ip: "Unknown", ipv4_egress_ok: "Unknown", ipv6_egress_ok: "Unknown",
      scanner_public_ipv4: "Unknown", scanner_public_ipv6: "Unknown",
      geo_country: "Unknown", geo_region: "Unknown", geo_city: "Unknown", geo_org: "Unknown",
      warnings: [],
    };
    render(<MeasurementsView context={context} />);
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(5);
  });

  it("a real false value is preserved and never upgraded to Unknown", () => {
    // Every field below mirrors the REAL API contract (scanner/context.py's
    // ScanContext.display()): a field is always either a genuine value or the literal
    // string "Unknown" - never JS `undefined` - so the fixture must reflect that too.
    const context = {
      resolver_ips: ["8.8.8.8"], resolver_upstream_ips: [], resolver_is_local_stub: false,
      resolver_egress_ip: "9.9.9.9", ipv4_egress_ok: true, ipv6_egress_ok: false,
      scanner_public_ipv4: "203.0.113.1", scanner_public_ipv6: "Unknown",
      geo_country: "IN", geo_region: "PB", geo_city: "Anandpur", geo_org: "Example ISP",
      geo_source: "ipinfo.io",
      warnings: ["IPv6 egress unavailable from the scanner host: IPv6 probe results must be reported as NOT_TESTED."],
    };
    render(<MeasurementsView context={context} />);
    expect(screen.getByText("true")).toBeInTheDocument();
    expect(screen.getAllByText("false").length).toBe(2);  // resolver_is_local_stub + ipv6_egress_ok - NOT "Unknown"
    expect(screen.queryAllByText("Unknown")).toHaveLength(1);  // only scanner_public_ipv6 is genuinely unknown here
    expect(screen.getByText(/NOT_TESTED/)).toBeInTheDocument();
  });
});
