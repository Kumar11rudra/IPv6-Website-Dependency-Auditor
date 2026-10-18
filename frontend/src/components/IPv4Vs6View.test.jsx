import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import IPv4Vs6View from "./IPv4Vs6View";

describe("IPv4Vs6View", () => {
  it("renders empty state when no probes exist", () => {
    render(<IPv4Vs6View probes={[]} />);
    expect(screen.getByText(/no probed hosts recorded yet/i)).toBeInTheDocument();
  });

  it("renders host comparison columns with StatusBadges", () => {
    const probes = [
      {
        hostname: "www.cyberinspects.in",
        port: 443,
        family: 4,
        verdict: "IPv4_REACHABLE",
        family_comparison: "IPV6_BROKEN",
      },
      {
        hostname: "www.cyberinspects.in",
        port: 443,
        family: 6,
        verdict: "TCP_TIMEOUT",
        family_comparison: "IPV6_BROKEN",
      },
    ];

    render(<IPv4Vs6View probes={probes} />);

    // Check table headers
    expect(screen.getByText("Host:Port")).toBeInTheDocument();
    expect(screen.getByText("DNS")).toBeInTheDocument();
    expect(screen.getByText("Protocols")).toBeInTheDocument();
    expect(screen.getByText("IPv4")).toBeInTheDocument();
    expect(screen.getByText("IPv6")).toBeInTheDocument();
    expect(screen.getByText("Comparison")).toBeInTheDocument();

    // Check host key
    expect(screen.getByText("www.cyberinspects.in:443")).toBeInTheDocument();
  });
});

