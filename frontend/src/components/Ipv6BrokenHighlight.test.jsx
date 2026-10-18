import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Ipv6BrokenHighlight from "./Ipv6BrokenHighlight";

function brokenProbe(overrides) {
  return { hostname: "broken.test", port: 443, family: 6, family_comparison: "IPV6_BROKEN",
          verdict: "TCP_FAILURE", failure_stage: "TCP", failure_subtype: "REFUSED", ...overrides };
}

describe("Ipv6BrokenHighlight", () => {
  it("renders nothing when no probes exist yet (scan not run / in progress)", () => {
    const { container } = render(<Ipv6BrokenHighlight probes={[]} resources={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows an explicit all-clear message when nothing is IPv4-OK/IPv6-broken", () => {
    render(<Ipv6BrokenHighlight probes={[{ hostname: "ok.test", port: 443, family: 6, family_comparison: "BOTH_OK", verdict: "IPv6_REACHABLE" }]} resources={[]} />);
    expect(screen.getByText(/no resources were found/i)).toBeInTheDocument();
  });

  it("lists a host that works over IPv4 but fails over IPv6, with a plain-English explanation", () => {
    render(<Ipv6BrokenHighlight probes={[brokenProbe()]} resources={[]} />);
    expect(screen.getByText("broken.test")).toBeInTheDocument();
    expect(screen.getByText(/fails at the tcp connection/i)).toBeInTheDocument();
    expect(screen.getByText(/connection was refused/i)).toBeInTheDocument();
  });

  it("only lists IPV6_BROKEN hosts, never BOTH_OK/IPV4_BROKEN/INCONCLUSIVE ones", () => {
    const probes = [
      brokenProbe({ hostname: "really-broken.test" }),
      { hostname: "fine.test", port: 443, family: 6, family_comparison: "BOTH_OK", verdict: "IPv6_REACHABLE" },
      { hostname: "v4-is-the-broken-one.test", port: 443, family: 6, family_comparison: "IPV4_BROKEN", verdict: "IPv6_REACHABLE" },
    ];
    render(<Ipv6BrokenHighlight probes={probes} resources={[]} />);
    expect(screen.getByText("really-broken.test")).toBeInTheDocument();
    expect(screen.queryByText("fine.test")).not.toBeInTheDocument();
    expect(screen.queryByText("v4-is-the-broken-one.test")).not.toBeInTheDocument();
  });

  it("counts affected resources on the broken host", () => {
    const resources = [{ hostname: "broken.test", port: 443 }, { hostname: "broken.test", port: 443 }];
    render(<Ipv6BrokenHighlight probes={[brokenProbe()]} resources={resources} />);
    expect(screen.getByText(/2 resources on this host/i)).toBeInTheDocument();
  });

  it("deduplicates to one entry per host:port even with many resources on it", () => {
    const probes = [brokenProbe(), brokenProbe()]; // same host:port reported twice (shouldn't happen, but defend anyway)
    render(<Ipv6BrokenHighlight probes={probes} resources={[]} />);
    expect(screen.getAllByText("broken.test")).toHaveLength(1);
  });
});
