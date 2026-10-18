import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import ResourceTable from "./ResourceTable";

function resource(overrides) {
  return { resource_id: "r1", url: "https://host.test/a.js", hostname: "host.test",
          resource_type: "script", load_status: "LOADED", ...overrides };
}
function probe(family, overrides) {
  return { hostname: "host.test", port: 443, family, verdict: `IPv${family}_REACHABLE`, ...overrides };
}

describe("ResourceTable", () => {
  it("shows an empty state when no resources were discovered, not a blank table", () => {
    render(<ResourceTable resources={[]} probes={[]} />);
    expect(screen.getByText(/no resources were discovered/i)).toBeInTheDocument();
  });

  it("renders NOT_TESTED as a dash, never as a confirmed failure (✗)", () => {
    render(<ResourceTable resources={[resource()]} probes={[
      probe(4, { verdict: "IPv4_REACHABLE" }),
      probe(6, { verdict: "NOT_TESTED" }),
    ]} />);
    const cells = screen.getAllByRole("cell");
    const texts = cells.map((c) => c.textContent);
    expect(texts).toContain("✓");   // IPv4 confirmed reachable
    expect(texts).toContain("—");   // IPv6 not tested - must NOT be "✗"
    expect(texts).not.toContain("✗");
  });

  it("renders a confirmed IPv6 failure as ✗, with the failure stage shown", () => {
    render(<ResourceTable resources={[resource()]} probes={[
      probe(4, { verdict: "IPv4_REACHABLE" }),
      probe(6, { verdict: "TCP_FAILURE", failure_stage: "TCP" }),
    ]} />);
    expect(screen.getAllByRole("cell").map((c) => c.textContent)).toContain("✗");
    expect(screen.getByText("TCP")).toBeInTheDocument();
  });

  it("the IPv4-only filter selects exactly the IPv4-works/IPv6-fails resources", async () => {
    const resources = [resource({ resource_id: "r1", url: "https://broken.test/a.js", hostname: "broken.test" }),
                       resource({ resource_id: "r2", url: "https://fine.test/b.js", hostname: "fine.test" })];
    const probes = [
      { hostname: "broken.test", port: 443, family: 4, verdict: "IPv4_REACHABLE" },
      { hostname: "broken.test", port: 443, family: 6, verdict: "TCP_FAILURE", failure_stage: "TCP" },
      { hostname: "fine.test", port: 443, family: 4, verdict: "IPv4_REACHABLE" },
      { hostname: "fine.test", port: 443, family: 6, verdict: "IPv6_REACHABLE" },
    ];
    render(<ResourceTable resources={resources} probes={probes} />);
    await userEvent.click(screen.getByRole("button", { name: "IPv4-only" }));
    expect(screen.getByText("broken.test/a.js")).toBeInTheDocument();
    expect(screen.queryByText("fine.test/b.js")).not.toBeInTheDocument();
  });

  it("a resource whose IPv6 was simply never tested is NOT counted as IPv4-only", async () => {
    // Guards the exact bug fixed in Phase 4: NOT_TESTED must not be conflated with a
    // confirmed IPv6 failure.
    const resources = [resource({ hostname: "untested.test", url: "https://untested.test/x.js" })];
    const probes = [
      { hostname: "untested.test", port: 443, family: 4, verdict: "IPv4_REACHABLE" },
      { hostname: "untested.test", port: 443, family: 6, verdict: "NOT_TESTED" },
    ];
    render(<ResourceTable resources={resources} probes={probes} />);
    await userEvent.click(screen.getByRole("button", { name: "IPv4-only" }));
    expect(screen.getByText(/no resources match this filter/i)).toBeInTheDocument();
  });

  it("the Blocked filter selects resources whose load_status or verdict is BLOCKED", async () => {
    const resources = [resource({ hostname: "blocked.test", url: "https://blocked.test/x.js", load_status: "BLOCKED" }),
                       resource({ resource_id: "r2", hostname: "ok.test", url: "https://ok.test/y.js" })];
    render(<ResourceTable resources={resources} probes={[]} />);
    await userEvent.click(screen.getByRole("button", { name: "Blocked" }));
    expect(screen.getByText("blocked.test/x.js")).toBeInTheDocument();
    expect(screen.queryByText("ok.test/y.js")).not.toBeInTheDocument();
  });
});
