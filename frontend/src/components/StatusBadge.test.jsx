import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import StatusBadge from "./StatusBadge";

describe("StatusBadge", () => {
  it("renders a known verdict verbatim", () => {
    render(<StatusBadge value="IPv6_REACHABLE" />);
    expect(screen.getByText("IPv6 REACHABLE")).toBeInTheDocument();
  });

  it("renders Unknown for null/undefined", () => {
    render(<StatusBadge value={null} />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });
});

describe("StatusBadge scan/batch status terms", () => {
  it("styles every real scan/batch status distinctly - SCAN_FAILED must look like a failure, not 'untested'", () => {
    const { container: completed } = render(<StatusBadge value="COMPLETED" />);
    const { container: failed } = render(<StatusBadge value="SCAN_FAILED" />);
    const { container: notTested } = render(<StatusBadge value="NOT_TESTED" />);
    expect(completed.querySelector("span").className).toContain("status-green");
    expect(failed.querySelector("span").className).toContain("status-red");
    // the actual regression: SCAN_FAILED must NOT share NOT_TESTED's gray styling
    expect(failed.querySelector("span").className).not.toBe(notTested.querySelector("span").className);
  });
});
