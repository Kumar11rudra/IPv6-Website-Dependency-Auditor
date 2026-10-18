import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import BatchView from "./BatchView";

describe("BatchView", () => {
  it("shows a start button and explanation before any batch has been run", () => {
    render(<BatchView batch={null} sites={[]} error={null} onStart={vi.fn()} onViewSite={vi.fn()} running={false} />);
    expect(screen.getByRole("button", { name: /run 30-site batch/i })).toBeInTheDocument();
  });

  it("calling onStart happens on click", async () => {
    const onStart = vi.fn();
    render(<BatchView batch={null} sites={[]} error={null} onStart={onStart} onViewSite={vi.fn()} running={false} />);
    await userEvent.click(screen.getByRole("button", { name: /run 30-site batch/i }));
    expect(onStart).toHaveBeenCalled();
  });

  it("shows live progress (completed/total) and a per-status breakdown while running", () => {
    const batch = { batch_id: "b1", status: "RUNNING", total: 3,
                    summary: { completed: 1, total: 3, by_status: { COMPLETED: 1 } } };
    render(<BatchView batch={batch} sites={[]} error={null} onStart={vi.fn()} onViewSite={vi.fn()} running={true} />);
    expect(screen.getByText("1 / 3 completed")).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("renders every site's name, url and status, including BLOCKED and SCAN_FAILED", () => {
    const batch = { batch_id: "b1", status: "COMPLETED", total: 3,
                    summary: { completed: 3, total: 3, by_status: { COMPLETED: 1, BLOCKED: 1, SCAN_FAILED: 1 } } };
    const sites = [
      { scan_id: "s1", name: "Good Site", url: "https://good.test/", status: "COMPLETED" },
      { scan_id: "s2", name: "Blocked Site", url: "https://169.254.169.254/", status: "BLOCKED" },
      { scan_id: "s3", name: "Failed Site", url: "https://down.test/", status: "SCAN_FAILED" },
    ];
    render(<BatchView batch={batch} sites={sites} error={null} onStart={vi.fn()} onViewSite={vi.fn()} running={false} />);
    expect(screen.getByText("Good Site")).toBeInTheDocument();
    expect(screen.getByText("Blocked Site")).toBeInTheDocument();
    expect(screen.getByText("Failed Site")).toBeInTheDocument();
    // "BLOCKED" legitimately appears twice: once in the by_status breakdown chip, once
    // on the site's own row - both are real, intentional renderings, not a duplicate bug.
    expect(screen.getAllByText("BLOCKED").length).toBe(2);
    expect(screen.getAllByText("SCAN FAILED").length).toBe(2);  // StatusBadge renders underscores as spaces
  });

  it("clicking View on a site calls onViewSite with that site's scan_id", async () => {
    const onViewSite = vi.fn();
    const batch = { batch_id: "b1", status: "COMPLETED", total: 1, summary: { completed: 1, total: 1, by_status: {} } };
    const sites = [{ scan_id: "scan123", name: "Site A", url: "https://a.test/", status: "COMPLETED" }];
    render(<BatchView batch={batch} sites={sites} error={null} onStart={vi.fn()} onViewSite={onViewSite} running={false} />);
    await userEvent.click(screen.getByRole("button", { name: /view/i }));
    expect(onViewSite).toHaveBeenCalledWith("scan123");
  });

  it("shows report download links only once the batch has completed", () => {
    const running = { batch_id: "b1", status: "RUNNING", total: 1, summary: { completed: 0, total: 1, by_status: {} } };
    const { rerender } = render(<BatchView batch={running} sites={[]} error={null} onStart={vi.fn()} onViewSite={vi.fn()} running={true} />);
    expect(screen.queryByText(/download batch json/i)).not.toBeInTheDocument();

    const done = { ...running, status: "COMPLETED" };
    rerender(<BatchView batch={done} sites={[]} error={null} onStart={vi.fn()} onViewSite={vi.fn()} running={false} />);
    expect(screen.getByText(/download batch json/i)).toBeInTheDocument();
    expect(screen.getByText(/download batch csv/i)).toBeInTheDocument();
  });

  it("surfaces an error message without crashing", () => {
    const batch = { batch_id: "b1", status: "RUNNING", total: 1, summary: { completed: 0, total: 1, by_status: {} } };
    render(<BatchView batch={batch} sites={[]} error="network blip" onStart={vi.fn()} onViewSite={vi.fn()} running={true} />);
    expect(screen.getByText("network blip")).toBeInTheDocument();
  });
});
