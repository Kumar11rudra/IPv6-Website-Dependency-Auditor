import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import Footer from "./Footer";

describe("Footer Component", () => {
  it("renders all compliance and legal statements", () => {
    render(<Footer onNavigate={() => {}} />);

    expect(screen.getByText(/Terms of Use:/i)).toBeInTheDocument();
    expect(screen.getByText(/Privacy Statement:/i)).toBeInTheDocument();
    expect(screen.getByText(/Data Retention Statement:/i)).toBeInTheDocument();
    expect(screen.getByText(/Cookie Statement:/i)).toBeInTheDocument();
    expect(screen.getByText(/This service uses no cookies/i)).toBeInTheDocument();
  });

  it("triggers navigation when links are clicked", () => {
    const onNav = vi.fn();
    render(<Footer onNavigate={onNav} />);

    const termsLink = screen.getByRole("link", { name: "Terms of Use" });
    fireEvent.click(termsLink);
    expect(onNav).toHaveBeenCalledWith("terms");

    const privacyLink = screen.getByRole("link", { name: "Privacy Policy" });
    fireEvent.click(privacyLink);
    expect(onNav).toHaveBeenCalledWith("privacy");
  });
});
