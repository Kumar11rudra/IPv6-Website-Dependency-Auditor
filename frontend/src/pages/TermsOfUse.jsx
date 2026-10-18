export default function TermsOfUse({ onBack }) {
  const scrollToTop = () => {
    if (typeof window !== "undefined" && typeof window.scrollTo === "function") {
      try {
        window.scrollTo({ top: 0, behavior: "smooth" });
      } catch {
        // safe fallback
      }
    }
  };

  return (
    <article className="max-w-7xl w-full mx-auto px-6 pt-8 pb-8 flex flex-col gap-6">
      {/* Breadcrumb Navigation */}
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs sm:text-sm text-muted font-medium">
        <button
          onClick={onBack}
          className="hover:text-primary hover:underline transition-colors flex items-center gap-1 focus:outline-none focus:ring-1 focus:ring-primary rounded"
        >
          <span>Auditor Dashboard</span>
        </button>
        <span className="text-muted/60">/</span>
        <span className="text-muted/80">Legal</span>
        <span className="text-muted/60">/</span>
        <span className="text-primary font-semibold" aria-current="page">Terms of Use</span>
      </nav>

      {/* Responsive Header */}
      <header className="flex items-start sm:items-center justify-between border-b border-border pb-4 flex-wrap gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-primary">Terms of Use</h1>
          <p className="text-xs sm:text-sm text-ink/70 font-medium mt-1">
            Last Updated: October 2026 &middot; Project A3-PS027-TC039
          </p>
        </div>
        <button
          onClick={onBack}
          className="bg-primary hover:bg-primary-hover active:scale-[0.98] text-white text-xs sm:text-sm font-semibold px-4 py-2.5 rounded-lg transition-all shadow-xs flex items-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-primary/40"
        >
          <span>&larr;</span>
          <span>Back to Auditor Dashboard</span>
        </button>
      </header>

      {/* Main Legal Content Card */}
      <div className="bg-surface border border-border rounded-xl p-6 sm:p-8 md:p-10 flex flex-col gap-8 shadow-xs">
        <section className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">1. Acceptance of Terms</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            By accessing or using the IPv6 Website &amp; Dependency Readiness Auditor (Project A3-PS027-TC039), you agree to be bound by these Terms of Use. This service is provided as a research and diagnostic tool under the AIORI Hackathon (Problem Statement PS-027: Internet Measurement). If you do not agree to these terms, please do not use the service.
          </p>
        </section>

        <section className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">2. Permitted Use &amp; Authorized Testing</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            This tool is designed to test internet-facing web properties and their third-party dependencies for IPv6 reachability. You agree to use this service exclusively for legitimate benchmarking, security assessment, and technical diagnosis. You must not use this tool to perform denial-of-service attacks, flood endpoints, or attempt unauthorized penetration testing.
          </p>
        </section>

        <section className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">3. Nature of Measurement &amp; &quot;As-Is&quot; Warranty</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            This service is provided &quot;as is&quot; without warranties of any kind, whether express or implied. Reachability verdicts (such as DNS status, TCP handshake times, TLS negotiation, and HTTP codes) represent active probe results from the vantage point of the scanning infrastructure at the time of execution. Network conditions, transient routing policies, CDN geodistribution, and firewall rules may influence outcomes.
          </p>
        </section>

        <section className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">4. Security &amp; SSRF Protection Enforcement</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            To prevent Server-Side Request Forgery (SSRF) and protect private infrastructure, our backend strictly forbids and rejects requests aimed at loopback interfaces (e.g. 127.0.0.1, localhost), private RFC-1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and link-local or cloud metadata services (such as 169.254.169.254).
          </p>
        </section>

        <section className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">5. Rate Limiting and Concurrency Safeguards</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            To maintain service reliability and respect third-party server resources, automated concurrency limits and per-host request throttling are enforced. Excessive automated requests may result in temporary throttling.
          </p>
        </section>

        <section className="flex flex-col gap-2.5 pb-2">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">6. Limitation of Liability</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            Under no circumstances shall the creators, contributors, or affiliated hackathon entities be liable for any direct, indirect, incidental, or consequential damages resulting from the use or inability to use this auditing platform.
          </p>
        </section>
      </div>

      {/* Bottom Actions */}
      <div className="flex items-center justify-between flex-wrap gap-4 pt-2">
        <button
          onClick={scrollToTop}
          className="text-xs sm:text-sm text-primary hover:underline font-semibold flex items-center gap-1 focus:outline-none focus:ring-1 focus:ring-primary rounded p-1"
        >
          <span>&uarr; Back to Top</span>
        </button>
        <button
          onClick={onBack}
          className="bg-primary hover:bg-primary-hover active:scale-[0.98] text-white text-xs sm:text-sm font-semibold px-4 py-2.5 rounded-lg transition-all shadow-xs"
        >
          &larr; Return to Dashboard
        </button>
      </div>
    </article>
  );
}
