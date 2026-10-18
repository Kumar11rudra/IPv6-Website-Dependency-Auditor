export default function PrivacyPolicy({ onBack }) {
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
        <span className="text-primary font-semibold" aria-current="page">Privacy Policy</span>
      </nav>

      {/* Responsive Header */}
      <header className="flex items-start sm:items-center justify-between border-b border-border pb-4 flex-wrap gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-primary">Privacy &amp; Data Policy</h1>
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

      {/* Main Content Card */}
      <div className="bg-surface border border-border rounded-xl p-6 sm:p-8 md:p-10 flex flex-col gap-8 shadow-xs">
        <section id="processing" className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">1. Information We Process</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            The IPv6 Website &amp; Dependency Readiness Auditor collects and processes strictly technical internet measurement data, including:
          </p>
          <ul className="list-disc pl-5 mt-2 space-y-1.5 text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            <li>User-submitted target URLs for IPv6 readiness auditing.</li>
            <li>Discovered third-party subresource URLs, asset types, and protocols (e.g. scripts, stylesheets, images, fonts).</li>
            <li>Resolved IPv4 (A) and IPv6 (AAAA) DNS records and recursive lookup metrics.</li>
            <li>Active probe diagnostic timings (TCP SYN latency, TLS negotiation handshake, and HTTP response codes).</li>
          </ul>
        </section>

        <section id="redaction" className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">2. Automated Credential &amp; Token Redaction</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            We adhere to rigorous data privacy principles. The backend automatically scrubs and redacts sensitive credentials, authentication tokens, tracking query parameters, and session identifiers from resource URLs and error messages before they are stored or exported in JSON/CSV reports.
          </p>
        </section>

        <section id="cookies" className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">3. Zero Cookie &amp; Tracking Policy</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            This application uses <strong className="font-bold text-[#111827]">no cookies</strong> (neither first-party nor third-party tracking or profiling cookies). All application state operates statelessly or in transient local memory.
          </p>
        </section>

        <section id="retention" className="flex flex-col gap-2.5 border-b border-border/40 pb-6">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">4. Data Retention &amp; Archival</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            Detailed measurement telemetry, probe traces, and dependency graphs generated by audits are stored in the local SQLite database for up to 90 days. Aggregated statistical scores and benchmark records may be retained indefinitely for network trend evaluation.
          </p>
        </section>

        <section id="third-party" className="flex flex-col gap-2.5 pb-2">
          <div className="flex items-baseline gap-2">
            <h2 className="text-lg sm:text-xl font-bold text-primary">5. Third-Party Network Services</h2>
          </div>
          <p className="text-[15px] sm:text-base leading-[1.7] text-[#1F2937] font-normal">
            During diagnostic resolution, public IP addresses resolved by the auditor may be queried against Regional Internet Registry (RIR) WHOIS services and public recursive resolvers to infer Autonomous System Numbers (ASN) and geographic routing characteristics.
          </p>
        </section>
      </div>

      {/* Bottom Actions and Jump Links */}
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
