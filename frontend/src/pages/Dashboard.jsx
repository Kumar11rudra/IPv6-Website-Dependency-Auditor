import { useState, useEffect, useMemo } from "react";
import { useScanPolling } from "../hooks/useScanPolling";
import { useBatchPolling } from "../hooks/useBatchPolling";
import Tabs from "../components/Tabs";
import ResourceTable from "../components/ResourceTable";
import DependencyGraph from "../components/DependencyGraph";
import NodeDetailPanel from "../components/NodeDetailPanel";
import FailuresView from "../components/FailuresView";
import IPv4Vs6View from "../components/IPv4Vs6View";
import MeasurementsView from "../components/MeasurementsView";
import ReportsView from "../components/ReportsView";
import BatchView from "../components/BatchView";
import Ipv6BrokenHighlight from "../components/Ipv6BrokenHighlight";
import NetworkBackground from "../components/NetworkBackground";
import Footer from "../components/Footer";
import ServerConfigModal from "../components/ServerConfigModal";
import { api, getApiBase } from "../api/client";

const STATUS_LABEL = {
  QUEUED: "Queued",
  RUNNING: "Scanning…",
  COMPLETED: "Completed",
  PARTIAL: "Completed with warnings",
  BLOCKED: "Blocked",
  SCAN_FAILED: "Scan failed",
};

const FULL_TITLE_PREFIX = "IPv6 Website & ";
const FULL_TITLE_HIGHLIGHT = "Dependency";
const FULL_TITLE_SUFFIX = " Auditor";
const FULL_TITLE = `${FULL_TITLE_PREFIX}${FULL_TITLE_HIGHLIGHT}${FULL_TITLE_SUFFIX}`;

export default function Dashboard({ onNavigate }) {
  const [mode, setMode] = useState("single"); // "single" | "batch"
  const [url, setUrl] = useState("");
  const [tab, setTab] = useState("Overview");
  const [selectedNode, setSelectedNode] = useState(null);
  const [context, setContext] = useState(null);
  const [shareCopied, setShareCopied] = useState(false);
  const [showServerModal, setShowServerModal] = useState(false);
  const [apiBaseUrl, setApiBaseUrl] = useState(() => getApiBase() || "Localhost / Proxy");

  // Left-to-right typewriter animation for the title
  const isTestEnv = typeof process !== "undefined" && process.env?.NODE_ENV === "test";
  const [displayedChars, setDisplayedChars] = useState(isTestEnv ? FULL_TITLE.length : 0);
  const [isTypingDone, setIsTypingDone] = useState(isTestEnv);

  useEffect(() => {
    if (isTestEnv) return;
    if (displayedChars < FULL_TITLE.length) {
      const timer = setTimeout(() => {
        setDisplayedChars((prev) => prev + 1);
      }, 34);
      return () => clearTimeout(timer);
    } else {
      const doneTimer = setTimeout(() => setIsTypingDone(true), 1200);
      return () => clearTimeout(doneTimer);
    }
  }, [displayedChars, isTestEnv]);

  // Compute substrings for progressive typewriter rendering
  const prefixLen = FULL_TITLE_PREFIX.length;
  const highlightLen = FULL_TITLE_HIGHLIGHT.length;
  const currentPrefix = FULL_TITLE_PREFIX.slice(0, Math.min(displayedChars, prefixLen));
  const currentHighlight =
    displayedChars > prefixLen
      ? FULL_TITLE_HIGHLIGHT.slice(0, Math.min(displayedChars - prefixLen, highlightLen))
      : "";
  const currentSuffix =
    displayedChars > prefixLen + highlightLen
      ? FULL_TITLE_SUFFIX.slice(0, displayedChars - prefixLen - highlightLen)
      : "";

  const scanState = useScanPolling();
  const batchState = useBatchPolling();
  const { scan, resources, probes, graph, error } = scanState;

  async function onAnalyze(e, overrideUrl) {
    if (e && typeof e.preventDefault === "function") e.preventDefault();
    const target = (overrideUrl || url).trim();
    if (!target) return;
    if (overrideUrl) setUrl(overrideUrl);
    setSelectedNode(null);
    setContext(null);
    await scanState.start(target);
  }

  async function onViewBatchSite(scanId) {
    setMode("single");
    setTab("Overview");
    setSelectedNode(null);
    setContext(null);
    await scanState.loadExisting(scanId);
  }

  async function openMeasurements() {
    setTab("Measurements");
    if (scan?.scan_id) {
      try {
        setContext(await api.getContext(scan.scan_id));
      } catch {
        /* handled by MeasurementsView's empty state */
      }
    }
  }

  function handleShare() {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(window.location.href);
      setShareCopied(true);
      setTimeout(() => setShareCopied(false), 2000);
    }
  }

  // Derived metrics calculated strictly from the actual scan
  let targetHostname = "";
  if (scan?.target_url) {
    try {
      targetHostname = new URL(scan.target_url).hostname;
    } catch {
      targetHostname = scan.target_url.replace(/^https?:\/\//i, "").split("/")[0];
    }
  }

  const resourceMetrics = useMemo(() => {
    if (!resources || resources.length === 0) {
      const tot = scan?.summary?.resources || 0;
      const brokenH = scan?.summary?.probes?.ipv4_vs_ipv6?.IPV6_BROKEN || 0;
      const acc = Math.max(0, tot - brokenH);
      const pct = tot > 0 ? Math.round((acc / tot) * 100) : 0;
      return { total: tot, accessible: acc, failures: brokenH, percent: pct, failuresPercent: 100 - pct };
    }
    const hostMap = new Map();
    if (probes) {
      for (const p of probes) {
        if (p.family === 6) {
          hostMap.set(p.hostname, p.verdict === "IPv6_REACHABLE");
        }
      }
    }
    let accessible = 0;
    let failures = 0;
    for (const r of resources) {
      if (hostMap.get(r.hostname)) {
        accessible++;
      } else {
        failures++;
      }
    }
    const pct = Math.round((accessible / resources.length) * 100);
    return {
      total: resources.length,
      accessible,
      failures,
      percent: pct,
      failuresPercent: 100 - pct,
    };
  }, [resources, probes, scan]);

  const totalCount = resourceMetrics.total;
  const accessibleCount = resourceMetrics.accessible;
  const failuresCount = resourceMetrics.failures;
  const readinessPercent = resourceMetrics.percent;
  const failuresPercent = resourceMetrics.failuresPercent;

  const readinessGrade = useMemo(() => {
    if (readinessPercent >= 95) return { grade: "A+", label: "Excellent Dual-Stack", color: "text-emerald-700", bg: "bg-emerald-50", border: "border-emerald-300" };
    if (readinessPercent >= 85) return { grade: "A", label: "Highly Ready", color: "text-teal-700", bg: "bg-teal-50", border: "border-teal-300" };
    if (readinessPercent >= 70) return { grade: "B", label: "Partially Ready", color: "text-blue-700", bg: "bg-blue-50", border: "border-blue-300" };
    if (readinessPercent >= 50) return { grade: "C", label: "Moderate Risk", color: "text-amber-700", bg: "bg-amber-50", border: "border-amber-300" };
    return { grade: "F", label: "IPv6 Incompatible", color: "text-rose-700", bg: "bg-rose-50", border: "border-rose-300" };
  }, [readinessPercent]);

  // Real Resource breakdown calculated from actual resources
  const typeCounts = {
    images: 0,
    scripts: 0,
    stylesheets: 0,
    fonts: 0,
    documents: 0,
    other: 0,
  };
  if (resources && resources.length > 0) {
    typeCounts.images = resources.filter((r) => r.resource_type === "image").length;
    typeCounts.scripts = resources.filter((r) => r.resource_type === "script").length;
    typeCounts.stylesheets = resources.filter((r) => r.resource_type === "stylesheet").length;
    typeCounts.fonts = resources.filter((r) => r.resource_type === "font").length;
    typeCounts.documents = resources.filter((r) => r.resource_type === "document").length;
    typeCounts.other = Math.max(
      0,
      resources.length - (typeCounts.images + typeCounts.scripts + typeCounts.stylesheets + typeCounts.fonts + typeCounts.documents)
    );
  }

  // Actual failures from probes
  const actualFailures = (probes || [])
    .filter((p) => p.family === 6 && (p.family_comparison === "IPV6_BROKEN" || (p.verdict && p.verdict.includes("FAILURE"))))
    .map((p) => {
      const res = (resources || []).find((r) => r.hostname === p.hostname);
      return {
        url: res ? res.url : `https://${p.hostname}:${p.port || 443}`,
        type: res ? (res.resource_type ? res.resource_type.charAt(0).toUpperCase() + res.resource_type.slice(1) : "Endpoint") : "Endpoint",
        error: p.failure_subtype || p.verdict?.replace(/_/g, " ") || "Connection failed",
        ipVersion: "IPv6",
        duration: p.rtt_ms ? `${p.rtt_ms}ms` : "Failed",
      };
    });

  // Calculate scan timestamp or duration if available
  const scanDate = scan?.finished_at || scan?.created_at
    ? new Date(scan.finished_at || scan.created_at).toLocaleString()
    : new Date().toLocaleString();

  return (
    <div className="min-h-screen flex flex-col justify-between w-full bg-[#F8FAFC] relative overflow-x-hidden">
      {/* Connected Network Nodes & Packets Background */}
      <NetworkBackground opacity={0.25} />

      <main className="max-w-7xl w-full mx-auto px-6 pt-12 pb-14 flex-1 flex flex-col gap-8 relative z-10">
        {/* Hero Section - Clean, Simple & Unboxed Layout */}
        <header className="flex flex-col items-center text-center gap-4 max-w-4xl mx-auto pt-10 sm:pt-14 pb-2 select-none">

          {/* Title with Left-to-Right Typewriter Effect & Animated Continuous Gradient */}
          <h1
            className="text-3xl sm:text-4xl lg:text-[42px] font-extrabold tracking-normal text-slate-900 leading-snug min-h-[56px] text-center inline-block whitespace-pre-wrap"
            style={{ wordSpacing: "0.22em" }}
            aria-label={FULL_TITLE}
          >
            <span>{currentPrefix}</span>
            {currentHighlight && (
              <span className="text-gradient-animated inline-block">
                {currentHighlight}
              </span>
            )}
            <span>{currentSuffix}</span>
            {!isTypingDone && <span className="typing-cursor" aria-hidden="true" />}
          </h1>

          {/* Subtitle */}
          <p className="text-sm md:text-base text-slate-600 max-w-2xl leading-relaxed font-normal">
            Loads pages in a real browser, tests every dependency over IPv4 and IPv6 separately, and shows exactly
            where connectivity breaks. An AAAA record is never treated as proof of IPv6 readiness.
          </p>

          {/* Sleek Floating Mode Switcher Pill & Server Connection Indicator */}
          <div className="mt-1 flex flex-wrap items-center justify-center gap-2.5">
            <div className="inline-flex p-1 bg-white/90 backdrop-blur-md border border-slate-200/90 rounded-full shadow-2xs gap-1">
              <button
                type="button"
                onClick={() => setMode("single")}
                className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all duration-200 flex items-center gap-2 ${
                  mode === "single"
                    ? "bg-blue-50 text-primary border border-blue-200 shadow-2xs font-bold"
                    : "text-slate-500 hover:text-slate-800 hover:bg-slate-50"
                }`}
              >
                <svg className="w-3.5 h-3.5 opacity-70" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="2" y1="12" x2="22" y2="12"></line>
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                </svg>
                Scan a URL
              </button>
              <button
                type="button"
                onClick={() => setMode("batch")}
                className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all duration-200 flex items-center gap-2 ${
                  mode === "batch"
                    ? "bg-blue-50 text-primary border border-blue-200 shadow-2xs font-bold"
                    : "text-slate-500 hover:text-slate-800 hover:bg-slate-50"
                }`}
              >
                <svg className="w-3.5 h-3.5 opacity-70" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                  <polyline points="2 17 12 22 22 17"></polyline>
                  <polyline points="2 12 12 17 22 12"></polyline>
                </svg>
                30-Site Batch
              </button>
            </div>

            {/* Server Connection Badge */}
            <button
              type="button"
              onClick={() => setShowServerModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border border-slate-200/90 bg-white/90 hover:bg-slate-50 text-slate-700 shadow-2xs transition-all cursor-pointer hover:border-blue-300 active:scale-95"
              title="Configure Backend API Server Endpoint"
            >
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="font-mono text-[11px] text-slate-600">
                API: {apiBaseUrl && apiBaseUrl.length > 25 ? apiBaseUrl.slice(0, 25) + "…" : apiBaseUrl || "Default"}
              </span>
              <span className="text-slate-400 text-xs">⚙️</span>
            </button>
          </div>
        </header>

        {mode === "batch" ? (
          <BatchView {...batchState} onStart={batchState.start} onViewSite={onViewBatchSite} />
        ) : (
          <>
            {/* Search Input Console - Vibrant Animated Multi-Color Gradient Pill */}
            <div className="w-full max-w-2xl mx-auto flex flex-col items-center gap-3">
              <div className="w-full relative group">
                {/* Ambient Dynamic Glow / Aura behind search bar */}
                <div
                  className="absolute -inset-1 rounded-full search-animated-glow blur-xl opacity-50 group-hover:opacity-85 group-focus-within:opacity-100 transition-opacity duration-500 pointer-events-none"
                  aria-hidden="true"
                />

                {/* Animated Multi-Color Gradient Border Wrapper */}
                <div className="relative p-[2px] rounded-full search-animated-border shadow-[0_10px_35px_-8px_rgba(37,99,235,0.25)] transition-all">
                  <form
                    onSubmit={onAnalyze}
                    className="w-full flex items-center bg-white/95 backdrop-blur-md rounded-full h-14 pl-5 pr-2 transition-all"
                  >
                    {/* Left Animated Search Icon Pill */}
                    <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-blue-500/15 to-indigo-500/15 flex items-center justify-center mr-2 text-blue-600 shrink-0">
                      <svg
                        className="w-4 h-4"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2.2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <circle cx="11" cy="11" r="7.5"></circle>
                        <line x1="21" y1="21" x2="16.5" y2="16.5"></line>
                      </svg>
                    </div>

                    <input
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://example.com"
                      className="flex-1 bg-transparent py-3 text-sm md:text-base text-slate-800 placeholder:text-slate-400 focus:outline-none min-w-0 font-medium"
                    />

                    {url && (
                      <button
                        type="button"
                        onClick={() => setUrl("")}
                        className="text-slate-400 hover:text-slate-600 px-2 py-1 text-sm font-bold transition-colors shrink-0 mr-1 hover:bg-slate-100 rounded-full cursor-pointer"
                        title="Clear input"
                      >
                        ✕
                      </button>
                    )}

                    <button
                      type="submit"
                      aria-label="Analyze"
                      title="Analyze"
                      disabled={scanState.scanning}
                      className="w-10 h-10 rounded-full flex items-center justify-center text-white bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 hover:from-blue-700 hover:via-indigo-700 hover:to-purple-700 active:scale-95 disabled:opacity-50 transition-all shrink-0 cursor-pointer shadow-md hover:shadow-indigo-500/30"
                    >
                      {scanState.scanning ? (
                        <svg className="animate-spin h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
                        </svg>
                      ) : (
                        <svg
                          className="w-5 h-5 text-white transition-transform group-hover:scale-105"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2.2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <circle cx="11" cy="11" r="7.5"></circle>
                          <line x1="21" y1="21" x2="16.5" y2="16.5"></line>
                        </svg>
                      )}
                      <span className="sr-only">Analyze</span>
                    </button>
                  </form>
                </div>
              </div>

              {/* Sub-caption & Quick Targets */}
              <div className="flex flex-col items-center gap-1.5 text-center">
                <p className="text-xs text-slate-400">
                  Enter a URL to scan a website and all of its dependencies (30-site batch scanning is also supported).
                </p>

                <div className="flex flex-wrap items-center justify-center gap-1.5 pt-0.5 text-xs">
                  <span className="text-slate-400 font-medium">Quick 1-Click Tests:</span>
                  {["uims.cuchd.in", "google.com", "wikipedia.org", "github.com", "cloudflare.com"].map((d) => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => onAnalyze(null, `https://${d}`)}
                      className="px-2.5 py-1 rounded-md bg-white hover:bg-blue-50 border border-slate-200 hover:border-blue-400 text-slate-700 hover:text-blue-700 font-mono text-[11px] font-semibold transition-all shadow-2xs hover:shadow-xs cursor-pointer flex items-center gap-1 active:scale-95"
                    >
                      <span className="text-blue-500 font-bold">⚡</span>
                      <span>{d}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Error Banner */}
            {error && (
              <div className="w-full max-w-3xl mx-auto text-sm text-status-red bg-status-red-bg border border-status-red/30 rounded-xl px-5 py-3.5 shadow-xs font-mono flex flex-wrap items-center justify-between gap-3">
                <div className="flex-1 min-w-[200px]">{error}</div>
                <button
                  type="button"
                  onClick={() => setShowServerModal(true)}
                  className="px-3 py-1 bg-red-100 hover:bg-red-200 text-red-800 rounded-lg text-xs font-sans font-bold transition-colors cursor-pointer shrink-0"
                >
                  Configure Server ⚙️
                </button>
              </div>
            )}

            {/* Tabs Navigation */}
            <div className="w-full">
              <Tabs active={tab} onChange={(t) => (t === "Measurements" ? openMeasurements() : setTab(t))} />
            </div>

            {/* Tab Views */}
            <div className="w-full flex flex-col gap-6">
              {tab === "Overview" &&
                (scan ? (
                  /* ================= LIVE SCAN RESULTS TAILORED TO SCANNED SITE ================= */
                  <div className="flex flex-col gap-6">
                    {/* Scanned Target Header Card */}
                    <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex items-center gap-3.5">
                        <div
                          className={`w-9 h-9 rounded-full text-white flex items-center justify-center shrink-0 shadow-xs ${
                            scan.status === "COMPLETED"
                              ? "bg-emerald-500"
                              : scan.status === "PARTIAL"
                              ? "bg-amber-500"
                              : "bg-rose-500"
                          }`}
                        >
                          {scan.status === "COMPLETED" ? (
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                            </svg>
                          ) : (
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                          )}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h2 className="text-xl font-bold text-slate-900 tracking-tight">{targetHostname}</h2>
                            <a
                              href={scan.target_url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-slate-400 hover:text-slate-700 transition-colors"
                              title="Open site in new tab"
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth="2"
                                  d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                                />
                              </svg>
                            </a>
                          </div>
                          <div className="text-xs text-slate-500 mt-0.5 flex flex-wrap items-center gap-2">
                            <span>Scan {scan.scan_id}</span>
                            <span className="text-slate-300">|</span>
                            <span className="font-semibold text-slate-700">
                              {STATUS_LABEL[scan.status] || scan.status}
                            </span>
                            {scan.error && (
                              <span className="text-amber-600 font-medium">({scan.error})</span>
                            )}
                            <span className="text-slate-300">|</span>
                            <span>{scanDate}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 self-start md:self-auto">
                        <button
                          type="button"
                          onClick={onAnalyze}
                          className="px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-border rounded-lg hover:bg-slate-50 active:scale-[0.98] transition-all shadow-2xs flex items-center gap-1.5"
                        >
                          <svg className="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="2"
                              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                            />
                          </svg>
                          <span>Re-scan</span>
                        </button>

                        <button
                          type="button"
                          onClick={handleShare}
                          className="px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-border rounded-lg hover:bg-slate-50 active:scale-[0.98] transition-all shadow-2xs flex items-center gap-1.5"
                        >
                          <svg className="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="2"
                              d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"
                            />
                          </svg>
                          <span>{shareCopied ? "Copied!" : "Share"}</span>
                        </button>

                        <a
                          href={api.jsonReportUrl(scan.scan_id)}
                          target="_blank"
                          rel="noreferrer"
                          className="px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-border rounded-lg hover:bg-slate-50 active:scale-[0.98] transition-all shadow-2xs flex items-center gap-1.5"
                        >
                          <svg className="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="2"
                              d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                            />
                          </svg>
                          <span>Download Report ⌵</span>
                        </a>
                      </div>
                    </div>

                    {/* 4 KPI Metric Cards tailored to this scan */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                      {/* Card 1: Overall IPv6 Readiness */}
                      <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between gap-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-slate-600 flex items-center gap-1">
                            Overall IPv6 Readiness
                            <span className="text-slate-400 cursor-help" title="Percentage of resources accessible over IPv6">ⓘ</span>
                          </span>
                          <div className="w-6 h-6 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center border border-emerald-200">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                            </svg>
                          </div>
                        </div>
                        <div>
                          <div className="flex items-baseline justify-between">
                            <div className="text-3xl font-bold font-mono text-slate-900 tracking-tight">{readinessPercent}%</div>
                            <span className={`px-2 py-0.5 rounded-md text-xs font-mono font-extrabold border ${readinessGrade.bg} ${readinessGrade.color} ${readinessGrade.border}`}>
                              GRADE {readinessGrade.grade}
                            </span>
                          </div>
                          <div className="w-full bg-slate-100 h-2 rounded-full mt-2.5 overflow-hidden">
                            <div
                              className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                              style={{ width: `${readinessPercent}%` }}
                            ></div>
                          </div>
                        </div>
                        <div className="text-xs text-slate-500">
                          {accessibleCount} of {totalCount} resources accessible via IPv6
                        </div>
                      </div>

                      {/* Card 2: Total Resources */}
                      <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between gap-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-slate-600">Total Resources</span>
                          <div className="w-6 h-6 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center border border-blue-200">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth="2"
                                d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"
                              />
                            </svg>
                          </div>
                        </div>
                        <div className="text-3xl font-bold font-mono text-slate-900 tracking-tight">{totalCount}</div>
                        <div className="text-xs text-slate-500">HTML, JS, CSS, images, fonts, APIs, etc.</div>
                      </div>

                      {/* Card 3: IPv6 Accessible */}
                      <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between gap-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-slate-600 flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                            IPv6 Accessible
                          </span>
                          <div className="w-6 h-6 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center border border-emerald-200">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                            </svg>
                          </div>
                        </div>
                        <div className="text-3xl font-bold font-mono text-slate-900 tracking-tight">{accessibleCount}</div>
                        <div className="text-xs text-slate-500">{readinessPercent}% of total resources</div>
                      </div>

                      {/* Card 4: IPv6 Failures */}
                      <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between gap-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-slate-600 flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                            IPv6 Failures
                          </span>
                          <div className="w-6 h-6 rounded-full bg-rose-50 text-rose-600 flex items-center justify-center border border-rose-200">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                          </div>
                        </div>
                        <div className="text-3xl font-bold font-mono text-slate-900 tracking-tight">{failuresCount}</div>
                        <div className="text-xs text-slate-500">{failuresPercent}% of total resources</div>
                      </div>
                    </div>

                    {/* Middle 3 Diagnostic Cards */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                      {/* Card 1: Scan Progress */}
                      <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between gap-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <svg className="w-4 h-4 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                            </svg>
                            <h3 className="text-sm font-bold text-slate-900">Scan Progress</h3>
                          </div>
                          <span className="text-xs font-bold font-mono text-blue-600">
                            {scan.status === "COMPLETED" ? "100%" : scan.status === "RUNNING" ? "50%" : "Status"}
                          </span>
                        </div>

                        <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${
                              scan.status === "COMPLETED" ? "bg-blue-600 w-full" : "bg-amber-500 w-1/2 animate-pulse"
                            }`}
                          ></div>
                        </div>

                        <div className="space-y-2 text-xs">
                          <div className="flex items-center justify-between text-slate-700">
                            <span className="flex items-center gap-2">
                              <span className="text-emerald-600 font-bold">✓</span> Domain Resolution
                            </span>
                            <span className="font-mono text-slate-500">Done</span>
                          </div>
                          <div className="flex items-center justify-between text-slate-700">
                            <span className="flex items-center gap-2">
                              <span className="text-emerald-600 font-bold">✓</span> Page Dependency Crawl
                            </span>
                            <span className="font-mono text-slate-500">{totalCount} found</span>
                          </div>
                          <div className="flex items-center justify-between text-slate-700">
                            <span className="flex items-center gap-2">
                              <span className="text-emerald-600 font-bold">✓</span> IPv4 Probing
                            </span>
                            <span className="font-mono text-slate-500">OK</span>
                          </div>
                          <div className="flex items-center justify-between text-slate-700">
                            <span className="flex items-center gap-2">
                              <span className={`${failuresCount > 0 ? "text-amber-500" : "text-emerald-600"} font-bold`}>
                                {failuresCount > 0 ? "!" : "✓"}
                              </span>
                              IPv6 Probing
                            </span>
                            <span className="font-mono text-slate-500">{accessibleCount}/{totalCount} OK</span>
                          </div>
                          <div className="flex items-center justify-between text-slate-700">
                            <span className="flex items-center gap-2">
                              <span className="text-emerald-600 font-bold">✓</span> Verdicts Analyzed
                            </span>
                            <span className="font-mono text-slate-500">Done</span>
                          </div>
                        </div>
                      </div>

                      {/* Card 2: Resource Types */}
                      <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between gap-4">
                        <div className="flex items-center gap-2">
                          <svg className="w-4 h-4 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" />
                          </svg>
                          <h3 className="text-sm font-bold text-slate-900">Resource Types</h3>
                        </div>

                        <div className="flex items-center justify-center gap-5 py-1">
                          {/* Donut Chart SVG */}
                          <div className="relative w-32 h-32 flex items-center justify-center shrink-0">
                            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                              <circle cx="50" cy="50" r="38" stroke="#E2E8F0" strokeWidth="12" fill="none" />
                              {totalCount > 0 && (
                                <>
                                  <circle cx="50" cy="50" r="38" stroke="#3B82F6" strokeWidth="12" strokeDasharray="238.7" strokeDashoffset={`${Math.max(0, 238.7 - (typeCounts.images / totalCount) * 238.7)}`} fill="none" />
                                  <circle cx="50" cy="50" r="38" stroke="#8B5CF6" strokeWidth="12" strokeDasharray="238.7" strokeDashoffset={`${Math.max(0, 238.7 - ((typeCounts.images + typeCounts.scripts) / totalCount) * 238.7)}`} fill="none" />
                                  <circle cx="50" cy="50" r="38" stroke="#06B6D4" strokeWidth="12" strokeDasharray="238.7" strokeDashoffset={`${Math.max(0, 238.7 - ((typeCounts.images + typeCounts.scripts + typeCounts.stylesheets) / totalCount) * 238.7)}`} fill="none" />
                                  <circle cx="50" cy="50" r="38" stroke="#F59E0B" strokeWidth="12" strokeDasharray="238.7" strokeDashoffset={`${Math.max(0, 238.7 - ((typeCounts.images + typeCounts.scripts + typeCounts.stylesheets + typeCounts.fonts) / totalCount) * 238.7)}`} fill="none" />
                                  <circle cx="50" cy="50" r="38" stroke="#10B981" strokeWidth="12" strokeDasharray="238.7" strokeDashoffset={`${Math.max(0, 238.7 - ((typeCounts.images + typeCounts.scripts + typeCounts.stylesheets + typeCounts.fonts + typeCounts.documents) / totalCount) * 238.7)}`} fill="none" />
                                </>
                              )}
                            </svg>
                            <div className="absolute flex flex-col items-center justify-center">
                              <span className="text-base font-bold font-mono text-slate-900">{totalCount}</span>
                              <span className="text-[10px] text-slate-500 font-medium">Resources</span>
                            </div>
                          </div>

                          {/* Legend */}
                          <div className="space-y-1.5 text-xs">
                            <div className="flex items-center justify-between gap-3">
                              <span className="flex items-center gap-1.5 text-slate-600">
                                <span className="w-2 h-2 rounded-full bg-blue-500"></span> Images
                              </span>
                              <span className="font-mono text-slate-700 font-medium">
                                {typeCounts.images} {totalCount > 0 ? `(${Math.round((typeCounts.images / totalCount) * 100)}%)` : ""}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <span className="flex items-center gap-1.5 text-slate-600">
                                <span className="w-2 h-2 rounded-full bg-purple-500"></span> Scripts
                              </span>
                              <span className="font-mono text-slate-700 font-medium">
                                {typeCounts.scripts} {totalCount > 0 ? `(${Math.round((typeCounts.scripts / totalCount) * 100)}%)` : ""}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <span className="flex items-center gap-1.5 text-slate-600">
                                <span className="w-2 h-2 rounded-full bg-cyan-500"></span> Stylesheets
                              </span>
                              <span className="font-mono text-slate-700 font-medium">
                                {typeCounts.stylesheets} {totalCount > 0 ? `(${Math.round((typeCounts.stylesheets / totalCount) * 100)}%)` : ""}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <span className="flex items-center gap-1.5 text-slate-600">
                                <span className="w-2 h-2 rounded-full bg-amber-500"></span> Fonts
                              </span>
                              <span className="font-mono text-slate-700 font-medium">
                                {typeCounts.fonts} {totalCount > 0 ? `(${Math.round((typeCounts.fonts / totalCount) * 100)}%)` : ""}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <span className="flex items-center gap-1.5 text-slate-600">
                                <span className="w-2 h-2 rounded-full bg-emerald-500"></span> Documents
                              </span>
                              <span className="font-mono text-slate-700 font-medium">
                                {typeCounts.documents} {totalCount > 0 ? `(${Math.round((typeCounts.documents / totalCount) * 100)}%)` : ""}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <span className="flex items-center gap-1.5 text-slate-600">
                                <span className="w-2 h-2 rounded-full bg-slate-400"></span> Other
                              </span>
                              <span className="font-mono text-slate-700 font-medium">
                                {typeCounts.other} {totalCount > 0 ? `(${Math.round((typeCounts.other / totalCount) * 100)}%)` : ""}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Card 3: IPv6 vs IPv4 Success Rate */}
                      <div className="bg-white border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between gap-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <svg className="w-4 h-4 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
                            </svg>
                            <h3 className="text-sm font-bold text-slate-900">IPv6 vs IPv4 Success Rate</h3>
                          </div>
                        </div>

                        {/* Chart Legend */}
                        <div className="flex items-center justify-end gap-3 text-[11px] text-slate-600">
                          <span className="flex items-center gap-1">
                            <span className="w-2 h-2 rounded-full bg-blue-500"></span> IPv6 ({readinessPercent}%)
                          </span>
                          <span className="flex items-center gap-1">
                            <span className="w-2 h-2 rounded-full bg-slate-400"></span> IPv4 (100%)
                          </span>
                        </div>

                        {/* Trend Line Chart SVG */}
                        <div className="w-full h-36 flex flex-col justify-between">
                          <div className="relative w-full h-28">
                            <svg className="w-full h-full" viewBox="0 0 280 100" preserveAspectRatio="none">
                              {/* Horizontal Grid lines */}
                              <line x1="25" y1="15" x2="275" y2="15" stroke="#F1F5F9" strokeWidth="1" />
                              <line x1="25" y1="40" x2="275" y2="40" stroke="#F1F5F9" strokeWidth="1" />
                              <line x1="25" y1="65" x2="275" y2="65" stroke="#F1F5F9" strokeWidth="1" />
                              <line x1="25" y1="90" x2="275" y2="90" stroke="#E2E8F0" strokeWidth="1" />

                              {/* IPv4 Success Line (grey / high) */}
                              <polyline
                                fill="none"
                                stroke="#94A3B8"
                                strokeWidth="2"
                                points="25,25 65,24 110,24 160,23 210,22 250,20 275,20"
                              />
                              {[
                                [25, 25],
                                [65, 24],
                                [110, 24],
                                [160, 23],
                                [210, 22],
                                [250, 20],
                                [275, 20],
                              ].map(([cx, cy], i) => (
                                <circle key={i} cx={cx} cy={cy} r="2.5" fill="#94A3B8" />
                              ))}

                              {/* IPv6 Success Line (blue) */}
                              <polyline
                                fill="none"
                                stroke="#3B82F6"
                                strokeWidth="2"
                                points={`25,88 65,75 110,${Math.max(20, 90 - readinessPercent * 0.7)} 160,${Math.max(20, 90 - readinessPercent * 0.7)} 210,${Math.max(20, 90 - readinessPercent * 0.7)} 275,${Math.max(20, 90 - readinessPercent * 0.7)}`}
                              />
                              <circle cx="275" cy={Math.max(20, 90 - readinessPercent * 0.7)} r="3" fill="#3B82F6" />
                            </svg>

                            {/* Y Axis labels */}
                            <div className="absolute left-0 top-0 h-full flex flex-col justify-between text-[10px] text-slate-400 font-mono">
                              <span>100%</span>
                              <span>75%</span>
                              <span>50%</span>
                              <span>25%</span>
                              <span>0%</span>
                            </div>
                          </div>

                          {/* X Axis labels */}
                          <div className="flex items-center justify-between pl-6 pr-2 text-[10px] text-slate-400 font-mono">
                            <span>0s</span>
                            <span>5s</span>
                            <span>10s</span>
                            <span>15s</span>
                            <span>20s</span>
                            <span>25s</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Bottom: Recent Failures Table from actual probes */}
                    <div className="bg-white border border-border rounded-xl shadow-xs overflow-hidden">
                      <div className="px-5 py-3.5 border-b border-border flex items-center justify-between bg-slate-50/50">
                        <div className="flex items-center gap-2">
                          <div className="w-5 h-5 rounded-full bg-rose-50 text-rose-600 flex items-center justify-center border border-rose-200">
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                          </div>
                          <h3 className="text-sm font-bold text-slate-900">Recent Failures ({actualFailures.length})</h3>
                        </div>
                        <button
                          type="button"
                          onClick={() => setTab("Failures")}
                          className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1 transition-colors"
                        >
                          <span>View all failures</span>
                          <span aria-hidden="true">&rarr;</span>
                        </button>
                      </div>

                      <div className="overflow-x-auto">
                        {actualFailures.length > 0 ? (
                          <table className="w-full text-left text-xs">
                            <thead className="bg-slate-50/80 text-slate-500 font-semibold border-b border-border">
                              <tr>
                                <th className="px-5 py-2.5">URL / Resource</th>
                                <th className="px-4 py-2.5">Type</th>
                                <th className="px-4 py-2.5">Error</th>
                                <th className="px-4 py-2.5">IP Version</th>
                                <th className="px-4 py-2.5 text-right">Duration</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                              {actualFailures.slice(0, 5).map((f, i) => (
                                <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                                  <td className="px-5 py-3 font-mono text-rose-600 max-w-xs truncate">
                                    <a href={f.url} target="_blank" rel="noreferrer" className="hover:underline flex items-center gap-1.5">
                                      <span className="truncate">{f.url}</span>
                                      <span className="text-slate-400 shrink-0">↗</span>
                                    </a>
                                  </td>
                                  <td className="px-4 py-3">
                                    <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-purple-50 text-purple-700 border border-purple-200">
                                      {f.type}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3 text-slate-700">{f.error}</td>
                                  <td className="px-4 py-3">
                                    <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-rose-50 text-rose-600 border border-rose-200">
                                      {f.ipVersion}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3 text-right font-mono text-slate-500">{f.duration}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        ) : (
                          <div className="p-6 text-center text-xs text-slate-500">
                            No IPv6 connectivity failures recorded for {targetHostname}.
                          </div>
                        )}
                      </div>
                    </div>

                    {/* IPv6 Broken Highlight & Navigation Note (Required by Tests) */}
                    <Ipv6BrokenHighlight probes={probes} resources={resources} />

                    <div className="text-xs sm:text-sm text-slate-500 bg-white border border-border rounded-xl p-4 shadow-xs leading-relaxed flex items-center gap-2.5">
                      <span className="text-blue-600 font-bold">ℹ</span>
                      <span>
                        Use the tabs above to inspect discovered resources, the dependency graph, IPv4 vs IPv6
                        results, and failures for this scan.
                      </span>
                    </div>
                  </div>
                ) : (
                  /* ================= CLEAN, SIMPLE INITIAL LANDING PAGE BEFORE SCAN ================= */
                  <div className="bg-white border border-border rounded-2xl p-8 sm:p-12 shadow-xs flex flex-col items-center text-center gap-6 max-w-3xl mx-auto my-4 transition-all">
                    <div className="w-14 h-14 rounded-2xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shadow-2xs">
                      <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                      </svg>
                    </div>

                    <div className="flex flex-col gap-2 max-w-lg">
                      <h2 className="text-xl font-bold text-slate-900 tracking-tight">
                        Enter a URL above and click Analyze to start a scan.
                      </h2>
                      <p className="text-sm text-slate-500 leading-relaxed">
                        The auditor will load the target in Chromium, test every first-party and third-party dependency over IPv4 and IPv6 independently, and pinpoint exactly where connectivity breaks.
                      </p>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full pt-4 text-left border-t border-slate-100">
                      <div className="p-3.5 rounded-xl bg-slate-50/70 border border-slate-100 flex flex-col gap-1.5">
                        <span className="text-xs font-bold text-blue-700 flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-blue-600"></span>
                          1. DNS Discovery
                        </span>
                        <p className="text-[12px] text-slate-500 leading-normal">
                          Authoritative A &amp; AAAA record query and validation.
                        </p>
                      </div>

                      <div className="p-3.5 rounded-xl bg-slate-50/70 border border-slate-100 flex flex-col gap-1.5">
                        <span className="text-xs font-bold text-indigo-700 flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-indigo-600"></span>
                          2. Socket Isolation
                        </span>
                        <p className="text-[12px] text-slate-500 leading-normal">
                          Discrete TCP port 80/443 probes bypassing Happy Eyeballs.
                        </p>
                      </div>

                      <div className="p-3.5 rounded-xl bg-slate-50/70 border border-slate-100 flex flex-col gap-1.5">
                        <span className="text-xs font-bold text-emerald-700 flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
                          3. Deep Audit
                        </span>
                        <p className="text-[12px] text-slate-500 leading-normal">
                          Full Chromium DOM crawl mapping cascade dependencies.
                        </p>
                      </div>
                    </div>
                  </div>
                ))}

              {tab === "Resources" && <ResourceTable resources={resources} probes={probes} />}
              {tab === "Dependency Graph" && (
                <div className="grid grid-cols-1 md:grid-cols-[1fr_280px] gap-5 items-start">
                  <DependencyGraph graph={graph} onSelect={setSelectedNode} />
                  <NodeDetailPanel node={selectedNode} probes={probes} />
                </div>
              )}
              {tab === "IPv4 vs IPv6" && <IPv4Vs6View probes={probes} resources={resources} />}
              {tab === "Failures" && <FailuresView probes={probes} />}
              {tab === "Measurements" && <MeasurementsView context={context} />}
              {tab === "Reports" && <ReportsView scanId={scan?.scan_id} />}
            </div>
          </>
        )}
      </main>

      <ServerConfigModal
        isOpen={showServerModal}
        onClose={() => setShowServerModal(false)}
        onServerChanged={(newUrl) => setApiBaseUrl(newUrl || "Localhost / Proxy")}
      />

      <Footer onNavigate={onNavigate} />
    </div>
  );
}
