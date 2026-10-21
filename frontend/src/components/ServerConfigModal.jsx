import { useState } from "react";
import { getApiBase, setApiBase } from "../api/client";

export default function ServerConfigModal({ isOpen, onClose, onServerChanged }) {
  const [currentBase, setCurrentBase] = useState(() => getApiBase() || "http://localhost:8000");
  const [testing, setTesting] = useState(false);
  const [status, setStatus] = useState(null); // { ok: boolean, message: string }

  if (!isOpen) return null;

  async function handleTestAndSave(overrideUrl) {
    const targetUrl = (overrideUrl !== undefined ? overrideUrl : currentBase).trim().replace(/\/+$/, "");
    setTesting(true);
    setStatus(null);

    try {
      const endpoint = `${targetUrl}/api/context`;
      const res = await fetch(endpoint, { method: "GET", headers: { "content-type": "application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      
      setApiBase(targetUrl);
      setCurrentBase(targetUrl);
      setStatus({
        ok: true,
        message: `Connected successfully! (IPv4: ${data.ipv4_egress_ok ? "OK" : "No"}, IPv6: ${data.ipv6_egress_ok ? "Native OK" : "Fallback Active"})`,
      });
      if (onServerChanged) onServerChanged(targetUrl);
      setTimeout(() => {
        onClose();
      }, 1200);
    } catch (err) {
      setStatus({
        ok: false,
        message: `Connection failed: ${err.message}. Check if backend is running and firewall allows port 8000.`,
      });
    } finally {
      setTesting(false);
    }
  }

  function handleReset() {
    setApiBase("");
    setCurrentBase(getApiBase() || "http://localhost:8000");
    setStatus({ ok: true, message: "Reset to default origin." });
    if (onServerChanged) onServerChanged(getApiBase());
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-200">
      <div className="bg-white rounded-2xl shadow-xl border border-slate-200 max-w-md w-full p-6 text-left relative">
        <button
          onClick={onClose}
          type="button"
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-100 transition-colors"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        <div className="flex items-center gap-2.5 mb-3">
          <div className="w-9 h-9 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center font-bold text-lg">
            ⚙️
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900">Backend Server Endpoint</h3>
            <p className="text-xs text-slate-500">Configure where the auditor sends scan and probe requests</p>
          </div>
        </div>

        <div className="mt-4 space-y-3">
          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
              API Base URL
            </label>
            <input
              type="text"
              value={currentBase}
              onChange={(e) => setCurrentBase(e.target.value)}
              placeholder="http://localhost:8000 or http://<VPS_IP>:8000"
              className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-mono text-slate-800 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
            />
          </div>

          <div className="flex items-center gap-2 pt-1 text-xs">
            <span className="text-slate-400">Presets:</span>
            <button
              type="button"
              onClick={() => {
                setCurrentBase("http://localhost:8000");
                handleTestAndSave("http://localhost:8000");
              }}
              className="px-2 py-0.5 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] transition-colors"
            >
              localhost:8000
            </button>
            <button
              type="button"
              onClick={() => {
                setCurrentBase("");
                handleReset();
              }}
              className="px-2 py-0.5 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] transition-colors"
            >
              Relative (Docker/Nginx)
            </button>
          </div>

          {status && (
            <div
              className={`p-3 rounded-xl text-xs font-medium border ${
                status.ok
                  ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                  : "bg-rose-50 text-rose-800 border-rose-200"
              }`}
            >
              {status.message}
            </div>
          )}
        </div>

        <div className="mt-6 flex items-center justify-end gap-2.5">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={testing}
            onClick={() => handleTestAndSave()}
            className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 active:scale-95 transition-all shadow-xs flex items-center gap-1.5 disabled:opacity-50"
          >
            {testing ? (
              <>
                <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>Testing...</span>
              </>
            ) : (
              <span>Save & Connect</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
