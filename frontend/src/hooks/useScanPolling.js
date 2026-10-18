import { useEffect, useRef, useState } from "react";
import { api, TERMINAL_STATUSES } from "../api/client";

/** Starts a scan (or attaches to an already-existing one, e.g. a batch site) and polls
 * until it reaches a terminal status, then loads resources/probes/graph once. Keeps all
 * polling logic in one place so the single-scan view and a batch's per-site drill-down
 * behave identically. */
export function useScanPolling() {
  const [scan, setScan] = useState(null);
  const [resources, setResources] = useState([]);
  const [probes, setProbes] = useState([]);
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState(null);
  const timer = useRef(null);

  const stop = () => { if (timer.current) clearInterval(timer.current); timer.current = null; };

  async function loadFinalData(scanId) {
    try {
      const [res, pr, gr] = await Promise.all([
        api.getResources(scanId), api.getProbes(scanId), api.getGraph(scanId),
      ]);
      setResources(res); setProbes(pr); setGraph(gr);
    } catch (e) { setError(e.message); }
  }

  function pollUntilDone(initialScan) {
    setScan(initialScan);
    if (TERMINAL_STATUSES.has(initialScan.status)) {
      loadFinalData(initialScan.scan_id);
      return;
    }
    timer.current = setInterval(async () => {
      try {
        const updated = await api.getScan(initialScan.scan_id);
        setScan(updated);
        if (TERMINAL_STATUSES.has(updated.status)) {
          stop();
          await loadFinalData(updated.scan_id);
        }
      } catch (e) { setError(e.message); stop(); }
    }, 1500);
  }

  async function start(url) {
    stop();
    setError(null); setResources([]); setProbes([]); setGraph(null);
    try {
      pollUntilDone(await api.startScan(url));
    } catch (e) { setError(e.message); }
  }

  /** Attaches to a scan that already exists (e.g. a row from a batch's site list)
   * instead of creating a new one. Used by "View" in BatchView. */
  async function loadExisting(scanId) {
    stop();
    setError(null); setResources([]); setProbes([]); setGraph(null);
    try {
      pollUntilDone(await api.getScan(scanId));
    } catch (e) { setError(e.message); }
  }

  useEffect(() => stop, []);
  return { scan, resources, probes, graph, error, start, loadExisting, running: !!timer.current };
}
