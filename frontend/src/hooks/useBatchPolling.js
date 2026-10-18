import { useEffect, useRef, useState } from "react";
import { api, BATCH_TERMINAL_STATUSES } from "../api/client";

/** Starts a batch scan and polls until it reaches COMPLETED, then loads the per-site
 * list once. Mirrors useScanPolling's shape so BatchView and Dashboard can share the
 * same mental model as the single-scan flow. */
export function useBatchPolling() {
  const [batch, setBatch] = useState(null);
  const [sites, setSites] = useState([]);
  const [error, setError] = useState(null);
  const timer = useRef(null);

  const stop = () => { if (timer.current) clearInterval(timer.current); timer.current = null; };

  async function loadSites(batchId) {
    try {
      setSites(await api.getBatchSites(batchId));
    } catch (e) { setError(e.message); }
  }

  async function start(sitesOverride, includeControlled) {
    stop();
    setError(null); setSites([]);
    try {
      const created = await api.startBatch(sitesOverride, includeControlled);
      setBatch(created);
      await loadSites(created.batch_id);  // the full planned site list exists immediately (Phase 6)
      timer.current = setInterval(async () => {
        try {
          const updated = await api.getBatch(created.batch_id);
          setBatch(updated);
          await loadSites(created.batch_id);  // refresh per-site statuses as they land
          if (BATCH_TERMINAL_STATUSES.has(updated.status)) stop();
        } catch (e) { setError(e.message); stop(); }
      }, 1500);
    } catch (e) { setError(e.message); }
  }

  useEffect(() => stop, []);
  return { batch, sites, error, start, running: !!timer.current };
}
