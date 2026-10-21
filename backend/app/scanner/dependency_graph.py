"""Builds the dependency graph payload from resource parent links + host probe verdicts.

Nodes: one per resource, plus a synthetic group node per hostname (so the graph can be
read "by host" as the brief's example ASCII tree does). Edges: resource -> its parent
resource, and resource -> its host group. Node color comes from the HOST's IPv6 verdict,
never from a bare AAAA-record check (PS-027 requirement 9).
"""
from __future__ import annotations
from collections import defaultdict

# Host-level color. A host is "reachable" only if EVERY port tested on it is reachable;
# any failure colors it red; a mix of tested-and-untested is yellow (partial/uncertain).
GREEN, YELLOW, RED, GRAY = "green", "yellow", "red", "gray"


def _host_color(family_verdicts: list[str | None]) -> str:
    verdicts = [v for v in family_verdicts if v]
    if not verdicts:
        return GRAY
    reachable = [v.endswith("_REACHABLE") for v in verdicts]
    testable = [v not in ("NOT_TESTED", "BLOCKED") for v in verdicts]
    if not any(testable):
        return GRAY
    if all(reachable[i] for i, t in enumerate(testable) if t) and all(testable):
        return GREEN
    if any(reachable[i] for i, t in enumerate(testable) if t):
        return YELLOW  # some tested ports reachable, others not: partial/uncertain
    return RED


def build_graph(resources: list[dict], probes: list[dict]) -> dict:
    by_host: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for p in probes:
        by_host[(p["hostname"], p["port"])].append(p)

    host_summary: dict[str, dict] = {}
    for host in {r["hostname"] for r in resources}:
        ipv6_verdicts, ipv4_verdicts, ports = [], [], set()
        for (h, port), plist in by_host.items():
            if h != host:
                continue
            ports.add(port)
            for p in plist:
                (ipv6_verdicts if p["family"] == 6 else ipv4_verdicts).append(p.get("verdict"))
        host_summary[host] = {
            "hostname": host, "ports": sorted(ports),
            "ipv4": ipv4_verdicts[0] if len(set(ipv4_verdicts)) == 1 else ("MIXED" if ipv4_verdicts else None),
            "ipv6": ipv6_verdicts[0] if len(set(ipv6_verdicts)) == 1 else ("MIXED" if ipv6_verdicts else None),
            "color": _host_color(ipv6_verdicts),
        }

    nodes = [{
        "id": f"host:{host}", "kind": "host", "label": host, "color": info["color"],
        "ipv4_verdict": info["ipv4"], "ipv6_verdict": info["ipv6"], "ports": info["ports"],
    } for host, info in sorted(host_summary.items())]

    def clean_label(u: str) -> str:
        p = u.split("?", 1)[0].split("#", 1)[0]
        n = p.rstrip("/").split("/")[-1] if "/" in p else p
        return (n[:22] + "...") if len(n) > 25 else (n or "/")

    edges = []
    for r in resources:
        host_node = f"host:{r['hostname']}"
        nodes.append({
            "id": r["resource_id"], "kind": "resource", "label": clean_label(r["url"]),
            "url": r["url"], "resource_type": r["resource_type"], "hostname": r["hostname"],
            "http_status": r["http_status"], "load_status": r["load_status"],
            "color": host_summary[r["hostname"]]["color"] if r["load_status"] == "LOADED" else GRAY,
        })
        edges.append({"id": f"e:{host_node}->{r['resource_id']}", "source": host_node,
                      "target": r["resource_id"], "kind": "hosts"})
        if r["parent_resource_id"]:
            edges.append({
                "id": f"e:{r['parent_resource_id']}->{r['resource_id']}",
                "source": r["parent_resource_id"], "target": r["resource_id"],
                "kind": "initiator", "inferred": r["parent_inferred"],
            })
    return {"nodes": nodes, "edges": edges, "legend": {
        GREEN: "IPv6 reachable", YELLOW: "IPv6 partially available / uncertain",
        RED: "IPv6 failure", GRAY: "Not tested / unavailable",
    }}
