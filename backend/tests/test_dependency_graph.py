from app.scanner.dependency_graph import GRAY, GREEN, RED, YELLOW, build_graph


def resource(rid, parent, host, url, load_status="LOADED", inferred=False, rtype="script"):
    return {"resource_id": rid, "parent_resource_id": parent, "parent_inferred": inferred, "url": url,
            "hostname": host, "resource_type": rtype, "http_status": 200, "load_status": load_status}


def probe(host, port, family, verdict):
    return {"hostname": host, "port": port, "family": family, "verdict": verdict}


def test_all_reachable_host_is_green():
    resources = [resource("r1", None, "ok.test", "https://ok.test/")]
    probes = [probe("ok.test", 443, 4, "IPv4_REACHABLE"), probe("ok.test", 443, 6, "IPv6_REACHABLE")]
    g = build_graph(resources, probes)
    host_node = next(n for n in g["nodes"] if n["id"] == "host:ok.test")
    assert host_node["color"] == GREEN and host_node["ipv6_verdict"] == "IPv6_REACHABLE"


def test_ipv6_failure_host_is_red():
    resources = [resource("r1", None, "v4only.test", "https://v4only.test/x.js")]
    probes = [probe("v4only.test", 443, 4, "IPv4_REACHABLE"), probe("v4only.test", 443, 6, "DNS_FAILURE")]
    g = build_graph(resources, probes)
    host_node = next(n for n in g["nodes"] if n["id"] == "host:v4only.test")
    assert host_node["color"] == RED
    resource_node = next(n for n in g["nodes"] if n["id"] == "r1")
    assert resource_node["color"] == RED  # loaded resource inherits its host's color


def test_untested_host_is_gray():
    resources = [resource("r1", None, "internal.test", "https://internal.test/")]
    probes = [probe("internal.test", 443, 4, "BLOCKED"), probe("internal.test", 443, 6, "NOT_TESTED")]
    node = next(n for n in build_graph(resources, probes)["nodes"] if n["id"] == "host:internal.test")
    assert node["color"] == GRAY


def test_no_probes_at_all_is_gray():
    resources = [resource("r1", None, "unprobed.test", "https://unprobed.test/")]
    node = next(n for n in build_graph(resources, [])["nodes"] if n["kind"] == "host")
    assert node["color"] == GRAY


def test_mixed_ports_partial_is_yellow():
    resources = [resource("r1", None, "mixed.test", "https://mixed.test/a"),
                resource("r2", None, "mixed.test", "https://mixed.test:8443/b")]
    probes = [probe("mixed.test", 443, 6, "IPv6_REACHABLE"), probe("mixed.test", 8443, 6, "TCP_FAILURE")]
    host_node = next(n for n in build_graph(resources, probes)["nodes"] if n["kind"] == "host")
    assert host_node["color"] == YELLOW and host_node["ports"] == [443, 8443]


def test_failed_resource_is_gray_even_on_green_host():
    resources = [resource("r1", None, "ok.test", "https://ok.test/", load_status="FAILED")]
    probes = [probe("ok.test", 443, 6, "IPv6_REACHABLE")]
    node = next(n for n in build_graph(resources, probes)["nodes"] if n["id"] == "r1")
    assert node["color"] == GRAY  # the resource itself never loaded; don't imply it worked


def test_edges_link_host_and_parent_with_inferred_flag():
    resources = [
        resource("r1", None, "site.test", "https://site.test/"),
        resource("r2", "r1", "site.test", "https://site.test/app.js"),
        resource("r3", "r1", "cdn.test", "https://cdn.test/font.woff2", inferred=True),
    ]
    g = build_graph(resources, [])
    by_pair = {(e["source"], e["target"]): e for e in g["edges"]}
    assert by_pair[("host:site.test", "r1")]["kind"] == "hosts"
    assert by_pair[("r1", "r2")]["kind"] == "initiator" and not by_pair[("r1", "r2")]["inferred"]
    assert by_pair[("r1", "r3")]["inferred"] is True
    assert by_pair[("host:cdn.test", "r3")]["kind"] == "hosts"


def test_legend_present_and_node_counts():
    resources = [resource("r1", None, "a.test", "https://a.test/"),
                resource("r2", "r1", "b.test", "https://b.test/x")]
    g = build_graph(resources, [])
    assert set(g["legend"]) == {GREEN, YELLOW, RED, GRAY}
    assert sum(n["kind"] == "host" for n in g["nodes"]) == 2
    assert sum(n["kind"] == "resource" for n in g["nodes"]) == 2
