import pytest


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


@pytest.mark.parametrize("url", ["http://localhost", "http://127.0.0.1", "http://169.254.169.254", "ftp://x.com"])
def test_scan_rejects_internal_targets(client, url):
    r = client.post("/api/scan", json={"url": url})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "TARGET_REJECTED"


def test_unknown_scan_404(client):
    assert client.get("/api/scan/nope").status_code == 404


def test_scanner_context_renders_unknown(client, monkeypatch):
    from app.scanner.context import ScanContext

    async def fake(force=False):
        return ScanContext(collected_at="2026-01-01T00:00:00Z", ipv4_egress_ok=True)
    monkeypatch.setattr("app.api.context.get_context", fake)
    body = client.get("/api/context").json()
    assert body["ipv4_egress_ok"] is True and body["ipv6_egress_ok"] == "Unknown"
    assert body["geo_city"] == "Unknown" and body["resolver_ips"] == "Unknown"


def test_graph_endpoint_shape(client, monkeypatch):
    import uuid
    from app.models.db import SessionLocal
    from app.models.tables import HostProbe, Resource, Scan

    scan_id = uuid.uuid4().hex[:12]
    with SessionLocal() as db:
        db.add(Scan(scan_id=scan_id, target_url="https://g.test/", status="COMPLETED", scanner_version="t"))
        db.add(Resource(scan_id=scan_id, resource_id="r1", parent_resource_id=None, parent_inferred=False,
                        url="https://g.test/", hostname="g.test", port=443, scheme="https",
                        resource_type="document", initiator="root", load_status="LOADED"))
        db.add(HostProbe(scan_id=scan_id, hostname="g.test", port=443, family=6, dns_status="OK",
                         verdict="IPv6_REACHABLE"))
        db.commit()
    body = client.get(f"/api/scan/{scan_id}/graph").json()
    assert {"nodes", "edges", "legend"} <= set(body)
    assert any(n["id"] == "host:g.test" and n["color"] == "green" for n in body["nodes"])


def test_graph_endpoint_404_for_unknown_scan(client):
    assert client.get("/api/scan/nope/graph").status_code == 404


# --------------------------------------------------------------------------- Phase 6: batch API
def test_batch_scan_with_custom_sites_rejects_bad_input(client):
    r = client.post("/api/batch-scan", json={"sites": []})
    assert r.status_code == 400  # semantically valid shape, rejected by our own business logic
    # Phase 9: a missing "url" is now caught by Pydantic's own schema validation
    # (SiteInput.url is required) BEFORE build_site_list's manual check ever runs -
    # earlier and stricter than before, hence the standard 422 rather than 400.
    r = client.post("/api/batch-scan", json={"sites": [{"name": "x"}]})  # missing url
    assert r.status_code == 422


def test_batch_scan_enforces_max_sites(client, monkeypatch):
    from app.api import batch as batch_api
    monkeypatch.setattr("app.services.batch_runner.settings",
                        __import__("dataclasses").replace(batch_api.settings, batch_max_sites=2))
    many = [{"name": f"s{i}", "url": f"https://s{i}.test/"} for i in range(5)]
    r = client.post("/api/batch-scan", json={"sites": many, "include_controlled": False})
    assert r.status_code == 400 and "exceeds" in r.json()["detail"]["detail"]


def test_batch_scan_lifecycle_via_api(client, monkeypatch):
    """Drives the batch entirely through the real HTTP API (as the frontend would),
    with only the actual browser/network call faked out, proving the full stack -
    endpoint -> background task -> DB -> progress polling -> per-site listing works."""
    from app.services import batch_runner as br
    from app.models.db import SessionLocal
    from app.models.tables import Scan

    async def fake_run_one_site(scan_id, timeout_s):
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()

    monkeypatch.setattr(br, "_run_one_site", fake_run_one_site)

    sites = [{"name": "a", "url": "https://a.test/"}, {"name": "b", "url": "https://b.test/"}]
    created = client.post("/api/batch-scan", json={"sites": sites, "include_controlled": False}).json()
    assert created["status"] == "QUEUED" and created["total"] == 2

    import time
    for _ in range(20):
        got = client.get(f"/api/batch-scan/{created['batch_id']}").json()
        if got["status"] == "COMPLETED":
            break
        time.sleep(0.05)
    assert got["status"] == "COMPLETED"
    assert got["summary"]["completed"] == 2
    assert got["summary"]["by_status"] == {"COMPLETED": 2}

    site_rows = client.get(f"/api/batch-scan/{created['batch_id']}/sites").json()
    assert len(site_rows) == 2
    assert {s["name"] for s in site_rows} == {"a", "b"}
    assert all(s["status"] == "COMPLETED" for s in site_rows)
    # every site's scan_id is independently usable with the existing single-scan endpoints -
    # this is "data that can later feed the dependency-graph UI" (Phase 4's /graph endpoint).
    for s in site_rows:
        assert client.get(f"/api/scan/{s['scan_id']}").status_code == 200


def test_unknown_batch_404(client):
    assert client.get("/api/batch-scan/nope").status_code == 404
    assert client.get("/api/batch-scan/nope/sites").status_code == 404


def test_batch_scan_default_sites_json_loads(client, monkeypatch):
    """Without a custom site list, the endpoint must load backend/sites.json (PS-027:
    'do not hard-code the websites into the scanner logic'), not fail or hang."""
    from app.services import batch_runner as br
    from app.models.db import SessionLocal
    from app.models.tables import Scan

    async def fast_fake(scan_id, timeout_s):
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()
    monkeypatch.setattr(br, "_run_one_site", fast_fake)

    r = client.post("/api/batch-scan", json={"include_controlled": False})
    assert r.status_code == 202
    body = r.json()
    assert body["source"] == "default" and body["total"] == 30  # matches sites.json's real count


# --------------------------------------------------------------------------- Phase 7: report API
def _seed_scan_with_report_data(scan_id: str):
    from app.models.db import SessionLocal
    from app.models.tables import HostProbe, Resource, Scan
    with SessionLocal() as db:
        db.add(Scan(scan_id=scan_id, target_url=f"https://{scan_id}.test/", status="COMPLETED",
                    scanner_version="t"))
        db.add(Resource(scan_id=scan_id, resource_id="r1", parent_resource_id=None, parent_inferred=False,
                        url=f"https://{scan_id}.test/x.js?token=SECRET123", hostname=f"{scan_id}.test",
                        port=443, scheme="https", resource_type="script", initiator="root",
                        load_status="LOADED", http_status=200))
        db.add(HostProbe(scan_id=scan_id, hostname=f"{scan_id}.test", port=443, family=6,
                         dns_status="OK", tcp_status="PASS", tls_status="PASS", http_stage_status="PASS",
                         http_code=200, verdict="IPv6_REACHABLE"))
        db.commit()


def test_scan_report_json_endpoint(client):
    _seed_scan_with_report_data("apirep0001")
    r = client.get("/api/scan/apirep0001/report/json")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    body = r.json()
    assert body["scan_id"] == "apirep0001"
    assert body["resources"][0]["ipv6"]["verdict"] == "IPv6_REACHABLE"
    assert "SECRET123" not in r.text  # endpoint-level proof, not just unit-level


def test_scan_report_csv_endpoint(client):
    _seed_scan_with_report_data("apirep0002")
    r = client.get("/api/scan/apirep0002/report/csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "SECRET123" not in r.text
    assert "ipv6_verdict" in r.text and "IPv6_REACHABLE" in r.text


def test_report_404_for_unknown_scan(client):
    assert client.get("/api/scan/nope/report/json").status_code == 404
    assert client.get("/api/scan/nope/report/csv").status_code == 404


def test_batch_report_endpoints(client, monkeypatch):
    from app.services import batch_runner as br
    from app.models.db import SessionLocal
    from app.models.tables import Scan

    async def fast_fake(scan_id, timeout_s):
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()
    monkeypatch.setattr(br, "_run_one_site", fast_fake)

    created = client.post("/api/batch-scan", json={
        "sites": [{"name": "x", "url": "https://x.test/"}], "include_controlled": False
    }).json()
    import time
    for _ in range(20):
        if client.get(f"/api/batch-scan/{created['batch_id']}").json()["status"] == "COMPLETED":
            break
        time.sleep(0.05)

    r = client.get(f"/api/batch-scan/{created['batch_id']}/report/json")
    assert r.status_code == 200 and r.json()["report_type"] == "batch"
    r = client.get(f"/api/batch-scan/{created['batch_id']}/report/csv")
    assert r.status_code == 200 and "site_name" in r.text


def test_batch_report_404_for_unknown_batch(client):
    assert client.get("/api/batch-scan/nope/report/json").status_code == 404
    assert client.get("/api/batch-scan/nope/report/csv").status_code == 404
