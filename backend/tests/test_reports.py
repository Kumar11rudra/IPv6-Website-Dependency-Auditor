"""Phase 7: JSON/CSV reports. Builds scan/resource/probe rows directly (no browser, no
network) and asserts on the generated report, per the established pattern in this codebase."""
import csv
import io
import json

import pytest

from app.models.db import SessionLocal, init_db
from app.models.tables import Batch, BatchSite, HostProbe, MeasurementContext, Resource, Scan
from app.reports.csv_report import build_batch_csv_report, build_scan_csv_report
from app.reports.json_report import build_batch_json_report, build_scan_json_report
from app.reports.redact import redact_text, redact_url


@pytest.fixture(autouse=True)
def _db():
    init_db()


def make_scan(scan_id: str, **kw) -> Scan:
    defaults = dict(scan_id=scan_id, target_url=f"https://{scan_id}.test/", scanner_version="t",
                    status="COMPLETED")
    defaults.update(kw)
    with SessionLocal() as db:
        s = Scan(**defaults)
        db.add(s)
        db.commit()
    return s


def add_resource(scan_id: str, resource_id: str, **kw) -> None:
    defaults = dict(scan_id=scan_id, resource_id=resource_id, parent_resource_id=None,
                    parent_inferred=False, url=f"https://{scan_id}.test/{resource_id}",
                    hostname=f"{scan_id}.test", port=443, scheme="https", resource_type="script",
                    initiator="root", load_status="LOADED", http_status=200, timestamp="2026-01-01T00:00:00Z")
    defaults.update(kw)
    with SessionLocal() as db:
        db.add(Resource(**defaults))
        db.commit()


def add_probe(scan_id: str, hostname: str, port: int, family: int, **kw) -> None:
    defaults = dict(scan_id=scan_id, hostname=hostname, port=port, family=family,
                    dns_status="OK", tcp_status="PASS", tls_status="PASS", http_stage_status="PASS",
                    http_code=200, verdict=f"IPv{family}_REACHABLE")
    defaults.update(kw)
    with SessionLocal() as db:
        db.add(HostProbe(**defaults))
        db.commit()


def json_report(scan_id: str) -> dict:
    with SessionLocal() as db:
        return build_scan_json_report(db, db.get(Scan, scan_id))


def csv_report(scan_id: str) -> str:
    with SessionLocal() as db:
        return build_scan_csv_report(db, db.get(Scan, scan_id))


def parse_csv(text: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(text)))


# --------------------------------------------------------------------------- correctness
def test_json_report_basic_shape_and_verdict_terminology_preserved():
    make_scan("rep0000001")
    add_resource("rep0000001", "r1")
    add_probe("rep0000001", "rep0000001.test", 443, 4, verdict="IPv4_REACHABLE")
    add_probe("rep0000001", "rep0000001.test", 443, 6, verdict="TCP_FAILURE", tcp_status="FAIL",
             tls_status="NOT_REACHED", http_stage_status="NOT_REACHED", failure_stage="TCP",
             failure_subtype="REFUSED", http_code=None)
    report = json_report("rep0000001")
    assert report["report_type"] == "scan" and report["scan_id"] == "rep0000001"
    assert report["status"] == "COMPLETED"
    res = report["resources"][0]
    assert res["ipv4"]["verdict"] == "IPv4_REACHABLE"          # EXACT existing terminology
    assert res["ipv6"]["verdict"] == "TCP_FAILURE"
    assert res["ipv6"]["failure_stage"] == "TCP" and res["ipv6"]["failure_subtype"] == "REFUSED"
    assert res["ipv6"]["tls_status"] == "NOT_REACHED"          # preserved verbatim, not reworded


def test_csv_report_basic_shape_and_terminology_preserved():
    make_scan("rep0000002")
    add_resource("rep0000002", "r1")
    add_probe("rep0000002", "rep0000002.test", 443, 4, verdict="IPv4_REACHABLE")
    add_probe("rep0000002", "rep0000002.test", 443, 6, verdict="TLS_FAILURE", tls_status="FAIL",
             http_stage_status="NOT_REACHED", failure_stage="TLS", failure_subtype="CERT_VERIFY", http_code=None)
    rows = parse_csv(csv_report("rep0000002"))
    assert len(rows) == 1
    assert rows[0]["ipv4_verdict"] == "IPv4_REACHABLE"
    assert rows[0]["ipv6_verdict"] == "TLS_FAILURE"
    assert rows[0]["ipv6_failure_stage"] == "TLS" and rows[0]["ipv6_failure_subtype"] == "CERT_VERIFY"


def test_ipv4_and_ipv6_are_genuinely_distinguished_not_merged():
    make_scan("rep0000003")
    add_resource("rep0000003", "r1")
    add_probe("rep0000003", "rep0000003.test", 443, 4, verdict="IPv4_REACHABLE", dns_status="OK")
    add_probe("rep0000003", "rep0000003.test", 443, 6, verdict="DNS_FAILURE", dns_status="NO_RECORD",
             tcp_status="NOT_REACHED", tls_status="NOT_REACHED", http_stage_status="NOT_REACHED",
             failure_stage="DNS", failure_subtype="NO_RECORD", http_code=None)
    res = json_report("rep0000003")["resources"][0]
    assert res["ipv4"]["dns_status"] == "OK" and res["ipv6"]["dns_status"] == "NO_RECORD"
    assert res["ipv4"] != res["ipv6"]  # never collapsed into one shared block


# --------------------------------------------------------------------------- empty / partial / failed
def test_empty_scan_produces_well_formed_empty_report():
    make_scan("rep0000004", status="SCAN_FAILED", error="No resources captured")
    report = json_report("rep0000004")
    assert report["resources"] == [] and report["status"] == "SCAN_FAILED"
    rows = parse_csv(csv_report("rep0000004"))
    assert rows == []  # header only, no data rows, no crash


def test_partial_scan_includes_whatever_resources_exist():
    make_scan("rep0000005", status="PARTIAL", error="scan deadline reached")
    add_resource("rep0000005", "r1", load_status="LOADED")
    add_resource("rep0000005", "r2", load_status="INCOMPLETE")
    report = json_report("rep0000005")
    assert report["status"] == "PARTIAL" and report["error"] == "scan deadline reached"
    assert len(report["resources"]) == 2
    assert {r["load_status"] for r in report["resources"]} == {"LOADED", "INCOMPLETE"}


def test_scan_failed_report_carries_the_error():
    make_scan("rep0000006", status="SCAN_FAILED", error="TimeoutError: boom")
    report = json_report("rep0000006")
    assert report["status"] == "SCAN_FAILED" and "boom" in report["error"]


# --------------------------------------------------------------------------- blocked targets
def test_blocked_target_report_has_no_resources_but_valid_shape():
    make_scan("rep0000007", status="BLOCKED", target_url="http://169.254.169.254/",
             error="169.254.169.254 resolves to non-public address 169.254.169.254")
    report = json_report("rep0000007")
    assert report["status"] == "BLOCKED"
    assert "non-public" in report["error"]
    assert report["resources"] == []
    rows = parse_csv(csv_report("rep0000007"))
    assert rows == []


# --------------------------------------------------------------------------- Unknown values
def test_missing_measurement_context_renders_unknown_not_null_or_crash():
    make_scan("rep0000008")  # no MeasurementContext row at all
    ctx = json_report("rep0000008")["measurement_context"]
    assert ctx["ipv4_egress_ok"] == "Unknown" and ctx["geo_country"] == "Unknown"
    assert ctx["resolver_ips"] == "Unknown"


def test_partial_measurement_context_only_unknown_where_actually_missing():
    with SessionLocal() as db:
        db.add(MeasurementContext(scan_id="rep0000009", collected_at="2026-01-01T00:00:00Z",
                                  ipv4_egress_ok=True, ipv6_egress_ok=False, geo_country=None))
        db.commit()
    make_scan("rep0000009")
    ctx = json_report("rep0000009")["measurement_context"]
    assert ctx["ipv4_egress_ok"] is True        # real value preserved
    assert ctx["ipv6_egress_ok"] is False        # real False, not Unknown - a false IS a known value
    assert ctx["geo_country"] == "Unknown"       # genuinely missing


# --------------------------------------------------------------------------- duplicate resources/hosts
def test_duplicate_resource_urls_both_appear_not_merged():
    make_scan("rep0000010")
    add_resource("rep0000010", "r1", url="https://rep0000010.test/retry", load_status="FAILED",
                 http_status=None, error_text="net::ERR_CONNECTION_RESET")
    add_resource("rep0000010", "r2", url="https://rep0000010.test/retry", load_status="LOADED", http_status=200)
    report = json_report("rep0000010")
    assert len(report["resources"]) == 2  # NOT deduplicated by URL
    statuses = {r["load_status"] for r in report["resources"]}
    assert statuses == {"FAILED", "LOADED"}  # the real first-failed-then-succeeded history is preserved


def test_duplicate_hosts_each_resource_gets_its_own_hosts_correct_probe_data():
    """Two DIFFERENT hosts, each with its own resources and its own distinct verdict -
    guards against a hostname->probe lookup dict accidentally cross-contaminating."""
    make_scan("rep0000011")
    add_resource("rep0000011", "r1", hostname="good.test", url="https://good.test/a.js")
    add_resource("rep0000011", "r2", hostname="good.test", url="https://good.test/b.js")
    add_resource("rep0000011", "r3", hostname="bad.test", url="https://bad.test/c.js")
    add_probe("rep0000011", "good.test", 443, 6, verdict="IPv6_REACHABLE")
    add_probe("rep0000011", "bad.test", 443, 6, verdict="TCP_FAILURE", tcp_status="FAIL",
             tls_status="NOT_REACHED", http_stage_status="NOT_REACHED", failure_stage="TCP", http_code=None)
    report = json_report("rep0000011")
    by_url = {r["url"]: r for r in report["resources"]}
    assert by_url["https://good.test/a.js"]["ipv6"]["verdict"] == "IPv6_REACHABLE"
    assert by_url["https://good.test/b.js"]["ipv6"]["verdict"] == "IPv6_REACHABLE"  # same host, same data
    assert by_url["https://bad.test/c.js"]["ipv6"]["verdict"] == "TCP_FAILURE"      # different host, NOT mixed up


# --------------------------------------------------------------------------- CSV escaping
def test_csv_escapes_commas_quotes_and_newlines():
    make_scan("rep0000012")
    add_resource("rep0000012", "r1", url='https://rep0000012.test/x?note=a,"b",c',
                 error_text="line one\nline two, with a comma and \"quotes\"")
    text = csv_report("rep0000012")
    rows = parse_csv(text)
    assert len(rows) == 1
    # round-tripped through csv.DictReader, the ORIGINAL values must come back EXACTLY -
    # this is the real proof of correct escaping, not just "the file doesn't crash".
    assert rows[0]["resource_url"] == 'https://rep0000012.test/x?note=a,"b",c'
    assert rows[0]["error_text"] == "line one\nline two, with a comma and \"quotes\""


def test_csv_handles_none_values_without_crashing():
    make_scan("rep0000013")
    add_resource("rep0000013", "r1", http_status=None, error_text=None)
    rows = parse_csv(csv_report("rep0000013"))
    assert rows[0]["http_status"] == "" and rows[0]["error_text"] == ""


# --------------------------------------------------------------------------- sensitive data
def test_json_report_never_contains_raw_url_credentials_or_tokens():
    make_scan("rep0000014", target_url="https://user:TopSecretPW@rep0000014.test/")
    add_resource("rep0000014", "r1", url="https://rep0000014.test/x?api_key=SUPERSECRETVALUE&page=1")
    dump = json.dumps(json_report("rep0000014"))
    assert "TopSecretPW" not in dump
    assert "SUPERSECRETVALUE" not in dump
    assert "page=1" in dump or "page%3D1" in dump or '"page": "1"' in dump  # non-sensitive data preserved


def test_csv_report_never_contains_raw_url_credentials_or_tokens():
    make_scan("rep0000015", target_url="https://user:TopSecretPW@rep0000015.test/")
    add_resource("rep0000015", "r1", url="https://rep0000015.test/x?token=SUPERSECRETVALUE2&ok=1")
    text = csv_report("rep0000015")
    assert "TopSecretPW" not in text
    assert "SUPERSECRETVALUE2" not in text
    assert "ok=1" in text


def test_error_text_authorization_and_cookie_values_are_scrubbed():
    make_scan("rep0000016")
    add_resource("rep0000016", "r1",
                 error_text="upstream replied Authorization: Bearer abc.def.verysecret and Cookie: sid=realsession123")
    dump = json.dumps(json_report("rep0000016"))
    assert "verysecret" not in dump and "realsession123" not in dump


def test_redact_functions_directly_for_edge_cases():
    assert redact_url("") == ""
    assert redact_url(None) is None
    assert redact_text(None) is None
    assert redact_text("") == ""
    assert redact_url("https://plain.test/path?a=1&b=2") == "https://plain.test/path?a=1&b=2"


# --------------------------------------------------------------------------- batch reports
def make_batch_with_sites(batch_id: str, site_scans: list[tuple[str, str, str]]) -> None:
    """site_scans: list of (scan_id, name, url) - each gets a Scan row + BatchSite row."""
    with SessionLocal() as db:
        db.add(Batch(batch_id=batch_id, total=len(site_scans), source="custom", scanner_version="t",
                     status="COMPLETED"))
        db.commit()
    for i, (scan_id, name, url) in enumerate(site_scans):
        make_scan(scan_id, target_url=url)
        with SessionLocal() as db:
            db.add(BatchSite(batch_id=batch_id, site_index=i, name=name, url=url, scan_id=scan_id))
            db.commit()


def test_batch_json_report_includes_per_site_summary():
    make_batch_with_sites("batchrep01", [("brs0000001", "Site A", "https://a.test/"),
                                         ("brs0000002", "Site B", "https://b.test/")])
    add_resource("brs0000001", "r1")
    add_probe("brs0000001", "brs0000001.test", 443, 6, verdict="IPv6_REACHABLE")
    with SessionLocal() as db:
        db.get(Scan, "brs0000001").summary = {"resources": 1, "hosts": 1}
        db.get(Scan, "brs0000002").status = "BLOCKED"
        db.get(Scan, "brs0000002").error = "blocked for test"
        db.commit()

    with SessionLocal() as db:
        report = build_batch_json_report(db, db.get(Batch, "batchrep01"))

    assert report["report_type"] == "batch" and report["total"] == 2
    assert report["summary"]["by_status"] == {"COMPLETED": 1, "BLOCKED": 1}
    by_name = {s["name"]: s for s in report["sites"]}
    assert by_name["Site A"]["status"] == "COMPLETED"
    assert by_name["Site A"]["scan_summary"]  # that site's own scan.summary counts are included
    assert by_name["Site B"]["status"] == "BLOCKED" and by_name["Site B"]["error"] == "blocked for test"


def test_batch_csv_report_one_row_per_site_resource_with_site_columns():
    make_batch_with_sites("batchrep02", [("brs0000003", "Site C", "https://c.test/"),
                                         ("brs0000004", "Site D", "https://d.test/")])
    add_resource("brs0000003", "r1", url="https://c.test/x.js")
    add_resource("brs0000003", "r2", url="https://c.test/y.js")
    add_resource("brs0000004", "r1", url="https://d.test/z.js")

    with SessionLocal() as db:
        text = build_batch_csv_report(db, db.get(Batch, "batchrep02"))
    rows = parse_csv(text)
    assert len(rows) == 3  # 2 resources for Site C + 1 for Site D
    by_site = {}
    for r in rows:
        by_site.setdefault(r["site_name"], []).append(r["resource_url"])
    assert sorted(by_site["Site C"]) == ["https://c.test/x.js", "https://c.test/y.js"]
    assert by_site["Site D"] == ["https://d.test/z.js"]
    assert all(r["batch_id"] == "batchrep02" for r in rows)


def test_batch_csv_report_site_with_no_resources_still_gets_a_row():
    """A BLOCKED/failed site has zero resources, but must still appear in the CSV (one
    row with the site columns filled and resource columns blank) rather than silently
    vanishing from the export - a missing row would look like the site was never tested."""
    make_batch_with_sites("batchrep03", [("brs0000005", "Site E", "https://e.test/")])
    with SessionLocal() as db:
        db.get(Scan, "brs0000005").status = "BLOCKED"
        db.commit()
    with SessionLocal() as db:
        text = build_batch_csv_report(db, db.get(Batch, "batchrep03"))
    rows = parse_csv(text)
    assert len(rows) == 1
    assert rows[0]["site_name"] == "Site E" and rows[0]["site_status"] == "BLOCKED"
    assert rows[0]["resource_url"] == ""  # no resource for this site, but the site itself is represented


def test_batch_report_redacts_site_urls_too():
    make_batch_with_sites("batchrep04", [("brs0000006", "Site F", "https://user:hunter2@f.test/")])
    with SessionLocal() as db:
        dump = json.dumps(build_batch_json_report(db, db.get(Batch, "batchrep04")))
    assert "hunter2" not in dump
