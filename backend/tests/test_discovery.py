from app.scanner.browser import Capture
from app.scanner.resource_discovery import normalize

SITE = "https://site.test"


def req(c, rid, url, typ, initiator, frame="F1", **extra):
    c.on_request({"requestId": rid, "request": {"url": url}, "type": typ, "frameId": frame,
                  "initiator": initiator, "wallTime": 1_700_000_000.0, **extra})


def resp(c, rid, status=200, ip="[2001:db8::1]", proto="h2"):
    c.on_response({"requestId": rid, "response": {"status": status, "protocol": proto, "remoteIPAddress": ip}})


def build():
    c = Capture(max_resources=100)
    req(c, "1", f"{SITE}/", "Document", {"type": "other"});                       resp(c, "1")
    req(c, "2", f"{SITE}/style.css", "Stylesheet", {"type": "parser", "url": f"{SITE}/"}); resp(c, "2")
    req(c, "3", f"{SITE}/font.woff2", "Font", {"type": "parser", "url": f"{SITE}/style.css"}); resp(c, "3")
    req(c, "4", f"{SITE}/app.js", "Script", {"type": "parser", "url": f"{SITE}/"}); resp(c, "4")
    req(c, "5", f"{SITE}/api/data", "Fetch",
        {"type": "script", "stack": {"callFrames": [{"url": ""}], "parent": {"callFrames": [{"url": f"{SITE}/app.js"}]}}})
    resp(c, "5", ip="93.184.216.34")
    # redirect chain: http -> https
    req(c, "6", "http://cdn.test/a.png", "Image", {"type": "parser", "url": f"{SITE}/"})
    req(c, "6", "https://cdn.test/a.png", "Image", {"type": "parser", "url": f"{SITE}/"},
        redirectResponse={"status": 301, "protocol": "http/1.1", "remoteIPAddress": "203.0.113.5"})
    resp(c, "6", ip="[2001:db8::5]")
    # failed request
    req(c, "7", "https://v4only.test/x.png", "Image", {"type": "parser", "url": f"{SITE}/"})
    c.on_failed({"requestId": "7", "errorText": "net::ERR_NAME_NOT_RESOLVED"})
    # preflight must be ignored; data: URL must be ignored; iframe classified
    req(c, "8", f"{SITE}/api/data", "Preflight", {"type": "other"})
    req(c, "9", "data:image/png;base64,AAAA", "Image", {"type": "parser", "url": f"{SITE}/"})
    req(c, "10", "https://embed.test/", "Document", {"type": "parser", "url": f"{SITE}/"}, frame="F2"); resp(c, "10")
    return c


def by_url(rows):
    return {r["url"]: r for r in rows}


def test_tree_structure_and_types():
    rows = by_url(normalize(build().requests))
    root = rows[f"{SITE}/"]
    assert root["parent_resource_id"] is None and root["initiator"] == "root"
    assert rows[f"{SITE}/style.css"]["parent_resource_id"] == root["resource_id"]
    # font initiated by the stylesheet, not the document
    assert rows[f"{SITE}/font.woff2"]["parent_resource_id"] == rows[f"{SITE}/style.css"]["resource_id"]
    # fetch() initiated by a script found via the async stack parent
    api = rows[f"{SITE}/api/data"]
    assert api["parent_resource_id"] == rows[f"{SITE}/app.js"]["resource_id"] and not api["parent_inferred"]
    assert api["resource_type"] == "fetch"
    assert rows["https://embed.test/"]["resource_type"] == "iframe"


def test_redirect_chain_and_ip_family():
    rows = by_url(normalize(build().requests))
    hop1, hop2 = rows["http://cdn.test/a.png"], rows["https://cdn.test/a.png"]
    assert hop1["http_status"] == 301 and hop1["remote_family"] == 4
    assert hop2["parent_resource_id"] == hop1["resource_id"] and hop2["initiator"] == "redirect"
    assert hop2["remote_family"] == 6 and hop2["remote_ip"] == "2001:db8::5"


def test_failures_and_filtering():
    rows = normalize(build().requests)
    urls = [r["url"] for r in rows]
    assert not any(u.startswith("data:") for u in urls)
    failed = by_url(rows)["https://v4only.test/x.png"]
    assert failed["load_status"] == "FAILED" and "ERR_NAME_NOT_RESOLVED" in failed["error_text"]
    assert sum(r["url"] == f"{SITE}/api/data" for r in rows) == 1   # preflight dropped


def test_unknown_initiator_is_inferred_from_root():
    c = Capture(10)
    req(c, "1", f"{SITE}/", "Document", {"type": "other"})
    req(c, "2", f"{SITE}/x.js", "Script", {"type": "script", "url": "https://gone.test/unknown.js"})
    rows = normalize(c.requests)
    assert rows[1]["parent_resource_id"] == rows[0]["resource_id"] and rows[1]["parent_inferred"]


def test_resource_limit_truncates():
    c = Capture(2)
    for i in range(5):
        req(c, str(i), f"{SITE}/{i}.js", "Script", {"type": "parser", "url": f"{SITE}/"})
    assert len(c.requests) == 2 and c.truncated


def test_guard_blocked_is_labelled():
    c = Capture(10)
    req(c, "1", f"{SITE}/", "Document", {"type": "other"})
    req(c, "2", "http://10.0.0.1/x.js", "Script", {"type": "parser", "url": f"{SITE}/"})
    c.on_failed({"requestId": "2", "errorText": "net::ERR_BLOCKED_BY_CLIENT"})
    rows = normalize(c.requests, {"http://10.0.0.1/x.js"})
    assert rows[1]["load_status"] == "BLOCKED" and "SSRF" in rows[1]["error_text"]
