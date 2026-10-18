"""Actual browser resource loading: Playwright + Chrome DevTools Protocol.

Discovery only (Phase 1). Nothing here judges IPv6 readiness. `remote_ip` is the
address Chromium happened to connect to on a dual-stack host (Happy Eyeballs), so
it is evidence of what was used, NOT proof that the other family works or fails.
"""
from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..config import Settings
from .ssrf_guard import HostGuard

log = logging.getLogger(__name__)


@dataclass
class RawRequest:
    key: str                       # unique per hop (a redirect chain shares one CDP requestId)
    request_id: str
    url: str
    cdp_type: str
    frame_id: str | None
    initiator_type: str | None
    initiator_url: str | None
    redirected_from: str | None    # key of the previous hop
    wall_time: float | None
    status: int | None = None
    protocol: str | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    mime: str | None = None
    from_cache: bool = False
    failed: bool = False
    error_text: str | None = None
    blocked_reason: str | None = None
    canceled: bool = False
    finished: bool = False


def _stack_url(stack: dict | None) -> str | None:
    """First script URL found in a CDP async stack trace (walks parent stacks)."""
    while stack:
        for frame in stack.get("callFrames", []):
            if frame.get("url"):
                return frame["url"]
        stack = stack.get("parent")
    return None


def _clean_ip(ip: str | None) -> str | None:
    return ip.strip("[]") if ip else None


class FetchInterceptor:
    """SSRF guard + redirect-depth limit, enforced via CDP's raw Fetch domain rather
    than Playwright's higher-level route()/page.route() API.

    This is NOT a stylistic choice. Playwright's maintainers made a deliberate,
    permanent decision (microsoft/playwright#2617, 2020) to never re-invoke route()
    handlers for a request that results from an HTTP redirect, on ANY browser, because
    Firefox and WebKit cannot support it consistently - confirmed still true as of
    Playwright 1.50 (microsoft/playwright#34994). That means a route()-based guard,
    exactly like the one this project shipped from Phase 1 through Phase 8, NEVER sees
    - and therefore never gets a chance to block - the actual target of any redirect: a
    compromised or malicious site the scanner is told to visit only has to respond with
    an ordinary 302 to a private/internal address, with no DNS-rebinding timing games
    needed at all, and Chromium will connect there directly. This was found and
    confirmed empirically during the Phase 9 audit (see docs/decisions.md), not assumed.

    CDP's Fetch domain, used directly (bypassing Playwright's abstraction), does NOT
    have this limitation for Chromium: Fetch.requestPaused fires for every hop of a
    redirect chain, each with its own requestId and a redirectedRequestId linking back
    to the previous hop - confirmed directly against a real multi-hop redirect chain.
    Since this project only ever drives Chromium (never Firefox/WebKit), there is no
    cross-browser constraint stopping us from relying on this.
    """

    def __init__(self, guard: HostGuard, max_redirects: int,
                guard_blocked_urls: set[str], redirect_limit_urls: set[str]) -> None:
        self.guard = guard
        self.max_redirects = max_redirects
        self.guard_blocked_urls = guard_blocked_urls
        self.redirect_limit_urls = redirect_limit_urls
        self._depth: dict[str, int] = {}

    def _chain_depth(self, request_id: str, redirected_from: str | None) -> int:
        depth = (self._depth.get(redirected_from, 0) + 1) if redirected_from else 0
        self._depth[request_id] = depth
        return depth

    async def handle(self, cdp, params: dict) -> None:
        request_id = params["requestId"]
        url = params["request"]["url"]
        try:
            depth = self._chain_depth(request_id, params.get("redirectedRequestId"))
            # Checked before the SSRF guard: a chain this deep is already a
            # resource-exhaustion concern regardless of where it leads, and checking
            # depth first means an attacker can't use an excessive chain to also burn
            # extra DNS-resolution work in guard.allowed() on every single hop.
            if depth > self.max_redirects:
                self.redirect_limit_urls.add(url)
                await cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
                return
            parts = urlsplit(url)
            if parts.scheme in ("http", "https", "ws", "wss") and parts.hostname:
                if not await self.guard.allowed(parts.hostname):
                    self.guard_blocked_urls.add(url)
                    await cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
                    return
            await cdp.send("Fetch.continueRequest", {"requestId": request_id})
        except Exception:  # noqa: BLE001 - fail CLOSED: an unexpected error here must
            log.exception("Fetch interception error for %s; failing the request closed", url)
            try:  # block it, not let it through unchecked.
                await cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "Failed"})
            except Exception:  # noqa: BLE001 - request may already be gone; nothing more to do
                pass


class Capture:
    """Turns raw CDP Network events into RawRequest records.
    Free of Playwright objects so it can be unit-tested with synthetic events."""

    def __init__(self, max_resources: int) -> None:
        self.max_resources = max_resources
        self.requests: list[RawRequest] = []
        self.truncated = False
        self.guard_blocked_urls: set[str] = set()
        self.redirect_limit_urls: set[str] = set()
        self._current: dict[str, RawRequest] = {}

    @staticmethod
    def _apply_response(req: RawRequest, resp: dict) -> None:
        req.status = resp.get("status")
        req.protocol = resp.get("protocol")
        req.remote_ip = _clean_ip(resp.get("remoteIPAddress"))
        req.remote_port = resp.get("remotePort")
        req.mime = resp.get("mimeType")
        req.from_cache = bool(resp.get("fromDiskCache") or resp.get("fromServiceWorker"))

    def on_request(self, p: dict) -> None:
        rid, request = p["requestId"], p["request"]
        url = request["url"]
        if not url.startswith(("http://", "https://")):
            return  # data:, blob:, chrome-extension: ... are not network dependencies

        redirected_from = None
        prev = self._current.get(rid)
        if prev is not None and "redirectResponse" in p:
            self._apply_response(prev, p["redirectResponse"])
            prev.finished = True
            redirected_from = prev.key

        if len(self.requests) >= self.max_resources:
            self.truncated = True
            self._current.pop(rid, None)
            return

        ini = p.get("initiator") or {}
        req = RawRequest(
            key=f"{rid}#{len(self.requests)}",
            request_id=rid,
            url=url,
            cdp_type=p.get("type", "Other"),
            frame_id=p.get("frameId"),
            initiator_type=ini.get("type"),
            initiator_url=ini.get("url") or _stack_url(ini.get("stack")),
            redirected_from=redirected_from,
            wall_time=p.get("wallTime"),
        )
        self.requests.append(req)
        self._current[rid] = req

    def on_response(self, p: dict) -> None:
        req = self._current.get(p["requestId"])
        if req is not None:
            self._apply_response(req, p["response"])

    def on_failed(self, p: dict) -> None:
        req = self._current.get(p["requestId"])
        if req is not None:
            req.failed = True
            req.finished = True
            req.error_text = p.get("errorText")
            req.blocked_reason = p.get("blockedReason")
            req.canceled = bool(p.get("canceled"))

    def on_finished(self, p: dict) -> None:
        req = self._current.get(p["requestId"])
        if req is not None:
            req.finished = True


@dataclass
class CaptureResult:
    requests: list[RawRequest]
    final_url: str | None = None
    nav_error: str | None = None
    truncated: bool = False
    deadline_hit: bool = False
    guard_blocked_urls: set[str] = field(default_factory=set)
    redirect_limit_urls: set[str] = field(default_factory=set)


async def capture_page(url: str, settings: Settings, guard: HostGuard) -> CaptureResult:
    # Imported lazily so unit tests don't need browsers installed.
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeout
    from playwright.async_api import async_playwright

    cap = Capture(settings.max_resources)
    result = CaptureResult(requests=cap.requests, guard_blocked_urls=cap.guard_blocked_urls,
                           redirect_limit_urls=cap.redirect_limit_urls)

    # Single-process frames so ONE CDP session also sees cross-site iframe traffic.
    args = ["--disable-site-isolation-trials", "--disable-features=IsolateOrigins,site-per-process"]
    if settings.chromium_no_sandbox:
        args.append("--no-sandbox")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=args)
        try:
            ctx = await browser.new_context(
                ignore_https_errors=False,   # invalid certs must surface as failures
                service_workers="block",     # a SW would hide requests from the network layer
                accept_downloads=False,
                permissions=[],
                viewport={"width": 1366, "height": 900},
            )

            page = await ctx.new_page()

            cdp = await ctx.new_cdp_session(page)
            await cdp.send("Network.enable")
            await cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})  # force real fetches
            cdp.on("Network.requestWillBeSent", cap.on_request)
            cdp.on("Network.responseReceived", cap.on_response)
            cdp.on("Network.loadingFailed", cap.on_failed)
            cdp.on("Network.loadingFinished", cap.on_finished)

            # Fetch domain, not Playwright's route(): see FetchInterceptor's docstring
            # for why - route() never sees (and so can never block) a redirect target.
            interceptor = FetchInterceptor(guard, settings.max_redirects_per_chain,
                                           cap.guard_blocked_urls, cap.redirect_limit_urls)
            cdp.on("Fetch.requestPaused", lambda p: asyncio.create_task(interceptor.handle(cdp, p)))
            await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})

            async def drive() -> None:
                try:
                    await page.goto(url, wait_until="load", timeout=settings.page_load_timeout_ms)
                except PlaywrightTimeout:
                    result.nav_error = "TIMEOUT"
                    return
                except PlaywrightError as e:
                    result.nav_error = str(e).splitlines()[0][:300]
                    return
                try:
                    await page.wait_for_load_state("networkidle", timeout=settings.idle_timeout_ms)
                except PlaywrightTimeout:
                    pass
                try:  # trigger lazy-loaded content once
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                except PlaywrightError:
                    pass
                await page.wait_for_timeout(settings.settle_ms)

            try:
                await asyncio.wait_for(drive(), settings.scan_deadline_s)
            except asyncio.TimeoutError:
                result.deadline_hit = True

            result.final_url = page.url if page.url and page.url != "about:blank" else None
        finally:
            await browser.close()

    result.truncated = cap.truncated
    return result
