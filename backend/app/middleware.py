"""Phase 9: request body size limit, enforced before any route or Pydantic parsing runs.

Without this, a client could POST a JSON body of unbounded size (e.g. a batch-scan
request with an enormous "sites" array) and the server would spend memory and CPU
reading and parsing the ENTIRE body before any of our own validation - Pydantic's
max_length constraints, build_site_list's own checks - gets a chance to reject it. The
rejection would still be correct, but only after the resource-exhaustion cost was
already paid. This checks the Content-Length header and rejects an oversized request
immediately, with a 413, before Starlette/FastAPI reads the body at all.

Documented, deliberate scope limit: this checks Content-Length, which every normal
HTTP client (browsers' fetch(), httpx, this project's own React frontend) sends for a
JSON POST body - the realistic case here. A client using chunked transfer-encoding
WITHOUT a Content-Length header could bypass this specific check; Pydantic's own
max_length constraints (added in Phase 9 alongside this) are the second, independent
layer of defense for that narrower residual case - the body would still be fully
parsed before rejection in that scenario, so the protection there is "bounded damage",
not "zero damage", which is accepted here as a proportionate tradeoff against the risk
of a hand-rolled streaming body reader introducing its own ASGI-level bugs.
"""
from starlette.types import ASGIApp, Receive, Scope, Send


class MaxBodySizeMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = False  # malformed header; let normal request handling deal with it
                if too_big:
                    await send({"type": "http.response.start", "status": 413,
                               "headers": [(b"content-type", b"application/json")]})
                    await send({"type": "http.response.body",
                               "body": b'{"detail":"Request body exceeds the maximum allowed size"}'})
                    return
                break

        await self.app(scope, receive, send)
