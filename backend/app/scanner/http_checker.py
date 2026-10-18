"""HTTP stage: send one small request over the already-established connection and read only
the response head. Transport-level only: ANY complete HTTP response passes here; whether a
status code counts as a failure is decided by classifier.http_outcome()."""
from __future__ import annotations
import asyncio
import re
import ssl
import time

from .classifier import FAIL, PASS, StageResult

_HOST_RE = re.compile(r"^[A-Za-z0-9._\-:\[\]]+$")
_PATH_RE = re.compile(r"^/[!-~]*$")
_STATUS_RE = re.compile(rb"^HTTP/1\.[01] (\d{3})(?: |$)")


def build_request(host: str, port: int, scheme: str, path: str, user_agent: str) -> bytes:
    if not _HOST_RE.match(host):
        raise ValueError("unsafe host header")
    if not _PATH_RE.match(path or ""):
        path = "/"   # no control chars / spaces can ever reach the wire
    hosthdr = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port != (443 if scheme == "https" else 80):
        hosthdr += f":{port}"
    return (f"GET {path} HTTP/1.1\r\nHost: {hosthdr}\r\nUser-Agent: {user_agent}\r\n"
            "Accept: */*\r\nRange: bytes=0-0\r\nConnection: close\r\n\r\n").encode("ascii")


def parse_status_line(head: bytes) -> int | None:
    m = _STATUS_RE.match(head.split(b"\r\n", 1)[0])
    if not m:
        return None
    code = int(m.group(1))
    return code if 100 <= code <= 599 else None


async def fetch_headers(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int,
                        scheme: str, path: str, timeout: float, user_agent: str) -> tuple[StageResult, int | None]:
    t0 = time.monotonic()

    def res(status, subtype=None, detail=None):
        return StageResult(status, subtype, detail, int((time.monotonic() - t0) * 1000))

    try:
        req = build_request(host, port, scheme, path, user_agent)

        async def go() -> bytes:
            writer.write(req)
            await writer.drain()
            return await reader.readuntil(b"\r\n\r\n")

        head = await asyncio.wait_for(go(), timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return res(FAIL, "TIMEOUT", "No HTTP response head before timeout"), None
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            return res(FAIL, "NO_RESPONSE", "Connection closed without sending a response"), None
        return res(FAIL, "MALFORMED", "Connection closed mid-response"), None
    except asyncio.LimitOverrunError:
        return res(FAIL, "MALFORMED", "Response head exceeded size limit"), None
    except ValueError as e:
        return res(FAIL, "ERROR", str(e)), None
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
        return res(FAIL, "RESET", "Connection reset while sending request / reading response"), None
    except OSError as e:
        return res(FAIL, "ERROR", f"{type(e).__name__}: {e}"[:200]), None

    code = parse_status_line(head)
    if code is None:
        return res(FAIL, "MALFORMED", "Response did not start with a valid HTTP/1.x status line"), None
    return res(PASS), code
