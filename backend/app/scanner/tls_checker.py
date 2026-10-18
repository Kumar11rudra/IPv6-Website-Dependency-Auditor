"""TLS stage: upgrade the ALREADY-CONNECTED TCP socket, so TCP and TLS failures stay separate.
Certificates are verified (system trust store, SNI). A verification failure is a TLS-stage
failure; compare with the IPv4 result to see whether it is IPv6-specific."""
from __future__ import annotations
import asyncio
import ssl
import time

from .classifier import FAIL, PASS, StageResult

_default: ssl.SSLContext | None = None


def default_context() -> ssl.SSLContext:
    global _default
    if _default is None:
        _default = ssl.create_default_context()
        _default.set_alpn_protocols(["http/1.1"])  # our HTTP stage speaks HTTP/1.1
    return _default


async def run_tls(writer: asyncio.StreamWriter, host: str, ctx: ssl.SSLContext,
                  timeout: float) -> tuple[StageResult, str | None]:
    t0 = time.monotonic()

    def ms() -> int:
        return int((time.monotonic() - t0) * 1000)

    try:
        if hasattr(writer, "start_tls"):
            await writer.start_tls(ctx, server_hostname=host, ssl_handshake_timeout=timeout)
        else:
            transport = writer.transport
            protocol = transport.get_protocol()
            loop = asyncio.get_running_loop()
            new_transport = await loop.start_tls(
                transport, protocol, ctx, server_side=False, server_hostname=host, ssl_handshake_timeout=timeout
            )
            writer._transport = new_transport
            if hasattr(writer, "_protocol"):
                writer._protocol = new_transport.get_protocol()
    except ssl.SSLCertVerificationError as e:
        return StageResult(FAIL, "CERT_VERIFY", (e.verify_message or str(e))[:200], ms()), None
    except ssl.SSLError as e:
        return StageResult(FAIL, "HANDSHAKE", f"{e.reason or type(e).__name__}: {e}"[:200], ms()), None
    except (asyncio.TimeoutError, TimeoutError):
        return StageResult(FAIL, "TIMEOUT", "TLS handshake timed out", ms()), None
    except ConnectionAbortedError as e:
        # asyncio's own ssl_handshake_timeout fires as THIS, not TimeoutError/asyncio.TimeoutError.
        if "handshake is taking longer than" in str(e):
            return StageResult(FAIL, "TIMEOUT", "TLS handshake timed out (no ServerHello)", ms()), None
        return StageResult(FAIL, "RESET", f"Connection aborted during TLS handshake: {e}"[:200], ms()), None
    except (ConnectionResetError, BrokenPipeError, EOFError):
        return StageResult(FAIL, "RESET", "Connection closed during TLS handshake", ms()), None
    except OSError as e:
        return StageResult(FAIL, "ERROR", f"{type(e).__name__}: {e}"[:200], ms()), None
    sslobj = writer.get_extra_info("ssl_object")
    return StageResult(PASS, None, None, ms()), (sslobj.version() if sslobj else None)
