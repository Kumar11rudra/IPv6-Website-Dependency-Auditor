"""TCP stage: does a handshake to the tested address complete?"""
import asyncio
import errno
import socket

LIMIT = 65536
_UNREACHABLE = {getattr(errno, n) for n in
                ("ENETUNREACH", "EHOSTUNREACH", "EAFNOSUPPORT", "EADDRNOTAVAIL", "ENETDOWN", "EHOSTDOWN")
                if hasattr(errno, n)}


def classify_error(e: BaseException) -> tuple[str, str]:
    """(subtype, human detail). TimeoutError is checked first: it is an OSError subclass."""
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return "TIMEOUT", "No response to connection attempt (packets dropped or filtered)"
    if isinstance(e, ConnectionRefusedError):
        return "REFUSED", "Connection refused (RST): nothing listening on this address/port"
    if isinstance(e, ConnectionResetError):
        return "RESET", "Connection reset during handshake"
    if isinstance(e, OSError):
        if e.errno in _UNREACHABLE:
            return "UNREACHABLE", f"{errno.errorcode.get(e.errno, e.errno)}: {e.strerror}"
        return "ERROR", f"{type(e).__name__}: {e}"[:200]
    return "ERROR", f"{type(e).__name__}: {e}"[:200]


async def connect(ip: str, port: int, family: int, timeout: float):
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    return await asyncio.wait_for(asyncio.open_connection(ip, port, family=fam, limit=LIMIT), timeout)


async def connect_any(addresses: list[str], port: int, family: int, timeout: float):
    """Try every advertised address concurrently (like a browser would).
    Returns (winner, per_address) where winner = (ip, reader, writer) for the FIRST address in
    DNS order that connected, or None. Extra successful connections are closed."""
    async def one(ip: str):
        try:
            r, w = await connect(ip, port, family, timeout)
            return ip, (r, w), None
        except Exception as e:  # noqa: BLE001 - every failure is a measurement result
            return ip, None, classify_error(e)

    results = await asyncio.gather(*(one(ip) for ip in addresses))
    winner, per = None, []
    for ip, conn, err in results:
        if conn is None:
            per.append({"address": ip, "ok": False, "subtype": err[0], "detail": err[1]})
            continue
        per.append({"address": ip, "ok": True})
        if winner is None:
            winner = (ip, conn[0], conn[1])
        else:
            conn[1].close()
    return winner, per
