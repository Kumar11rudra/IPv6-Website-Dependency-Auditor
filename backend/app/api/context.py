from fastapi import APIRouter

from ..scanner.context import get_context

router = APIRouter(prefix="/api")


@router.get("/context")
async def scanner_context(refresh: bool = False):
    """Current scanner-host context (egress, public IP, geolocation, resolver).
    Check this on the VPS before a measurement run: ipv6_egress_ok must be true."""
    return (await get_context(force=refresh)).display()
