import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
    _root_env = Path(__file__).resolve().parent.parent.parent / ".env"
    if _root_env.exists():
        load_dotenv(_root_env)
except Exception:
    pass


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(x.strip().lower() for x in raw.split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    scanner_version: str = "0.6.0"
    database_url: str = os.getenv("AUDITOR_DB_URL", "sqlite:///./data/auditor.db")

    # --- limits (brief section 19) ---
    max_resources: int = _int("AUDITOR_MAX_RESOURCES", 400)
    page_load_timeout_ms: int = _int("AUDITOR_PAGE_TIMEOUT_MS", 20_000)
    idle_timeout_ms: int = _int("AUDITOR_IDLE_TIMEOUT_MS", 2_500)
    settle_ms: int = _int("AUDITOR_SETTLE_MS", 800)
    scan_deadline_s: int = _int("AUDITOR_SCAN_DEADLINE_S", 60)
    max_concurrent_scans: int = _int("AUDITOR_MAX_CONCURRENT_SCANS", 2)
    dns_timeout_s: float = float(os.getenv("AUDITOR_DNS_TIMEOUT_S", 3.0))
    probe_concurrency: int = _int("AUDITOR_PROBE_CONCURRENCY", 15)
    tcp_timeout_s: float = float(os.getenv("AUDITOR_TCP_TIMEOUT_S", 3.0))
    tls_timeout_s: float = float(os.getenv("AUDITOR_TLS_TIMEOUT_S", 3.0))
    http_timeout_s: float = float(os.getenv("AUDITOR_HTTP_TIMEOUT_S", 4.0))
    max_addresses_per_family: int = _int("AUDITOR_MAX_ADDRESSES_PER_FAMILY", 4)
    batch_concurrency: int = _int("AUDITOR_BATCH_CONCURRENCY", 3)
    batch_site_timeout_s: int = _int("AUDITOR_BATCH_SITE_TIMEOUT_S", 150)
    batch_max_sites: int = _int("AUDITOR_BATCH_MAX_SITES", 50)
    sites_config_path: str = os.getenv("AUDITOR_SITES_CONFIG", "sites.json")
    controlled_site_url: str = os.getenv("AUDITOR_CONTROLLED_SITE_URL", "")

    # --- Phase 9 hardening ---
    max_redirects_per_chain: int = _int("AUDITOR_MAX_REDIRECTS", 15)
    max_request_body_bytes: int = _int("AUDITOR_MAX_REQUEST_BODY_BYTES", 1_048_576)  # 1 MiB
    max_hosts_per_scan: int = _int("AUDITOR_MAX_HOSTS_PER_SCAN", 100)
    context_ttl_s: int = _int("AUDITOR_CONTEXT_TTL_S", 300)

    # --- SSRF policy ---
    allowed_ports: tuple[int, ...] = tuple(int(p) for p in _csv("AUDITOR_ALLOWED_PORTS", "80,443,8080,8443"))
    # Hostnames (and their subdomains) exempt from the private-IP check.
    # ONLY for the controlled test site in local/Docker development.
    ssrf_allow_hosts: tuple[str, ...] = _csv("AUDITOR_SSRF_ALLOW_HOSTS")

    # Needed when Chromium runs as root inside a container.
    chromium_no_sandbox: bool = os.getenv("AUDITOR_CHROMIUM_NO_SANDBOX", "0") == "1"

    # When running on host without IPv6 egress, enable dual-stack validation fallback
    simulate_ipv6_if_no_egress: bool = os.getenv("AUDITOR_SIMULATE_IPV6", "1") == "1"


settings = Settings()
