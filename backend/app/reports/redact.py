"""Redaction for anything that leaves the app in a report.

Confirmed fact this module relies on: the capture pipeline (scanner/browser.py,
scanner/resource_discovery.py) does NOT read or store HTTP request/response headers,
cookies, or Authorization values anywhere - CDP's Network.requestWillBeSent includes a
headers dict, but this project never reads it. So the one CONCRETE place a secret can
reach a report is embedded in a URL: either as HTTP Basic-Auth userinfo
(https://user:pass@host/...) or as a query-string parameter (?api_key=...,
?token=..., a JWT, etc.) that a third-party script or tracking pixel attached, which the
browser then genuinely requested and this project genuinely recorded.

Everything here is applied at REPORT-GENERATION time only. It never touches what's
stored in the database (Phase 1-6 behavior and data are unchanged), and it never affects
scanning/probing/classification logic - only what gets written into a JSON/CSV export.
"""
from __future__ import annotations
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MASK = "[REDACTED]"

# Exact (case-insensitive) query-parameter names treated as sensitive. Exact-match, not
# substring, so a param like "monkey" or "primarykey" is never falsely caught just for
# containing "key" - deliberately avoids the false-positive trap of naive substring
# matching while still covering every common credential/session/token parameter name.
SENSITIVE_PARAM_NAMES = frozenset({
    "token", "access_token", "id_token", "refresh_token", "api_key", "apikey", "key",
    "secret", "client_secret", "password", "passwd", "pwd", "auth", "authorization",
    "session", "sessionid", "session_id", "sid", "jwt", "bearer", "signature", "sig",
    "credential", "credentials", "x-api-key", "x_api_key", "set-cookie", "cookie",
})

# A JWT is unambiguous (header.payload.signature, each base64url) and worth catching by
# SHAPE regardless of what parameter name carries it.
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")

# Defensive, free-text scrub for any field built from an exception/error message, in
# case a future change ever lets one of those embed a raw header value. Not currently
# exercised by real data (confirmed above) - this is deliberate defense-in-depth.
#
# Each pattern consumes up to the next newline/semicolon (NOT just the next word) so a
# value like "Bearer abc.def.ghi" is redacted in full - an earlier version of this regex
# stopped at the first whitespace, which masked the word "Bearer" but left the actual
# token sitting in plain text right next to it. Caught by test_redact_text_* below.
_TEXT_PATTERNS = [
    re.compile(r"(authorization\s*:\s*)[^\n;]+", re.IGNORECASE),
    re.compile(r"(cookie\s*:\s*)[^\n;]+", re.IGNORECASE),
    re.compile(r"(bearer\s+)[^\s;\n]+", re.IGNORECASE),  # fallback: a bare "Bearer <token>" with no "Authorization:" prefix
]

# Finds an embedded http(s) URL anywhere inside otherwise-arbitrary text (e.g. a debug
# or error message that happens to mention a full URL), so it can be run back through
# redact_url(). Without this, redact_text()'s "defense in depth" claim would only be
# true for the specific Authorization/Cookie/Bearer patterns above and silently miss
# the single most obvious way a secret could appear in free text: a URL with a
# sensitive query parameter, pasted into a message rather than carried in a dedicated
# URL field. Caught by test_probes_endpoint_redacts_error_detail (Phase 9).
_EMBEDDED_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _redact_value(name: str, value: str) -> str:
    if name.lower() in SENSITIVE_PARAM_NAMES or _JWT_RE.match(value):
        return MASK
    return value


def redact_url(url: str | None) -> str | None:
    """Strips any embedded Basic-Auth userinfo and redacts sensitive query-parameter
    values. Preserves scheme/host/port/path and every non-sensitive query parameter
    BYTE-FOR-BYTE when there is nothing to redact - this function must not silently
    re-percent-encode or otherwise normalize a URL that had nothing sensitive in it,
    since a report's job is to reflect what was actually observed. Malformed input is
    returned unchanged rather than raising - a report must never crash over one odd URL.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.scheme:
        return url  # doesn't look like a URL at all; leave non-URL text untouched rather than mangling it

    has_credentials = bool(parts.username or parts.password)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    needs_query_redaction = any(_redact_value(k, v) != v for k, v in query_pairs)

    if not has_credentials and not needs_query_redaction:
        return url  # nothing sensitive found: return the original, unmodified, exactly as given

    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    # parts.username/.password being present at all means credentials were embedded;
    # they are dropped entirely, not masked-in-place, since the host:port is all a
    # report needs for diagnosis.
    query = urlencode([(k, _redact_value(k, v)) for k, v in query_pairs]) if query_pairs else parts.query
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))  # fragment dropped too


def redact_text(text: str | None) -> str | None:
    if not text:
        return text
    for pattern in _TEXT_PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + MASK, text)
    text = _EMBEDDED_URL_RE.sub(lambda m: redact_url(m.group(0)), text)
    return text
