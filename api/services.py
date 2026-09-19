"""Honest minimal service logic for the Phase 0 sandbox.

RULE: never fake verification. Every service does real work (plain HTTPS
fetches via stdlib urllib) and plainly labels what it cannot check. Every
result carries sandbox:true.
"""

from __future__ import annotations

import html
import ipaddress
import re
import socket
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

FETCH_TIMEOUT = 10
MAX_BODY_BYTES = 2_000_000
USER_AGENT = "A2A-Sandbox/0.1 (+local test sandbox; no commercial use)"

# ---------------------------------------------------------------- SSRF protection
# A task-supplied URL must never make the sandbox fetch internal addresses
# (localhost, private LAN ranges, cloud metadata endpoints). Enforcement is
# layered because this VM's egress goes through a managed proxy:
#  1. IP literals are always checked against the denylist (no DNS involved):
#     http://127.0.0.1/, http://169.254.169.254/, http://[::1]/ are refused.
#  2. Hostnames fetched DIRECTLY (proxy bypass, e.g. localhost) are resolved
#     via DNS and every resolved address must be public. This catches numeric
#     tricks like http://2130706433/ (== 127.0.0.1) on direct connections.
#  3. Hostnames fetched THROUGH the egress proxy rely on the proxy's egress
#     policy for the connection, plus a block on internal-looking names
#     (localhost, *.local, single-label hosts, cloud metadata hostnames).
#     NOTE: on a standard public host with no proxy configured, layer 2
#     covers every hostname via real DNS.
# Redirect targets pass through the same gate before being followed.
_NON_PUBLIC_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "::/128", "fe80::/10", "fc00::/7", "ff00::/8",
    )
]


def _host_is_public(hostname: str) -> bool:
    """True only if hostname resolves and every resolved address is public."""
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return False
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if any(ip in net for net in _NON_PUBLIC_NETS):
            return False
    return True


_CLOUD_METADATA_NAMES = {
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
    "instance-data.compute.internal",
}
_INTERNAL_SUFFIXES = (".local", ".localdomain", ".internal", ".lan", ".home", ".corp", ".invalid")


def _name_looks_internal(host: str) -> bool:
    """Heuristic block on internal-looking hostnames (no DNS involved)."""
    h = host.lower().rstrip(".")
    if h in _CLOUD_METADATA_NAMES or h == "localhost":
        return True
    if "." not in h:  # single-label names never address public hosts
        return True
    return h.endswith(_INTERNAL_SUFFIXES)


def _numeric_ip(host: str):
    """Parse any numeric IPv4/IPv6 form (dotted, decimal, hex, octal).

    socket.inet_aton accepts the lenient forms that strict ipaddress rejects
    (e.g. 2130706433, 0x7f.0.0.1, 0177.0.0.1, 127.1) — the same forms a
    downstream resolver would interpret as 127.0.0.1. Returns an ipaddress
    object, or None if the host is not numeric at all.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.inet_aton(host))
    except OSError:
        return None


def _fetch_target_allowed(url: str) -> Tuple[bool, str]:
    """SSRF gate for a fetch target. Returns (allowed, reason)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False, f"refused non-http(s) URL: {url[:60]}"
    host = parts.hostname or ""
    if not host:
        return False, "refused URL with no hostname"
    ip = _numeric_ip(host.rstrip("."))
    if ip is not None:
        if any(ip in net for net in _NON_PUBLIC_NETS):
            return False, f"refused non-public address: {host[:60]}"
        return True, "ok"
    # not a numeric IP: hostname path below
    if _name_looks_internal(host):
        return False, f"refused internal-looking hostname: {host[:60]}"
    if urllib.request.proxy_bypass(host):
        # direct connection: verify every resolved address is public
        if _host_is_public(host):
            return True, "ok"
        return False, f"refused non-public address: {host[:60]}"
    # proxied: the managed egress proxy makes the connection and enforces
    # its own egress policy on the resolved address.
    return True, "ok"


class _PublicOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when the target passes the SSRF gate."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        allowed, reason = _fetch_target_allowed(target)
        if not allowed:
            raise ValueError(f"refused redirect ({reason}): {target[:80]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_FETCH_OPENER = urllib.request.build_opener()
# The default redirect handler is chained before custom ones, so remove it and
# install the validating one instead.
_FETCH_OPENER.handlers = [
    h for h in _FETCH_OPENER.handlers
    if type(h) is not urllib.request.HTTPRedirectHandler
]
_FETCH_OPENER.add_handler(_PublicOnlyRedirect())

TRIPWIRES: Dict[str, Dict[str, Any]] = {}


def fetch_url(url: str) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Fetch a URL over plain HTTPS. Returns (status, content_type, text, error)."""
    parts = urllib.parse.urlsplit(url)
    allowed, reason = _fetch_target_allowed(url)
    if not allowed:
        return None, None, None, reason
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with _FETCH_OPENER.open(req, timeout=FETCH_TIMEOUT) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type")
            body = resp.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                return status, content_type, None, "body exceeds 2MB sandbox cap"
            charset = resp.headers.get_content_charset() or "utf-8"
            try:
                text = body.decode(charset, errors="replace")
            except Exception:
                text = body.decode("utf-8", errors="replace")
            return status, content_type, text, None
    except ValueError as exc:
        # redirect refusal from _PublicOnlyRedirect
        return None, None, None, str(exc)[:120]
    except Exception as exc:
        return None, None, None, f"{type(exc).__name__}: {exc}"


def _text_contains(page: str, needle: str) -> Optional[bool]:
    if not needle:
        return None
    # compare against both raw and HTML-unescaped text
    hay = page + "\n" + html.unescape(re.sub(r"<[^>]+>", " ", page))
    norm = lambda s: re.sub(r"\s+", " ", s).strip().lower()
    return norm(needle) in norm(hay)


# ---------------------------------------------------------------- claim-verification
def claim_verification(inp: Dict[str, Any]) -> Dict[str, Any]:
    verdicts = []
    for claim_item in inp["claims"][:10]:
        claim = claim_item["claim"]
        evidence = []
        any_found = False
        any_fetch_ok = False
        for src in claim_item["sources"][:5]:
            url = src["url"]
            quoted = src.get("quoted_text", "")
            status, ctype, text, err = fetch_url(url)
            found = _text_contains(text, quoted) if (text and quoted) else None
            if status and 200 <= status < 400:
                any_fetch_ok = True
            if found:
                any_found = True
            evidence.append(
                {
                    "url": url,
                    "http_status": status,
                    "content_type": ctype,
                    "quoted_text_provided": bool(quoted),
                    "quoted_text_found": found,
                    "fetch_error": err,
                }
            )
        if any_found:
            verdict = "supported"
        else:
            verdict = "unverified"
        verdicts.append(
            {
                "claim": claim,
                "verdict": verdict,
                "evidence": evidence,
                "honesty_note": (
                    "'supported' means the quoted text was found verbatim in the cited "
                    "source — it does NOT mean the claim itself is true. The sandbox "
                    "does not perform independent research; uncheckable claims are "
                    "marked 'unverified', never 'contradicted'."
                ),
            }
        )
    return {"sandbox": True, "verdicts": verdicts}


# ---------------------------------------------------------------- citation-audit
def citation_audit(inp: Dict[str, Any]) -> Dict[str, Any]:
    results = []
    for cit in inp["citations"][:25]:
        url = cit["url"]
        quoted = cit.get("quoted_text", "")
        status, ctype, text, err = fetch_url(url)
        found = _text_contains(text, quoted) if (text and quoted) else None
        results.append(
            {
                "url": url,
                "label": cit.get("label", ""),
                "http_status": status,
                "content_type": ctype,
                "quoted_text_found": found,
                "fetch_error": err,
            }
        )
    ok = sum(1 for r in results if r["http_status"] and 200 <= r["http_status"] < 400)
    matched = sum(1 for r in results if r["quoted_text_found"] is True)
    return {
        "sandbox": True,
        "results": results,
        "summary": {
            "total": len(results),
            "resolving": ok,
            "quoted_text_matched": matched,
            "note": "Resolves = URL fetched with 2xx/3xx. Match = quoted text found verbatim. Paywalled/JS-heavy pages may fetch but not match.",
        },
    }


# ---------------------------------------------------------------- structured-extraction
def structured_extraction(inp: Dict[str, Any]) -> Dict[str, Any]:
    source = "text"
    text = inp.get("text", "")
    if inp.get("url"):
        status, ctype, fetched, err = fetch_url(inp["url"])
        if err or not fetched:
            return {
                "sandbox": True,
                "method": "heuristic",
                "extraction": {"fetch_error": err or f"http_status={status}", "note": "URL could not be fetched; no extraction performed."},
            }
        text = fetched
        source = "url"
    text = text[:100_000]
    headings_md = re.findall(r"^#{1,6}\s+(.+)$", text, re.M)
    headings_html = re.findall(r"<h[1-6][^>]*>(.*?)</h[1-6]>", text, re.S | re.I)
    links_md = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text)
    links_html = re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', text, re.I)
    tables_md = len(re.findall(r"^\|.*\|$", text, re.M))
    words = len(re.findall(r"\S+", re.sub(r"<[^>]+>", " ", text)))
    return {
        "sandbox": True,
        "method": "heuristic",
        "extraction": {
            "source": source,
            "word_count": words,
            "char_count": len(text),
            "headings": (headings_md + [re.sub(r"<[^>]+>", "", h).strip() for h in headings_html])[:50],
            "links": [{"text": t, "url": u} for t, u in links_md][:100]
            + [{"text": "", "url": u} for u in links_html][:100],
            "markdown_table_rows": tables_md,
            "honesty_note": "Deterministic heuristics only — headings, links, counts. No semantic understanding; not an LLM extraction.",
        },
    }


# ---------------------------------------------------------------- news-tripwire
def news_tripwire(inp: Dict[str, Any]) -> Dict[str, Any]:
    import uuid as _uuid

    action = inp["action"]
    keywords = [k for k in inp.get("keywords", []) if k][:20]
    if action == "register":
        tw_id = f"tw_{_uuid.uuid4().hex[:12]}"
        TRIPWIRES[tw_id] = {
            "tripwire_id": tw_id,
            "label": inp.get("label", ""),
            "url": inp.get("url", ""),
            "keywords": keywords,
            "registered_at": time.time(),
        }
        return {
            "sandbox": True,
            "action": "register",
            "tripwire_id": tw_id,
            "note": "Sandbox: tripwires are checked on demand via action=check. No background scheduler in Phase 0.",
        }
    # check
    tw = TRIPWIRES.get(inp.get("tripwire_id", ""), {})
    url = inp.get("url") or tw.get("url", "")
    kws = keywords or tw.get("keywords", [])
    if not url:
        return {"sandbox": True, "action": "check", "error": "no url provided and tripwire has none"}
    status, ctype, text, err = fetch_url(url)
    matches = []
    if text:
        low = text.lower()
        for kw in kws:
            count = low.count(kw.lower())
            snippets: List[str] = []
            if count:
                for m in re.finditer(re.escape(kw), text, re.I):
                    start = max(0, m.start() - 120)
                    end = min(len(text), m.end() + 120)
                    snippets.append(re.sub(r"\s+", " ", text[start:end]).strip())
                    if len(snippets) >= 3:
                        break
            matches.append({"keyword": kw, "occurrences": count, "snippets": snippets})
    return {
        "sandbox": True,
        "action": "check",
        "tripwire_id": inp.get("tripwire_id", ""),
        "url": url,
        "http_status": status,
        "fetch_error": err,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "matches": matches,
        "honesty_note": "Reports keyword presence in the fetched page only. Not a news-judgement service.",
    }


# ---------------------------------------------------------------- proof-of-work-audit
def proof_of_work_audit(inp: Dict[str, Any]) -> Dict[str, Any]:
    checks = []
    all_resolve = True
    for ev in inp["evidence"][:10]:
        url = ev["url"]
        expected = ev.get("expected_text", "")
        status, ctype, text, err = fetch_url(url)
        resolves = bool(status and 200 <= status < 400)
        if not resolves:
            all_resolve = False
        found = _text_contains(text, expected) if (text and expected) else None
        checks.append(
            {
                "url": url,
                "label": ev.get("label", ""),
                "http_status": status,
                "resolves": resolves,
                "expected_text_provided": bool(expected),
                "expected_text_found": found,
                "fetch_error": err,
            }
        )
    verdict = "evidence_resolves" if all_resolve else "evidence_missing"
    return {
        "sandbox": True,
        "verdict": verdict,
        "work_claim": inp["work_claim"],
        "evidence_checks": checks,
        "honesty_note": (
            "This checks that evidence URLs resolve and contain the expected text. "
            "It CANNOT verify that the claimed work actually happened — that "
            "requires human judgement. Never treat this verdict as proof of work."
        ),
    }


DISPATCH = {
    "claim-verification": claim_verification,
    "citation-audit": citation_audit,
    "structured-extraction": structured_extraction,
    "news-tripwire": news_tripwire,
    "proof-of-work-audit": proof_of_work_audit,
}

REQUIRED_KEYS = {
    "claim-verification": ["verdicts"],
    "citation-audit": ["results", "summary"],
    "structured-extraction": ["extraction"],
    "news-tripwire": ["action"],
    "proof-of-work-audit": ["verdict", "evidence_checks"],
}


def execute_service(service_id: str, inp: Dict[str, Any]) -> Dict[str, Any]:
    fn = DISPATCH[service_id]
    return fn(inp)


def qa_gate(service: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """Adversarial second pass (sandbox-simple): schema conformance + honesty flags."""
    checks = []
    ok = True
    if not isinstance(result, dict):
        return {"pass": False, "checks": ["result is not an object"]}
    checks.append("result is an object")
    if result.get("sandbox") is not True:
        ok = False
        checks.append("FAIL: missing sandbox:true flag")
    else:
        checks.append("sandbox flag present")
    for key in REQUIRED_KEYS.get(service["id"], []):
        if key not in result:
            ok = False
            checks.append(f"FAIL: missing required output key '{key}'")
        else:
            checks.append(f"output key '{key}' present")
    # honesty: no service may claim a 'verified' verdict it cannot support
    blob = str(result).lower()
    if "verified" in blob and service["id"] == "proof-of-work-audit":
        # proof-of-work may only say evidence_resolves, never 'verified work'
        if "verified work" in blob or '"verdict": "verified"' in blob:
            ok = False
            checks.append("FAIL: proof-of-work must not claim verified work")
    return {"pass": ok, "checks": checks, "service_id": service["id"]}
