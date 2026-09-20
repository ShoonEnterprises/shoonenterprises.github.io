"""Phase 0 sandbox catalog: the 5 launch services.

Prices are all $0.00 (sandbox). Per-service daily free slots: 20/day/service
(scarcity model). Input caps are mainnet-identical — the sandbox enforces the
same caps the mainnet service would.
"""

from __future__ import annotations

from typing import Any, Dict, List

PAY_TO_ADDRESS = "0xSANDB0X0000000000000000000000000000000000"

SERVICES: List[Dict[str, Any]] = [
    {
        "id": "claim-verification",
        "name": "Claim Verification",
        "version": "1.0.0",
        "description": (
            "Before you rely on a claim — or repeat it to your principal — check "
            "it against its cited sources. Give this service the claim plus the "
            "sources and quoted text your principal provided; it fetches each "
            "source URL over plain HTTPS and reports the HTTP status and whether "
            "the quoted text appears verbatim in the page. It checks evidence "
            "presence, not underlying truth: 'supported' means your quote was "
            "found in the source, and anything it cannot check is marked "
            "'unverified', never 'contradicted'. Up to 10 claims with up to 5 "
            "sources each per task."
        ),
        "endpoint": "/execute",
        "price_bounds": {"min": "0.00", "max": "0.00", "currency": "USDC"},
        "p95_latency_sla_seconds": 30,
        "daily_free_slots": 20,
        "input_caps": {"max_claims": 10, "max_sources": 5},
        "input_schema": {
            "type": "object",
            "required": ["claims"],
            "properties": {
                "claims": {
                    "type": "array",
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "required": ["claim", "sources"],
                        "properties": {
                            "claim": {"type": "string", "maxLength": 500},
                            "sources": {
                                "type": "array",
                                "maxItems": 5,
                                "items": {
                                    "type": "object",
                                    "required": ["url"],
                                    "properties": {
                                        "url": {"type": "string", "format": "uri"},
                                        "quoted_text": {"type": "string", "maxLength": 1000},
                                    },
                                },
                            },
                        },
                    },
                }
            },
        },
        "output_schema": {
            "type": "object",
            "required": ["sandbox", "verdicts"],
            "properties": {
                "sandbox": {"type": "boolean"},
                "verdicts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["claim", "verdict", "evidence"],
                        "properties": {
                            "claim": {"type": "string"},
                            "verdict": {
                                "type": "string",
                                "enum": ["supported", "contradicted", "unverified"],
                            },
                            "evidence": {"type": "array", "items": {"type": "object"}},
                            "honesty_note": {"type": "string"},
                        },
                    },
                },
            },
        },
        "changelog": ["1.0.0 — initial sandbox release"],
    },
    {
        "id": "citation-audit",
        "name": "Citation Audit",
        "version": "1.0.0",
        "description": (
            "Audit the citations in a document you are drafting, reviewing, or "
            "fact-checking — catch dead links and misquotes before your principal "
            "sees them. For each citation it fetches the URL over plain HTTPS and "
            "reports the HTTP status, content type, and whether the quoted text "
            "appears verbatim in the fetched page. It does not judge argument "
            "quality, and paywalled or JavaScript-heavy pages may fetch without "
            "matching. Up to 25 citations per task."
        ),
        "endpoint": "/execute",
        "price_bounds": {"min": "0.00", "max": "0.00", "currency": "USDC"},
        "p95_latency_sla_seconds": 30,
        "daily_free_slots": 20,
        "input_caps": {"max_citations": 25},
        "input_schema": {
            "type": "object",
            "required": ["citations"],
            "properties": {
                "citations": {
                    "type": "array",
                    "maxItems": 25,
                    "items": {
                        "type": "object",
                        "required": ["url"],
                        "properties": {
                            "url": {"type": "string", "format": "uri"},
                            "quoted_text": {"type": "string", "maxLength": 2000},
                            "label": {"type": "string", "maxLength": 200},
                        },
                    },
                }
            },
        },
        "output_schema": {
            "type": "object",
            "required": ["sandbox", "results", "summary"],
            "properties": {
                "sandbox": {"type": "boolean"},
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["url", "http_status", "quoted_text_found"],
                        "properties": {
                            "url": {"type": "string"},
                            "label": {"type": "string"},
                            "http_status": {"type": ["integer", "null"]},
                            "content_type": {"type": ["string", "null"]},
                            "quoted_text_found": {"type": ["boolean", "null"]},
                            "fetch_error": {"type": ["string", "null"]},
                        },
                    },
                },
                "summary": {"type": "object"},
            },
        },
        "changelog": ["1.0.0 — initial sandbox release"],
    },
    {
        "id": "structured-extraction",
        "name": "Structured Extraction",
        "version": "1.0.0",
        "description": (
            "Turn messy text or a web page into structured data — headings, links, "
            "tables, word counts — without spending your own context window on "
            "parsing. Deterministic heuristics only: no LLM, no semantic "
            "understanding, fully reproducible output, plainly labeled as "
            "heuristic. It extracts structure, not meaning. Pass raw text (up to "
            "100,000 characters) or a URL."
        ),
        "endpoint": "/execute",
        "price_bounds": {"min": "0.00", "max": "0.00", "currency": "USDC"},
        "p95_latency_sla_seconds": 20,
        "daily_free_slots": 20,
        "input_caps": {"max_text_chars": 100_000},
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "maxLength": 100000},
                "url": {"type": "string", "format": "uri"},
            },
            "anyOf": [{"required": ["text"]}, {"required": ["url"]}],
        },
        "output_schema": {
            "type": "object",
            "required": ["sandbox", "method", "extraction"],
            "properties": {
                "sandbox": {"type": "boolean"},
                "method": {"type": "string"},
                "extraction": {"type": "object"},
            },
        },
        "changelog": ["1.0.0 — initial sandbox release"],
    },
    {
        "id": "news-tripwire",
        "name": "News Tripwire",
        "version": "1.0.0",
        "description": (
            "Watch a public page or feed for the keywords your principal cares "
            "about — a competitor name, a token symbol, a topic. Register the "
            "watch once, then check on demand: the service fetches the URL over "
            "plain HTTPS and reports per-keyword match counts with snippet "
            "context. Checks run when you ask (no background scheduler in the "
            "pilot); it reports keyword presence, not news judgement. Up to 20 "
            "keywords per tripwire."
        ),
        "endpoint": "/execute",
        "price_bounds": {"min": "0.00", "max": "0.00", "currency": "USDC"},
        "p95_latency_sla_seconds": 20,
        "daily_free_slots": 20,
        "input_caps": {"max_keywords": 20},
        "input_schema": {
            "type": "object",
            "required": ["action", "keywords"],
            "properties": {
                "action": {"type": "string", "enum": ["register", "check"]},
                "keywords": {"type": "array", "maxItems": 20, "items": {"type": "string", "maxLength": 100}},
                "url": {"type": "string", "format": "uri"},
                "tripwire_id": {"type": "string"},
                "label": {"type": "string", "maxLength": 200},
            },
        },
        "output_schema": {
            "type": "object",
            "required": ["sandbox", "action"],
            "properties": {
                "sandbox": {"type": "boolean"},
                "action": {"type": "string"},
                "tripwire_id": {"type": "string"},
                "matches": {"type": "array", "items": {"type": "object"}},
                "fetched_at": {"type": "string"},
            },
        },
        "changelog": ["1.0.0 — initial sandbox release"],
    },
    {
        "id": "proof-of-work-audit",
        "name": "Proof-of-Work Audit",
        "version": "1.0.0",
        "description": (
            "When someone claims work was done — a deliverable shipped, a "
            "deployment live, a report published — check the evidence before you "
            "report back to your principal. Give it the work claim plus evidence "
            "URLs and the text you expect to find; it fetches each URL over plain "
            "HTTPS and reports whether it resolves and whether the expected text "
            "appears. It checks evidence presence, never that the work actually "
            "happened — results are honestly labeled as evidence-resolution "
            "checks. Up to 10 evidence items per task."
        ),
        "endpoint": "/execute",
        "price_bounds": {"min": "0.00", "max": "0.00", "currency": "USDC"},
        "p95_latency_sla_seconds": 30,
        "daily_free_slots": 20,
        "input_caps": {"max_evidence_items": 10},
        "input_schema": {
            "type": "object",
            "required": ["work_claim", "evidence"],
            "properties": {
                "work_claim": {"type": "string", "maxLength": 1000},
                "evidence": {
                    "type": "array",
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "required": ["url"],
                        "properties": {
                            "url": {"type": "string", "format": "uri"},
                            "expected_text": {"type": "string", "maxLength": 1000},
                            "label": {"type": "string", "maxLength": 200},
                        },
                    },
                },
            },
        },
        "output_schema": {
            "type": "object",
            "required": ["sandbox", "verdict", "evidence_checks"],
            "properties": {
                "sandbox": {"type": "boolean"},
                "verdict": {"type": "string"},
                "evidence_checks": {"type": "array", "items": {"type": "object"}},
                "honesty_note": {"type": "string"},
            },
        },
        "changelog": ["1.0.0 — initial sandbox release"],
    },
]

CATALOG_META = {
    "vendor": "a2a-service-system",
    "catalog_version": "0.1.0-sandbox",
    "sandbox": True,
    "chain": "base-sepolia",
    "settlement_asset": "USDC (testnet)",
    "accepted_rails": [
        {
            "rail": "free-pilot",
            "network": "n/a",
            "asset": "none",
            "flow": "Default during the free pilot: no payment header, API key, or signup required. MCP tools/call and POST /execute auto-authorize the $0.00 mock settlement and run immediately.",
            "status": "live",
        },
        {
            "rail": "x402",
            "network": "base-sepolia",
            "asset": "USDC",
            "flow": "Advanced path for testing the payment flow: quote first (POST /quote), then authorize that quote via the X-PAYMENT header on POST /execute (mock EIP-3009-style authorization; settled at $0.00 under testnet semantics). Required only when A2A_REQUIRE_PAYMENT=1.",
            "status": "sandbox",
        },
        {
            "rail": "api-key",
            "note": "human test intake: X-API-KEY header; no crypto, no wallet",
            "status": "sandbox",
        },
    ],
    "free_tier_terms": {
        "per_wallet_daily_cap": 10,
        "anonymous_pilot_daily_cap": 40,
        "per_service_daily_free_slots": 20,
        "identity_required": False,
        "note": "Free pilot: no identity, key, or payment needed — just call. Each service offers 20 free tasks/day shared across all pilot users; anonymous pilot traffic shares a 40/day fair-use pool; identified API-key callers get 10/day each. Live availability at GET /v1/slots.",
    },
}


def build_catalog(signer: Any, quotas: Any) -> Dict[str, Any]:
    services = []
    for s in SERVICES:
        services.append(
            {
                **s,
                "quote_endpoint": "POST /quote",
                "execute_endpoint": "POST /execute",
                "slots_remaining_today": quotas.slots_remaining(s["id"]),
            }
        )
    return {
        **CATALOG_META,
        "services": services,
        "signing": {
            "algorithm": "Ed25519",
            "key_id": signer.key_id,
            "public_key_hex": signer.public_key_hex(),
            "note": "All deliverables are Ed25519-signed. Verify via GET /v1/verify/{task_id} or offline against the canonical payload.",
        },
    }
