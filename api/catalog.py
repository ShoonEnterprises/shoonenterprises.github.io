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
            "Check factual claims against their cited sources. For each claim the "
            "sandbox fetches each provided source URL over plain HTTPS and reports "
            "the HTTP status and whether the quoted text appears in the page. It "
            "does NOT browse the open web or perform independent research; anything "
            "it cannot check is marked 'unverified — sandbox stub'."
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
            "Audit citations in a document: for each citation the sandbox fetches "
            "the URL over plain HTTPS and reports the HTTP status, content type, "
            "and whether the quoted text appears verbatim in the fetched page. It "
            "does not judge argument quality or check paywalled content."
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
            "Turn messy text (or a fetched page) into structured data using "
            "deterministic heuristics: headings, links, tables and key statistics. "
            "This is NOT an LLM extraction — no semantic understanding is claimed. "
            "Output is plainly labeled heuristic."
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
            "Watch a public URL (e.g. an RSS/Atom feed or a news page) for "
            "keywords. Register a tripwire, then trigger a check: the sandbox "
            "fetches the URL over plain HTTPS and reports whether each keyword "
            "appears, with match counts and snippet context. In the sandbox, "
            "checks run on demand via the check action (no background scheduler "
            "yet); recurring schedules arrive in Phase 1."
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
            "Audit a claim that work was performed. The sandbox fetches each "
            "evidence URL over plain HTTPS and reports whether the evidence "
            "resolves and whether the claimed artifact text appears. It CANNOT "
            "independently verify that work happened — results are honestly "
            "labeled as evidence-resolution checks, never as verified work."
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
            "rail": "x402",
            "network": "base-sepolia",
            "asset": "USDC",
            "flow": "commit-then-settle (mock EIP-3009-style authorization in X-PAYMENT header; settled at $0.00 under testnet semantics)",
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
        "per_service_daily_free_slots": 20,
        "identity_required": True,
        "note": "Scarcity model: each service offers 20 free tasks/day globally; each wallet/API key is limited to 10 tasks/day. Public slots-remaining counter at GET /v1/slots.",
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
