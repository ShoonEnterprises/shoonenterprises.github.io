"""A2A Service System — Phase 0 sandbox gateway.

Local-only test sandbox. Everything free, testnet semantics, no real money,
no real crypto, no external accounts. Binds to 127.0.0.1 only.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Body, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from catalog import PAY_TO_ADDRESS, SERVICES, build_catalog
from ledger import Ledger
from quotas import QuotaManager
from services import execute_service, qa_gate
from signing import Signer

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

SIGNER = Signer(DATA_DIR / "keys")
LEDGER = Ledger(DATA_DIR / "ledger.jsonl")

_ADMIN_TOKEN = os.environ.get("A2A_SANDBOX_ADMIN")
if not _ADMIN_TOKEN:
    raise RuntimeError(
        "A2A_SANDBOX_ADMIN is not set — refusing to start without an admin secret. "
        "Set it to a long random value before launching."
    )

QUOTAS = QuotaManager(
    daily_token_budget=500_000,  # simulated token units/day; auto-pause on breach
    admin_token=_ADMIN_TOKEN,
    db_path=DATA_DIR / "quotas.db",  # SQLite: usage + pause state survive restarts
)

executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="a2a-task")

app = FastAPI(
    title="A2A Service System — Phase 0 Sandbox",
    version="0.1.0-sandbox",
    docs_url="/docs",
    redoc_url=None,
)

# ---------------------------------------------------------------- in-memory stores
quotes: Dict[str, Dict[str, Any]] = {}
tasks: Dict[str, Dict[str, Any]] = {}
deliverables: Dict[str, Dict[str, Any]] = {}
quotes_lock = threading.Lock()
tasks_lock = threading.Lock()

# Human API keys — identity labels for the free pilot (not payment secrets).
# Override via A2A_HUMAN_API_KEYS env var (comma-separated) on public deploys
# so the keys in use aren't the publicly visible demo ones.
HUMAN_API_KEYS = {
    k.strip()
    for k in os.environ.get(
        "A2A_HUMAN_API_KEYS", "TEST-KEY-DEMO,TEST-KEY-ALPHA,TEST-KEY-BETA"
    ).split(",")
    if k.strip()
}

SERVICE_IDS = {s["id"] for s in SERVICES}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def utc_today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


# ---------------------------------------------------------------- policy check (RT-S1)
BLOCKED_SCHEMES = ("file://", "ftp://", "gopher://", "data:")


def policy_check(service_id: str, payload: Dict[str, Any]) -> Optional[str]:
    """Return a rejection reason string, or None if the input passes policy."""
    blob = json.dumps(payload)
    for scheme in BLOCKED_SCHEMES:
        if scheme in blob:
            return f"blocked input scheme: {scheme}"
    if len(blob) > 200_000:
        return "input payload exceeds 200KB sandbox cap"
    return None


# ---------------------------------------------------------------- static Tier-A files
@app.get("/.well-known/agent.json")
def agent_card() -> JSONResponse:
    return JSONResponse(json.loads((STATIC_DIR / "agent.json").read_text()))


@app.get("/llms.txt")
def llms_txt() -> PlainTextResponse:
    return PlainTextResponse((STATIC_DIR / "llms.txt").read_text())


@app.get("/robots.txt")
def robots() -> PlainTextResponse:
    return PlainTextResponse((STATIC_DIR / "robots.txt").read_text())


@app.get("/test.html")
def test_page() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "test.html").read_text())


@app.get("/v1/catalog.json")
def catalog() -> JSONResponse:
    return JSONResponse(build_catalog(SIGNER, QUOTAS))


@app.get("/v1/openapi.json")
def openapi_spec() -> JSONResponse:
    return JSONResponse(app.openapi())


# ---------------------------------------------------------------- slots / health
@app.get("/v1/slots")
def slots() -> JSONResponse:
    return JSONResponse(
        {
            "sandbox": True,
            "date": utc_today(),
            "paused": QUOTAS.paused,
            "services": [
                {
                    "service_id": s["id"],
                    "daily_free_slots": s["daily_free_slots"],
                    "slots_remaining_today": QUOTAS.slots_remaining(s["id"]),
                }
                for s in SERVICES
            ],
        }
    )


@app.get("/v1/health")
def health() -> JSONResponse:
    return JSONResponse({"ok": True, "sandbox": True, "paused": QUOTAS.paused, "time": now_iso()})



# ---------------------------------------------------------------- client IP behind a reverse proxy
def _client_ip(request: Request) -> str:
    """Client IP for the quote rate limiter.

    Behind Render's proxy the direct peer is the proxy itself, so use
    X-Forwarded-For's leftmost entry. Spoofing only affects rate-limit
    bucketing; per-identity task quotas are still enforced separately.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- per-IP rate limit on the free quote endpoint
_QUOTE_RL_WINDOW_S = 60
_QUOTE_RL_MAX = 60  # quotes per IP per rolling minute
_quote_hits: Dict[str, List[float]] = {}
_quote_hits_lock = threading.Lock()


def _quote_rate_ok(ip: str) -> bool:
    now = time.time()
    with _quote_hits_lock:
        if len(_quote_hits) > 10_000:  # memory hygiene under IP-spray
            _quote_hits.clear()
        hits = [t for t in _quote_hits.get(ip, []) if now - t < _QUOTE_RL_WINDOW_S]
        if len(hits) >= _QUOTE_RL_MAX:
            _quote_hits[ip] = hits
            return False
        hits.append(now)
        _quote_hits[ip] = hits
        return True


# ---------------------------------------------------------------- quoting
def _create_quote_record(service_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate input against policy + caps and create a binding sandbox quote.

    Shared by POST /quote and the MCP tools/call path. Raises HTTPException
    on policy/cap rejection.
    """
    reason = policy_check(service_id, payload)
    if reason:
        raise HTTPException(status_code=400, detail={"error": "policy_rejected", "reason": reason})

    service = next(s for s in SERVICES if s["id"] == service_id)
    # input-size caps from the catalog, enforced identically in sandbox (mainnet-identical caps)
    for cap_key, cap_val in service["input_caps"].items():
        actual = _measure_cap(payload, cap_key)
        if actual is not None and actual > cap_val:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "input_cap_exceeded",
                    "cap": cap_key,
                    "limit": cap_val,
                    "actual": actual,
                },
            )

    quote_id = f"q_{uuid.uuid4().hex}"
    expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15)
    record = {
        "quote_id": quote_id,
        "service_id": service_id,
        "input": payload,
        "amount": "0.00",
        "currency": "USDC",
        "network": "base-sepolia",
        "sandbox": True,
        "expires_at": expires_at.isoformat(),
        "created_at": now_iso(),
    }
    with quotes_lock:
        quotes[quote_id] = record
    LEDGER.append(
        {
            "event": "quoted",
            "quote_id": quote_id,
            "service_id": service_id,
            "amount": "0.00",
            "currency": "USDC",
            "sandbox": True,
        }
    )
    return record


@app.post("/quote")
def quote(body: Dict[str, Any], request: Request) -> JSONResponse:
    if QUOTAS.paused:
        raise HTTPException(
            status_code=503,
            detail={
                "sandbox": True,
                "error": "service_paused",
                "message": "Intake is paused (auto-pause or kill switch). In-flight paid tasks complete; no new intake. No auto-resume.",
            },
        )
    client_ip = _client_ip(request)
    if not _quote_rate_ok(client_ip):
        raise HTTPException(
            status_code=429,
            detail={"error": "rate_limited", "message": "too many quote requests; slow down"},
        )
    service_id = body.get("service_id")
    payload = body.get("input")
    if service_id not in SERVICE_IDS:
        raise HTTPException(status_code=400, detail={"error": "unknown_service", "service_id": service_id})
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail={"error": "invalid_input", "message": "input must be a JSON object"})

    record = _create_quote_record(service_id, payload)
    return JSONResponse(
        {
            "quote_id": record["quote_id"],
            "service_id": service_id,
            "amount": "0.00",
            "currency": "USDC",
            "network": "base-sepolia",
            "sandbox": True,
            "expires_at": record["expires_at"],
            "slots_remaining_today": QUOTAS.slots_remaining(service_id),
            "pay_to": PAY_TO_ADDRESS,
            "note": "Binding sandbox quote, 15-minute expiry. Quoting is free and costs zero tokens by construction.",
        }
    )


def _measure_cap(payload: Dict[str, Any], cap_key: str) -> Optional[int]:
    if cap_key == "max_claims" and isinstance(payload.get("claims"), list):
        return len(payload["claims"])
    if cap_key == "max_citations" and isinstance(payload.get("citations"), list):
        return len(payload["citations"])
    if cap_key == "max_sources" and isinstance(payload.get("sources"), list):
        return len(payload["sources"])
    if cap_key == "max_text_chars" and isinstance(payload.get("text"), str):
        return len(payload["text"])
    if cap_key == "max_evidence_items" and isinstance(payload.get("evidence"), list):
        return len(payload["evidence"])
    if cap_key == "max_keywords" and isinstance(payload.get("keywords"), list):
        return len(payload["keywords"])
    return None


# ---------------------------------------------------------------- x402-style payment verification (sandbox mock, real shape)
def _verify_payment_header(payment_b64: str, quote: Dict[str, Any]) -> Tuple[bool, str, Optional[str]]:
    """Verify the mock EIP-3009-style authorization. Returns (ok, reason, payer)."""
    try:
        raw = base64.b64decode(payment_b64).decode("utf-8")
        auth = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return False, "X-PAYMENT header is not valid base64 JSON", None
    for field in ("from", "amount", "currency", "network", "validBefore", "quote_id"):
        if field not in auth:
            return False, f"authorization missing field: {field}", None
    if auth["quote_id"] != quote["quote_id"]:
        return False, "authorization quote_id does not match", None
    if auth["amount"] != quote["amount"] or auth["currency"] != quote["currency"]:
        return False, "authorization amount/currency does not match quote", None
    if int(auth["validBefore"]) <= int(time.time()):
        return False, "authorization expired (validBefore in the past)", None
    return True, "ok", str(auth["from"])


def _payment_required_response(quote: Dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        status_code=402,
        content={
            "error": "payment_required",
            "sandbox": True,
            "x402Version": 1,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": "0",
                    "resource": "/execute",
                    "description": f"Sandbox commit-then-settle authorization for quote {quote['quote_id']} ($0.00 testnet USDC)",
                    "mimeType": "application/json",
                    "payTo": PAY_TO_ADDRESS,
                    "maxTimeoutSeconds": 60,
                    "asset": "0xTEST_USDC_BASE_SEPOLIA",
                    "extra": {
                        "sandbox": True,
                        "note": "Testnet semantics. In sandbox the $0.00 authorization is a mock EIP-3009-style commitment sent as base64 JSON in the X-PAYMENT header.",
                    },
                }
            ],
        },
    )


def _accept_task(
    quote: Dict[str, Any],
    payer: str,
    intake_kind: str,
    origin: str,
    webhook_url: Optional[str] = None,
) -> Tuple[str, str]:
    """Consume quota, create the task, queue the worker. Returns (task_id, read_token).

    Shared by POST /execute and the MCP tools/call path. Raises HTTPException
    on quota rejection. `origin` is the traffic channel: human | machine | mcp.
    """
    service_id = quote["service_id"]
    service = next(s for s in SERVICES if s["id"] == service_id)

    # --- quota enforcement: ≤10 tasks/day/identity, ≤20/day/service, token budget
    est_tokens = _estimate_tokens(quote["input"])
    allowed, reason = QUOTAS.check_and_consume(payer, service_id, est_tokens)
    if not allowed:
        if QUOTAS.paused:
            LEDGER.append({"event": "auto_paused", "reason": reason, "sandbox": True})
            raise HTTPException(status_code=503, detail={"error": "service_paused", "reason": reason, "sandbox": True})
        raise HTTPException(status_code=429, detail={"error": "quota_exceeded", "reason": reason, "sandbox": True})
    QUOTAS.record_origin(origin)

    LEDGER.append(
        {
            "event": "authorized",
            "quote_id": quote["quote_id"],
            "service_id": service_id,
            "buyer_ref": payer,
            "intake": intake_kind,
            "origin": origin,
            "amount": "0.00",
            "currency": "USDC",
            "sandbox": True,
        }
    )

    task_id = f"t_{uuid.uuid4().hex}"
    read_token = secrets.token_urlsafe(32)
    task = {
        "task_id": task_id,
        "quote_id": quote["quote_id"],
        "service_id": service_id,
        "buyer_ref": payer,
        "intake": intake_kind,
        "origin": origin,
        "status": "queued",
        "created_at": now_iso(),
        "webhook_url": webhook_url,
        "est_tokens": est_tokens,
        "read_token": read_token,
    }
    with tasks_lock:
        tasks[task_id] = task
    LEDGER.append({"event": "task_queued", "task_id": task_id, "service_id": service_id, "sandbox": True})
    executor.submit(_run_task, task_id, quote["input"], service)
    return task_id, read_token


# ---------------------------------------------------------------- execute
@app.post("/execute")
def execute(
    body: Dict[str, Any],
    x_payment: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> JSONResponse:
    if QUOTAS.paused:
        raise HTTPException(status_code=503, detail={"error": "service_paused", "sandbox": True})

    quote_id = body.get("quote_id")
    webhook_url = body.get("webhook_url")
    if not quote_id:
        raise HTTPException(status_code=400, detail={"error": "missing_quote_id"})
    with quotes_lock:
        quote = quotes.get(quote_id)
    if not quote:
        raise HTTPException(status_code=404, detail={"error": "unknown_quote"})
    if dt.datetime.fromisoformat(quote["expires_at"]) < dt.datetime.now(dt.timezone.utc):
        raise HTTPException(status_code=410, detail={"error": "quote_expired"})

    # --- intake requires identity: wallet (machine) or test API key (human)
    payer: Optional[str] = None
    intake_kind: Optional[str] = None
    if x_payment:
        ok, reason, payer_addr = _verify_payment_header(x_payment, quote)
        if not ok:
            raise HTTPException(status_code=400, detail={"error": "invalid_authorization", "reason": reason})
        payer = payer_addr
        intake_kind = "machine"
    elif x_api_key:
        if x_api_key not in HUMAN_API_KEYS:
            raise HTTPException(status_code=401, detail={"error": "invalid_api_key"})
        payer = f"api-key:{x_api_key}"
        intake_kind = "human"
    else:
        # x402 semantics: no payment attached -> 402 with payment requirements
        return _payment_required_response(quote)

    task_id, read_token = _accept_task(
        quote, payer, intake_kind, origin=intake_kind, webhook_url=webhook_url
    )

    base = "/v1"
    return JSONResponse(
        status_code=202,
        content={
            "task_id": task_id,
            "status": "accepted",
            "sandbox": True,
            "read_token": read_token,
            "poll_url": f"{base}/tasks/{task_id}",
            "deliverable_url": f"{base}/tasks/{task_id}/deliverable",
            "message": "Authorization verified (sandbox mock). Work queued; settle occurs on completion under testnet semantics.",
            "privacy_note": "Keep read_token secret. It is the only key to this task's status, deliverable and ledger entries — each task is private to its buyer.",
        },
    )


# ---------------------------------------------------------------- MCP: Model Context Protocol (Streamable HTTP, stateless)
MCP_PROTOCOL_VERSION = "2025-06-18"


def _mcp_tools() -> List[Dict[str, Any]]:
    tools = []
    for s in SERVICES:
        tools.append(
            {
                "name": s["id"].replace("-", "_"),
                "description": s["description"]
                + " Sandbox: free during the testing phase, testnet semantics, deliverables Ed25519-signed.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "input": s["input_schema"],
                        "quote_id": {
                            "type": "string",
                            "description": (
                                "Machine flow: a quote_id from POST /quote for this service. "
                                "When given, the quote's input is used and the X-PAYMENT header "
                                "must authorize that quote. Human flow (X-API-KEY): pass input instead."
                            ),
                        },
                    },
                },
            }
        )
    return tools


_MCP_TOOL_SERVICE = {s["id"].replace("-", "_"): s["id"] for s in SERVICES}


def _wait_for_task(task_id: str, timeout_s: float = 75.0) -> Dict[str, Any]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with tasks_lock:
            task = tasks.get(task_id)
        if task and task.get("status") in ("complete", "failed"):
            return task
        time.sleep(0.5)
    raise TimeoutError(f"task {task_id} still running after {timeout_s}s")


def _mcp_tools_call(
    req_id: Any,
    params: Dict[str, Any],
    x_payment: Optional[str],
    x_api_key: Optional[str],
) -> Dict[str, Any]:
    def err(code: int, message: str, data: Any = None) -> Dict[str, Any]:
        e: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            e["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": e}

    def ok(content: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(content)}],
                "isError": is_error,
            },
        }

    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return err(-32602, "arguments must be a JSON object")
    service_id = _MCP_TOOL_SERVICE.get(name) if isinstance(name, str) else None
    if not service_id:
        return err(-32602, f"unknown tool: {name}", {"known_tools": sorted(_MCP_TOOL_SERVICE)})
    task_input = arguments.get("input")
    quote_id_arg = arguments.get("quote_id")

    # --- quote: supplied (machine flow) or created here (human one-step flow)
    # Machine flow: the client quotes first via POST /quote, then authorizes that
    # quote_id in the X-PAYMENT header. The quote's input is authoritative.
    record: Optional[Dict[str, Any]] = None
    if isinstance(quote_id_arg, str):
        with quotes_lock:
            record = quotes.get(quote_id_arg)
        if not record:
            return err(-32602, "unknown quote_id")
        if record["service_id"] != service_id:
            return err(-32602, "quote_id is for a different service")
        if dt.datetime.fromisoformat(record["expires_at"]) < dt.datetime.now(dt.timezone.utc):
            return err(-32602, "quote expired")
        task_input = record["input"]
    else:
        if not isinstance(task_input, dict):
            return err(-32602, "arguments.input must be a JSON object (or pass arguments.quote_id from POST /quote)")
        try:
            record = _create_quote_record(service_id, task_input)
        except HTTPException as e:
            return err(-32602, f"quote rejected: {e.detail}")

    # identity — same rails as POST /execute
    payer: Optional[str] = None
    intake_kind: Optional[str] = None
    if x_payment:
        valid, reason, payer_addr = _verify_payment_header(x_payment, record)
        if not valid:
            return err(-32001, f"authorization invalid: {reason}")
        payer = payer_addr
        intake_kind = "machine"
    elif x_api_key:
        if x_api_key not in HUMAN_API_KEYS:
            return err(-32001, "invalid X-API-KEY")
        payer = f"api-key:{x_api_key}"
        intake_kind = "human"
    else:
        return err(
            -32001,
            "authentication required",
            {
                "note": "Pass X-PAYMENT (mock EIP-3009-style base64 JSON authorization) or X-API-KEY header.",
                "machine_flow": "POST /quote first, then tools/call with arguments {quote_id} and the X-PAYMENT header authorizing that quote.",
                "free_testing": "Quotes are $0.00 during the free testing phase; daily caps apply (10/identity/day, 20/service/day).",
            },
        )

    try:
        task_id, read_token = _accept_task(record, payer, intake_kind, origin="mcp")
    except HTTPException as e:
        return err(-32000, f"task not accepted: {e.detail}", {"sandbox": True})

    try:
        task = _wait_for_task(task_id)
    except TimeoutError:
        return ok(
            {
                "status": "running",
                "task_id": task_id,
                "read_token": read_token,
                "poll_url": f"/v1/tasks/{task_id}",
                "note": "Still running after 75s; poll the HTTP endpoint with the read_token.",
                "sandbox": True,
            }
        )
    if task.get("status") == "failed":
        return ok(
            {
                "status": "failed",
                "task_id": task_id,
                "error": task.get("error"),
                "sandbox": True,
            },
            is_error=True,
        )
    signed = deliverables.get(task_id)
    return ok(
        {
            "status": "complete",
            "task_id": task_id,
            "read_token": read_token,
            "deliverable": signed,
            "sandbox": True,
            "privacy_note": "Keep read_token secret; it is the only key to this task.",
        }
    )


def _mcp_handle_one(
    msg: Any, x_payment: Optional[str], x_api_key: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Handle one JSON-RPC message. Returns the response dict, or None for notifications."""
    req_id = msg.get("id") if isinstance(msg, dict) else None
    is_notification = isinstance(msg, dict) and "id" not in msg
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "invalid request"}}
    method = msg["method"]
    params = msg.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "a2a-sandbox", "version": "0.1.0-sandbox"},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _mcp_tools()}}
    if method == "tools/call":
        return _mcp_tools_call(req_id, params, x_payment, x_api_key)
    if is_notification:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


@app.post("/mcp")
def mcp_endpoint(
    payload: Any = Body(...),
    x_payment: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> Any:
    """MCP Streamable HTTP (stateless): initialize / tools/list / tools/call as JSON-RPC 2.0."""
    if QUOTAS.paused:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": "service paused", "data": {"sandbox": True}},
            }
        )
    if isinstance(payload, list):
        responses = []
        for m in payload:
            r = _mcp_handle_one(m, x_payment, x_api_key)
            if r is not None:
                responses.append(r)
        if not responses:
            return Response(status_code=202)
        return JSONResponse(responses)
    resp = _mcp_handle_one(payload, x_payment, x_api_key)
    if resp is None:
        return Response(status_code=202)
    return JSONResponse(resp)


@app.get("/mcp")
def mcp_get() -> JSONResponse:
    return JSONResponse(
        status_code=405,
        content={
            "error": "method_not_allowed",
            "message": "MCP Streamable HTTP uses POST /mcp with JSON-RPC 2.0 bodies.",
        },
    )


def _estimate_tokens(payload: Dict[str, Any]) -> int:
    # Simulated token accounting: ~1 token per 4 bytes of input, floor 50, QA gate overhead included.
    return max(50, len(json.dumps(payload).encode("utf-8")) // 4 + 250)


def _run_task(task_id: str, input_payload: Dict[str, Any], service: Dict[str, Any]) -> None:
    started = time.time()
    try:
        with tasks_lock:
            tasks[task_id]["status"] = "running"
        LEDGER.append({"event": "task_started", "task_id": task_id, "sandbox": True})

        result = execute_service(service["id"], input_payload)

        qa = qa_gate(service, result)
        if not qa["pass"]:
            result["qa_gate"] = qa
            result["honesty_note"] = (
                "QA gate flagged schema issues; delivering best-effort result with flags rather than failing silently."
            )

        latency = round(time.time() - started, 2)
        payload = {
            "sandbox": True,
            "task_id": task_id,
            "service_id": service["id"],
            "service_version": service["version"],
            "created_at": now_iso(),
            "latency_seconds": latency,
            "result": result,
            "qa_gate": qa,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = SIGNER.sign(canonical)
        signed = {
            "payload": payload,
            "signature": {
                "key_id": SIGNER.key_id,
                "algorithm": "Ed25519",
                "value": signature,
                "note": "Verify by canonicalizing payload with sorted keys and compact separators, then Ed25519-verify.",
            },
        }
        with tasks_lock:
            tasks[task_id]["status"] = "complete"
            tasks[task_id]["completed_at"] = now_iso()
            tasks[task_id]["latency_seconds"] = latency
        deliverables[task_id] = signed
        LEDGER.append(
            {
                "event": "task_completed",
                "task_id": task_id,
                "service_id": service["id"],
                "latency_seconds": latency,
                "qa_pass": qa["pass"],
                "sandbox": True,
            }
        )
        LEDGER.append(
            {
                "event": "settled",
                "task_id": task_id,
                "service_id": service["id"],
                "amount": "0.00",
                "currency": "USDC",
                "network": "base-sepolia",
                "sandbox": True,
                "note": "Testnet semantics: $0.00 mock settlement, no value moved.",
            }
        )
    except Exception as exc:  # never leave a task hanging silently
        with tasks_lock:
            tasks[task_id]["status"] = "failed"
            tasks[task_id]["error"] = str(exc)
        LEDGER.append({"event": "task_failed", "task_id": task_id, "error": str(exc), "sandbox": True})


def _extract_read_token(request: Request) -> Optional[str]:
    # Header-only: tokens in query strings end up in server access logs.
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


def _require_task_token(task_id: str, request: Request) -> Dict[str, Any]:
    """Per-task privacy: only the holder of the task's read_token may read it."""
    with tasks_lock:
        task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail={"error": "unknown_task"})
    token = _extract_read_token(request)
    if not token or not secrets.compare_digest(token, task.get("read_token", "")):
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "a valid read_token for this task is required"},
        )
    return task


def _require_admin(request: Request) -> None:
    # Header-only: tokens in query strings end up in server access logs.
    admin = request.headers.get("x-admin-token")
    if not admin or not secrets.compare_digest(admin, QUOTAS.admin_token):
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "admin token required"},
        )


# ---------------------------------------------------------------- task read APIs (per-task private via read_token)
@app.get("/v1/tasks/{task_id}")
def task_status(task_id: str, request: Request) -> JSONResponse:
    task = _require_task_token(task_id, request)
    public = {k: v for k, v in task.items() if k not in ("webhook_url", "read_token")}
    return JSONResponse(public)


@app.get("/v1/tasks/{task_id}/deliverable")
def task_deliverable(task_id: str, request: Request) -> JSONResponse:
    task = _require_task_token(task_id, request)
    signed = deliverables.get(task_id)
    if not signed:
        raise HTTPException(status_code=409, detail={"error": "not_ready", "status": task["status"]})
    return JSONResponse(signed)


@app.get("/v1/verify/{task_id}")
def verify_signature(task_id: str, request: Request) -> JSONResponse:
    """Convenience endpoint: re-verify the deliverable signature server-side."""
    _require_task_token(task_id, request)
    signed = deliverables.get(task_id)
    if not signed:
        raise HTTPException(status_code=404, detail={"error": "no_deliverable"})
    payload = signed["payload"]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ok = SIGNER.verify(canonical, signed["signature"]["value"])
    return JSONResponse({"task_id": task_id, "signature_valid": ok, "key_id": SIGNER.key_id, "sandbox": True})


# ---------------------------------------------------------------- ledger + tax-export stub
# Privacy: the full ledger (all buyers' task metadata) is admin-only.
# A buyer can view just their own task's entries via ?task_id=...&read_token=...
@app.get("/v1/ledger")
def ledger_tail(request: Request, limit: int = 50) -> JSONResponse:
    task_id = request.query_params.get("task_id")
    if task_id:
        task = _require_task_token(task_id, request)
        quote_id = task["quote_id"]
        records = [
            r for r in LEDGER.all()
            if r.get("task_id") == task_id or r.get("quote_id") == quote_id
        ]
        return JSONResponse({"sandbox": True, "task_id": task_id, "records": records})
    _require_admin(request)
    return JSONResponse({"sandbox": True, "records": LEDGER.tail(limit)})


@app.get("/v1/ledger/export")
def ledger_export(request: Request, format: str = "csv") -> Any:
    task_id = request.query_params.get("task_id")
    if task_id:
        task = _require_task_token(task_id, request)
        quote_id = task["quote_id"]
        rows = [
            r for r in LEDGER.all()
            if r.get("task_id") == task_id or r.get("quote_id") == quote_id
        ]
    else:
        _require_admin(request)
        rows = LEDGER.all()
    if format == "json":
        return JSONResponse({"sandbox": True, "export_note": "SANDBOX tax-export stub: no real income exists.", "records": rows})
    lines = [
        "ts_utc,event,task_id,service_id,buyer_ref,amount,currency,amount_gbp_spot,fees_gbp,notes",
    ]
    for r in rows:
        lines.append(
            ",".join(
                [
                    str(r.get("ts_utc", "")),
                    str(r.get("event", "")),
                    str(r.get("task_id", "")),
                    str(r.get("service_id", "")),
                    str(r.get("buyer_ref", "")),
                    str(r.get("amount", "")),
                    str(r.get("currency", "")),
                    "0.00",
                    "0.00",
                    "SANDBOX - no real income; testnet semantics",
                ]
            )
        )
    return PlainTextResponse("\n".join(lines), media_type="text/csv")


# ---------------------------------------------------------------- admin: kill switch / pause
@app.post("/v1/admin/kill")
def admin_kill(body: Dict[str, Any]) -> JSONResponse:
    if not secrets.compare_digest(str(body.get("admin_token") or ""), QUOTAS.admin_token):
        raise HTTPException(status_code=403, detail={"error": "forbidden"})
    active = bool(body.get("active", True))
    QUOTAS.set_paused(active, reason="kill switch (feature flag)")
    LEDGER.append({"event": "kill_switch", "active": active, "sandbox": True})
    return JSONResponse({"sandbox": True, "paused": QUOTAS.paused})


@app.post("/v1/admin/resume")
def admin_resume(body: Dict[str, Any]) -> JSONResponse:
    if not secrets.compare_digest(str(body.get("admin_token") or ""), QUOTAS.admin_token):
        raise HTTPException(status_code=403, detail={"error": "forbidden"})
    # RT-S9: no auto-resume ever; resume is an explicit human action.
    QUOTAS.set_paused(False, reason="explicit human resume")
    LEDGER.append({"event": "resumed", "sandbox": True, "note": "explicit human resume; auto-resume is never permitted"})
    return JSONResponse({"sandbox": True, "paused": QUOTAS.paused})


@app.get("/v1/admin/stats")
def admin_stats(request: Request) -> JSONResponse:
    """Admin-only usage stats: quotas, pause state, and traffic origin split
    (human vs machine vs mcp) for channel attribution."""
    _require_admin(request)
    return JSONResponse({"sandbox": True, **QUOTAS.usage_snapshot()})
