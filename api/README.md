# A2A Service System — Phase 0 Sandbox (local test only)

**TEST SANDBOX.** Everything free ($0.00), testnet semantics, binds to
127.0.0.1 only. No real crypto, no real payments, no external accounts,
no money movement. Nothing here is public or commercial.

## Run

```bash
cd ~/workspace/compound/a2a-economy/sandbox
pip3 install --user --break-system-packages -r requirements.txt
# admin secret is REQUIRED — the server refuses to start without it
export A2A_SANDBOX_ADMIN="$(cat ~/.config/a2a-sandbox-admin)"
python3 -m uvicorn app:app --host 127.0.0.1 --port 8741
```

Generate the secret once (stored with owner-only permissions, never in chat/logs):

```bash
mkdir -p ~/.config
python3 -c "import secrets; print(secrets.token_hex(32))" > ~/.config/a2a-sandbox-admin
chmod 600 ~/.config/a2a-sandbox-admin
```

Then in another terminal:

```bash
# machine-readable catalog (Tier A)
curl -s http://127.0.0.1:8741/v1/catalog.json | head -c 600

# public free-slot counter
curl -s http://127.0.0.1:8741/v1/slots

# synthetic buyer harness (full loop per service, green/red per stage)
python3 harness.py

# human test page
# open http://127.0.0.1:8741/test.html in a browser (test API key prefilled)
```

## What is REAL vs STUBBED

**Real (protocol fully implemented):**
- `POST /quote` — free, zero-token, formula-based binding quote, 15-min expiry, input-cap + policy checks, ledger entry
- `POST /execute` — 402 without payment (x402-shaped response), mock commit-then-settle authorization verification (structure + quote match + validBefore expiry), 202 + task_id, async job queue, Ed25519-signed deliverables, settle event
- Quota enforcement: identity required, ≤10 tasks/day/wallet-or-API-key, ≤20/day/service with public slots counter, global daily token budget with auto-pause
- Kill switch as feature flag (`POST /v1/admin/kill` / `/v1/admin/resume`, token via `A2A_SANDBOX_ADMIN` env — the server refuses to start without it); no auto-resume
- SSRF protection: task-supplied URLs are resolved and every address must be public (loopback, private LAN, link-local and cloud-metadata ranges refused, including via redirects); non-http(s) schemes refused
- Append-only JSONL ledger + CSV/JSON tax-export stub (`/v1/ledger/export`)
- **Per-task privacy (locked per buyer):** every task gets a random 256-bit `read_token` at accept time (returned in the 202 response — keep it secret, treat it like a password). Task status, deliverable, signature check and that task's ledger entries all require it via the `Authorization: Bearer <token>` header. Header-only by design: tokens in URLs would land in server access logs. No token → 401. The full ledger (all buyers) is admin-only (`X-Admin-Token` header). Task and quote IDs are 128-bit random; admin token comparisons are constant-time.
- **Persistent quotas:** usage counters and pause state live in SQLite (`data/quotas.db`) — a restart no longer resets daily caps or the kill-switch state.
- **MCP (Model Context Protocol):** `POST /mcp` speaks Streamable HTTP (stateless JSON-RPC 2.0): `initialize`, `tools/list` (the 5 services), `tools/call` (runs quote → accept → wait synchronously, returns the signed deliverable). Two auth flows: human one-step (`X-API-KEY` header + `arguments.input`), or machine two-step (`POST /quote` first, then `tools/call` with `arguments.quote_id` and the `X-PAYMENT` header authorizing that quote). Calls count as `mcp` origin traffic.
- **Origin tracking:** every accepted task is counted by channel — `human`, `machine`, `mcp` — visible at admin-only `GET /v1/admin/stats` alongside quota usage.
- Tier A machine-readable files: `/v1/catalog.json`, `/.well-known/agent.json`, `/llms.txt`, `/v1/openapi.json`, `/robots.txt` (AI crawlers allowed)
- Honest service logic: real HTTPS fetches of user-supplied URLs; results plainly labeled

**Stubbed / simulated:**
- The EIP-3009 authorization is a mock (base64 JSON in X-PAYMENT header) — verification checks shape, quote match and expiry, not an on-chain signature
- Settlement is a $0.00 ledger event under "testnet semantics" — no chain interaction, no faucet funds
- Token budget is simulated (estimated from input bytes), not real LLM tokens
- News tripwires check on demand; no background scheduler yet
- No facilitator, no escrow, no webhooks delivery (webhook_url accepted but not called), no Postgres/Inngest
- Human pilot API keys are fixed test keys, not issued per user

## Honesty rules (enforced in code)

- Every deliverable carries `"sandbox": true`
- Claim verification: "supported" = quoted text found verbatim in the cited source, NOT "the claim is true". Uncheckable → "unverified"
- Citation audit: reports real HTTP status + verbatim text match
- Proof-of-work: evidence-resolution check only; never claims work was verified
- QA gate: fails any result missing the sandbox flag or required output keys

## Files

- `app.py` — FastAPI gateway
- `catalog.py` — the 5 service definitions (schemas, caps, slots)
- `services.py` — honest minimal service logic + QA gate
- `signing.py` — Ed25519 key mgmt
- `ledger.py` — append-only JSONL ledger
- `quotas.py` — scarcity quotas, token budget, kill switch
- `harness.py` — synthetic buyer harness
- `static/` — agent.json, llms.txt, robots.txt, test.html (human page)
- `data/` — keys + ledger.jsonl (created at runtime, git-ignored by convention)
