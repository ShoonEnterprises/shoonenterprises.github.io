#!/usr/bin/env python3
"""Synthetic buyer harness for the A2A Phase 0 sandbox.

Acts as a buyer agent and runs the full loop per service:
quote -> 402 (no payment) -> authorize (mock X-PAYMENT) -> 202 -> poll ->
deliverable -> Ed25519 signature verify -> ledger entry check.

Reports green/red per stage, per service. Exit 0 only if ALL stages green.

Usage: python3 harness.py [--base http://127.0.0.1:8741]
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.request
import urllib.error

EXAMPLE_INPUTS = {
    "claim-verification": {
        "claims": [
            {
                "claim": "Example.com is a reserved documentation domain.",
                "sources": [{"url": "https://www.example.com", "quoted_text": "Example Domain"}],
            }
        ]
    },
    "citation-audit": {
        "citations": [{"url": "https://www.example.com", "quoted_text": "Example Domain", "label": "example"}]
    },
    "structured-extraction": {"url": "https://www.example.com"},
    "news-tripwire": {"action": "check", "url": "https://www.example.com", "keywords": ["Example"]},
    "proof-of-work-audit": {
        "work_claim": "Harness smoke test executed.",
        "evidence": [{"url": "https://www.example.com", "expected_text": "Example Domain"}],
    },
}

WALLET = "0xHARNESS0000000000000000000000000000000001"


class Harness:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.results = []  # (service, stage, ok, detail)
        self.pubkey = None
        self.key_id = None

    def _req(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"raw": raw[:500]}

    def stage(self, service, name, ok, detail=""):
        ok = bool(ok)
        self.results.append((service, name, ok, detail))
        mark = "GREEN" if ok else "RED"
        print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""), flush=True)
        return ok

    def run_service(self, service_id):
        print(f"\n== {service_id} ==")
        inp = EXAMPLE_INPUTS[service_id]
        ok_all = True

        # 1. quote
        s, q = self._req("POST", "/quote", {"service_id": service_id, "input": inp})
        ok = self.stage(service_id, "quote", s == 200 and q.get("quote_id"), f"http={s}")
        ok_all &= ok
        if not ok:
            return False
        quote_id = q["quote_id"]
        if q.get("amount") != "0.00":
            self.stage(service_id, "quote amount is $0.00", False, str(q.get("amount")))
            return False
        self.stage(service_id, "quote amount is $0.00", True)

        # 2. execute without payment -> expect 402
        s, r = self._req("POST", "/execute", {"quote_id": quote_id})
        ok = self.stage(service_id, "execute w/o payment -> 402", s == 402, f"http={s}")
        ok_all &= ok

        # 3. authorize -> expect 202
        auth = {
            "from": WALLET,
            "amount": "0.00",
            "currency": "USDC",
            "network": "base-sepolia",
            "validBefore": int(time.time()) + 900,
            "quote_id": quote_id,
        }
        pay_b64 = base64.b64encode(json.dumps(auth).encode()).decode()
        s, r = self._req("POST", "/execute", {"quote_id": quote_id}, {"X-PAYMENT": pay_b64})
        ok = self.stage(service_id, "authorize -> 202", s == 202 and r.get("task_id"), f"http={s}")
        ok_all &= ok
        if not ok:
            return False
        task_id = r["task_id"]
        read_token = r.get("read_token")
        ok = self.stage(service_id, "read_token issued", bool(read_token))
        ok_all &= ok
        if not ok:
            return False
        authz = {"Authorization": f"Bearer {read_token}"}

        # 3b. task reads without the token must be rejected (per-task privacy)
        s, _ = self._req("GET", f"/v1/tasks/{task_id}")
        ok = self.stage(service_id, "task read w/o token -> 401", s == 401, f"http={s}")
        ok_all &= ok
        s, _ = self._req("GET", f"/v1/tasks/{task_id}", headers={"Authorization": "Bearer wrong-token"})
        ok = self.stage(service_id, "task read w/ wrong token -> 401", s == 401, f"http={s}")
        ok_all &= ok

        # 4. poll until complete
        done = False
        status = None
        for _ in range(45):
            time.sleep(1)
            s, status = self._req("GET", f"/v1/tasks/{task_id}", headers=authz)
            if s == 200 and status.get("status") in ("complete", "failed"):
                done = True
                break
        ok = self.stage(service_id, "poll -> complete", done and status.get("status") == "complete",
                        f"status={status.get('status') if status else 'timeout'}")
        ok_all &= ok
        if not ok:
            return False

        # 5. deliverable
        s, d = self._req("GET", f"/v1/tasks/{task_id}/deliverable", headers=authz)
        ok = self.stage(service_id, "deliverable fetched", s == 200 and d.get("payload", {}).get("sandbox") is True, f"http={s}")
        ok_all &= ok
        if not ok:
            return False

        # 6. Ed25519 signature verify (offline, against catalog public key)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.pubkey))
            canonical = json.dumps(d["payload"], sort_keys=True, separators=(",", ":")).encode()
            pub.verify(bytes.fromhex(d["signature"]["value"]), canonical)
            sig_ok = True
        except Exception as e:
            sig_ok = False
            detail = str(e)[:100]
        else:
            detail = f"key_id={d['signature'].get('key_id')}"
        ok = self.stage(service_id, "Ed25519 signature valid", sig_ok, detail)
        ok_all &= ok

        # 7. ledger has the task lifecycle (task-scoped view via read_token)
        s, led = self._req("GET", f"/v1/ledger?limit=500&task_id={task_id}", headers=authz)
        events = {r.get("event") for r in led.get("records", []) if r.get("task_id") == task_id}
        need = {"task_queued", "task_started", "task_completed", "settled"}
        ok = self.stage(service_id, "ledger lifecycle complete", need <= events, f"missing={need - events}")
        ok_all &= ok

        # 7b. full ledger without admin token must be rejected
        s, _ = self._req("GET", "/v1/ledger?limit=5")
        ok = self.stage(service_id, "full ledger w/o admin -> 401", s == 401, f"http={s}")
        ok_all &= ok

        # 8. slots counter decremented (sanity)
        s, slots = self._req("GET", "/v1/slots")
        entry = next((x for x in slots.get("services", []) if x["service_id"] == service_id), None)
        ok = self.stage(service_id, "slots counter live", entry is not None and entry["slots_remaining_today"] < 20,
                        str(entry))
        ok_all &= ok
        return ok_all

    def run(self):
        print("A2A sandbox synthetic buyer harness")
        print(f"base: {self.base}")
        s, cat = self._req("GET", "/v1/catalog.json")
        if s != 200 or not cat.get("sandbox"):
            print("[RED] catalog not reachable or not sandbox — aborting")
            return 1
        self.pubkey = cat["signing"]["public_key_hex"]
        self.key_id = cat["signing"]["key_id"]
        print(f"catalog ok (sandbox:true, key_id={self.key_id})")
        print(f"services: {[x['id'] for x in cat['services']]}")

        all_ok = True
        for svc in cat["services"]:
            if not self.run_service(svc["id"]):
                all_ok = False

        print("\n================ SUMMARY ================")
        greens = sum(1 for _, _, ok, _ in self.results if ok)
        reds = sum(1 for _, _, ok, _ in self.results if not ok)
        print(f"stages green: {greens}, red: {reds}")
        for service, name, ok, detail in self.results:
            if not ok:
                print(f"  RED: {service} / {name} — {detail}")
        print("OVERALL:", "ALL GREEN" if all_ok else "FAILURES PRESENT")
        return 0 if all_ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8741")
    args = ap.parse_args()
    sys.exit(Harness(args.base).run())
