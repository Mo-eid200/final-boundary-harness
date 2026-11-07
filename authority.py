#!/usr/bin/env python3
"""Authority service: issues authorizations, revokes, and answers lease requests.

* Every invalidation is an EPOCH BUMP, including evidence expiry: when a
  VERIFIED evidence record expires, every scope that relied on it is revoked.
  The resource therefore never needs a wall clock to judge evidence.
* On every revocation the authority pushes a signed fence notice to each
  resource. revoke() returns EFFECTIVE only after every resource has
  acknowledged it. If a resource cannot be reached, revoke() returns PENDING
  with an explicit bound: that resource's lease was requested before the
  revocation and runs from its own send time, so it fails closed no later
  than  revoke_time + lease_s.
* Leases are answered on request: the answer is signed and echoes the
  resource's challenge (see resource.py).
* Epochs, sequence numbers and evidence records are persisted atomically.

The /test/partition endpoint exists only for the harness. It simulates a
network partition between the authority and the resource (pushes dropped,
lease requests refused). Remove it in a real deployment.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from common import action_hash, canon, load_sk, post, sign

MUT = set(filter(None, os.environ.get("FBH_MUTATION", "").split(",")))


class Authority:
    def __init__(self, sk_path: str, state_path: str, resources: list[str],
                 lease_s: float, push_timeout: float) -> None:
        self.sk = load_sk(Path(sk_path))
        self.state_path = Path(state_path)
        self.resources, self.lease_s, self.push_timeout = resources, lease_s, push_timeout
        self.lock = threading.RLock()
        self.partitioned = False
        st = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.epochs: dict[str, int] = st.get("epochs", {})
        self.seq: int = st.get("seq", 0)
        self.evidence: dict[str, dict] = st.get("evidence", {})
        self.ev_scopes: dict[str, list[str]] = st.get("ev_scopes", {})

    # ---------------------------------------------------------------- persistence
    def _persist(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump({"epochs": self.epochs, "seq": self.seq, "evidence": self.evidence,
                       "ev_scopes": self.ev_scopes}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    # ---------------------------------------------------------------- notices
    def _notice(self, scope: str) -> dict:
        self.seq += 1
        n = {"scope": scope, "epoch": self.epochs[scope], "seq": self.seq,
             "issued_at": time.time()}
        self._persist()
        return {"notice": n, "sig": sign(self.sk, n)}

    def _push(self, msg: dict) -> bool:
        if self.partitioned:
            return False
        ok = True
        for url in self.resources:
            try:
                ok &= bool(post(url + "/fence", msg, timeout=self.push_timeout).get("ok"))
            except Exception:
                ok = False
        return ok

    # ---------------------------------------------------------------- API
    def lease(self, challenge: str) -> tuple[int, dict]:
        if self.partitioned:
            return 503, {"ok": False, "reason": "PARTITIONED"}
        with self.lock:
            body = {"challenge": challenge, "lease_s": self.lease_s,
                    "epochs": dict(self.epochs), "issued_at": time.time()}
        return 200, {"body": body, "sig": sign(self.sk, body)}

    def add_evidence(self, ev_id: str, ttl_s: float) -> dict:
        with self.lock:
            now = time.time()
            self.evidence[ev_id] = {"id": ev_id, "status": "VERIFIED", "verified_at": now,
                                    "valid_until": now + ttl_s, "expiry_processed": False}
            self._persist()
            return self.evidence[ev_id]

    def grant(self, principal: str, holder_pk: str, action: dict, ev_id: str) -> tuple[int, dict]:
        with self.lock:
            ev = self.evidence.get(ev_id)
            if not ev or time.time() > ev["valid_until"]:
                return 403, {"ok": False, "reason": "EVIDENCE_NOT_VALID"}
            scope = f"{principal}@{action['resource']}"
            new_scope = scope not in self.epochs
            if new_scope:
                self.epochs[scope] = 1
            self.ev_scopes.setdefault(ev_id, [])
            if scope not in self.ev_scopes[ev_id]:
                self.ev_scopes[ev_id].append(scope)
            payload = {"principal": principal, "holder_pk": holder_pk, "scope": scope,
                       "action_hash": action_hash(action), "epoch": self.epochs[scope],
                       "evidence_id": ev_id, "nonce": secrets.token_hex(16),
                       "issued_at": time.time()}
            msg = self._notice(scope) if new_scope else None
        if msg:
            self._push(msg)                     # resource learns the scope and pulls a lease
        return 200, {"ok": True, "auth": {"payload": payload, "sig": sign(self.sk, payload)}}

    def revoke(self, scope: str, reason: str) -> dict:
        with self.lock:
            if scope not in self.epochs:
                return {"ok": False, "reason": "UNKNOWN_SCOPE"}
            self.epochs[scope] += 1
            msg = self._notice(scope)
            t0 = time.time()
        acked = self._push(msg)
        out = {"ok": True, "scope": scope, "new_epoch": msg["notice"]["epoch"],
               "reason": reason, "status": "EFFECTIVE" if acked else "PENDING"}
        if not acked:
            out["effective_by"] = t0 + self.lease_s
        return out

    # ---------------------------------------------------------------- background
    def expiry_loop(self) -> None:
        if "no_evidence_revoke" in MUT:
            return                                       # fault injection only
        while True:
            time.sleep(0.05)
            due = []
            with self.lock:
                for ev_id, ev in self.evidence.items():
                    if not ev["expiry_processed"] and time.time() > ev["valid_until"]:
                        ev["expiry_processed"] = True    # history kept, status unchanged
                        due += self.ev_scopes.get(ev_id, [])
                if due:
                    self._persist()
            for scope in due:
                self.revoke(scope, "evidence expired")


def make_handler(a: Authority):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code: int, body: dict) -> None:
            data = canon(body)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/lease":
                return self._send(*a.lease(str(req.get("challenge", ""))))
            if self.path == "/grant":
                return self._send(*a.grant(req["principal"], req["holder_pk"],
                                           req["action"], req["evidence_id"]))
            if self.path == "/revoke":
                return self._send(200, a.revoke(req["scope"], req.get("reason", "")))
            if self.path == "/evidence":
                return self._send(200, a.add_evidence(req["id"], float(req["ttl_s"])))
            if self.path == "/test/partition":
                a.partitioned = bool(req["on"])
                return self._send(200, {"ok": True, "partitioned": a.partitioned})
            self._send(404, {"ok": False})

        def do_GET(self):
            if self.path.startswith("/evidence/"):
                ev = a.evidence.get(self.path.split("/")[-1])
                return self._send(200 if ev else 404, ev or {})
            if self.path == "/health":
                return self._send(200, {"ok": True})
            self._send(404, {"ok": False})
    return H


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sk", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--resource", action="append", default=[])
    ap.add_argument("--lease-s", type=float, default=1.0)
    ap.add_argument("--push-timeout", type=float, default=0.5)
    args = ap.parse_args()
    a = Authority(args.sk, args.state, args.resource, args.lease_s, args.push_timeout)
    threading.Thread(target=a.expiry_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(a))
    print("READY", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
