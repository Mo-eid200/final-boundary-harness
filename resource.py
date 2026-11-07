#!/usr/bin/env python3
"""Resource service: the single enforcement point at the final boundary.

Every request is checked here, inside one serialized SQLite transaction
together with the action itself:

  1. authorization signed by the authority (Ed25519)        UNAUTHENTICATED
  2. exact action hash                                      ACTION_MISMATCH
  3. proof of possession by the holder named in the token   NO_PROOF_OF_POSSESSION
  4. a fence exists and a fresh lease is held for it        NO_FENCE / LEASE_EXPIRED
  5. token epoch == fence                                   STALE_FENCING_TOKEN / UNKNOWN_EPOCH
  6. nonce never used before (durable, UNIQUE)              NONCE_REUSED
  then the action is applied and committed.

Fences
    Raised by signed notices that the authority pushes on every revocation.
    A fence only ever increases, so a delayed or replayed notice is harmless.
    Fences, nonces and the event log are durable (SQLite, WAL, synchronous=FULL).

Leases (pull-based, challenge-response)
    The resource asks the authority for a lease with a fresh random challenge
    and remembers the MONOTONIC time at which it SENT the request. It accepts
    only a signed answer to an outstanding challenge, and the lease runs from
    the send time. Consequences:
      * a delayed, captured or replayed lease answer buys nothing;
      * the lease never outlives  send_time + lease_s,  whatever the network
        does, so a revocation that cannot be delivered still takes effect
        within lease_s of being issued;
      * wall-clock skew between machines does not matter (only clock rate);
      * leases live in memory only, so after a crash or restart the resource
        fails closed until it obtains a fresh lease.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from common import action_hash, canon, pop_message, post, verify

SCHEMA = """
CREATE TABLE IF NOT EXISTS fence  (scope TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS applied(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                                   scope TEXT, epoch INTEGER, fence_at_commit INTEGER,
                                   action TEXT, t REAL);
CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT,
                                   body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);
"""
MAX_WORK_S = 0.05
# Fault injection for mutation testing only (see mutate.py). Empty in normal use.
MUT = set(filter(None, os.environ.get("FBH_MUTATION", "").split(",")))


class Resource:
    def __init__(self, db_path: str, authority_pk: str, authority_url: str | None,
                 lease_s: float) -> None:
        self.authority_pk, self.authority_url, self.lease_s = authority_pk, authority_url, lease_s
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()
        self.lease: dict[str, tuple[int, float]] = {}   # scope -> (epoch, mono deadline)
        self.outstanding: dict[str, float] = {}         # challenge -> mono send time
        self.mem_nonces: set[str] = set()               # used only by a mutation

    # ------------------------------------------------------------ evidence log
    def _event(self, **body) -> None:
        row = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else "0" * 64
        body["t"] = time.time()
        b = json.dumps(body, sort_keys=True)
        h = hashlib.sha256((prev + b).encode()).hexdigest()
        self.db.execute("INSERT INTO events(body, prev, hash) VALUES (?,?,?)", (b, prev, h))

    def _raise_fence(self, scope: str, epoch: int) -> tuple[int, bool]:
        row = self.db.execute("SELECT epoch FROM fence WHERE scope=?", (scope,)).fetchone()
        cur = row[0] if row else 0
        new = max(cur, epoch)
        if new != cur:
            self.db.execute("INSERT INTO fence(scope, epoch) VALUES (?,?) ON CONFLICT(scope) "
                            "DO UPDATE SET epoch=excluded.epoch", (scope, new))
            self.lease.pop(scope, None)                  # a new fence needs a new lease
            self._event(kind="FENCE", scope=scope, epoch=new)
        return new, new != cur

    # ------------------------------------------------------------ fence notices (push)
    def on_fence(self, req: dict) -> tuple[int, dict]:
        notice, sig = req.get("notice", {}), req.get("sig", "")
        with self.lock:
            if "no_notice_sig" not in MUT and not verify(self.authority_pk, notice, sig):
                return 401, {"ok": False, "reason": "BAD_NOTICE_SIGNATURE"}
            self.db.execute("BEGIN IMMEDIATE")
            try:
                new, raised = self._raise_fence(notice["scope"], int(notice["epoch"]))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        if raised:
            self.pull_lease()                            # outside the lock
        return 200, {"ok": True, "fence": new}

    # ------------------------------------------------------------ leases (pull)
    def pull_lease(self) -> str:
        if not self.authority_url:
            return "NO_AUTHORITY"
        ch = secrets.token_hex(16)
        with self.lock:
            self.outstanding[ch] = time.monotonic()      # lease runs from SEND time
        try:
            resp = post(self.authority_url + "/lease", {"challenge": ch}, timeout=0.5)
        except Exception:
            with self.lock:
                self.outstanding.pop(ch, None)
            return "UNREACHABLE"
        code, body = self.on_lease(resp)
        return body.get("reason", "OK")

    def on_lease(self, resp: dict) -> tuple[int, dict]:
        body, sig = resp.get("body", {}), resp.get("sig", "")
        with self.lock:
            if "no_notice_sig" not in MUT and not verify(self.authority_pk, body, sig):
                return 401, {"ok": False, "reason": "BAD_LEASE_SIGNATURE"}
            sent = self.outstanding.pop(body.get("challenge", ""), None)
            if sent is None:
                if "no_challenge" not in MUT:
                    return 409, {"ok": False, "reason": "UNSOLICITED_LEASE"}
                sent = time.monotonic()
            for k in [k for k, t in self.outstanding.items() if t < sent]:
                del self.outstanding[k]                  # older challenges are dead
            self.db.execute("BEGIN IMMEDIATE")
            try:
                for scope, ep in body.get("epochs", {}).items():
                    fence, _ = self._raise_fence(scope, int(ep))
                    if int(ep) == fence:
                        self.lease[scope] = (fence, sent + float(body["lease_s"]))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        return 200, {"ok": True}

    def lease_loop(self) -> None:
        while True:
            self.pull_lease()
            time.sleep(self.lease_s / 3)

    # ------------------------------------------------------------ apply
    def on_apply(self, req: dict) -> tuple[int, dict]:
        auth, action = req.get("auth", {}), req.get("action", {})
        p, sig = auth.get("payload", {}), auth.get("sig", "")
        work_s = min(float(req.get("work_s", 0.0)), MAX_WORK_S)
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                reason = self._check(p, sig, action, req.get("pop_sig", ""))
                if reason:
                    self._event(kind="REJECTED", scope=p.get("scope"), epoch=p.get("epoch"),
                                reason=reason)
                    self.db.execute("COMMIT")
                    return 403, {"ok": False, "reason": reason}
                if "memory_nonces" in MUT:
                    self.mem_nonces.add(p["nonce"])
                else:
                    self.db.execute("INSERT INTO nonces(nonce) VALUES (?)", (p["nonce"],))
                if work_s:
                    time.sleep(work_s)
                fence = self.db.execute("SELECT epoch FROM fence WHERE scope=?",
                                        (p["scope"],)).fetchone()[0]
                cur = self.db.execute(
                    "INSERT INTO applied(scope, epoch, fence_at_commit, action, t) "
                    "VALUES (?,?,?,?,?)",
                    (p["scope"], p["epoch"], fence, json.dumps(action), time.time()))
                self._event(kind="APPLIED", scope=p["scope"], epoch=p["epoch"],
                            applied_seq=cur.lastrowid)
                self.db.execute("COMMIT")
                return 200, {"ok": True, "reason": "APPLIED", "applied_seq": cur.lastrowid}
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _check(self, p: dict, sig: str, action: dict, pop_sig: str) -> str:
        if not p or ("no_sig" not in MUT and not verify(self.authority_pk, p, sig)):
            return "UNAUTHENTICATED"
        if "no_action" not in MUT and action_hash(action) != p.get("action_hash"):
            return "ACTION_MISMATCH"
        if "no_pop" not in MUT and not verify(p.get("holder_pk", ""),
                                              pop_message(p, action), pop_sig):
            return "NO_PROOF_OF_POSSESSION"
        row = self.db.execute("SELECT epoch FROM fence WHERE scope=?", (p["scope"],)).fetchone()
        if not row:
            return "NO_FENCE"
        fence = row[0]
        lease = self.lease.get(p["scope"])
        if "no_lease" not in MUT and (not lease or lease[0] != fence
                                      or time.monotonic() > lease[1]):
            return "LEASE_EXPIRED"
        if "no_fence_check" not in MUT:
            if p["epoch"] < fence:
                return f"STALE_FENCING_TOKEN({p['epoch']}<{fence})"
            if p["epoch"] > fence:
                return f"UNKNOWN_EPOCH({p['epoch']}>{fence})"
        if "no_nonce" not in MUT and (p["nonce"] in self.mem_nonces or self.db.execute(
                "SELECT 1 FROM nonces WHERE nonce=?", (p["nonce"],)).fetchone()):
            return "NONCE_REUSED"
        return ""

    # ------------------------------------------------------------ inspection
    def state(self) -> dict:
        with self.lock:
            fences = self.db.execute("SELECT scope, epoch FROM fence").fetchall()
            applied = self.db.execute(
                "SELECT seq, scope, epoch, fence_at_commit FROM applied").fetchall()
            events = self.db.execute("SELECT seq, body, prev, hash FROM events").fetchall()
        prev, chain_ok = "0" * 64, True
        for _, body, pv, h in events:
            if pv != prev or hashlib.sha256((pv + body).encode()).hexdigest() != h:
                chain_ok = False
            prev = h
        return {"fences": fences, "applied": applied, "chain_ok": chain_ok,
                "events": [json.loads(b) | {"seq": s} for s, b, _, _ in events]}


def make_handler(res: Resource):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
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
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"ok": False, "reason": "BAD_JSON"})
            if self.path == "/apply":
                return self._send(*res.on_apply(req))
            if self.path == "/fence":
                return self._send(*res.on_fence(req))
            if self.path == "/test/inject_lease":       # harness only: simulates a MITM
                return self._send(*res.on_lease(req))   # substituting a lease answer
            self._send(404, {"ok": False})

        def do_GET(self):
            if self.path == "/state":
                return self._send(200, res.state())
            if self.path == "/health":
                return self._send(200, {"ok": True})
            self._send(404, {"ok": False})
    return H


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--authority-pk", required=True, help="file with hex public key")
    ap.add_argument("--authority", default=None, help="authority URL (omit: never leased)")
    ap.add_argument("--lease-s", type=float, default=1.0)
    a = ap.parse_args()
    res = Resource(a.db, Path(a.authority_pk).read_text().strip(), a.authority, a.lease_s)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(res))
    if a.authority:
        threading.Thread(target=res.lease_loop, daemon=True).start()
    print("READY", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
