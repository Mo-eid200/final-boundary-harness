#!/usr/bin/env python3
"""
Final-boundary authority revalidation: a reference test harness.

Question under test
    Does the executor check the *current* authoritative state for the *exact*
    action at the final boundary, so that a valid past authorization never
    silently becomes permission to act in the present?

Design (standard library only, Python 3.9+)
    Authority      issues signed authorizations bound to (principal, resource),
                   an action hash, an authorization EPOCH and an evidence id.
                   Revocation increments the epoch. Evidence records are never
                   deleted: an expired VERIFIED record stays readable but
                   grants nothing new.
    Resource       enforces a FENCING TOKEN: it rejects any request whose epoch
                   is lower than the highest epoch it has already accepted, so a
                   revocation wins even against a slow or buggy executor.
    NaiveExecutor  signature + nonce only (the state that is already tested).
    FencedExecutor signature, exact action hash, then, atomically with the
                   action itself: nonce consume, epoch == current epoch,
                   evidence valid *now*, fenced write.

Every case is run against both executors. The naive executor is a negative
control: the suite is only meaningful if it FAILS where expected.

Outputs
    evidence_<executor>.jsonl   hash-chained, append-only event log
    REPORT.md                   expected vs observed outcome for every case
Exit code 0 iff the fenced executor passes every case AND the naive control
fails every case it is supposed to fail.

Changelog
    v1.2  The resource is the single enforcement point: it also consumes the
          nonce and checks evidence validity (C9, C10: both bypassable in
          v1.1 by calling the resource directly). Ed25519 signatures when the
          `cryptography` package is installed, so verifiers cannot mint tokens.
    v1.1  The resource is treated as part of the adversarial boundary:
          revocation is pushed to the resource, and the resource verifies the
          signature, the exact action and epoch == published fence. Adds C7
          and C8, both reported by Krzysztof Śliwka in a review of v1.0.
    v1.0  Initial release (C0-C6).

Signatures use HMAC-SHA256 to stay dependency-free; swap sign()/verify() for
Ed25519 (or your existing signing path) without changing anything else.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import random
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


try:  # asymmetric: verifiers (executor, resource) hold only the public key
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _SK = Ed25519PrivateKey.generate()
    _PK = _SK.public_key()
    SIG_SCHEME = "Ed25519"

    def sign(payload: dict) -> str:
        return _SK.sign(canon(payload)).hex()

    def verify(payload: dict, sig: str) -> bool:
        try:
            _PK.verify(bytes.fromhex(sig), canon(payload))
            return True
        except (InvalidSignature, ValueError):
            return False
except ImportError:  # stdlib fallback: shared key, so verifiers could also mint
    _KEY = secrets.token_bytes(32)
    SIG_SCHEME = "HMAC-SHA256 (fallback: pip install cryptography for Ed25519)"

    def sign(payload: dict) -> str:
        return hmac.new(_KEY, canon(payload), hashlib.sha256).hexdigest()

    def verify(payload: dict, sig: str) -> bool:
        return hmac.compare_digest(sign(payload), sig)


def action_hash(action: dict) -> str:
    return hashlib.sha256(canon(action)).hexdigest()


class Clock:
    """Injectable clock so expiry can be tested deterministically."""

    def __init__(self) -> None:
        self._offset = 0.0

    def now(self) -> float:
        return time.time() + self._offset

    def advance(self, seconds: float) -> None:
        self._offset += seconds


class EvidenceLog:
    """Append-only, hash-chained event log (tamper-evident)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.entries: list[dict] = []
        self._prev = "0" * 64
        self._seq = 0

    def append(self, event: str, **fields) -> dict:
        with self._lock:
            self._seq += 1
            entry = {"seq": self._seq, "t": time.time(), "event": event, **fields,
                     "prev": self._prev}
            entry["hash"] = hashlib.sha256(canon(entry)).hexdigest()
            self._prev = entry["hash"]
            self.entries.append(entry)
            return entry

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev or hashlib.sha256(canon(body)).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True

    def dump(self, path: Path) -> None:
        path.write_text("".join(json.dumps(e) + "\n" for e in self.entries))


# --------------------------------------------------------------------------
# authority, resource
# --------------------------------------------------------------------------
class Authority:
    def __init__(self, clock: Clock, log: EvidenceLog) -> None:
        self.lock = threading.RLock()          # the final-boundary lock
        self.clock, self.log = clock, log
        self._epoch: dict[str, int] = {}
        self._evidence: dict[str, dict] = {}
        self.resources: list = []              # fenced resources to notify

    @staticmethod
    def scope(principal: str, resource: str) -> str:
        return f"{principal}@{resource}"

    def current_epoch(self, scope: str) -> int:
        with self.lock:
            return self._epoch.setdefault(scope, 1)

    def add_evidence(self, evidence_id: str, ttl_s: float) -> None:
        with self.lock:
            rec = {"id": evidence_id, "status": "VERIFIED",
                   "verified_at": self.clock.now(),
                   "valid_until": self.clock.now() + ttl_s}
            self._evidence[evidence_id] = rec
            self.log.append("EVIDENCE_VERIFIED", **rec)

    def evidence_record(self, evidence_id: str) -> Optional[dict]:
        """Historical record: always readable, never deleted."""
        with self.lock:
            rec = self._evidence.get(evidence_id)
            return dict(rec) if rec else None

    def evidence_valid_now(self, evidence_id: str) -> bool:
        rec = self.evidence_record(evidence_id)
        return bool(rec and rec["status"] == "VERIFIED"
                    and self.clock.now() <= rec["valid_until"])

    def grant(self, principal: str, action: dict, evidence_id: str) -> dict:
        with self.lock:
            sc = self.scope(principal, action["resource"])
            payload = {"principal": principal, "scope": sc,
                       "action_hash": action_hash(action),
                       "epoch": self.current_epoch(sc),
                       "evidence_id": evidence_id,
                       "nonce": secrets.token_hex(16),
                       "issued_at": self.clock.now()}
            auth = {"payload": payload, "sig": sign(payload)}
            self.log.append("GRANTED", **payload)
            return auth

    def revoke(self, principal: str, resource: str, reason: str) -> int:
        with self.lock:                        # blocks while an action commits
            sc = self.scope(principal, resource)
            self._epoch[sc] = self.current_epoch(sc) + 1
            for res in self.resources:         # push the new fence
                res.advance_fence(sc, self._epoch[sc])
            self.log.append("REVOKED", scope=sc, new_epoch=self._epoch[sc],
                            reason=reason)
            return self._epoch[sc]


class Resource:
    """The resource is part of the adversarial boundary: any caller may reach
    it directly, so a fenced resource trusts nothing it cannot verify itself.

    * Revocation is PUSHED to the resource (its fence advances at revoke time),
      so a revoked epoch is rejected even before any newer-epoch write (C7).
    * Every request must carry a validly signed authorization for the exact
      action, and its epoch must EQUAL the fence the authority has published.
      A forged or unannounced higher epoch is rejected, so an attacker can
      neither act nor lock out legitimate callers by inflating the epoch (C8).
    * The resource is the single enforcement point: it also consumes the
      nonce (C9) and requires the evidence to be valid now (C10), so going
      around the executor gains an attacker nothing.
    """

    def __init__(self, log: EvidenceLog, fenced: bool,
                 authority: Optional["Authority"] = None) -> None:
        self.log, self.fenced, self.authority = log, fenced, authority
        self._lock = threading.Lock()
        self._fence: dict[str, int] = {}
        self._nonces: set[str] = set()
        self.applied: list[dict] = []

    def advance_fence(self, scope: str, epoch: int) -> None:
        """Called by the authority on revocation (authenticated channel)."""
        with self._lock:
            self._fence[scope] = max(self._fence.get(scope, 1), epoch)

    def apply(self, auth: dict, action: dict,
              work_s: float = 0.0) -> tuple[bool, str]:
        p = auth["payload"]
        scope, ep = p["scope"], p["epoch"]
        with self._lock:
            if self.fenced:
                if not verify(p, auth["sig"]):
                    return False, "UNAUTHENTICATED"
                if action_hash(action) != p["action_hash"]:
                    return False, "ACTION_MISMATCH"
                fence = self._fence.get(scope, 1)
                if ep < fence:
                    return False, f"STALE_FENCING_TOKEN({ep}<{fence})"
                if ep > fence:
                    return False, f"UNKNOWN_EPOCH({ep}>{fence})"
                if p["nonce"] in self._nonces:
                    return False, "NONCE_REUSED_AT_RESOURCE"
                self._nonces.add(p["nonce"])
                if self.authority and not self.authority.evidence_valid_now(p["evidence_id"]):
                    return False, "EVIDENCE_EXPIRED_AT_RESOURCE"
            if work_s:
                time.sleep(work_s)             # the action takes real time
            self.applied.append({"scope": scope, "epoch": ep, **action})
            return True, "APPLIED"


# --------------------------------------------------------------------------
# executors
# --------------------------------------------------------------------------
@dataclass
class Outcome:
    executed: bool
    reason: str
    epoch_used: int = 0
    epoch_at_commit: int = 0


Hook = Optional[Callable[[], None]]


class NaiveExecutor:
    """Signature + nonce only: what is demonstrated today."""
    name = "naive"

    def __init__(self, authority: Authority, resource: Resource, log: EvidenceLog):
        self.a, self.r, self.log = authority, resource, log
        self._nonces: set[str] = set()
        self._nlock = threading.Lock()

    def execute(self, auth: dict, action: dict, between: Hook = None,
                work_s: float = 0.0) -> Outcome:
        p = auth["payload"]
        if not verify(p, auth["sig"]):
            return self._done(p, False, "BAD_SIGNATURE")
        with self._nlock:
            if p["nonce"] in self._nonces:
                return self._done(p, False, "NONCE_REUSED")
            self._nonces.add(p["nonce"])
        if between:
            between()                          # latency: decision -> boundary
        ok, why = self.r.apply(auth, action, work_s)
        return self._done(p, ok, why)

    def _done(self, p: dict, ok: bool, why: str) -> Outcome:
        cur = self.a.current_epoch(p["scope"])
        self.log.append("EXECUTED" if ok else "REJECTED", executor=self.name,
                        scope=p["scope"], epoch_used=p["epoch"],
                        epoch_at_commit=cur, reason=why)
        return Outcome(ok, why, p["epoch"], cur)


class FencedExecutor(NaiveExecutor):
    """Re-validates current authority for the exact action, atomically."""
    name = "fenced"

    def execute(self, auth: dict, action: dict, between: Hook = None,
                work_s: float = 0.0) -> Outcome:
        p = auth["payload"]
        if not verify(p, auth["sig"]):
            return self._done(p, False, "BAD_SIGNATURE")
        if action_hash(action) != p["action_hash"]:
            return self._done(p, False, "ACTION_MISMATCH")
        if between:
            between()                          # latency: decision -> boundary
        # ---- final boundary: check and act under one lock -----------------
        with self.a.lock:
            with self._nlock:
                if p["nonce"] in self._nonces:
                    return self._done(p, False, "NONCE_REUSED")
                self._nonces.add(p["nonce"])   # consumed even if rejected below
            cur = self.a.current_epoch(p["scope"])
            if p["epoch"] != cur:
                return self._done(p, False, f"EPOCH_MISMATCH(granted={p['epoch']},current={cur})")
            if not self.a.evidence_valid_now(p["evidence_id"]):
                return self._done(p, False, "EVIDENCE_EXPIRED")
            ok, why = self.r.apply(auth, action, work_s)
            return self._done(p, ok, why)


# --------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------
PRINCIPAL, RES = "agent-7", "svc/files"
ACTION = {"resource": RES, "op": "write", "path": "/reports/q3.csv"}


def world(executor_cls, fenced_resource: bool):
    log, clock = EvidenceLog(), Clock()
    a = Authority(clock, log)
    r = Resource(log, fenced=fenced_resource, authority=a)
    a.resources.append(r)
    a.add_evidence("ev-1", ttl_s=3600)
    return a, r, executor_cls(a, r, log), clock, log


def case_c0(cls, fenced):
    a, r, ex, *_ = world(cls, fenced)
    o = ex.execute(a.grant(PRINCIPAL, ACTION, "ev-1"), ACTION)
    return o.executed, o.reason


def case_c1(cls, fenced):
    a, r, ex, *_ = world(cls, fenced)
    auth = a.grant(PRINCIPAL, ACTION, "ev-1")
    o = ex.execute(auth, ACTION,
                   between=lambda: a.revoke(PRINCIPAL, RES, "operator revoked"))
    return not o.executed, o.reason


def case_c2(cls, fenced):
    a, r, ex, clock, _ = world(cls, fenced)
    auth = a.grant(PRINCIPAL, ACTION, "ev-1")
    o = ex.execute(auth, ACTION, between=lambda: clock.advance(7200))
    rec = a.evidence_record("ev-1")
    history_kept = bool(rec and rec["status"] == "VERIFIED"
                        and rec["valid_until"] < clock.now())
    return (not o.executed) and history_kept, f"{o.reason}; history_kept={history_kept}"


def case_c3(cls, fenced, trials: int = 300):
    """Revocation races the action.

    Property: no action may complete after a revocation for its scope has been
    recorded. Revocations land at random times before, during or after the
    action; the fenced executor linearizes them (a revocation waits for an
    in-flight commit, or the commit sees the new epoch and refuses)."""
    violations = 0
    rng = random.Random(7)
    for _ in range(trials):
        a, r, ex, *_ = world(cls, fenced)
        auth = a.grant(PRINCIPAL, ACTION, "ev-1")
        delay = rng.uniform(0, 0.008)
        t = threading.Thread(target=lambda: (time.sleep(delay),
                                             a.revoke(PRINCIPAL, RES, "race")))
        t.start()
        o = ex.execute(auth, ACTION, between=lambda: time.sleep(0.002),
                       work_s=0.002)
        t.join()
        if o.executed and o.epoch_used != o.epoch_at_commit:
            violations += 1
    return violations == 0, f"stale_commits={violations}/{trials}"


def case_c4(cls, fenced):
    a, r, ex, *_ = world(cls, fenced)
    auth = a.grant(PRINCIPAL, ACTION, "ev-1")
    other = {**ACTION, "op": "delete"}
    o = ex.execute(auth, other)
    return not o.executed, o.reason


def case_c5(cls, fenced):
    a, r, ex, *_ = world(cls, fenced)
    auth = a.grant(PRINCIPAL, ACTION, "ev-1")
    ex.execute(auth, ACTION)
    o = ex.execute(auth, ACTION)
    return not o.executed, o.reason


def case_c6(cls, fenced):
    """A stale token reaches the resource directly, bypassing the executor."""
    a, r, ex, *_ = world(cls, fenced)
    old = a.grant(PRINCIPAL, ACTION, "ev-1")
    a.revoke(PRINCIPAL, RES, "rotate")
    ex.execute(a.grant(PRINCIPAL, ACTION, "ev-1"), ACTION)       # epoch 2 lands
    ok, why = r.apply(old, ACTION)
    return not ok, why


def case_c7(cls, fenced):
    """Revoked authorization reaches the resource directly BEFORE any
    newer-epoch write (reported by K. Śliwka against v1.0)."""
    a, r, ex, *_ = world(cls, fenced)
    old = a.grant(PRINCIPAL, ACTION, "ev-1")
    a.revoke(PRINCIPAL, RES, "revoked, no newer write yet")
    ok, why = r.apply(old, ACTION)
    return not ok, why


def case_c8(cls, fenced):
    """Unauthenticated higher-epoch request reaches the resource directly
    (reported by K. Śliwka against v1.0). Two variants: an inflated epoch on
    a stolen signature, and a payload signed with an attacker's own key."""
    a, r, ex, *_ = world(cls, fenced)
    stolen = a.grant(PRINCIPAL, ACTION, "ev-1")
    forged_payload = {**stolen["payload"], "epoch": 999}
    v1 = {"payload": forged_payload, "sig": stolen["sig"]}
    v2 = {"payload": forged_payload,
          "sig": hmac.new(secrets.token_bytes(32), canon(forged_payload),
                          hashlib.sha256).hexdigest()}
    ok1, why1 = r.apply(v1, ACTION)
    ok2, why2 = r.apply(v2, ACTION)
    # the legitimate caller must still be able to act afterwards
    ok3, _ = ex.execute(a.grant(PRINCIPAL, ACTION, "ev-1"), ACTION).executed, None
    return (not ok1) and (not ok2) and ok3, f"{why1}; {why2}; legit_after={ok3}"


def case_c9(cls, fenced):
    """A valid, current authorization is replayed directly at the resource,
    bypassing the executor's nonce check."""
    a, r, ex, *_ = world(cls, fenced)
    auth = a.grant(PRINCIPAL, ACTION, "ev-1")
    ok1, _ = r.apply(auth, ACTION)
    ok2, why2 = r.apply(auth, ACTION)
    return ok1 and not ok2, f"first={'APPLIED' if ok1 else 'REJECTED'}; second={why2}"


def case_c10(cls, fenced):
    """Authorization whose evidence has expired is sent directly to the
    resource, bypassing the executor's evidence check."""
    a, r, ex, clock, _ = world(cls, fenced)
    auth = a.grant(PRINCIPAL, ACTION, "ev-1")
    clock.advance(7200)
    ok, why = r.apply(auth, ACTION)
    return not ok, why


CASES = [
    ("C0", "Control: valid authorization executes", case_c0, False),
    ("C1", "Authorization valid at decision, revoked before execution", case_c1, True),
    ("C2", "VERIFIED evidence expires: record kept, no new authority", case_c2, True),
    ("C3", "Revocation arrives during execution (300 randomized races)", case_c3, True),
    ("C4", "Authorization for action A presented for action B", case_c4, True),
    ("C5", "Replay of a consumed authorization", case_c5, False),
    ("C6", "Stale fencing token reaches the resource directly", case_c6, True),
    ("C7", "Revoked token reaches the resource before any newer-epoch write", case_c7, True),
    ("C8", "Unauthenticated higher-epoch request reaches the resource", case_c8, True),
    ("C9", "Valid current token replayed directly at the resource", case_c9, True),
    ("C10", "Expired-evidence token sent directly to the resource", case_c10, True),
]
# 4th field: True if the naive control is expected to FAIL this case.


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    rows, ok_all = [], True
    for cid, title, fn, naive_should_fail in CASES:
        fp, fr = fn(FencedExecutor, True)
        np_, nr = fn(NaiveExecutor, False)
        naive_expected = (not np_) if naive_should_fail else np_
        ok_all &= fp and naive_expected
        rows.append((cid, title, fp, fr, np_, nr, naive_should_fail))
        print(f"{cid}  fenced={'PASS' if fp else 'FAIL'}  "
              f"naive={'PASS' if np_ else 'FAIL'}  ({fr})")

    # one full run per executor for the archived evidence logs
    for cls, fenced in ((FencedExecutor, True), (NaiveExecutor, False)):
        a, r, ex, clock, log = world(cls, fenced)
        auth = a.grant(PRINCIPAL, ACTION, "ev-1")
        ex.execute(auth, ACTION, between=lambda: a.revoke(PRINCIPAL, RES, "C1 demo"))
        assert log.verify_chain()
        log.dump(out / f"evidence_{cls.name}.jsonl")

    lines = ["# Final-boundary authority revalidation: results", "",
             "Question: does the executor check the current authoritative state "
             "for the exact action at the final boundary?", "",
             "| Case | Scenario | Fenced executor | Naive control (sig + nonce) |",
             "|---|---|---|---|"]
    for cid, title, fp, fr, np_, nr, nsf in rows:
        exp = "expected FAIL" if nsf else "expected PASS"
        lines.append(f"| {cid} | {title} | **{'PASS' if fp else 'FAIL'}**: {fr} "
                     f"| {'PASS' if np_ else 'FAIL'} ({exp}): {nr} |")
    lines += ["", f"Suite valid: **{ok_all}** (fenced passes all; naive control "
              "fails exactly where expected).", "",
              f"Signature scheme: {SIG_SCHEME}.", "",
              "Evidence logs are hash-chained; `EvidenceLog.verify_chain()` "
              "checks integrity."]
    (out / "REPORT.md").write_text("\n".join(lines) + "\n")
    print(f"\nsuite valid: {ok_all}   report: {out / 'REPORT.md'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
