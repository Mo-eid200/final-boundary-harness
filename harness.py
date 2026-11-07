#!/usr/bin/env python3
"""Distributed test harness: real authority and resource processes over HTTP.

Run:  python3 harness.py [outdir]
Writes REPORT.md and the resource's hash-chained event log to outdir.
"""
from __future__ import annotations

import json
import os
import random
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from common import get, new_key, pk_hex, pop_message, post, save_sk, sign

HERE = Path(__file__).resolve().parent
LEASE_S, PUSH_TIMEOUT = 1.0, 0.5
RES_NAME = "svc/files"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Cluster:
    def __init__(self, work: Path) -> None:
        self.work = work
        self.procs: list[subprocess.Popen] = []
        self.auth_sk = new_key()
        save_sk(self.auth_sk, work / "authority.key")
        (work / "authority.pub").write_text(pk_hex(self.auth_sk))
        self.rport, self.aport = free_port(), free_port()
        self.R = f"http://127.0.0.1:{self.rport}"
        self.A = f"http://127.0.0.1:{self.aport}"
        self.res_proc = self._start_resource(self.rport, work / "resource.db")
        self.auth_proc = self._spawn([
            "authority.py", "--sk", str(work / "authority.key"),
            "--state", str(work / "authority.json"), "--port", str(self.aport),
            "--resource", self.R, "--lease-s", str(LEASE_S),
            "--push-timeout", str(PUSH_TIMEOUT)])

    def _spawn(self, args: list[str]) -> subprocess.Popen:
        p = subprocess.Popen([sys.executable, str(HERE / args[0]), *args[1:]],
                             cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, env={**os.environ, "PYTHONPATH": str(HERE)})
        self.procs.append(p)
        line = p.stdout.readline()
        if "READY" not in line:
            raise RuntimeError(f"{args[0]} failed: {p.stderr.read()}")
        return p

    def _start_resource(self, port: int, db: Path, leased: bool = True) -> subprocess.Popen:
        args = ["resource.py", "--db", str(db), "--port", str(port),
                "--authority-pk", str(self.work / "authority.pub"), "--lease-s", str(LEASE_S)]
        if leased:
            args += ["--authority", self.A]
        return self._spawn(args)

    def kill_resource(self) -> None:
        self.res_proc.send_signal(signal.SIGKILL)
        self.res_proc.wait()

    def restart_resource(self) -> None:
        self.res_proc = self._start_resource(self.rport, self.work / "resource.db")

    def stop(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()

    # ---------------------------------------------------------------- client side
    def evidence(self, ev_id: str, ttl: float) -> None:
        post(self.A + "/evidence", {"id": ev_id, "ttl_s": ttl})

    def grant(self, principal: str, holder_sk, action: dict, ev_id: str) -> dict:
        r = post(self.A + "/grant", {"principal": principal, "holder_pk": pk_hex(holder_sk),
                                     "action": action, "evidence_id": ev_id})
        return r

    def apply(self, auth: dict, action: dict, holder_sk, work_s: float = 0.0,
              url: str | None = None) -> dict:
        pop = sign(holder_sk, pop_message(auth["payload"], action))
        return post((url or self.R) + "/apply",
                    {"auth": auth, "action": action, "pop_sig": pop, "work_s": work_s},
                    timeout=5)

    def revoke(self, scope: str, reason: str = "test") -> dict:
        return post(self.A + "/revoke", {"scope": scope, "reason": reason}, timeout=5)

    def partition(self, on: bool) -> None:
        post(self.A + "/test/partition", {"on": on})


def act(principal: str) -> dict:
    return {"resource": RES_NAME, "op": "write", "path": f"/{principal}/out.csv"}


# =================================================================== cases
def d0(c: Cluster):
    k = new_key(); c.evidence("ev0", 60)
    a = act("d0"); t = c.grant("d0", k, a, "ev0")["auth"]
    r = c.apply(t, a, k)
    return r["ok"], r["reason"]


def d1(c: Cluster):
    k = new_key(); c.evidence("ev1", 60)
    a = act("d1"); t = c.grant("d1", k, a, "ev1")["auth"]
    rv = c.revoke(t["payload"]["scope"])
    r = c.apply(t, a, k)
    return (rv["status"] == "EFFECTIVE" and not r["ok"]), f"revoke={rv['status']}; {r['reason']}"


def d2(c: Cluster):
    k = new_key(); c.evidence("ev2", 1.0)
    a = act("d2"); t = c.grant("d2", k, a, "ev2")["auth"]
    time.sleep(1.6)
    r = c.apply(t, a, k)
    rec = get(c.A + "/evidence/ev2")
    g = c.grant("d2", k, a, "ev2")
    kept = rec.get("status") == "VERIFIED" and rec["valid_until"] < time.time()
    ok = (not r["ok"]) and kept and not g["ok"]
    return ok, f"{r['reason']}; history_kept={kept}; new_grant={g.get('reason')}"


def d3(c: Cluster, trials: int = 150):
    """Revoke and apply are fired concurrently at random offsets.

    Checked two ways: (a) over the resource's serialized log, every APPLIED
    event carries the fence in force at that moment; (b) from the client side,
    no apply sent after revoke() returned EFFECTIVE may succeed."""
    k = new_key(); c.evidence("ev3", 600)
    a = act("d3"); rng = random.Random(3)
    applied = rejected = client_violations = 0
    for _ in range(trials):
        t = c.grant("d3", k, a, "ev3")["auth"]
        scope = t["payload"]["scope"]
        d_rev, d_app = rng.uniform(0, 0.02), rng.uniform(0, 0.02)
        box = {}

        def do_revoke():
            time.sleep(d_rev)
            r = c.revoke(scope, "race")
            box["rev_done"] = time.time() if r.get("status") == "EFFECTIVE" else None

        th = threading.Thread(target=do_revoke)
        th.start()
        time.sleep(d_app)
        sent = time.time()
        r = c.apply(t, a, k, work_s=0.005)
        th.join()
        applied += r["ok"]; rejected += not r["ok"]
        if r["ok"] and box.get("rev_done") and sent > box["rev_done"]:
            client_violations += 1
    st = get(c.R + "/state", timeout=10)
    fence, log_violations = {}, 0
    for e in st["events"]:
        if e["kind"] == "FENCE":
            fence[e["scope"]] = e["epoch"]
        elif e["kind"] == "APPLIED" and e["epoch"] != fence.get(e["scope"]):
            log_violations += 1
    log_violations += sum(1 for row in st["applied"] if row[2] != row[3])
    ok = (log_violations == 0 and client_violations == 0 and st["chain_ok"]
          and applied > 0 and rejected > 0)          # both outcomes must occur
    return ok, (f"log_violations={log_violations}; client_violations={client_violations}; "
                f"applied={applied}; rejected={rejected}; chain_ok={st['chain_ok']}")


def d4(c: Cluster):
    k = new_key(); c.evidence("ev4", 60)
    a = act("d4"); t = c.grant("d4", k, a, "ev4")["auth"]
    r = c.apply(t, {**a, "op": "delete"}, k)
    return not r["ok"], r["reason"]


def d5(c: Cluster):
    k = new_key(); c.evidence("ev5", 60)
    a = act("d5"); t = c.grant("d5", k, a, "ev5")["auth"]
    r1, r2 = c.apply(t, a, k), c.apply(t, a, k)
    return r1["ok"] and not r2["ok"], f"first={r1['reason']}; second={r2['reason']}"


def d6(c: Cluster):
    k, atk = new_key(), new_key(); c.evidence("ev6", 60)
    a = act("d6"); t = c.grant("d6", k, a, "ev6")["auth"]
    forged = {**t["payload"], "epoch": 999}
    r1 = c.apply({"payload": forged, "sig": t["sig"]}, a, k)
    r2 = c.apply({"payload": forged, "sig": sign(atk, forged)}, a, k)
    fab = {**t["payload"], "holder_pk": pk_hex(atk), "nonce": "f" * 32}
    r4 = c.apply({"payload": fab, "sig": sign(atk, fab)}, a, atk)  # current epoch, own key
    r3 = c.apply(t, a, k)
    ok = not r1["ok"] and not r2["ok"] and not r4["ok"] and r3["ok"]
    return ok, (f"inflated={r1['reason']}; attacker_signed={r2['reason']}; "
                f"fabricated_current_epoch={r4['reason']}; legit_after={r3['reason']}")


def d7(c: Cluster):
    k, atk = new_key(), new_key(); c.evidence("ev7", 60)
    a = act("d7"); t = c.grant("d7", k, a, "ev7")["auth"]
    r1 = c.apply(t, a, atk)                                   # stolen token, own PoP key
    swapped = {**t["payload"], "holder_pk": pk_hex(atk)}
    r2 = c.apply({"payload": swapped, "sig": t["sig"]}, a, atk)  # rebinding to attacker
    r3 = c.apply(t, a, k)                                     # owner still can act
    ok = not r1["ok"] and not r2["ok"] and r3["ok"]
    return ok, f"{r1['reason']}; {r2['reason']}; owner_after={r3['reason']}"


def d8(c: Cluster):
    k = new_key(); c.evidence("ev8", 600)
    a = act("d8")
    t_old = c.grant("d8", k, a, "ev8")["auth"]
    rv = c.revoke(t_old["payload"]["scope"])
    t1 = c.grant("d8", k, a, "ev8")["auth"]
    ok1 = c.apply(t1, a, k)["ok"]
    t2 = c.grant("d8", k, a, "ev8")["auth"]
    c.partition(True)
    c.kill_resource(); c.restart_resource()
    r_closed = c.apply(t2, a, k)                              # no lease after restart
    c.partition(False); time.sleep(LEASE_S)                   # renewal arrives
    r_replay, r_stale, r_ok = c.apply(t1, a, k), c.apply(t_old, a, k), c.apply(t2, a, k)
    chain = get(c.R + "/state", timeout=10)["chain_ok"]
    ok = (rv["status"] == "EFFECTIVE" and ok1 and not r_closed["ok"]
          and not r_replay["ok"] and not r_stale["ok"] and r_ok["ok"] and chain)
    return ok, (f"after_restart={r_closed['reason']}; replay={r_replay['reason']}; "
                f"old_epoch={r_stale['reason']}; valid={r_ok['reason']}; chain_ok={chain}")


def d9(c: Cluster, replay_lease: bool = False):
    """Partition between authority and resource, then revoke.

    revoke() must report PENDING (not EFFECTIVE), old-epoch tokens may be
    accepted only until revoke_time + lease_s, after which the resource fails
    closed. With replay_lease, an attacker also injects a genuine signed lease
    answer captured before the partition; it must be refused."""
    k = new_key(); principal = "d10" if replay_lease else "d9"
    ev = "ev10" if replay_lease else "ev9"
    c.evidence(ev, 600); a = act(principal)
    toks = [c.grant(principal, k, a, ev)["auth"] for _ in range(60)]
    time.sleep(0.4)
    captured = post(c.A + "/lease", {"challenge": "attacker-" + os.urandom(4).hex()})
    c.partition(True)
    rv = c.revoke(toks[0]["payload"]["scope"], "revoked during partition")
    t_rev = rv.get("effective_by", 0) - LEASE_S
    replay = post(c.R + "/test/inject_lease", captured) if replay_lease else None
    accepted_at, first_reject = [], None
    for t in toks[:-1]:
        r = c.apply(t, a, k)
        now = time.time()
        if r["ok"]:
            accepted_at.append(now)
        else:
            first_reject = (now, r["reason"])
            break
        time.sleep(0.05)
    late = [x for x in accepted_at if x > rv.get("effective_by", 0)]
    c.partition(False); time.sleep(LEASE_S)
    after = c.apply(toks[-1], a, k)
    window = (accepted_at[-1] - t_rev) if accepted_at else 0.0
    ok = (rv["status"] == "PENDING" and not late and first_reject is not None
          and first_reject[1] == "LEASE_EXPIRED" and not after["ok"]
          and (replay is None or replay.get("reason") == "UNSOLICITED_LEASE"))
    detail = (f"revoke={rv['status']}; old epoch accepted until +{window:.2f}s after revoke "
              f"(bound {LEASE_S:.1f}s); then {first_reject[1] if first_reject else None}; "
              f"after heal={after['reason']}")
    if replay is not None:
        detail = f"injected captured lease={replay.get('reason')}; " + detail
    return ok, detail


def d10(c: Cluster):
    return d9(c, replay_lease=True)


def d11(c: Cluster):
    k = new_key(); c.evidence("ev11", 60)
    a = act("d11"); t = c.grant("d11", k, a, "ev11")["auth"]
    port = free_port()
    p = c._start_resource(port, c.work / "fresh.db", leased=False)
    try:
        r = c.apply(t, a, k, url=f"http://127.0.0.1:{port}")
    finally:
        p.kill(); p.wait()
    return not r["ok"], r["reason"]


def d12(c: Cluster):
    atk = new_key()
    n = {"scope": "d12@svc/files", "epoch": 10**6, "seq": 10**9, "issued_at": time.time()}
    r1 = post(c.R + "/fence", {"notice": n, "sig": sign(atk, n)})
    body = {"challenge": "x", "lease_s": 3600, "epochs": {"d12@svc/files": 1},
            "issued_at": time.time()}
    r2 = post(c.R + "/test/inject_lease", {"body": body, "sig": sign(atk, body)})
    return (not r1.get("ok") and not r2.get("ok")), f"notice={r1.get('reason')}; lease={r2.get('reason')}"


CASES = [
    ("D0", "Control: valid authorization executes", d0),
    ("D1", "Revoked before execution (revoke acknowledged)", d1),
    ("D2", "VERIFIED evidence expires: auto-revocation, history kept, no new grants", d2),
    ("D3", "Revocation races execution across processes (150 trials)", d3),
    ("D4", "Authorization for action A presented for action B", d4),
    ("D5", "Replay of a valid token at the resource", d5),
    ("D6", "Forged tokens: inflated epoch, attacker-signed, fabricated for the current epoch", d6),
    ("D7", "Stolen valid token used by another party; holder rebinding", d7),
    ("D8", "Resource killed (SIGKILL) and restarted: durable fence and nonces, fail-closed", d8),
    ("D9", "Network partition: revoke PENDING, old epoch stops within lease bound", d9),
    ("D10", "Partition + attacker injects a genuine lease answer captured earlier", d10),
    ("D11", "Resource that never received a fence", d11),
    ("D12", "Fence notice and lease answer signed by an attacker", d12),
]


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "out_v2")
    out.mkdir(parents=True, exist_ok=True)
    rows, all_ok = [], True
    with tempfile.TemporaryDirectory() as td:
        c = Cluster(Path(td))
        try:
            for cid, title, fn in CASES:
                t0 = time.time()
                try:
                    ok, detail = fn(c)
                except Exception as e:  # a crash is a failure, not a skip
                    ok, detail = False, f"ERROR {type(e).__name__}: {e}"
                all_ok &= ok
                rows.append((cid, title, ok, detail))
                print(f"{cid:4s} {'PASS' if ok else 'FAIL'}  {detail}  [{time.time()-t0:.1f}s]",
                      flush=True)
            st = get(c.R + "/state", timeout=10)
            (out / "resource_events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in st["events"]))
        finally:
            c.stop()
    lines = ["# Distributed final-boundary harness: results", "",
             f"Authority and resource run as separate OS processes over HTTP. "
             f"Lease {LEASE_S}s (pull-based, challenge-response), push timeout "
             f"{PUSH_TIMEOUT}s, Ed25519 throughout.", "",
             "| Case | Scenario | Result | Evidence |", "|---|---|---|---|"]
    lines += [f"| {c_} | {t} | **{'PASS' if ok else 'FAIL'}** | {d} |" for c_, t, ok, d in rows]
    lines += ["", f"All cases pass: **{all_ok}**"]
    (out / "REPORT.md").write_text("\n".join(lines) + "\n")
    print(f"\nall pass: {all_ok}   report: {out / 'REPORT.md'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
