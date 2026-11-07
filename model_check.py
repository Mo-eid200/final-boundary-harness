#!/usr/bin/env python3
"""Exhaustive explicit-state model check of the final-boundary protocol.

The abstract model mirrors authority.py and resource.py. Breadth-first search
visits EVERY reachable state within the bounds below and checks four safety
properties on every apply. The adversary controls the network completely:

  * any message ever sent can be delivered at any later time, any number of
    times, in any order (delay, reordering, duplication, replay);
  * the attacker can obtain a genuine lease answer for a challenge of its own;
  * the attacker can submit a forged token (signatures are assumed unforgeable,
    so the forged token is modelled as unsigned);
  * any issued token can be submitted at any time, any number of times;
  * the resource can crash at any moment (memory lost, durable state kept);
  * revocations, lease requests, clock ticks and applies interleave freely.

Safety properties, checked whenever an action is applied:
  P1 AUTH      only authority-issued tokens are ever applied
  P2 ONCE      no token is applied twice
  P3 KNOWN     no token is applied once the resource knows a newer epoch
  P4 BOUNDED   no token of epoch e is applied later than
               (time epoch e+1 was issued) + LEASE, even if the revocation
               never reaches the resource

Then every defence is removed one at a time (mutation testing): the checker
must find a counterexample trace for each one, and prints the shortest.

Run:  python3 model_check.py
"""
from __future__ import annotations

import sys
import time
from collections import deque
from typing import NamedTuple, Optional

T_MAX, LEASE, E_MAX, C_MAX, CRASH_MAX = 6, 2, 3, 2, 1

# Sound reductions (no behaviour is lost):
#  * tokens of the same epoch are interchangeable, so the model offers, at any
#    time, a FRESH token of every epoch that has existed (e <= a_ep) and a
#    REPLAY of any token already consumed; consumed tokens are tracked per epoch;
#  * every fence notice ever sent is exactly {1..a_ep}, so notices need no state;
#  * a forged token can be submitted at any time, so it needs no state either.


class S(NamedTuple):
    t: int                      # global clock (ticks)
    a_ep: int                   # authority epoch
    rev_t: tuple                # rev_t[e] = time epoch e was issued
    fence: int                  # resource fence (durable)
    known: int                  # ghost: highest fence the resource has ever held
    lease: Optional[tuple]      # (epoch, deadline) in resource memory
    outstanding: frozenset      # {(cid, send_t)} in resource memory
    next_cid: int
    requests: frozenset         # lease requests in flight to the authority
    answers: frozenset          # {(cid, epoch)} ever sent: replayable forever
    consumed: frozenset         # epochs whose (representative) token nonce is consumed
    ever: frozenset             # ghost: epochs whose token was ever applied
    crashes: int


def init() -> S:
    return S(t=0, a_ep=1, rev_t=(None, 0), fence=0, known=0, lease=None,
             outstanding=frozenset(), next_cid=0, requests=frozenset(),
             answers=frozenset(), consumed=frozenset(), ever=frozenset(), crashes=0)


def lease_ok(s: S, M: set) -> bool:
    return "no_lease" in M or bool(s.lease and s.lease[0] == s.fence and s.t <= s.lease[1])


def successors(s: S, M: set):
    """Yield (label, next_state, violation_or_None)."""
    # --- clock
    if s.t < T_MAX:
        yield "tick", s._replace(t=s.t + 1), None
    # --- authority revokes (its notice joins {1..a_ep}; delivery is up to the network)
    if s.a_ep < E_MAX:
        yield f"revoke->e{s.a_ep + 1}", s._replace(a_ep=s.a_ep + 1, rev_t=s.rev_t + (s.t,)), None
    # --- attacker obtains a genuine lease answer for its own challenge
    if ("atk", s.a_ep) not in s.answers:
        yield f"attacker gets lease@e{s.a_ep}", s._replace(answers=s.answers | {("atk", s.a_ep)}), None
    # --- resource sends a lease request with a fresh challenge
    if s.next_cid < C_MAX:
        c = s.next_cid
        yield f"resource requests lease c{c}", s._replace(
            next_cid=c + 1, outstanding=s.outstanding | {(c, s.t)},
            requests=s.requests | {c}), None
    # --- authority answers a request (with its epoch at that moment)
    for c in s.requests:
        yield f"authority answers c{c}@e{s.a_ep}", s._replace(
            requests=s.requests - {c}, answers=s.answers | {(c, s.a_ep)}), None
    # --- network delivers any fence notice ever sent (replay allowed)
    for e in range(1, s.a_ep + 1):
        new = e if "fence_non_monotonic" in M else max(s.fence, e)
        if new == s.fence:
            continue
        yield f"deliver notice e{e}", s._replace(fence=new, known=max(s.known, new),
                                                 lease=None), None
    # --- network delivers any lease answer ever sent (replay allowed)
    for (c, e) in s.answers:
        sent = next((st for (cc, st) in s.outstanding if cc == c), None)
        if sent is None:
            if "no_challenge" not in M:
                continue                                  # UNSOLICITED_LEASE
            sent = s.t
        if "lease_from_receive" in M:
            sent = s.t
        out = frozenset(x for x in s.outstanding if x[0] != c and x[1] >= sent)
        fence = max(s.fence, e)
        lease = s.lease if fence == s.fence else None
        if e == fence:
            lease = (fence, sent + LEASE)
        yield f"deliver lease c{c}@e{e}", s._replace(fence=fence, known=max(s.known, fence),
                                                     lease=lease, outstanding=out), None
    # --- resource crashes (memory lost, durable fence and nonces kept)
    if s.crashes < CRASH_MAX:
        yield "resource crash+restart", s._replace(
            crashes=s.crashes + 1, lease=None, outstanding=frozenset(),
            consumed=frozenset() if "memory_nonces" in M else s.consumed), None
    # --- apply: forged token, fresh token of any past/current epoch, or a replay
    if lease_ok(s, M):
        cands = [("forged", s.a_ep, False, False)]
        cands += [(f"fresh@e{e}", e, True, False) for e in range(1, s.a_ep + 1)]
        cands += [(f"replay@e{e}", e, True, True) for e in s.ever]
        for name, e, signed, replay in cands:
            if not signed and "no_sig" not in M:
                continue
            if "no_fence_check" not in M and e != s.fence:
                continue
            if replay and "no_nonce" not in M and e in s.consumed:
                continue
            v = None
            if not signed:
                v = "P1 AUTH: forged token applied"
            elif replay:
                v = f"P2 ONCE: token of epoch {e} applied twice"
            elif e < s.known:
                v = f"P3 KNOWN: token of epoch {e} applied after the resource learned epoch {s.known}"
            elif e < s.a_ep and s.t > s.rev_t[e + 1] + LEASE:
                v = (f"P4 BOUNDED: token of epoch {e} applied at t={s.t}, revoked at "
                     f"t={s.rev_t[e + 1]}, bound {s.rev_t[e + 1] + LEASE}")
            n = s._replace(consumed=s.consumed | {e}, ever=s.ever | {e})
            yield f"apply {name}", n, v


def check(M: set) -> tuple[int, Optional[list]]:
    start = init()
    parent = {start: None}
    q = deque([start])
    while q:
        s = q.popleft()
        for label, n, v in successors(s, M):
            if v:
                trace, cur = [(label, v)], s
                while parent[cur] is not None:
                    prev, lab = parent[cur]
                    trace.append((lab, None))
                    cur = prev
                return len(parent), list(reversed(trace))
            if n not in parent:
                parent[n] = (s, label)
                q.append(n)
    return len(parent), None


MUTATIONS = [
    ("no_sig", "resource skips the authority signature"),
    ("no_nonce", "resource skips the nonce check"),
    ("memory_nonces", "nonces lost on crash (not durable)"),
    ("no_fence_check", "resource ignores the epoch fence"),
    ("no_lease", "resource ignores leases"),
    ("no_challenge", "resource accepts lease answers it did not request"),
    ("lease_from_receive", "lease runs from RECEIVE time instead of SEND time"),
    ("fence_non_monotonic", "a replayed old notice may lower the fence"),
]


def main() -> int:
    print(f"bounds: T_MAX={T_MAX} LEASE={LEASE} E_MAX={E_MAX} C_MAX={C_MAX} "
          f"CRASH_MAX={CRASH_MAX}")
    t0 = time.time()
    n, trace = check(set())
    ok = trace is None
    print(f"\nPROTOCOL: {'all properties hold' if ok else 'VIOLATION'} "
          f"in {n:,} reachable states ({time.time() - t0:.1f}s)")
    lines = ["# Exhaustive model check", "",
             f"Bounds: clock 0..{T_MAX}, lease {LEASE}, epochs up to {E_MAX}, "
             f"{C_MAX} lease challenges, unlimited tokens of every epoch, forged tokens, "
             f"{CRASH_MAX} crash; "
             "adversarial network (delay, reorder, duplicate, replay).", "",
             f"**Protocol:** {'all four safety properties hold' if ok else 'VIOLATION'} "
             f"in every one of {n:,} reachable states.", "",
             "### Mutation testing (each defence removed alone)", "",
             "| Mutation | Defence removed | Result | Shortest counterexample |",
             "|---|---|---|---|"]
    all_killed = True
    for m, desc in MUTATIONS:
        t1 = time.time()
        nm, tr = check({m})
        killed = tr is not None
        all_killed &= killed
        steps = " → ".join(lab for lab, _ in tr) if tr else "none found"
        viol = tr[-1][1] if tr else ""
        print(f"  {m:20s} {'KILLED' if killed else 'SURVIVED'} ({nm:,} states, "
              f"{time.time() - t1:.1f}s)\n      {viol}\n      {steps}")
        lines.append(f"| `{m}` | {desc} | **{'KILLED' if killed else 'SURVIVED'}** | "
                     f"{steps}<br>⇒ {viol} |")
    lines += ["", f"All mutations killed: **{all_killed}**"]
    out = sys.argv[1] if len(sys.argv) > 1 else "MODEL_CHECK.md"
    open(out, "w").write("\n".join(lines) + "\n")
    print(f"\nall mutations killed: {all_killed}")
    return 0 if ok and all_killed else 1


if __name__ == "__main__":
    sys.exit(main())
