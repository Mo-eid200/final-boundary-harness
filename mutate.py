#!/usr/bin/env python3
"""Mutation testing of the distributed implementation.

Each mutation disables exactly one defence in the real services (via the
FBH_MUTATION fault-injection switch). The full harness is then run against
the mutated system. A defence counts as *necessary and tested* only if the
harness FAILS the case that targets it. A mutation that survives (all cases
still pass) would mean that defence is untested or redundant.

Run:  python3 mutate.py [outdir]
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

MUTATIONS = [
    ("no_sig", "resource skips the authority signature", "D6"),
    ("no_action", "resource skips the exact action hash", "D4"),
    ("no_pop", "resource skips proof of possession", "D7"),
    ("no_lease", "resource ignores leases", "D9"),
    ("no_fence_check", "resource ignores the epoch fence", "D1"),
    ("no_nonce", "resource skips the nonce check", "D5"),
    ("memory_nonces", "nonces kept in memory, not durably", "D8"),
    ("no_challenge", "resource accepts lease answers it did not request", "D10"),
    ("no_notice_sig", "resource accepts unsigned fence notices and leases", "D12"),
    ("no_evidence_revoke", "authority does not revoke on evidence expiry", "D2"),
]


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "out_mutation")
    out.mkdir(parents=True, exist_ok=True)
    rows, killed_all = [], True
    for mut, desc, target in MUTATIONS:
        r = subprocess.run([sys.executable, str(HERE / "harness.py"), str(out / mut)],
                           cwd=HERE, capture_output=True, text=True, timeout=600,
                           env={**os.environ, "FBH_MUTATION": mut})
        failed = re.findall(r"^(D\d+)\s+FAIL", r.stdout, re.M)
        killed = target in failed
        killed_all &= killed
        rows.append((mut, desc, target, killed, failed))
        print(f"{mut:20s} target {target:4s} {'KILLED' if killed else 'SURVIVED'}  "
              f"failing cases: {', '.join(failed) or 'none'}", flush=True)
    lines = ["# Mutation testing: every defence is necessary and tested", "",
             "Each row disables one defence in the running services and reruns the "
             "full distributed harness. KILLED means the harness detected the "
             "missing defence.", "",
             "| Mutation | Defence removed | Target case | Result | Cases that failed |",
             "|---|---|---|---|---|"]
    lines += [f"| `{m}` | {d} | {t} | **{'KILLED' if k else 'SURVIVED'}** | {', '.join(f) or 'none'} |"
              for m, d, t, k, f in rows]
    lines += ["", f"All mutations killed: **{killed_all}**"]
    (out / "MUTATION_REPORT.md").write_text("\n".join(lines) + "\n")
    print(f"\nall killed: {killed_all}")
    return 0 if killed_all else 1


if __name__ == "__main__":
    sys.exit(main())
