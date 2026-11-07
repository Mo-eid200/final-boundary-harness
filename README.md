# Final-boundary authority revalidation: test harness

A small reference harness for one open question in M6:

> Does the executor check the **current** authoritative state for the **exact** action at the final boundary, so that a valid past authorization never silently becomes permission to act in the present?

It has one file, uses only the standard library, and runs in about 3 seconds:

```
python3 m6_final_boundary.py out
```

The output is `out/REPORT.md`, with expected and observed results for every case, plus hash-chained evidence logs (`out/evidence_*.jsonl`).

## Cases

| Case | Scenario | Expected outcome at the final boundary |
|---|---|---|
| C0 | Control: valid authorization | EXECUTED (the suite does not just reject everything) |
| C1 | Valid at decision time, revoked before execution | REJECT `EPOCH_MISMATCH(granted=N, current=N+1)` |
| C2 | VERIFIED evidence expires | REJECT `EVIDENCE_EXPIRED`. The historical record stays readable, but it grants no new authority |
| C3 | Revocation arrives *during* execution (300 randomized races) | No action completes after a revocation is recorded |
| C4 | Authorization for action A presented for action B | REJECT `ACTION_MISMATCH` |
| C5 | Replay | REJECT `NONCE_REUSED` |
| C6 | Stale token reaches the resource directly, bypassing the executor | REJECT `STALE_FENCING_TOKEN` |

Every case runs against two executors:

- **Fenced executor.** It verifies the signature and the exact action hash. Then, **atomically with the action itself**, it consumes the nonce, requires `epoch == current epoch`, requires that the evidence is valid *now*, and writes through a fenced resource.
- **Naive control.** It checks the signature and the nonce only. The suite counts as valid only if this control **fails** C1–C4 and C6. That shows the tests can tell the two executors apart.

Current result: the fenced executor passes all 7 cases. The naive control fails exactly where expected; in C3 it commits after revocation in roughly half of the 300 races (the exact count varies with thread timing).

## Two design points the cases encode

1. **Check and act must be one atomic step.** If the executor checks the epoch and then acts as a separate step, the time-of-check/time-of-use window gets smaller but does not go away (C3).
2. **Fencing at the resource.** The resource rejects any epoch lower than the highest epoch it has accepted. A revocation then wins even against a slow, crashed-and-resumed or buggy executor (C6). This is the standard fencing-token pattern from distributed locking.

## Plugging into an existing system

- Replace `sign()`/`verify()` (HMAC-SHA256 here, to stay dependency-free) with your Ed25519 signing path.
- Map `Authority` to your authoritative state store, and keep `revoke()` and the final-boundary block under the same lock or transaction.
- Across processes or machines, the in-process lock becomes a transactional compare-and-set on the epoch (or a conditional write at the resource). C6 is the case that still protects you there.

## Limitations

This is a single-process reference model with an in-process lock and an injectable clock. It shows the *required behaviour* and *how to test it*. It does not show that any particular deployment has that behaviour.

License: MIT. Author: Mohamed Eid (ORCID 0009-0008-8404-978X).
