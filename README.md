# Final-boundary authority revalidation

A verified reference design for one question in agent authorization:

> Does the executor check the **current** authoritative state for the **exact** action at the final boundary, so that a valid past authorization never silently becomes permission to act in the present?

It is a working distributed implementation. It is tested against real processes, real crashes and real network partitions, and its protocol is model-checked exhaustively. Every defence is shown to be necessary: removing any one of them is caught.

```
pip install -r requirements.txt
python3 run_all.py            # about 4 minutes; writes RESULTS.md
```

## Guarantees

The guarantees below hold under the assumptions listed in the next section. They are checked as four safety properties:

| | Property | Meaning |
|---|---|---|
| P1 | **Authentic** | Only authorizations issued by the authority are ever executed. |
| P2 | **Once** | No authorization is executed twice, including across crashes. |
| P3 | **Never after known revocation** | Once the resource has learned of a revocation, no older authorization executes, ever. |
| P4 | **Bounded revocation** | Even if the revocation never reaches the resource (partition, attacker, crash), no older authorization executes later than `revocation time + lease`. |

In addition:

- **The action is bound.** An authorization for action A cannot be used for action B.
- **The holder is bound.** A stolen authorization cannot be used by anyone else (proof of possession).
- **Evidence expiry is a revocation.** When VERIFIED evidence expires, the authority revokes every scope that relied on it. The historical record stays readable but grants nothing new.
- **Revocation reports the truth.** `revoke()` returns `EFFECTIVE` only after the resource has acknowledged it. Otherwise it returns `PENDING` with the exact time by which it is guaranteed to take effect.

### What cannot be guaranteed, by any design

During a network partition, no protocol can make a revocation take effect *instantly* and also keep the resource *available*. This design chooses safety:

- The revocation takes effect within one lease period (P4).
- The resource then **fails closed**, which means legitimate actions are also refused until the partition heals.

The lease length is the trade-off knob: a shorter lease gives a smaller window and more renewal traffic.

## Assumptions (threat model)

- **The attacker controls the network:** delay, reordering, duplication, replay, injection and capturing any message.
- **The attacker cannot forge Ed25519 signatures,** and the authority's private key and each holder's private key stay secret.
- **The authority is trusted.** The resource enforces; it is not compromised itself. If the enforcement point is compromised, no protocol can help.
- **Clocks may differ by any amount.** Only their *rate* is assumed to be roughly correct, because leases are measured with each machine's monotonic clock.
- **One resource instance.** If the resource is replicated, every replica must share the fence and nonce state transactionally (see below).

## How it works

```
Authority ──(signed fence notice on every revoke)──▶ Resource
Authority ◀──(lease request + fresh challenge)────── Resource
Authority ──(signed lease answer echoing it)──────▶ Resource
Holder ────(authorization + proof of possession)──▶ Resource ── one transaction:
                                                    check everything, then act
```

1. **Epochs.** Every invalidation (operator revocation or evidence expiry) increments the scope's epoch. Authorizations carry the epoch they were issued in.
2. **Fences.** The resource keeps the highest epoch it has learned, durably. The fence only ever increases, so a delayed or replayed notice is harmless.
3. **Pull leases with challenge-response.** The resource asks for a lease with a fresh random challenge. It accepts only a signed answer to an *outstanding* challenge, and the lease runs from the moment the resource **sent** the request. A delayed, captured or replayed answer therefore buys nothing, and this is what makes P4 hold against an attacker who controls the network. Leases live in memory only, so a restarted resource fails closed until it gets a fresh lease.
4. **Single enforcement point.** The resource checks the following in one serialized database transaction together with the action itself:
   - the authority's signature
   - the exact action
   - the proof of possession
   - fence and lease
   - `epoch == fence`
   - the durable nonce

   There is no gap between check and act, and no path around the checks.

## Verification: four layers

| Layer | File | What it shows |
|---|---|---|
| 1 | `m6_final_boundary.py` | Single-process reference model, 11 cases, plus a naive control (signature + nonce only) that fails 9 of them. This shows the tests can tell a correct executor from a naive one. |
| 2 | `harness.py` | The real system: authority and resource as separate OS processes over HTTP, 13 cases. Includes `SIGKILL` and restart, network partitions, an attacker injecting captured leases, stolen tokens, and 150 concurrent revoke/execute races checked against the resource's serialized log. |
| 3 | `mutate.py` | Each of 10 defences is switched off in the running services, and the harness must catch it. All 10 are caught, so every defence is necessary and tested. |
| 4 | `model_check.py` | Exhaustive breadth-first search over **every** interleaving of the protocol within bounds. It covers an adversarial network, unlimited tokens of every epoch, forged tokens, crashes at any point, and revocations racing everything. P1–P4 hold in all 2.5 million reachable states. Then 8 defences are removed one at a time, and each produces a concrete shortest attack trace. |

Current results are in `RESULTS.md`.

The model check is *bounded* (clock 0..6, up to 3 epochs, 2 lease challenges, 1 crash). It does not prove the protocol for unbounded runs. The bugs it targets, however, all appear within a few steps, as the counterexample traces show. The model is an abstraction of the code; layer 3 ties the two together by checking that the real services fail in the same way when the same defence is removed.

## Running the parts separately

```
python3 m6_final_boundary.py out     # layer 1, about 3 s
python3 harness.py out_v2            # layer 2, about 15 s
python3 mutate.py out_mutation       # layer 3, about 2 min
python3 model_check.py MODEL.md      # layer 4, about 1 min
```

## Taking it to a real deployment

- **Authority endpoints.** `/grant` and `/revoke` must be authenticated (mTLS or similar). Remove the `/test/*` endpoints, which exist only for the harness.
- **Replicated resource.** Put the fence and nonce tables in one transactional store that all replicas share, or use one resource per scope.
- **Lease length.** Set it to the longest acceptable revocation window during a partition.
- **Authority availability.** If the authority is down for longer than a lease, resources fail closed. Run it highly available if that matters.

## Changelog

- **v2.0:** Distributed implementation with durable state, pull leases with challenge-response, proof of possession, evidence expiry as revocation, mutation testing of the real services, and an exhaustive model checker.
  - During development, mutation testing exposed a test gap: a forged epoch was being caught by the fence check, so the signature check was never tested on its own. A case that only the signature check can stop was added.
  - The model checker confirmed why the lease must run from the request's send time, not its receive time.
- **v1.2:** Resource as single enforcement point (C9, C10); Ed25519.
- **v1.1:** Resource as part of the adversarial boundary (C7, C8). Both gaps were found by **Krzysztof Śliwka** in a code review of v1.0.
- **v1.0:** Initial single-file harness (C0–C6).

## Acknowledgements

Thanks to **Krzysztof Śliwka**, whose work on M6 posed the question this harness answers. His code review of v1.0 found the first two gaps (C7, C8), and it led directly to treating the resource as part of the adversarial boundary, which is the basis of v2.

License: MIT. Author: Mohamed Eid (ORCID 0009-0008-8404-978X).
