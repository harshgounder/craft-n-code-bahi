# Master Index — BAHI Bench / Stress / Attack

This is the index for the `bench/` deliverable. Everything below is real output
produced on this machine against the frozen snapshot (`d8e7511`).

## Start here

| Doc | What it is |
|---|---|
| [`../README.md`](../README.md) | What this directory is + how to run |
| [`../REPORT.md`](../REPORT.md) | **Full findings + numbers** (the deliverable) |

## The three suites

| Suite | File | What it does | Status |
|---|---|---|---|
| Adversarial audit | [`../attacks.py`](../attacks.py) | 25 findings, each a live exploit: 8 FIXED / 12 STILL-OPEN / 5 NEW | 17 actively exploitable |
| Stress tests | [`../stress_tests.py`](../stress_tests.py) | 12 robustness probes (scale, unicode, extremes, determinism) | 12/12 pass |
| Benchmarks | [`../benchmarks.py`](../benchmarks.py) | throughput + O(N) scaling + memory | see report §2 |

## Raw evidence (captured output)

| File | Contents |
|---|---|
| [`../output/attacks.txt`](../output/attacks.txt) | full per-finding EXPLOITED/RESISTED evidence |
| [`../output/stress.txt`](../output/stress.txt) | full stress run |
| [`../output/benchmarks.txt`](../output/benchmarks.txt) | full benchmark run |

## Provenance

| File | Purpose |
|---|---|
| [`../SNAPSHOT_SHA.txt`](../SNAPSHOT_SHA.txt) | git SHA of audited code (`d8e7511`) |
| [`../SNAPSHOT_HASHES.txt`](../SNAPSHOT_HASHES.txt) | SHA-256 of every frozen source file |
| [`../src/`](../src/) | frozen code under test (chain/witness/loans/exporter) |

## Finding map (severity)

**CRITICAL (still open):** A02 — witness signatures not cryptographically
verified.

**HIGH (still open):** A04 (receipt aliases live state), A05 (meeting-root
overwrite).

**MEDIUM (still open):** A08 (float truncation), A09 (negative outstanding),
A10 (seq unvalidated), A11 (close-type injection), A12 (prev_hash injection),
N1 (group not hashed), N2 (hint_flags crash on string seq), N4 (correction
no-op).

**LOW (still open):** A18, A19, A20, A21, N3, N5.

**FIXED (defenses verified):** A01, A03, A06, A07, A13, A14, A15, A22.

## How to re-audit a newer version

1. Copy the current `chain.py`, `witness.py`, `loans.py`, `exporter.py` into
   `src/`.
2. `git rev-parse HEAD > SNAPSHOT_SHA.txt` and
   `sha256sum src/*.py > SNAPSHOT_HASHES.txt`.
3. Re-run the three suites.
