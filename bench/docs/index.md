# Master Index — BAHI Bench / Stress / Attack

This is the index for the `bench/` deliverable. Everything below is real output
produced on this machine against the frozen snapshot (pinned in
`SNAPSHOT_SHA.txt`, currently the head of the round-4 branch).

## Start here

| Doc | What it is |
|---|---|
| [`../README.md`](../README.md) | What this directory is + how to run |
| [`../REPORT.md`](../REPORT.md) | **Full findings + numbers** (the deliverable) |
| [`../ATTACK-CATALOG.md`](../ATTACK-CATALOG.md) | ~70 attack vectors across the full threat surface |
| [`../../docs/PRODUCT-DECISIONS.md`](../../docs/PRODUCT-DECISIONS.md) | 33 non-code product/trust decisions (identity, keys, anchoring, privacy) |

## The five suites

| Suite | File | What it does | Status |
|---|---|---|---|
| Adversarial audit | [`../attacks.py`](../attacks.py) | 25 findings, each a live exploit | see REPORT |
| Stress tests | [`../stress_tests.py`](../stress_tests.py) | 12 robustness probes (scale, unicode, extremes, determinism) | 12/12 pass |
| Benchmarks | [`../benchmarks.py`](../benchmarks.py) | throughput + O(N) scaling + memory | see REPORT §2 |
| Attack fuzz | [`../attack_fuzz.py`](../attack_fuzz.py) | 6 seeded suites: CSV (1200), XSS (1200), mutation (1200), property (4500), receipt (1200), type (1000) | 10,424/10,424 pass |
| Benchmark matrix | [`../benchmark_matrix.py`](../benchmark_matrix.py) | microbench (11 ops × 1000) + scaling sweep (12 sizes × 5 ops) | 11,180 timed samples |

## Raw evidence (captured output)

| File | Contents |
|---|---|
| [`../output/attacks.txt`](../output/attacks.txt) | full per-finding EXPLOITED/RESISTED evidence |
| [`../output/stress.txt`](../output/stress.txt) | full stress run |
| [`../output/benchmarks.txt`](../output/benchmarks.txt) | full benchmark run |
| [`../output/fuzz.txt`](../output/fuzz.txt) | full fuzz run (per-suite counts + failures) |
| [`../output/bench_matrix.txt`](../output/bench_matrix.txt) | full microbench + scaling sweep |

## Provenance

| File | Purpose |
|---|---|
| [`../SNAPSHOT_SHA.txt`](../SNAPSHOT_SHA.txt) | git SHA of the audited code |
| [`../SNAPSHOT_HASHES.txt`](../SNAPSHOT_HASHES.txt) | SHA-256 of every frozen source file |
| [`../src/`](../src/) | frozen code under test (chain/witness/loans/exporter) |

## Resolution map (findings -> where fixed)

| Finding | Severity | Fixed in |
|---|---|---|
| A02 witness signatures not crypto-verified | CRITICAL | PR #10 (HMAC) + round-4 Ed25519 (offline verify) |
| A04 receipt aliases live state | HIGH | PR #10 (deep copy) |
| A05 meeting-root overwrite | HIGH | PR #10 (dup-close raise) |
| A08/A09/A10/A11/A12/A18-A21 validation | MED/LOW | PR #10 |
| N1 group hashing, N2/N3/N4/N5 | MED/LOW | PR #10 |
| C1 quorum gaming (same witness twice) | CRITICAL | PR #10 (unique-name quorum) |
| R1 legacy receipt (no member_events) | HIGH | PR #10 |
| B1/B2/B3 audit blind spots | MED | PR #10 + round-4 (severity + UI) |
| W1 hint-box XSS | HIGH | round-4 (server-side html_escape) |
| D1 CSV leading-whitespace injection | LOW | round-4 (csv_safe_cell) |
| Crash on non-dict / field-missing events | HIGH | round-4 (fuzz-driven) |

## How to re-audit a newer version

1. Copy the current `chain.py`, `witness.py`, `loans.py`, `exporter.py` into
   `src/`.
2. `git rev-parse HEAD > SNAPSHOT_SHA.txt` and
   `sha256sum src/*.py > SNAPSHOT_HASHES.txt`.
3. Re-run the five suites (or `python run_all.py`).
