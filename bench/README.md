# BAHI — Benchmarks, Stress Tests & Adversarial Audit

An independent benchmark + stress + attack battery for the **BAHI** SHG ledger
prototype (Craft N Code 2026, PS-17). This directory is self-contained: it
ships a frozen copy of the code under test (`src/`) and five deterministic
suites that import that snapshot.

The core chain is Python 3 stdlib only (no network). The optional Ed25519
witness-signature path needs `pip install cryptography`; the legacy HMAC path and
the entire fuzz/bench harness run dependency-free (Ed25519 suites self-skip).

```
bench/
├── README.md             this file
├── REPORT.md             full findings + numbers (start here)
├── ATTACK-CATALOG.md     ~70 attack vectors across the full threat surface
├── SNAPSHOT_SHA.txt      git SHA of the audited code
├── SNAPSHOT_HASHES.txt   SHA-256 of every frozen source file
├── src/                  frozen code under test
│   ├── chain.py  witness.py  loans.py  exporter.py
├── attacks.py            25 adversarial findings (severity-ranked)
├── stress_tests.py       12 robustness probes
├── benchmarks.py         throughput + scaling
├── attack_fuzz.py        10,424 seeded fuzz probes (6 suites)
├── benchmark_matrix.py   11,180 timed samples (microbench + scaling sweep)
├── round3_probe.py       round-3 regression probes (business-logic/replay)
├── round3b_probe.py      round-3b probes
├── output/               raw captured output (evidence)
│   ├── attacks.txt  stress.txt  benchmarks.txt  fuzz.txt  bench_matrix.txt
└── docs/
    └── index.md          master index
```

## Run it

```bash
cd bench
python attacks.py            # 25 findings: 8 FIXED / 12 STILL-OPEN / 5 NEW
python stress_tests.py       # 12/12 pass
python benchmarks.py         # timing + scaling
python attack_fuzz.py        # 10,424 seeded fuzz probes (csv/xss/mutation/property/receipt/type)
python benchmark_matrix.py   # 11,180 timed samples (microbenchmarks + scaling sweep)
python run_all.py            # everything, captured to output/
```

## What it found (TL;DR)

- The **hash chain is sound** — every tamper (edit/delete/reorder/root-swap/
  witness-removal/ghost-meeting/cross-group/corrupt-file) is detected.
- The **HMAC-symmetric caveat is solved**: Ed25519 witness signatures let an
  offline member verify a witness signature with only the public key on the
  receipt (no shared secret). See `../demo_ed25519.py`.
- **21,604 fuzz + benchmark probes** now run deterministically (10,424 fuzz,
  11,180 timed samples), and they surfaced + fixed a real crash-resistance gap:
  `verify()`/`hint_flags()`/`export_csv()`/`balances()` crashed on non-dict or
  field-missing events from a hand-edited JSON — all now return structured
  verdicts / skip.
- `hint_flags` is **O(E log E)** (was quadratic) and never raises on any input.
- `attack_fuzz.py` runs **6 suites**: CSV-injection (1200), XSS (1200), chain
  mutation/corruption (1200), random-ledger property (4500), receipt tamper
  (1200), and type-confusion (1000) — all deterministic, all green.

Full detail and the prioritized fix list: **`REPORT.md`**. Non-code decisions
(identity/KYC, key custody, anchoring, privacy): **`../docs/PRODUCT-DECISIONS.md`**.

## Why a frozen snapshot?

The upstream repository is under active, concurrent development (the code
changed between the start and end of this audit — several findings were fixed
mid-audit). To make the results reproducible, the source under test was copied
to `src/` and pinned by SHA-256. Re-running any suite re-tests that exact code.
To re-audit a newer version, copy the fresh `chain.py`, `witness.py`,
`loans.py`, `exporter.py` into `src/` and update `SNAPSHOT_SHA.txt`.
