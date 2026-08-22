# BAHI — Benchmarks, Stress Tests & Adversarial Audit

An independent benchmark + stress + attack battery for the **BAHI** SHG ledger
prototype (Craft N Code 2026, PS-17). This directory is self-contained: it
ships a frozen copy of the code under test (`src/`) and three deterministic
suites that import that snapshot.

```
bench/
├── README.md             this file
├── REPORT.md             full findings + numbers (start here)
├── SNAPSHOT_SHA.txt      git SHA of the audited code
├── SNAPSHOT_HASHES.txt   SHA-256 of every frozen source file
├── src/                  frozen code under test
│   ├── chain.py  witness.py  loans.py  exporter.py
├── attacks.py            25 adversarial findings (severity-ranked)
├── stress_tests.py       12 robustness probes
├── benchmarks.py         throughput + scaling
├── output/               raw captured output (evidence)
│   ├── attacks.txt  stress.txt  benchmarks.txt
└── docs/
    └── index.md          master index
```

## Run it

```bash
cd bench
python attacks.py        # 25 findings: 8 FIXED / 12 STILL-OPEN / 5 NEW
python stress_tests.py   # 12/12 pass
python benchmarks.py     # timing + scaling
```

Everything is Python 3 stdlib only. No dependencies, no network.

## What it found (TL;DR)

- The **hash chain is sound** — every tamper (edit/delete/reorder/root-swap/
  witness-removal/ghost-meeting/cross-group/corrupt-file) is detected; all 12
  upstream tests pass.
- **17 of 25 findings are still exploitable**, the worst being **A02**: witness
  "signatures" are opaque strings compared by set-membership, never
  cryptographically verified — any two strings satisfy quorum and verify MATCH.
- `hint_flags` is still **O(meetings × events)** (quadratic), a real scaling
  problem at federation size, even though its correctness bug is fixed.
- The code is crash-resistant under extreme input (1M events, unicode, 2^63
  amounts, 10k meetings, 10k witnesses) — **12/12 stress tests pass**.

Full detail and the prioritized fix list: **`REPORT.md`**.

## Why a frozen snapshot?

The upstream repository is under active, concurrent development (the code
changed between the start and end of this audit — several findings were fixed
mid-audit). To make the results reproducible, the source under test was copied
to `src/` and pinned by SHA-256. Re-running any suite re-tests that exact code.
To re-audit a newer version, copy the fresh `chain.py`, `witness.py`,
`loans.py`, `exporter.py` into `src/` and update `SNAPSHOT_SHA.txt`.
