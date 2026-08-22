# BAHI — Benchmarks, Stress Tests & Adversarial Audit

Audit + performance + robustness battery for the BAHI ("witnessed ledger")
prototype, written for the Craft N Code 2026 Round-1 project (PS-17 / SHG
digital ledger).

- **Audited snapshot:** `d8e7511` (`SNAPSHOT_SHA.txt`) — source frozen in `src/`.
  Note: the upstream repo is under active, concurrent development; several
  findings below were already fixed by the time this report was written.
- **Scope:** `chain.py`, `witness.py`, `loans.py`, `exporter.py` (the truth +
  audit path). `demo.py` / `server.py` are a scripted UI and were not the
  target of the security battery, though one server-path crash (N2) is noted.

Run everything:

```bash
cd bench
python attacks.py        # 25 findings, severity-ranked
python stress_tests.py   # 12 robustness probes
python benchmarks.py     # throughput + scaling
```

Raw output is captured in `output/`. The three suites are deterministic and
import the frozen `src/` (not the live tree), so re-running reproduces the same
numbers against the same code.

---

## 1. Verdict in one paragraph

The core claim — *"edit any past event and every later hash breaks; recompute
from genesis and you detect the fork"* — is **sound**. All 12 upstream protocol
tests pass, and every genuine tamper (edit, delete, reorder, root swap, witness
removal, ghost meeting, cross-group, corrupt file) is caught. The prototype
survives 1M-event chains, unicode names, 2^63 amounts, 10k meetings, and 10k
witnesses without crashing (12/12 stress tests pass).

The remaining risk is **not** in the hash chain; it is in the *edges*: witness
"signatures" are structural strings, not cryptographic proofs (A02); a handful
of input-validation gaps admit malformed events (A08–A12, A21); and two receipt
fields were only loosely bound (A04). 17 of 25 findings are still exploitable,
the worst being A02.

---

## 2. Benchmark results (this machine: win32 / Python 3.11.15)

| Operation | Throughput | Notes |
|---|---|---|
| `h()` SHA-256 | ~691,000 ops/s | field-hashed with unit-separator delimiters |
| `add_event` append | ~332,000 ev/s | includes normalization + hash |
| witness `sign` (HMAC) | ~145,000 sig/s | |
| witness `verify` (HMAC) | ~145,000 ver/s | |

Full-chain recompute (`verify`), which is the security anchor, scales **linearly**:

| Events | verify() time |
|---|---|
| 1,000 | 0.003 s |
| 10,000 | 0.027 s |
| 100,000 | 0.262 s |
| 1,000,000 | 2.18 s |

Derived views:

| Events | balances() | export_csv() |
|---|---|---|
| 1,000 | <0.001 s | 0.001 s |
| 10,000 | 0.001 s | 0.014 s |
| 100,000 | 0.021 s | 0.137 s |

IO: `save(100k)` 1.11 s → 31.8 MB JSON (+ `.bak`); `load(100k)` 0.17 s;
`verify_receipt` on a 100k-event chain 0.39 s. Memory: a 500k-event chain peaks
at ~254 MB (~500 bytes/event — dominated by per-event dict overhead).

### Performance finding: `hint_flags` is still O(meetings × events)

`exporter._meetings_with_events` re-scans the full event list once per meeting:

```python
for i, (seq, mid) in enumerate(root_seqs):
    ...
    out.append((mid, [e for e in events if lo <= e["seq"] <= hi]))
```

The correctness bug (cross-meeting misattribution) is fixed, but the **quadratic
cost remains**. At fixed 4,000 events, `hint_flags` time grows with the meeting
count (0.011 s @ 1 meeting → 0.062 s @ 500 meetings), and the per-flag
`not any(...)` dedup adds another O(flags) factor. At federation scale (millions
of events across thousands of meetings) this is the first thing that will fall
over. Fix: bucket events by `root_seq` in a single O(E) pass (a dict keyed by
meeting), then evaluate rules per bucket.

---

## 3. Stress test results (12/12 pass)

| # | Probe | Result |
|---|---|---|
| S1 | 1,000,000-event chain build + verify + save/load round-trip | PASS, deterministic |
| S2 | Unicode / emoji / combining / RTL member names | PASS |
| S3 | Amount extremes: 0, 10^18, 2^63−1, 2^63 | PASS |
| S4 | Negative amount | PASS (rejected: `ValueError`) |
| S5 | Float NaN / ±inf amount | PASS (rejected) |
| S6 | 100k-char member name | PASS |
| S7 | 10,000 meetings | PASS |
| S8 | 10,000-witness receipt | PASS |
| S9 | Pathological types (str seq / bool amount) | PASS (still **accepted** — see A21) |
| S10 | Determinism (5 runs) | PASS |
| S11 | verify() idempotency after tamper | PASS |
| S12 | hint_flags at scale | PASS |

The prototype is remarkably crash-resistant. The one stress result to read
carefully is S9: malformed *types* don't crash the chain (they just flow
through), but they *do* crash the audit layer — see N2.

---

## 4. Adversarial findings (25 total)

Legend: **FIXED** = closed by v1.2+ hardening · **STILL OPEN** = exploitable ·
**NEW** = found in the current code.

### FIXED (8) — the concurrent hardening worked

| ID | Sev | Title |
|---|---|---|
| A01 | CRITICAL | Hash domain-separation collision — `h()` now appends a `\x1f` separator per field |
| A03 | CRITICAL | Cross-group receipt confusion — `verify_receipt` binds `group` |
| A06 | HIGH | CSV injection — `csv.writer` quotes comma/quote/newline |
| A07 | HIGH | hint_flags cross-meeting misattribution — per-meeting `root_seq` bucketing |
| A13 | MEDIUM | duplicate_identity fired at ==2 — now `>=3` (advisory) |
| A14 | MEDIUM | `verify_receipt` ignored root_seq/member — now binds both |
| A15 | MEDIUM | `load()` had no validation — now returns structured "corrupt" state |
| A22 | LOW | save() canonicalization — verified deterministic (defense held) |

### STILL OPEN (12)

| ID | Sev | Title | One-line |
|---|---|---|---|
| **A02** | **CRITICAL** | **Witness signatures are not cryptographically verified** | `verify_receipt` compares sigs as an opaque-string *set* and never calls `witness.verify`; any two strings satisfy quorum → MATCH |
| A04 | HIGH | Receipt aliases live chain state | `receipt_payload` returns the witness *list by reference*; bookkeeper can mutate a member's receipt after issue |
| A05 | HIGH | close_meeting silently overwrites an existing root | re-closing the same meeting id destroys the prior root |
| A08 | MEDIUM | Float amounts silently truncated | `_norm_amount` does `int(v)`; 10000.9 → 10000 |
| A09 | MEDIUM | Over-repayment → negative outstanding | negative *amounts* now rejected, but `loaned − repaid` can still go negative |
| A10 | MEDIUM | Duplicate / out-of-order / string seq accepted | no seq validation; also corrupts hint_flags bucketing |
| A11 | MEDIUM | MEETING-CLOSE type injectable | `add_event` doesn't restrict the event-type set |
| A12 | MEDIUM | Arbitrary `prev_hash` accepted | breaks chain silently until next verify |
| A18 | LOW | member name `__root__` collides with close marker | |
| A19 | LOW | Timestamps not ordered/validated | |
| A20 | LOW | No nonce → identical consecutive events accepted | |
| A21 | LOW | Weak typing: str seq / bool amount | |

### NEW (5) — found in the current code

| ID | Sev | Title | One-line |
|---|---|---|---|
| N1 | MEDIUM | group_id not bound into the event hash | rename the group and every hash stays valid |
| N2 | MEDIUM | hint_flags / audit_report crash on a string seq | `lo <= e["seq"] <= hi` raises `TypeError`, taking down `/api/export` |
| N3 | LOW | verify() vs `corrupt` inconsistency | verify says "ok" for empty group_id, `corrupt` says corrupt |
| N4 | MEDIUM | correction events have no defined effect | ignored by balances() and every audit rule |
| N5 | LOW | close_meeting doesn't enforce quorum at close | 0-witness close is stored; quorum only checked at verify |

### Top three fixes to prioritize

1. **A02 (CRITICAL)** — verify each witness signature with
   `witness.verify({"root":..,"meeting":..}, sig, passphrase, witness)` instead
   of `set(sigs_then).issubset(set(sigs_now))`. As written, "2 witnesses signed"
   is a statement the bookkeeper can fabricate.
2. **A04 (HIGH)** — deep-copy the witness list (and root fields) in
   `receipt_payload` so a member's held receipt is an immutable snapshot.
3. **N2 + A10 (MEDIUM)** — coerce/validate `seq` to `int` and enforce
   monotonicity in `add_event`; this single change also removes the
   `hint_flags` crash and the bucketing corruption.

The remaining LOW findings (A18–A21, N3, N5) are hardening/hygiene, not
exploitable fraud paths by themselves.

---

## 5. Method

- **Freeze & isolate.** The upstream tree is being edited concurrently, so the
  source under test was copied to `src/` and SHA-256-pinned
  (`SNAPSHOT_HASHES.txt`); every suite imports that snapshot. The freeze
  reflects working-tree state at commit `d8e7511`, which already included the
  member-binding changes later merged upstream as PR4 (so A14 is correctly
  recorded as fixed).
- **Reproduce everything.** Every finding is a live, self-contained exploit that
  prints `EXPLOITED`/`RESISTED` and the exact evidence; nothing is asserted from
  reading alone.
- **Distinguish detection from prevention.** BAHI is fraud *detection* with a
  member-held receipt, not fraud *prevention*; findings respect that boundary
  (mass collusion at entry time is explicitly out of scope, per the README).

Full per-finding evidence: `output/attacks.txt`. Raw numbers:
`output/benchmarks.txt`, `output/stress.txt`.
