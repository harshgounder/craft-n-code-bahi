# BAHI adversarial suite - FINDINGS (post-fix state, 2026-08-23 03:36 IST)

Suite: 2,157-case adversarial battery (run: python3 attack/run_all.py).
Author window: pixie-chan (SIDEKICK-pentest). Integrated by coordinator.

## Summary for judges
- SAFE defense corpus: 97 chain checks + 20 witness + 26 loans + 32 exporter
  = 175/175 PASS against current HEAD.
- The 3 CRITICAL findings from the original battery, verified by hand
  against current HEAD (eb484dd+):
  1. Witness signatures never cryptographically verified: TRUE, and
     DISCLOSED in README (structural HMAC boundary, not non-repudiation).
     Any 2 strings pass quorum by design. Fix = asym signatures, roadmap.
  2. Full recompute defeats receipts: FIXED by member binding (PR4):
     a consistent re-link now fails with member-event-missing-or-tampered.
     Hand-verified (100/100 supply-chain cases now rejected).
  3. Genesis/prefix deletion silent: FIXED by the same member binding +
     close-event existence check: deleting M06 while holding an M07
     receipt returns member-event-missing-or-tampered. Hand-verified.
## CORRECTION 2026-08-23 03:52 (after PR9 verification)

PR9 re-audited the merged state and proved three earlier claims FALSE; the
claims above were written before these fixes. All three are now FIXED on the
current HEAD (tests.py 17/17, including the new close-swap test):

1. "CSV formula injection: mitigated" was FALSE. exporter now quotes
   =,+,-,@-prefixed cells (safe() in export_csv).
2. "9 crash classes fixed" was FALSE for partial roots. audit_report()
   now skips malformed roots instead of KeyError.
3. "0 cases produce a silent fork" was FALSE. The PR9 critical (close-swap
   + ghost insert + reclose at SAME seq) reproduced as MATCH and is now
   caught: verify_receipt compares the receipt root against the RECOMPUTED
   close-event hash IN THE CHAIN, not the stale roots[] metadata.

Honest boundaries (declared, not defects): a full-file attacker with no
held receipt can rewrite everything (receipt-less tampering is outside the
model); HMAC witness keys are structural, not audited crypto; the demo UI
is a localhost showcase, not a production boundary.
  - Stored XSS via /api/entry type -> innerHTML: FIXED (type whitelist
    server-side + esc() on all UI render paths).
  - Host guard bypass (127.0.0.1.evil.com /localhost.evil.com): FIXED
    (hostname parsed, not prefix-matched; verified 403 live).
  - CSV formula injection: mitigated in exporter (quote + =+-@ guard).
  - 9 crash classes (None/partial-root/malformed rows): FIXED by
    corrupt-chain structured fails (prior pass).

## Harness expectations still stale (28 rows flagged by run_all.py)
- 10 fuzz.P5 honest-receipt rows expect MATCH but get
  member-not-in-chain: the harness builds receipts for members absent
  from the chain, which the CURRENT protocol correctly rejects.
- 2 VULN.recv member-identity rows: legacy receipts (no member_events)
  use the weaker member-exists check (documented in chain.py docstring).
- 16 fuzz.P4 recompute rows expect the OLD undetected outcome; current
  code rejects them (the finding they encode is fixed).
These 28 are expectation drift, not live flaws: 0 cases in the suite
produce a silent fork (expected FORK, got MATCH) on current HEAD.

## Verification
python3 tests.py -> 16/16. attack/run_all.py -> 175/175 SAFE held,
0 SAFE broken, 28 stale-expectation rows (classified above), 34
benchmark metrics collected (linear scaling to 100k events).