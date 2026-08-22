# BAHI Round-2 Findings (post PR4/5/6, HEAD 85b0687) - 2026-08-23

Round 1 (PR #6) was integrated on main. This is the follow-up adversarial pass
against the FIXED code: 1,346 executed cases (100-iteration fuzz), verifying
which fixes actually hold, which claims in `attack/FINDINGS.md` are wrong, and
what NEW holes the fixes introduce. Run: `python3 attack/run_all.py 100`.

## Fix audit (what actually holds now)

| Claimed fix | Verdict | Evidence |
|---|---|---|
| Stored XSS via /api/entry type | FIXED, browser-verified | type whitelist + esc(); xss_proof.py: payload NOT stored, marker absent |
| Host suffix bypass (127.0.0.1.evil.com) | FIXED for that shape | t_server SAFE.http.host.* : 403 |
| Member binding (PR4) for member-present receipts | FIXED for non-close events | fuzz.P4a ~100/100: edit+recompute caught (member-event-missing-or-tampered) |
| Post-close entry reject | FIXED | t_server repeat.002, t_v2 closed-entry: ok=False, verdict stays MATCH |
| Double-close reject | FIXED | t_v2 double-close |
| Attack-while-open no-op | FIXED | t_v2 open-attack |
| Unknown paths | STILL 200 (no 404) | t_server base.003 |

## Claims in attack/FINDINGS.md that are FALSE

1. "CSV formula injection: mitigated in exporter (quote + =+-@ guard)" -
   exporter.py is UNCHANGED. No guard exists. `=HYPERLINK(...)` members still
   land raw in export (t_exporter csv.formula/prefix/ts all confirm).
2. "9 crash classes FIXED by corrupt-chain structured fails" - all 9 still
   crash: verify_receipt(None/str/partial roots), verify() non-dict rows,
   balances() KeyError/TypeError, audit_report() KeyError on __corrupt__,
   load() RecursionError. (t_chain, t_receipt, t_loans, t_exporter).
3. "0 cases in the suite produce a silent fork (expected FORK, got MATCH)" -
   FALSE. The close-swap + ghost-insert forgery below is exactly that.

## NEW CRITICAL: silent forgery inside a closed, bound-verified meeting

The member binding pins ONLY the receipt member's line items. Everything else
below the close is unprotected. Attack (all verified live):

1. Delete the meeting's MEETING-CLOSE event (with file control).
2. Insert ANY event(s) - e.g. another member's Rs 10,000,000 "contribution".
3. Re-append a MEETING-CLOSE at the SAME seq linked to the new tail.

Result: chain.verify() OK, Sita's BOUND receipt still MATCH - the forged entry
is invisible to every member receipt. Test IDs: t_v2.close-swap, t_v2.ghost-insert.

Same root cause as round-1 finding 2: the receipt root is compared against
roots[] METADATA (which the attacker leaves stale-equal), never against the
actual recomputed close event. Fuzz P4c: editing the close event's own ts +
recompute -> bound receipt MATCH ~100/100.

## NEW findings (severity order)

| # | Finding | Severity | Test IDs |
|---|---------|----------|----------|
| 1 | Ghost-insert forgery: delete close + insert arbitrary events + re-close same seq -> verify OK + bound receipt MATCH | CRITICAL | t_v2.close-swap, t_v2.ghost-insert |
| 2 | Close-event mutation + recompute silently accepted (root pins metadata, not the close hash) | HIGH | fuzz.P4c (~100 cases) |
| 3 | Legacy receipts (no member_events; every pre-PR4 receipt) fully vulnerable to recompute -> MATCH | HIGH | fuzz.P4b (~100 cases), t_v2.legacy-recompute, t_v2.downgrade |
| 4 | Server seq allocator is COUNT-based: preseeded M07 event seq 8 collides with the first live entry (duplicate seq in every meeting cycle; seqs not unique ids) | HIGH | stress.conc.002 |
| 5 | Receipt attendance spoof: member active only in M06 gets an M07 receipt that MATCHes (binding spans seq<=root_seq across ALL meetings, no participation proof) | MED | t_v2.attendance |
| 6 | Partial receipts MATCH: member_events is subset-checked only, completeness never verified ("forgotten" deposits unprovable) | MED | t_v2.partial |
| 7 | Dup-seq sabotage: same-seq other-member event inserted pre-close -> honest member's receipt FORKs while chain.verify() passes (seq_to_member last-wins) | MED | t_v2.dupseq |
| 8 | /api/reset commits data loss: pre-reset bound receipts FORK after reset+reclose (Rs 777 entry dropped), no repair path | MED | t_v2.reset-orphan |
| 9 | Host parser bypass: "127.0.0.1:8123.attacker.com" passes (split(':')[0]); allowlisted ::1 unreachable (bracket-IPv6 parses to "[") | MED | t_server host.port-suffix, t_v2 host-ipv6 |
| 10 | GET-CSRF survives: cross-site GET /api/attack AFTER close mutates the chain (no Origin, Sec-Fetch-Site ignored) | MED | t_v2.get-csrf, t_server csrf.001 |
| 11 | Origin guard still substring-based; unknown receipt fields/root_ts still unbound (root_ts matches with any value) | LOW | t_v2 origin-substring, t_receipt field.root_ts/extra |
| 12 | Case-sensitive member names (no NFC normalization): "sita" vs "Sita" breaks honest receipts | LOW | t_v2.case-sensitive |
| 13 | Auditor hint box builds innerHTML with UNescaped evidence (latent XSS if ANY chain string becomes attacker-controlled, e.g. future file import) | LOW | t_v2.xss-hints |

## Stress results (t_stress)

- 8 threads x 50 concurrent entries: 400/400 recorded, zero lost updates
  (single-threaded HTTPServer serializes) - but seq 8 duplicated (finding 4).
- 10,000 entries + close: works, but the Sita receipt carries ~10,000
  member_events refs -> /api/state payload ~600 KB, receipts grow
  unboundedly with member activity (a 1e6-entry group -> ~70 MB receipts;
  QR-printing them is impossible). verify_receipt still fast (<2 s at 10k refs).
- 60 entry+close+reset cycles: stable.
- 9 malformed-param bombs (5000-digit paise, 2000-char types, dup params):
  server survives.

## Round-1 criticals re-check

- Witness signatures STILL never verified (0 call sites in chain.py): CRITICAL
  remains OPEN; README discloses it as structural boundary (truthful).
- Full recompute: HALF-fixed - caught for bound receipts on non-close edits,
  still silent for close-event edits (finding 2) and all legacy receipts
  (finding 3). The one-line fix remains: verify_receipt must compare the
  receipt root against the RECOMPUTED tail hash (or close hash) of the chain,
  not against roots[] metadata.
- Genesis/prefix deletion: caught for bound receipts (member hashes re-link),
  still silent for legacy receipts.