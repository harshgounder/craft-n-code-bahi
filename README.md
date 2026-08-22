# BAHI - The Witnessed Ledger

Offline-first digital ledger for Indian Self-Help Groups (SHGs). The novel
part is not the record, it is the RECEIPT: every member leaves the meeting
holding a receipt that can prove, any time, offline, that the books were
not changed after she witnessed them.

## The problem in one line
The person who records the money is the only proof of the money. When the
recorder changes Rs 100 to Rs 10, nobody notices until the corpus is gone.

## The mechanism
- SHA-256 event chain on the meeting device: edit any past event and every
  later hash breaks
- Meeting close: 2+ witness keys sign the meeting root (quorum)
- Member receipt: root + meeting + member + witness signatures
- Offline verification: MATCH, or FORK-AT-EVENT-n with the exact divergence
- Pure Python stdlib. Offline: no cloud, no SIM, no internet. The demo
  UI is a local web page served by http.server on 127.0.0.1 only. No ML
  in the truth path (deterministic hash math decides).
- AI assists only (voice entry, hint flags); MATCH/FORK is always math.

## The demonstrated cases (verified sources)
| Case | Amount | Source |
|---|---|---|
| Tamil Nadu special audit, 186 block federations | Rs 107.94 crore deficiencies (news headline: Rs 108 crore) | Special audit released 18 Aug 2026 via RTI (NIExpress/Madurai) |
| Indian Overseas Bank, forged SHG minutes, 4 convicted | Rs 3.38 crore loss | CBI special court, June 2025, Chinthamani branch (lawfullegal.in, 12 Jul 2025) |
| Andhra Pradesh 2010 | collection abuse class | SC/audit record |
| Karnataka 2025 | law bans coercive collection from SHG borrowers | state legislation 2025 |

Scale: 144.22 lakh savings-linked SHG accounts (NABARD, 31 Mar 2024);
94.16 lakh SHGs / 10.03 crore members digitized under DAY-NRLM (PIB,
4 Jul 2026); Rs 11,07,479.60 crore cumulative credit linked, Rs 2,99,833.35
crore outstanding, NPA 1.76%.

## Run it
python3 tests.py        # 9 attack scenarios, all must pass
python3 server.py       # demo UI at http://127.0.0.1:8123
python3 demo.py         # scripted MATCH -> FORK-AT-EVENT-7 -> reset

Demo beats: entry with 4 icons + repeat-back, meeting close with 2 witness
signs, ATTACK button (Rs 100 -> Rs 10), member receipt shows FORK, auditor
view with hint flags + JSON/CSV export, honest redo shows MATCH.

## Honest boundaries
- Detects edits AFTER witnessing. It is not fraud prevention, it is fraud
  DETECTION with a member-held artifact. Mass collusion at entry time is
  outside our claim.
- Not a LokOS replacement. BAHI verifies; integrations come later.
- HMAC witness keys are a structural protocol for the prototype, not a
  security audit. Production path: asymmetric keys, receipt gossip,
  federation-scale analysis (roadmap).

## Tech
Python 3 stdlib only (http.server, hashlib, json). Single meeting device,
offline, deterministic: same files produce the same bytes and the same
verdict on any laptop.

Built for Craft N Code 2026 Round 1 (PS-17, SHG Digital Ledger). All
research claims traceable to the war-room corpus (21-statement
startup-diligence wave + SHG-specific deep research).