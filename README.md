# BAHI: the witnessed ledger
Offline member-witnessed SHG ledger. Every entry goes into a SHA-256 chain, every meeting is signed by witnesses, every member carries a receipt that exposes silent edits. No server needed. Team 511, Craft N Code Round 1, PS-17.

## What and why
10.03 crore women save together in 94.16 lakh SHGs (PIB, 2026-07-04). Today the person who records the money is the only proof of the money: the register belongs to the secretary, the server belongs to the app. Documented failures are national: Rs 107.94 crore in audit deficiencies across 186 blocks in Tamil Nadu (grade B, RTI-backed, New Indian Express, 2026-08-18), a Rs 3.38 crore bank loss with 4 convictions for fake SHGs (Indian Overseas Bank, June 2025), and 1.76% NPA on Rs 2,99,833.35 crore of outstanding SHG bank loans (PIB, 2025-08-08). BAHI makes every member a witness instead of a bystander.

## How it works
- Local SHA-256 event chain: edit anything in the past, every later hash breaks.
- Meeting close: 2+ members sign the root hash (quorum).
- Every member receives a QR receipt: group, meeting, her name, root, signatures.
- Verify OFFLINE anytime: MATCH, or FORK-AT-EVENT-n with a named divergence.
- Corrections are reversal + replacement only. No edits, ever.
- Loans and balances are computed deterministically from the chain (loans.py).
- AI is a hint layer only. The verdict (MATCH/FORK, balances) is pure hash math.

## Quick start
No dependencies. Python 3 stdlib only.
  python3 tests.py      # 9/9 tests, exit 0 = all green
  python3 server.py     # demo UI on http://localhost:8123 (opens browser)
  python3 demo.py       # 90-second demo runner in the terminal

## 90-second demo script
1. "Sita deposits Rs 100" via 4 icon buttons, voice repeat line + green tick (10s).
2. Close meeting M07, 2 witnesses sign, member receipt prints (10s).
3. ATTACK: secretary edits Rs 100 to Rs 10 on event 7 (5s).
4. Member receipt vs chain: FORK AT EVENT 7, red screen (5s).
5. Auditor view: fork report, chain table, loan tracker (15s).
6. Honest redo: MATCH, green screen (15s).
Zero network. Deterministic: same input, same verdict, every run.

## Honest boundaries
- Detects silent edits AFTER witnessing. Mass collusion at entry time (everyone agrees to enter a false amount) cannot be caught, and we say so.
- The receipt QRs in this demo are text placeholders rendered in the UI, not yet scannable QR codes.
- Not a security audit. Not a LokOS replacement. LokOS records the books; BAHI makes the books verifiable by the member who holds the receipt, offline, forever.
- Voice entry (Vosk Hindi 42 MB, 20.89% WER IITM) is a prototype path; the deterministic base is the icon + repeat-back flow.
- 50-500 events per group cannot train any neural net; hints are rules-first, per the research (TabPFN AUC 0.934 vs XGB 0.924 on 18 datasets applies only at federation scale).

## Scam evidence (every number sourced)
- Rs 107.94 crore deficiencies, 186 blocks, altered bills, unsupported payments, copied cashbooks, missing reconciliations (TN special audit via RTI, grade B, 18 Aug 2026).
- Rs 3.38 crore IOB loss: reused identities, forged signatures, fabricated minutes, no field verification; 4 convicted, 7-year sentences (June 2025, grade B).
- 2010 Andhra Pradesh: collection abuse allegations (threats, repeated visits, asset seizure); suicide causation contested by research.
- Rs 1,000 per transaction / Rs 5,000 stored UPI Lite caps: bounded local authority is a proven design pattern (NPCI, via priorart report).
- Source reports: war1v5-ps-18, war1v6-bahi-scams, war1v6-bahi-ai-voice, war1v6-bahi-sec-hardening, war1v7-bahi-datasets-real, war1v7-bahi-ml-methods (all in ~/parallel-ai-stack/test-results/, accessed 2026-08-22).

## Repo layout
chain.py   hash chain, receipts, verify_receipt (the core, pure stdlib)
witness.py witness signing
loans.py   deterministic balances, rupees formatting
server.py  demo web UI on port 8123
tests.py   9/9 attack tests (edit, delete, reorder, tamper, forgery, ghost)
demo.py    terminal demo runner
attack/    adversarial suite: 2,157 cases (97 defense checks, 107 flaw reproductions,
           1,900 seeded fuzz properties, 34 benchmarks, real-browser XSS proof)
FINDINGS.md severity-ranked audit results, evidence + one-line fixes

## Attack suite
  python3 attack/run_all.py    # full suite (t_chain, t_receipt, t_witness, t_loans,
                               # t_exporter, t_server, fuzz, bench) -> attack/results.json
  python3 attack/xss_proof.py  # real headless-Chromium proof of the stored XSS
Run before trusting any release. Every finding lives in FINDINGS.md with test IDs.

## Run it
  git clone <repo-url> && cd craft-n-code-bahi
  python3 tests.py
  python3 server.py     # then open http://localhost:8123
Built and tested on CachyOS, Python 3.14, zero packages installed.