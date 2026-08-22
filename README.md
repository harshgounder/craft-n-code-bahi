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
  python3 tests.py      # 50/50 tests, exit 0 = all green
  python3 server.py     # demo UI on http://localhost:8123 (opens browser)
  python3 demo.py       # 90-second demo runner in the terminal
  python3 attack/run_all.py   # 1,542-case adversarial battery, 0 SAFE broken

## 90-second demo script
1. Meeting M07 starts OPEN: amber PENDING, entries accepted (5s).
2. "Sita deposits Rs 100" via 4 icon+word buttons, voice repeat line + green tick (10s).
3. Close meeting M07, 2 witness records sign, member receipt prints (10s).
4. ATTACK: secretary edits Rs 100 to Rs 10 on event 8 (Sita's deposit) (5s).
5. Member receipt vs chain: FORK AT EVENT 8, red screen (5s).
6. Auditor view: fork report, chain table, loan tracker, CSV export (15s).
7. Honest redo: MATCH, green screen (15s).
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
witness.py witness name-bound records (HMAC), cryptographic check with keys
loans.py   deterministic balances, rupees formatting, over-repayment surfaced
server.py  demo web UI on port 8123 (Ledger & Parchment redesign)
tests.py   50/50 attack tests (edit, delete, reorder, tamper, forgery, ghost,
           member binding, close-hash tie, quorum, corrupt-file, open flow)
demo.py    terminal demo runner
attack/    adversarial suite: 1,542 cases (t_chain 100, t_receipt 37,
           t_witness 20, t_loans 27, t_exporter 32, t_server 46, t_v2 23,
           fuzz 1,241, stress 16, benchmarks 34) - 0 SAFE broken
FINDINGS-v2.md round-2 audit: fix verification + NEW critical (close-swap
           ghost-insert forgery) - fixed by the close-hash tie

## Attack suite
  python3 attack/run_all.py [fuzz-iters]  # full battery -> attack/results.json
  python3 attack/xss_proof.py  # real headless-Chromium XSS proof (marker present = vulnerable)
Run before trusting any release. Every finding lives in FINDINGS*.md with test IDs.

## Run it
  git clone <repo-url> && cd craft-n-code-bahi
  python3 tests.py
  python3 server.py     # then open http://localhost:8123
Built and tested on CachyOS, Python 3.14, zero packages installed.