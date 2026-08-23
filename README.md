# BAHI: the witnessed ledger

Offline member-witnessed SHG ledger. Every entry goes into a SHA-256 chain,
every meeting is closed under quorum witness, every member carries a receipt
that exposes silent edits. No server. No cloud. No SIM. No internet.
Python 3 stdlib only.

Team 511, Craft N Code Round 1, PS-17 SHG DIGITAL LEDGER -
TAMPER-EVIDENT FINANCIAL LOGS.

## What and why

10.03 crore women save together in 94.16 lakh SHGs (PIB, 2026-07-04). Today
the person who records the money is the only proof of the money: the register
belongs to the secretary, the server belongs to the app. Documented
failures are national:

- Rs 107.94 crore in audit deficiencies across 186 blocks in Tamil Nadu
  (grade B, RTI-backed, New Indian Express, 2026-08-18).
- Rs 3.38 crore bank loss with 4 convictions for fake SHGs (Indian Overseas
  Bank, June 2025).
- 1.76% NPA on Rs 2,99,833.35 crore of outstanding SHG bank loans
  (PIB, 2025-08-08).

BAHI makes every member a witness instead of a bystander. The law of the
ledger is SHA-256; the verdict is always math.

## How it works

- Local SHA-256 event chain: edit anything in the past, every later hash
  breaks.
- Hash domain separation: every field is separated by 0x1f and the group id
  is inside every hash, so ambiguous concatenations are impossible.
- Meeting close: 2+ distinct witnesses sign the root hash (quorum
  enforced). Witness records are name-bound; cryptographic verification is
  wired and optional via witness_keys.
- Member receipt: group, meeting, member, root, signatures, and the
  member's OWN event hashes (member binding). The receipt is tied to the
  RECOMPUTED close hash, so close-swap and ghost-insert forgeries fork.
- Verify OFFLINE anytime: MATCH, or FORK-AT-EVENT-n with a named divergence.
- Errors are structured: corrupt input yields "corrupt-file: <reason>",
  never a traceback.
- Corrections are reversal + replacement only. No edits, ever.
- Loans and balances are computed deterministically from the chain; over-
  repayment is surfaced as over_repaid_paise, never hidden debt.
- AI is a hint layer only (advisory rules). The verdict is pure hash math.

## Evidence trail (what we built and how we proved it)

### Attack resistance (live, in this repo)

- tests.py: 50/50 attack scenarios, exit 0 = all green.
  Covers: edit, delete, reorder, root tamper, missing witness, forged
  receipt, ghost meeting, determinism, quorum, group binding, corrupt file,
  close-swap, post-close append, consistent re-link rewrite, member binding,
  open-meeting flow.
- attack/run_all.py: 1,542-case adversarial battery, 0 SAFE broken,
  0 failed expectations.
  - t_chain 100, t_receipt 37, t_witness 20, t_loans 27, t_exporter 32,
    t_server 46, t_v2 23.
  - fuzz.py: 1,241 seeded fuzz properties (tamper matrix, recompute attacks,
    bound vs legacy receipts, balance invariants, roundtrip byte-identity).
  - stress.py: concurrent writers, torn writes, sqlite-vs-file equivalence.
  - benchmarks.py: 34 metrics.
- Every module writes findings to attack/results.json with test IDs.
  Run it before trusting any release: python3 attack/run_all.py

### Benchmarks (100,000-event chain, Python 3.14, this machine)

- verify: ~0.2-0.22 s per full-chain verify (100k events).
- balances: 0.025 s. hint flags: 0.392 s. save: 0.162 s. load: 0.227 s.
- HTTP API: 0.387 ms per state call, 0.517 ms per entry call.
- Peak memory at 100k events: 46.5 MB. File size: 30.9 MB (JSON, text-safe).
- 1000-event group verify: 0.001 s. A 40-member group with 10 meetings a
  year verifies 400 events in under 5 ms, on any phone or laptop.

### Research that shaped it

Run with the reports in ~/parallel-ai-stack/test-results/ (war1v5-ps-18,
war1v6-bahi-scams, war1v6-bahi-ai-voice, war1v6-bahi-sec-hardening,
war1v7-bahi-datasets-real, war1v7-bahi-ml-methods, war1v8-bahi-hardening,
war1v8-bahi-backend-wave, war1v8-bahi-ui-wave):

- Scam evidence with citations: the three national failures above.
- 62.2% of low-literacy users fail icon-only interfaces (UI study): every
  button carries an icon AND a word.
- Vosk Hindi 42 MB / 20.89% WER (IITM): voice prefill is a prototype path.
- TabPFN AUC 0.934 vs XGBoost 0.924 on 18 datasets: at federation scale,
  hints stay rules-first because 50-500 events per group cannot train nets.
- QR level Q for on-paper receipts (error correction for damaged print).

### Known honest boundaries (we say them out loud)

- Detects silent edits AFTER witnessing. Mass collusion at entry time
  (everyone agrees to enter a false amount) cannot be caught.
- HMAC witness signatures verify against keys when supplied; an offline
  member holding only the receipt verifies the root, the real fraud signal.
- Not a security audit. Not a LokOS replacement. LokOS records the books;
  BAHI makes the books verifiable by the member who holds the receipt,
  offline, forever.
- Receipt gossip across phones (flood the group with copies) is roadmap,
  not shipped.

## Run it on your machine

No dependencies. Python 3.8+ stdlib. Works on Linux, macOS, Windows,
Android (Termux), iOS (a-Shell / Pythonista), Raspberry Pi, any offline box.

### Terminal demo (fastest proof)

    git clone https://github.com/harshgounder/craft-n-code-bahi.git
    cd craft-n-code-bahi
    python3 tests.py          # 50/50 attack scenarios, exit 0 = green
    python3 demo.py           # 90-second scripted demo in the terminal

### Web UI (Ledger & Parchment)

    python3 server.py         # http://localhost:8123

Then: entry buttons (deposit / borrow / repay), close meeting under two
witnesses, ATTACK (the secretary edits an entry), watch the verdict flip to
FORK AT EVENT 8, export the audit CSV.

### Attack battery

    python3 attack/run_all.py         # 1,542 cases -> attack/results.json
    python3 attack/bench.py           # 34 benchmark metrics

### Windows

    py -3 tests.py
    py -3 server.py

Open http://localhost:8123 in any browser. Everything runs locally; the
laptop does not need to be online.

### Android (Termux)

    pkg install python
    git clone https://github.com/harshgounder/craft-n-code-bahi.git
    cd craft-n-code-bahi && python tests.py && python server.py

### Offline field note

Clone once on a laptop, copy the folder to every phone with USB or a
memory card. Zero network needed for the lifetime of the ledger. The chain
file is a single JSON; back it up like cash.

## Repo layout

    chain.py     hash chain, receipts, verify_receipt (the core, stdlib only)
    witness.py   name-bound witness records (HMAC), optional key verification
    loans.py     deterministic balances, rupees formatting, over-repayment
    server.py    web UI, Ledger & Parchment, Host/Origin guards, atomic saves
    tests.py     50/50 attack scenarios
    demo.py      terminal demo runner
    exporter.py  audit report (schema-validated), hint flags, CSV export
    audit-report.schema.json   machine-checkable audit output contract
    attack/      adversarial battery: 1,542 cases, fuzz, stress, benchmarks

## Attack suite stats (all in-repo, all runnable)

  t_chain 100 | t_receipt 37 | t_witness 20 | t_loans 27 | t_exporter 32
  t_server 46 | t_v2 23 | fuzz 1,241 (seeded, some skip) | stress 16
  benchmarks 34. run_all.py records 1,542 cases on a clean run.
  Ship state: 0 SAFE broken, 0 failed expectations.