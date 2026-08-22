# BAHI Attack Suite Findings

Audit date: 2026-08-23. Target: `craft-n-code-bahi` @ 3296ed3 (Python 3.14.4, pure stdlib).
Suite: `attack/` (2,157 executed cases: 97 SAFE defense checks all held, 107 VULN flaw
reproductions, 1,900 seeded fuzz property cases, 34 benchmark metrics, 1 real-browser XSS
proof). Run everything yourself:

    python3 attack/run_all.py          # whole suite (fuzz 200 iters)
    python3 attack/xss_proof.py        # real headless-Chromium XSS proof

Everything below was reproduced by actual execution; test IDs are clickable evidence.
Severity is relative to the product's own promises (append-only verified ledger, offline
receipts that expose silent edits, never-crash robustness).

---

## Executive verdict

| # | Finding | Severity | Test IDs | Fix in one line |
|---|---------|----------|----------|-----------------|
| 1 | Witness signatures are NEVER verified: any 2 strings pass quorum | CRITICAL | t_receipt wsig.fake/dupe/oneparty/unicode/dupname | call `witness.verify()` on every signature at verify_receipt + close time |
| 2 | Full recompute defeats receipts: edit + rehash whole chain -> verify OK + MATCH | CRITICAL | t_chain recompute.003/004, fuzz.P4 x100 | compare receipt root against the RECOMPUTED tail hash, not stale metadata |
| 3 | Genesis/prefix deletion is fully silent: whole M06 meeting erased, M07 receipt MATCHes | CRITICAL | t_chain del.first, del.prefix | bind receipts to a group genesis root; verify() must check head prev == GENESIS |
| 4 | Stored XSS via /api/entry `type` -> innerHTML sink, PROVEN in Chromium | HIGH | t_server xss.001-003, xss_proof.py | escape/whitelist `type`, use textContent |
| 5 | DNS-rebinding CSRF: Host/Origin prefix+substring checks bypassable; state-changing GETs | HIGH | t_server host.*, origin.*, rebind.001, csrf.001-005 | exact Host match, full Origin origin-check, POST-only mutations + CSRF token |
| 6 | CSV formula injection in auditor export (=, +, -, @ members/timestamps) | HIGH | t_exporter csv.formula/prefix/ts | escape formula-prefix cells |
| 7 | Receipt `member` and `root_ts` are NOT bound: wrong/absent member still MATCH | HIGH | t_receipt field.member/root_ts/extra, missing.member | verify receipt member + ts against chain |
| 8 | Hardcoded witness passphrases in server.py ("pass-Meera" etc.) | MED | t_witness fake.Meera/Laxmi, 005 | env config + per-group passphrase |
| 9 | verify_receipt crashes on None/str receipts, partial root metadata | MED | t_receipt none/str-receipt, t_chain roots.003 | type-check receipt and root_meta |
| 10 | verify() crashes on non-dict event rows (TypeError) | MED | t_chain load.events-not-dict | isinstance checks in verify loop |
| 11 | audit_report() crashes (KeyError) on the corrupt shape load() itself produces | MED | t_exporter report.006 | skip __corrupt__ roots in report |
| 12 | balances() crashes on missing/null/list amounts (KeyError/TypeError) | MED | t_loans corrupt/null/list | guard every field access |
| 13 | load() RecursionError crash on deeply nested JSON | MED | t_chain load.deep-nesting | catch RecursionError or pre-validate |
| 14 | /api/close double-call overwrites M08 root; entries after close silently invalidate receipts | MED | t_server repeat.001/002 | unique meeting ids, refuse post-close entries |
| 15 | Money-input misbooking: negative paise -> 0, garbage/digit-spam -> Rs 10000 silently | MED | t_server param.001-004 | reject, never silently substitute |
| 16 | Negative outstanding, loans > corpus, typo types vanish funds | MED | t_loans repay-noloan/overrepay/corpus/typo | cross-checks in balances() |
| 17 | Hint-layer blind spots: substring suppression (Ash vs Asha), 2-loan threshold, single-loan concentration invisible cross-meeting, orphan post-close events ignored, deleted roots silence exports | LOW | t_exporter hint.substr/duploan/singleloan/orphan/meet.002/003 | hardened rule keys, whole-group windows |
| 18 | Protocol laxity: string/bool/float/whitespace values, duplicate/out-of-order seqs, unverified group field, re-close orphaning, h() 0x1f injection collisions | LOW | t_chain H.006, amount.003-007, member.003, ts.001/002, seq.002-005, roots.005, recompute.006 | strict schema validation layer |

---

## CRITICAL findings (core ledger promise broken)

### 1. Witness signatures are NEVER verified — any 2 strings pass quorum
`witness.verify()` exists (witness.py:17) but has ZERO call sites in the entire repo.
`verify_receipt()` only checks: receipt has >= 2 witness entries, chain has >= 2 entries,
receipt entries are a string-subset of chain entries (chain.py:203-210). No crypto check.
Proof: receipts with witnesses `["aaa","bbb"]`, `["x","x"]`, two signatures from the SAME
single witness, or unicode garbage all verify `MATCH`.

    t_receipt: VULN.recv.wsig.fake / wsig-dupe / wsig-oneparty / wsig-unicode / wsig-dupname

Impact: the "2+ members sign the root" quorum is decorative. One collaborator (or the
bookkeeper) can close any meeting with two arbitrary strings and every receipt MATCHes.
Combined with findings 2 and 3, full ledger forgery is a few lines of Python.

### 2. Full recompute defeats receipts: edit + rehash everything -> verify OK + MATCH
`verify_receipt`'s root check compares the receipt root against `roots[meeting]["root_hash"]`
metadata. `chain.verify()` only re-checks internal hash consistency. Neither ever compares
the receipt root against the hash chain's RECOMPUTED tail. So: edit any event, recompute
every hash (attacker with file control), leave metadata alone -> chain.verify() OK,
receipt root == stale metadata root -> MATCH. Verified for naive recompute, recompute +
metadata update, and via 100 randomized fuzz cases.

    t_chain: VULN.recompute.003 / recompute.004
    fuzz:     P4.0000..P4.0099 (all MATCH)

The README claims "edit anything in the past, every later hash breaks" and "detects silent
edits AFTER witnessing". Both are false under full recompute, which their own docs
dismiss as "undetectable by design" — but it IS detectable: the receipt root pins a value
that the recomputed chain no longer produces. Trivial fix: `verify_receipt` should
recompute the tail (or expose it from verify()) and require receipt root == recomputed
tail.

### 3. Genesis/prefix deletion is fully silent
`chain.verify()` walks prev-pointers from the head; deleting the head (or any whole prefix
ending before the receipt's meeting close) leaves every remaining prev-link consistent.
Deleting the genesis event passes verify():

    t_chain: VULN.del.first

And deleting an ENTIRE earlier meeting (M06 loan Rs 20,000 + M06 close) still yields
`MATCH` for a held M07 receipt — history simply vanishes:

    t_chain: VULN.del.prefix

Impact: a bookkeeper with file control deletes up to the previous meeting's close with
zero detection; only receipts from the deleted meetings themselves fork (and only if
someone still checks them). Fix: verify() must assert the head event's prev equals
`h("GENESIS", group_id)`, and receipt verification should require every earlier root to
exist (or receipts should bind the full root set).

---

## HIGH findings (web layer / auditor workflow)

### 4. Stored XSS via /api/entry `type` — PROVEN in a real browser
`/api/entry` accepts any `type` string; `/api/state` returns it; INDEX_HTML builds the
chain table with `innerHTML += '<td>'+e.type+'</td>'` — no escaping exists anywhere in the
page JS. Attack: `GET /api/entry?type=<img src=x onerror=...>` then any page load executes
it. Proof (headless Chromium, real DOM):

    xss_proof.py: payload stored verbatim: True
    xss_proof.py: XSS marker in rendered DOM: True
    ... <body data-xss="PWNED"> ...

    t_server: VULN.http.xss.001 / xss.002 / xss.003

For a localhost demo the blast radius is the operator's own browser (chain state, receipts,
attacker can drive /api/* from the page) — but combined with finding 5 the attacker's page
can do all of it remotely.

### 5. DNS-rebinding CSRF: Host/Origin guards are prefix/substring checks, state-changing GETs
Host guard: `host.startswith("127.0.0.1")` / `host.startswith("localhost")`. Bypass:
`127.0.0.1.evil.com` and `localhost.evil.com` (and `127.0.0.1:8123.attacker.com`) pass.
Origin guard: `"127.0.0.1" in origin` / `"localhost" in origin`. Bypass: any Origin
containing the substring, e.g. `http://evil.example/?u=http://127.0.0.1:8123`. And when
Origin is ABSENT (img/form GET) the guard is skipped entirely — every mutation endpoint
(entry/close/attack/reset) is GET with no CSRF token. Full attack:

    <img src="http://127.0.0.1.evil.com:8123/api/attack">   # rebind domain -> 127.0.0.1

    t_server: VULN.http.host.127.0.0.1.evil.com / localhost.evil.com / 127.0.0.1:8123.attacker.com
              VULN.http.origin.127.0.0.1.evil.com / evil.example/?u=...
              VULN.http.origin.none / rebind.001 / csrf.001-005

### 6. CSV formula injection in the auditor export
`export_csv` quotes commas/newlines but not formula prefixes. Member names and timestamps
are attacker-influenced strings; `=HYPERLINK(...)`, `+1+1`, `-1`, `@x` cells execute when
the auditor opens the CSV in Excel/LibreOffice.

    t_exporter: VULN.csv.formula / csv.prefix / csv.ts

### 7. Receipt member and root_ts are NOT bound
`verify_receipt` never reads `receipt["member"]` or `receipt["root_ts"]`. A receipt for a
different member, with no member field, or with any timestamp still MATCHes. Receipts also
accept arbitrary unknown fields. The receipt QR promises to bind group+meeting+member+root;
it binds only group+meeting+root.

    t_receipt: VULN.recv.field.member / field.root_ts / field.extra / missing.member

---

## MEDIUM findings (crash / robustness / misbooking)

| ID | Crash / behavior | Evidence |
|----|------------------|----------|
| 8 | Hardcoded passphrases `pass-Meera`/`pass-Laxmi` in server.py; anyone with the repo forges seals (moot until #1 fixed, then critical) | t_witness fake.Meera, fake.Laxmi, 005 |
| 9 | `verify_receipt(None)` / `verify_receipt("str")` AttributeError; partial root_meta (missing root_hash) KeyError — violates "never crashes" | t_receipt none/str-receipt; t_chain roots.003 |
| 10 | `verify()` TypeError on non-dict event rows (`field not in ev`) | t_chain load.events-not-dict |
| 11 | `audit_report()` KeyError on `__corrupt__` roots (the exact shape `load()` produces on a bad file) | t_exporter report.006 |
| 12 | `balances()` KeyError (missing amount_paise) / TypeError (None, list amounts) — kills /api/state | t_loans corrupt/null/list |
| 13 | `load()` RecursionError on deeply nested JSON (100k brackets) — load catches only OSError/ValueError | t_chain load.deep-nesting |
| 14 | Double `/api/close` re-closes HARDCODED "M08", overwrites the M08 root metadata; `/api/entry` after close is accepted and instantly invalidates the fresh receipt (events-after-close) | t_server repeat.001/002 |
| 15 | paise handling: `-100` -> 0 (clamped, no error), `abc` -> Rs 10000 (silent default), 6000-digit -> Rs 10000 (int-limit fallback), `paise=1&paise=2` -> first wins silently | t_server param.001-004 |
| 16 | Negative outstanding (repayment without loan), loans exceeding corpus, type typo `repaid` swallows Rs 5,000 from the loan view | t_loans repay-noloan/overrepay/corpus/typo |
| 17 | `/api/entry` mints `MEETING-CLOSE` events with arbitrary amounts; 5 KB type strings accepted; any path returns the app (no 404) | t_server xss.003, param.007, base.003 |

---

## LOW findings (protocol & hint-layer hygiene)

- h() separator-injection: parts containing byte 0x1f make DIFFERENT tuples hash identically
  (`h("a\x1fb","c") == h("a","b\x1fc")`) — values are attacker-influenced strings.
  (t_chain H.006)
- Amount laxity: numeric strings, bools, floats (1.5 -> 1), whitespace members, None/dict
  timestamps accepted into the chain. (t_chain amount.003-007, member.003, ts.001/002)
- seq uniqueness/ordering unenforced: duplicate seqs with different identities coexist,
  close_meeting seq can be smaller than existing event seqs. (t_chain seq.002-005)
- per-event `group` field is NOT in the hash: tampering any event's group passes verify();
  cross-group events ride inside a chain (head-group check only). (t_chain tamper.*.group,
  recompute.006, fuzz.P3 group cases)
- re-close same meeting id overwrites the roots entry, orphaning every earlier receipt for
  that meeting (FORK for honest holders). (t_chain roots.005, t_receipt chain.004)
- empty group_id marks a well-formed chain "corrupt" by property. (t_chain group.002)
- duplicate_identity substring suppression: member "Ash" x3 is masked by existing "Asha"
  evidence. (t_exporter hint.substr)
- 2 identical loans never flagged (threshold 3); 100% single-loan concentration across
  meetings invisible (rule needs >= 2 loans inside one meeting); per-meeting arithmetic
  mismatch only; post-close orphan events invisible to every hint; deleting a roots entry
  silently erases that meeting from exports; duplicate root_seq rehomes events to the
  first meeting. (t_exporter hint.duploan/singleloan/crossmeeting/orphan, meet.002/003)
- Receipts accept unknown extra fields; int meeting ids tolerated; witnesses as non-list. (t_receipt field.extra, type.001-003)
- Witness layer: no revocation/rotation API, same passphrase -> same key for every group,
  int/float JSON canonicalization brittleness, NFC/NFD spellings sign differently. (t_witness 005-008, 016-017)

---

## What HELD (verified defenses, 97/97)

- All single-field tamper on hashed fields (amount/member/type/ts/seq/prev/hash) detected
  at every position (t_chain SAFE.tamper.*, fuzz.P3 x ~150)
- Swap detection, middle/last deletion detection (t_chain SAFE.swap/del)
- Receipt quorum counting (0/1 witness fails), witness subset direction, group binding at
  the head-group level, meeting-root-missing/close-missing/events-after-close paths (t_receipt)
- Negative-Amount rejection, non-str member rejection, NaN rejection (t_chain)
- CSV comma/newline quoting (t_exporter csv.comma/newline)
- HTTP: foreign Host/Origin 403, POST/PUT/DELETE 501, HEAD alias (t_server)
- Hint rules fire for the intra-meeting cases they were designed for (t_exporter SAFE.hint.*)
- Fuzz: honest chains always verify; recompute-consistent chains always verify internally
  (as designed); naive tamper always detected except group; balance arithmetic invariant
  holds; export/import roundtrip identical; witness roundtrips hold (fuzz P1-P3, P6-P8, P10)

## Benchmarks (Python 3.14.4, this machine)

| Metric | Value |
|--------|-------|
| h() throughput | ~672k hashes/sec |
| add_event 1k / 10k / 100k | 2.1 ms / 23.8 ms / 246 ms |
| verify() 1k / 10k / 100k | 1.9 ms / 19.9 ms / 195 ms |
| verify_receipt @ 100k events | 197 ms |
| balances() @ 100k | 14 ms |
| hint_flags @ 100k / 50 meetings | 442 ms |
| export JSON @ 100k | 27.9 MB |
| export CSV @ 100k | 11.3 MB |
| save / load @ 100k | 169 ms / 187 ms (30.9 MB file) |
| peak memory @ 100k events | ~46.5 MB |
| HTTP /api/state | 0.75 ms/req (sequential) |
| HTTP /api/entry | 0.80 ms/req (sequential) |

Linear scaling confirmed for add/verify/export; no quadratic hotspots up to 100k events.

## Threat-model note

All CRITICAL findings operate within the bookkeeper-control boundary the project already
disclaims; the difference is they were previously called "undetectable by design" when
they are actually detectable with 1-5 line fixes (recompute-tail pin, genesis check,
signature verification, member binding). Mass collusion at entry time (everyone agrees on
a false number) remains genuinely undetectable by any hash scheme — the suite does not
and cannot touch that.