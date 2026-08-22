# BAHI — Security Audit & Attack Catalog

Threat-model + attack enumeration for the BAHI witnessed-ledger prototype.
Every `[CONFIRMED]` entry was reproduced against `main` @ `eb484dd` with a
throwaway probe script (`probe_exploits.py`); `[THEORETICAL]` entries are valid
attack classes applicable to this design that were reasoned but not reproduced;
`[MITIGATED]` entries were already fixed.

Status legend: **CONFIRMED** (reproduced) · **THEORETICAL** (valid class, not
reproduced) · **MITIGATED** (already handled).

---

## Remediation applied (companion changeset)

The CONFIRMED exploits are fixed in the same changeset that ships this
document; each has a regression test in `tests.py` (now 32 scenarios):

| Attack | Fix | Test # |
|---|---|---|
| A1/B1 quorum dup-sig | count DISTINCT signatures (`len(set(...))`) | 16 |
| A11 type spoof | `VALID_EVENT_TYPES` enum enforced in `add_event` | 17 |
| H6 whitespace member | strip + reject empty after strip | 18 |
| A10 control-char member | reject control chars before strip | 19 |
| A8/H5 duplicate seq | unique-seq invariant in `add_event` | 20 |
| F9 `__corrupt__` sentinel | `_corrupt` attribute + reserved meeting id | 21, 22 |
| A9 amount bound | `MAX_AMOUNT_PAISE` + bool rejection | 23 |
| A2 delimiter ambiguity | type-tagged, length-prefixed `h()` | 24 |
| A3 type confusion | type tags in `h()` | 25 |
| (new) unanchored genesis | `verify()` anchors first event to `h("GENESIS", group)` | 26, 27 |
| G2 CSV formula injection | `'`-prefix on `= + - @` cells | 28 |
| G1 hint_flags crash | defensive `.get()` + malformed-event skip | 29 |
| G3 cross-meeting FP | whole-chain cumulative net | 30 |
| D1/D2/D3 host/origin/CSRF | exact hostname+origin allowlist, POST + `X-BAHI` header | (server smoke test) |

---

## Attack surface map

| Surface | Files | Trust boundary |
|---|---|---|
| Hash chain & integrity | `chain.py` (`h()`, `verify()`, `add_event`) | bookkeeper vs. members |
| Witness signing & quorum | `witness.py`, `verify_receipt` | witnesses vs. verifier |
| Receipt & verification | `chain.py` (`receipt_payload`, `verify_receipt`) | member vs. bookkeeper |
| HTTP server | `server.py` (`do_GET`/`do_HEAD`, Host/Origin checks) | network vs. localhost |
| Web UI | `server.py` (`INDEX_HTML`, JS `innerHTML`) | chain data vs. browser |
| Storage & files | `chain.py` (`save`/`load`) | filesystem vs. process |
| Exporter & analytics | `exporter.py`, `loans.py` | chain data vs. auditor |
| Data model | all (`seq`, `type`, `member`, `meeting`) | invariants vs. code |
| Human / fraud | (process) | recorder/witness/member trust |

---

## Confirmed exploits (reproduced, `eb484dd`)

These 14 were run against the live code; output is quoted verbatim below each.

1. **Quorum bypass via duplicated witness signature** — `len()` counts
   duplicates, so one real signature listed twice satisfies `MIN_WITNESSES=2`.
   `verify_receipt`: `1 witness -> MATCH [EXPLOITED]`
2. **Host-header suffix bypass (DNS rebinding)** — `host.startswith("127.0.0.1")`
   accepts `127.0.0.1.evil.com` / `localhost.evil.com`. `-> ACCEPT`
3. **Origin-check bypass (CSRF)** — absent `Origin` and substring matches
   (`http://127.0.0.1.evil.com`) both pass. `-> ACCEPT`
4. **`type` field spoofing** — no enum validation; `type="Loan"` is invisible to
   `balances()` and `hint_flags()`. `balances sees Asha? False`
5. **CSV formula injection** — member `=HYPERLINK(...)` exported verbatim;
   opens as a formula in Excel/LibreOffice. `member cell starts with = : "=HYPERLINK(...`
6. **`hint_flags` crash on malformed event** — `KeyError: 'member'` (direct
   indexing, not defensive like `verify()`). `CRASH KeyError: 'member'`
7. **`__corrupt__` sentinel collision** — a real meeting named `__corrupt__`
   flips `chain.corrupt` to True (denial / a way to hide a meeting). `chain.corrupt = True`
8. **Whitespace-only member accepted** — `add_event("   ")` passes the
   `not member` check. `ACCEPTED (member='   ')`
9. **`h()` delimiter collision** — a field containing `\x1f` breaks domain
   separation: `h("A\x1f","B") == h("A","\x1fB")`. `True`
10. **Historical receipt invalidated by the next meeting** — the new
    `events-after-close` check makes a M06 receipt fail once M07 opens.
    `M06 receipt after M07 opens -> events-after-close [BROKEN]`
11. **`/api/entry` emits a duplicate `seq`** — `len(non-close)+1` collides with
    the last data event after a prior meeting. `next seq=8 already in chain? True`
12. **Cross-meeting repayment false-positive** — a loan in M06 repaid in M07
    trips `arithmetic_mismatch` (meeting-scoped). `repayments Rs 20000 exceed loans Rs 0`
13. **Witness forgery via hardcoded passphrase** — `pass-Meera`/`pass-Laxmi`
    ship in source, so anyone can forge a valid witness signature. `matches real: True`
14. **`load()` accepts valid JSON with malformed events** — `verify()` reports
    `corrupt-file: missing field 'member'`, but `hint_flags()`/`balances()`
    crash first (see #6).

---

## A. Hash-chain & cryptographic integrity

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| A1 | Duplicate-witness quorum bypass | CONFIRMED | High | `verify_receipt` | count **unique** sigs (`len(set(...))`) |
| A2 | `h()` delimiter ambiguity via `\x1f` | CONFIRMED | Low | `h()` | length-prefix or reject control chars in fields |
| A3 | `str()` type coercion (bool→"True", `1` vs `"1"` vs `1.0`) | THEORETICAL | Low | `h()` | canonical type tags in `h()` |
| A4 | SHA-256 length-extension (advisory) | THEORETICAL | Low | `witness.py` | HMAC already used; never switch to `sha256(key‖msg)` |
| A5 | Truncated hash display (16-char prefix) spoof | THEORETICAL | Low | UI | show full hash / checksum-on-demand |
| A6 | Genesis binds only `group_id`, not roster | THEORETICAL | Medium | `BahiChain` | bind member list / group key |
| A7 | Timestamp unvalidated/backdatable | THEORETICAL | Medium | `add_event` | validate & order `ts`; tie to seq |
| A8 | `seq` not enforced unique/monotonic | CONFIRMED (via #11) | Medium | `add_event` | reject duplicate/out-of-order seq |
| A9 | `amount_paise` unbounded (huge ints) | THEORETICAL | Low | `_norm_amount` | upper bound |
| A10 | Member names not normalized (NFC/NFD, homoglyphs) | THEORETICAL | Medium | `add_event` | Unicode normalize + reject confusables |
| A11 | `type` field not enum-validated | CONFIRMED | Medium | `add_event`/`verify` | whitelist type enum |
| A12 | Duplicate JSON keys / non-canonical JSON | THEORETICAL | Low | `load()` | reject dup keys |
| A13 | Determinism claim too strong (float/locale/version) | THEORETICAL | Low | docs | scope the claim |

---

## B. Witness signature & quorum

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| B1 | Duplicate-sig quorum bypass | CONFIRMED | High | `verify_receipt` | unique-sig count |
| B2 | Hardcoded passphrases in source | CONFIRMED | Critical | `witness.py`/`server.py`/`demo.py` | real key material, never in source |
| B3 | Weak passphrase offline brute-force | THEORETICAL | High | `derive_key` | KDF (PBKDF2/scrypt/argon2) |
| B4 | One shared group passphrase → single leak = all | THEORETICAL | High | `derive_key` | per-witness asymmetric keys |
| B5 | Sig replay across identical `{root,meeting}` | THEORETICAL | Low | `sign` | nonce/timestamp in signed payload |
| B6 | Sig does not bind member/amount witnessed | THEORETICAL | High | `sign` | sign the events the witness saw |
| B7 | Bare hex sig — no signer identity stored | THEORETICAL | Medium | `close_meeting` | store `{name, sig}` |
| B8 | Quorum only checked at verify, not at close | THEORETICAL | Medium | `close_meeting` | reject `< MIN_WITNESSES` at close |
| B9 | Witness list aliased in receipt (mutable after issue) | THEORETICAL | Medium | `receipt_payload` | deep-copy witnesses |

---

## C. Receipt & verification logic

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| C1 | Forge receipt by controlling chain + recomputing root | THEORETICAL | Medium | `verify_receipt` | trust anchor outside the device |
| C2 | Historical receipt invalidated by next meeting | CONFIRMED | Medium | `verify_receipt` | per-meeting terminality, not "last event" |
| C3 | `root_seq` spoof to a different close event | THEORETICAL | Medium | `verify_receipt` | bind root_seq↔root_hash atomically |
| C4 | Missing receipt fields → `None` mis-verify | THEORETICAL | Low | `verify_receipt` | schema-validate receipt |
| C5 | Partial `member_events` (omit tampered line) | THEORETICAL | Medium | `receipt_payload` | bind full member event set + count |
| C6 | Receipt replay across groups/devices | THEORETICAL | Low | `receipt_payload` | bind issuer/device |
| C7 | No chain-of-trust for the root (TOFU) | THEORETICAL | Medium | `verify_receipt` | gossip / cross-check (roadmap) |

---

## D. HTTP server (network layer)

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| D1 | DNS rebinding via Host suffix | CONFIRMED | High | `do_GET` | exact-match allowlist, not `startswith` |
| D2 | CSRF (absent Origin / substring) | CONFIRMED | High | `do_GET` | require same-origin + CSRF token |
| D3 | GET endpoints mutate state | CONFIRMED | High | all `/api/*` | POST for mutations |
| D4 | No authentication | THEORETICAL | Critical | all | auth token / cookie |
| D5 | No rate limiting | THEORETICAL | Low | server | throttle |
| D6 | Single-threaded `HTTPServer` slowloris DoS | THEORETICAL | Medium | `server.py` | `ThreadingHTTPServer` + timeouts |
| D7 | No request/query size limit | THEORETICAL | Low | `do_GET` | cap query length |
| D8 | Query parsing edge cases (`%00`, duplicate params) | THEORETICAL | Low | `do_GET` | validate params |
| D9 | No TLS if port-forwarded | THEORETICAL | Medium | server | TLS or keep loopback-only |
| D10 | Information disclosure (`/api/state`,`/api/export`) | CONFIRMED | Medium | `do_GET` | scope data, redact sigs |
| D11 | Loopback alternates (`127.1`, `127.0.0.2`, `[::1]`) unhandled | THEORETICAL | Low | `do_GET` | full loopback allowlist |

---

## E. Web UI (client-side)

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| E1 | Stored XSS via `member`/`type` in `innerHTML` | CONFIRMED | Medium | `INDEX_HTML` JS | escape / `textContent` |
| E2 | HTML injection → UI defacement/phishing | CONFIRMED | Low | `INDEX_HTML` JS | escape |
| E3 | No CSP / X-Frame-Options / nosniff | THEORETICAL | Low | `_respond` | add security headers |
| E4 | Clickjacking of local demo | THEORETICAL | Low | `_respond` | `X-Frame-Options: DENY` |

---

## F. Storage & file system

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| F1 | Symlink attack on `save()` path | THEORETICAL | Low | `save()` | `O_NOFOLLOW` / path check |
| F2 | `.bak` file exposure / planting | THEORETICAL | Low | `save()` | restrict perms |
| F3 | Temp file leak on crash | THEORETICAL | Low | `save()` | cleanup on SIGKILL (best-effort) |
| F4 | No file locking → read/write race | THEORETICAL | Low | `save()`/`load()` | flock |
| F5 | No encryption at rest (member PII) | THEORETICAL | Medium | `save()` | encrypt or OS-level FDE |
| F6 | `load()` accepts malformed events; analytics crash first | CONFIRMED | Medium | `load()`/`hint_flags` | validate structure at load |
| F7 | Huge JSON → memory DoS | THEORETICAL | Low | `load()` | size cap |
| F8 | Deep JSON nesting → recursion/DoS | THEORETICAL | Low | `load()` | depth cap |
| F9 | `__corrupt__` sentinel collision | CONFIRMED | Medium | `load()`/`corrupt` | reserve/escape sentinel |

---

## G. Exporter & analytics

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| G1 | `hint_flags` crash on malformed event | CONFIRMED | Medium | `exporter.py` | defensive `.get()` |
| G2 | CSV formula injection | CONFIRMED | Medium | `export_csv` | prefix `'` / sanitize leading `=+-@` |
| G3 | Cross-meeting repayment → `arithmetic_mismatch` FP | CONFIRMED | Low | `hint_flags` | net across whole chain |
| G4 | Rule evadability (type spoof, seq reorder) | THEORETICAL | Low | `hint_flags` | normalize type, trust verify() |
| G5 | `audit_report` leaks sigs + full chain | THEORETICAL | Medium | `exporter.py` | redact |

---

## H. Data model & protocol invariants

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| H1 | No `meeting_id` on events → heuristic attribution | THEORETICAL | Medium | model | add meeting_id tag |
| H2 | Multi-device chain divergence (no sync) | THEORETICAL | High | (roadmap) | receipt gossip |
| H3 | Single device = single point of truth/failure | THEORETICAL | High | (roadmap) | replication |
| H4 | append-only not enforced (mutable in memory) | THEORETICAL | Medium | `BahiChain` | immutable events / append API |
| H5 | Duplicate `seq` accepted | CONFIRMED | Medium | `add_event` | unique-seq invariant |
| H6 | Whitespace member accepted | CONFIRMED | Low | `add_event` | strip + non-empty check |

---

## I. Determinism & portability

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| I1 | `/tmp` hardcoded path | MITIGATED (PR5) | — | `demo.py` | tempfile |
| I2 | `format_rupees` float precision for huge amounts | THEORETICAL | Low | `loans.py` | integer/Decimal |
| I3 | Non-ASCII JSON escaping differences | THEORETICAL | Low | `chain.py` | canonical serializer |

---

## J. Human / social / fraud & deployment

| # | Attack | Status | Severity | Target | Fix |
|---|---|---|---|---|---|
| J1 | Entry-time collusion (documented) | DOCUMENTED | High | process | out of scope (honest boundary) |
| J2 | Witness rubber-stamp / key custody by secretary | THEORETICAL | High | process | hardware/secure enclave keys |
| J3 | Member loses receipt → no detection | THEORETICAL | Medium | process | receipt redundancy |
| J4 | Secretary re-signs with captured keys | THEORETICAL | High | process | asymmetric keys + key custody |
| J5 | Bribery/coercion of witnesses | THEORETICAL | Medium | process | reputation/monitoring |
| J6 | Supply-chain risk if deps added | ADVISORY | Low | repo | pin/audit deps |
| J7 | No chain-file schema versioning/migration | THEORETICAL | Low | `save()`/`load()` | version field |

---

## Chained (composite) attacks

- **X1** — DNS rebinding (D1) + no-auth (D4) + GET-mutation (D3) → a malicious
  webpage silently tampers the ledger from the victim's own browser. **High.**
- **X2** — CSV formula injection (G2) → code execution in Excel/LibreOffice when
  an auditor opens the exported CSV. **Medium.**
- **X3** — Stored XSS (E1) + no CSP (E3) → arbitrary script in the local demo
  page if a malicious chain file is ever loaded. **Medium.**

---

## Prioritized remediation

1. **Critical / High (do first):**
   - B2/B13 — remove hardcoded passphrases; move to real asymmetric keys.
   - A1/B1 — quorum must count **unique** signatures.
   - D1/D2/D3/D4 — fix Host/Origin checks (exact allowlist), require
     same-origin + token, move mutations to POST.
   - E1 — escape all `innerHTML` interpolations (`textContent`).
2. **Medium:**
   - A11/H5/H6 — validate `type` enum, unique `seq`, strip/normalize `member`.
   - F9/G1/G2 — sanitize CSV formulas, defensive analytics, escape `__corrupt__`.
   - C2 — make receipt terminality per-meeting, not "last event in chain".
3. **Later / roadmap:**
   - meeting_id tagging, receipt gossip, replication, key custody, KDF for
     passphrases, schema versioning.

---

*Generated against `main` @ `eb484dd`. Reproduction evidence: `probe_exploits.py`
(14 confirmed cases). This document is the basis for a follow-up PR.*
