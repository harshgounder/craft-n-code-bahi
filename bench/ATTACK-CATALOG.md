# BAHI — Comprehensive Attack Catalog (Round 3)

A full-spectrum threat catalog for the BAHI SHG ledger prototype, written after
PR #9 (pixie-chan) and PR #10 (sujalsshukla) were reconciled. Each entry is
classified by **evidence level**:

- **VERIFIED** — reproduced by an executed probe against the current code
  (`round3_probe.py`, `round3b_probe.py`).
- **INSPECTION** — confirmed by reading the code path (no probe needed).
- **THEORETICAL** — a known attack class, assessed for applicability; not
  reproduced because it is out of the prototype's scope or requires an
  adversary capability the prototype doesn't yet model.

Severity is for the *product* a BAHI-style ledger would become in production,
not just the demo.

---

## 1. Cryptographic / hash-chain integrity

| # | Attack | Evidence | Sev | Notes & fix |
|---|---|---|---|---|
| C1 | **Quorum gaming: one witness signs twice** | VERIFIED | CRITICAL | `verify_receipt` counts witness *records*, not *unique names*. Two records both `{witness:"Meera"}` satisfy MIN_WITNESSES=2 → a single person can self-attest. Fix: require `len({name for name,_ in sigs}) >= MIN_WITNESSES`. |
| C2 | Witness signature forge via low-entropy passphrase | THEORETICAL | HIGH | HMAC key = `HMAC(passphrase, "BAHI-WITNESS:"+name)`; SHG passphrases are human-memorable → offline brute-force. Production needs asymmetric keys (README already flags this). |
| C3 | Witness key reuse across groups/meetings | THEORETICAL | MED | Same passphrase reused → one compromise exposes every meeting. Add per-meeting salt. |
| C4 | Length-extension on `h()` | THEORETICAL | LOW | SHA-256 is Merkle–Damgård, but `h()` hashes a delimited field string and outputs hexdigest; the chain structure (fixed fields + `\x1f`) leaves no room to append a valid event. Checked, not exploitable. |
| C5 | Delimiter injection (`\x1f`) in member names | THEORETICAL | LOW | A01 fixed the digit-absorption collision; a member name literally containing `\x1f` is not sanitized but no collision was constructible. |
| C6 | Majority rewrite (full file control) | INSPECTION | HIGH | Documented boundary: a bookkeeper with the file can re-link everything. Detection is only via the member-held receipt. Not a bug — the threat model. |
| C7 | Genesis substitution / group rename | VERIFIED(fixed) | — | Now caught: `group_id` is folded into every hash + genesis anchor (N1 in PR #10). |
| C8 | Cross-meeting event transplant | VERIFIED | MED | Move an event from M01 to M02 and re-link; `verify()` passes if seqs stay valid. Audit layer sees it only as a `duplicate_identity` hint, not a transplant. |
| C9 | Meeting replay (duplicate a whole meeting) | VERIFIED | LOW | Copy M01's (member,amount) set into M02; chain accepts (roots differ). Detected only as dup-id. |
| C10 | Timestamp forgery (ts not date-validated) | INSPECTION | LOW | `ts` is any non-empty string, hashed but never parsed; backdating is possible and invisible. |
| C11 | Block withholding / selective disclosure | THEORETICAL | LOW | A secretary could omit a meeting from an exported file; no append-only storage anchor (merkle root of all meetings) exists. |

---

## 2. Web UI / HTTP server

| # | Attack | Evidence | Sev | Notes & fix |
|---|---|---|---|---|
| W1 | **Stored XSS via member name (auditor hints)** | VERIFIED | HIGH | Member name `<img src=x onerror=…>` flows into `hint_flags` evidence → `/api/export` hints → `innerHTML` in `exportView()` **without `esc()`**. The chain/loan tables use `esc()`, the hints box does not. Fix: `esc(x.hint/meeting/evidence)`. |
| W2 | **CSRF via Origin-absent GET** | INSPECTION | MED | Origin check only fires when an `Origin` header exists; `<img>`/`<form>`/`<script>` requests send none → a foreign page can drive `/api/attack`, `/api/reset`, `/api/entry` against `127.0.0.1`. Fix: require a CSRF token / `X-Requested-With`, or move state-changers to POST. |
| W3 | State-changing verbs on GET | INSPECTION | LOW | `/api/entry`, `/api/close`, `/api/attack`, `/api/reset` are all GET; GET must be side-effect-free (RFC 7231) and is browser-prefetch/cache/CSRF-prone. |
| W4 | DNS rebinding (host guard) | INSPECTION | LOW | Host guard parses registered hostname (PR6) and blocks `127.0.0.1.evil.com`; it's a scope limit, not authentication. Adequate for a localhost demo. |
| W5 | Host/Origin parser edge cases | INSPECTION | LOW | `127.0.0.2`, `0.0.0.0`, `[::1]`, trailing-dot forms are rejected (over-strict, not a bypass). Origin check is substring-based. |
| W6 | DoS: `/api/export` on a large chain | INSPECTION | MED | `audit_report` + `export_csv` serialize the whole chain synchronously on a single-threaded server. No size cap. |
| W7 | DoS: slow-loris / no timeouts | THEORETICAL | LOW | `HTTPServer` is single-threaded, no socket timeouts; one slow client stalls all requests. |
| W8 | No auth on `/api/*` | INSPECTION | MED | Anyone able to reach the port can mutate state; only the Host guard (scope) protects it. |
| W9 | Hardcoded witness passphrases | INSPECTION | LOW | `"pass-Meera"`, `"pass-Laxmi"` in demo/server source; secret-in-code. |
| W10 | Open redirect (webbrowser.open) | THEORETICAL | LOW | Demo auto-opens the URL; harmless locally, but the pattern is unsafe if reused. |

---

## 3. Business logic (SHG-specific)

| # | Attack | Evidence | Sev | Notes & fix |
|---|---|---|---|---|
| B1 | **Loan double-spend** | VERIFIED | MED | Two loans, no repayment → outstanding grows; no audit hint flags it. Add `over_exposure` hint (loan > corpus share). |
| B2 | **Corpus insolvency** | VERIFIED | MED | Total loans > total contributions is never flagged; `arithmetic_mismatch` only checks repayment>loan. Add a corpus-balance hint. |
| B3 | **Correction laundering** | VERIFIED | MED | Now that corrections reduce outstanding, a secretary can "correct away" a real loan (50000 loan + 50000 correction → 0). No hint. Add `suspicious_correction` (correction w/o a matching prior event). |
| B4 | Cross-meeting replay (dup entries) | VERIFIED | LOW | Identical (member,amount) across meetings is normal SHG but is the primitive for double-counting. |
| B5 | Phantom member fabrication | VERIFIED | LOW | No identity/KYC layer; a secretary can invent contributors. Out of scope for a hash chain but the product needs it. |
| B6 | Secretary-as-witness (conflict of interest) | THEORETICAL | HIGH | If the recorder is also a required witness, the attestation is self-serving. Enforce disjoint roles. |
| B7 | Witness collusion (n−1 of n) | THEORETICAL | MED | Any quorum scheme collapses if the majority colludes; require ≥1 external witness (e.g. federation node). |
| B8 | Sybil / sock-puppet members | THEORETICAL | MED | One person controls many "members" to game concentration/loan caps. Identity binding needed. |
| B9 | Round-tripping to inflate activity | THEORETICAL | LOW | deposit→withdraw→deposit cycles to inflate volume; needs a net-flows hint. |
| B10 | Concentration of lending | VERIFIED | LOW | `concentrated_lending` hint exists (≥2 loans, >50%); it's advisory only. |

---

## 4. Receipt / member-held artifact

| # | Attack | Evidence | Sev | Notes & fix |
|---|---|---|---|---|
| R1 | **Legacy receipt weak binding** | VERIFIED | MED | A receipt without `member_events` only checks "member exists" — it proves nothing about *which* lines belong to the member. `receipt_payload(chain=…)` always builds `member_events`; reject legacy receipts or require member_events. |
| R2 | Receipt forgery (member fabricates) | THEORETICAL | MED | Member invents a receipt; currently the receipt carries no issuer signature, so the auditor can't tell who issued it. |
| R3 | Receipt loss/theft | THEORETICAL | LOW | The member holds the only copy; no duplicate/escrow mechanism. |
| R4 | Double-issue (same receipt to two members) | THEORETICAL | LOW | No nonce/issue-counter binds a receipt to a single issuance. |
| R5 | Receipt replay after chain advance | VERIFIED(fixed) | — | Caught: `events-after-close` (terminality). |
| R6 | Receipt root vs stale metadata (close-swap) | VERIFIED(fixed) | — | Caught: close-hash recompute tie (PR9). |

---

## 5. Data model / determinism / serialization

| # | Attack | Evidence | Sev | Notes & fix |
|---|---|---|---|---|
| D1 | **CSV formula injection (leading-space/tab bypass)** | VERIFIED | LOW | PR9 guard only catches `=+-@` at position 0; `" =cmd"` or `"\t=cmd"` slips through. Strip leading whitespace before guarding. |
| D2 | Unicode homoglyph member names | THEORETICAL | LOW | "Sita" vs fullwidth/confusable "Ｓita" are distinct hashes but identical visually → audit confusion. Normalize (NFC) or reject confusables. |
| D3 | Unicode NFC/NFD normalization | THEORETICAL | LOW | `é` as one vs two code points hash differently; normalize before hashing. |
| D4 | Float precision in `format_rupees` | INSPECTION | LOW | `paise/100.0` loses precision for huge amounts; use integer paise + manual formatting. |
| D5 | Huge-integer / huge-string DoS | THEORETICAL | LOW | No bound on amount/member length (100k-char name verifies fine). |
| D6 | Deeply-nested JSON on load | THEORETICAL | LOW | `json.load` recursion limit protects; error is not surfaced as a clean corrupt verdict. |
| D7 | Non-deterministic `set` iteration | INSPECTION | — | Checked: `set()` is used only for `issubset`, never iterated; output is deterministic. |
| D8 | `json.dumps` without `sort_keys` in `save()` | INSPECTION | — | Deterministic because dict insertion order is fixed; a benign non-issue. |

---

## 6. Supply chain / deployment / ops

| # | Attack | Evidence | Sev | Notes & fix |
|---|---|---|---|---|
| S1 | Malicious dependency | THEORETICAL | LOW | Pure stdlib today; adding `cryptography`/`pynacl` for asymmetric keys introduces the supply-chain surface — pin + hash-verify. |
| S2 | Backdoored build artifact | THEORETICAL | LOW | No reproducible-build / SBOM. |
| S3 | Secrets in repo / logs | INSPECTION | LOW | Witness passphrases hardcoded; log statements don't leak keys today but the pattern is fragile. |
| S4 | Insecure transport | THEORETICAL | MED | HTTP only; if ever deployed beyond localhost, MITM can read/write the chain. Use TLS + client certs. |
| S5 | No append-only storage anchor | THEORETICAL | MED | The chain file is replaceable; there is no external anchor (git, WORM, timestamping, federation gossip) to detect wholesale replacement. |
| S6 | Key rotation absent | THEORETICAL | LOW | No path to rotate a compromised witness key without re-signing history. |
| S7 | Backup/restore integrity | INSPECTION | LOW | `.bak` copy is best-effort; no checksum verification on restore. |

---

## Verified summary

Round-3 probes confirmed **11 new issues** against the fixed (PR#9+PR#10) code:

| ID | Finding | Sev |
|---|---|---|
| C1 | Quorum gaming (one witness signs twice) | CRITICAL |
| W1 | Stored XSS via member name in auditor hints box | HIGH |
| R1 | Legacy receipt proves only "member exists", not line items | MED |
| B1 | Loan double-spend undetected by hints | MED |
| B2 | Corpus insolvency undetected by hints | MED |
| B3 | Correction laundering (loan erased via correction) | MED |
| C8 | Cross-meeting event transplant undetected | MED |
| D1 | CSV formula guard leading-space bypass | LOW |
| B4 | Cross-meeting replay (dup-id only) | LOW |
| B5 | Phantom member (no identity layer) | LOW |
| C9 | Meeting replay accepted | LOW |

Plus 6 more by inspection (W2 CSRF, W3 GET-side-effects, W6 export DoS, W8 no-auth,
W9 hardcoded secrets, D4 float precision) and ~30 theoretical/contextual entries.

**Defenses that held** (verified): receipt replay (R5), close-swap (R6), group
rename (C7), the hash delimiter fix, and the tamper→recompute core.

Top three fixes to prioritize: **C1** (unique-witness quorum), **W1** (escape the
hints box), **R1** (require member_events on receipts). B1–B3 need new audit
hints, not chain changes.
