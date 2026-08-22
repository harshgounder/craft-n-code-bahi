# BAHI — 2nd/3rd-degree bug analysis & resolution (v1.4, on current main)

Scope: components that are NOT directly exploitable on their own, but can be
tinkered with to INDIRECTLY exploit another feature. This document records the
analysis, which findings were ALREADY fixed by the merged PR #10 ("Round-3
hardening"), which are FIXED by this PR, and which remain as documented
boundaries / owner decisions.

Branch base: `origin/main` @ aa45fcb (PR #9 + PR #10 merged).

---

## Findings FIXED by this PR (regression tests added to tests.py)

### [1]  HIGH — "events-after-close" was GLOBAL terminality, not per-meeting
Tinker: append the next week's meeting (normal op).
Exploit: the "verify offline anytime, forever" promise broke for every
meeting except the most recent.

Before (merged aa45fcb):
    last_ev = chain.events[-1]
    if last_ev.get("type") != "MEETING-CLOSE" or last_ev.get("seq") != receipt.get("root_seq"):
        return False, "events-after-close"
Confirmed live: an M06 receipt failed "events-after-close" the moment M07 closed.

After: the chain's LAST event must be a close of SOME meeting (a trailing
unwitnessed append still forks), but a later meeting no longer invalidates an
earlier meeting's receipt.
    last_ev = chain.events[-1]
    if not isinstance(last_ev, dict) or last_ev.get("type") != "MEETING-CLOSE":
        return False, "events-after-close"

### [6]  MEDIUM — amount type-coercion defeated detectability
Tinker: swap an event's amount_paise from int 100 to float 100.0 / str "100" /
"1_00".
Exploit: verify() normalised via _norm_amount(int()) before hashing, so the
type-swap was undetected and raw-value consumers (CSV export, UI `amount/100`)
broke.
Confirmed live: 100.0, "100", "1_00" all returned verify=True.

After: verify() requires a plain non-negative int (bool excluded); no coercion:
    amt = ev["amount_paise"]
    if isinstance(amt, bool) or not isinstance(amt, int) or amt < 0:
        return False, seq, "corrupt-file: amount_paise must be a non-negative integer ..."
(add_event still normalises on INPUT, so legit chains stay int.)

### [8]  MEDIUM — receipt member_events partial/attendance spoof
Tinker: drop a member's deposit from their receipt, or hand a member active
only in M06 an M07 receipt.
Exploit: the subset-only member check let a "forgotten deposit" pass and made
attendance unprovable.
Confirmed live: partial member_events (dropped deposit) -> MATCH; M06-only
Kavita -> valid M07 receipt.

After: the receipt must carry the member's COMPLETE per-meeting event set; a
member with no events in this meeting is rejected:
    (lo, root_seq] per-meeting range from previous meeting's root_seq;
    got set must EQUAL expected set; empty expected -> "member-not-in-meeting";
    else "member-events-incomplete-or-tampered".

### [7]  LOW — exporter silently dropped out-of-range integer events
Tinker: seq beyond the last closed meeting's root_seq.
Exploit: meeting-scoped hint rules (concentrated_lending, reversal_burst, ...)
never saw it.
After: _meetings_with_events also returns the unattributed tail and hint_flags
surfaces an "unattributed_events" flag instead of dropping it.

---

## Findings ALREADY fixed by merged PR #10 (not re-fixed here)

### [5]  MEDIUM — unbounded seq -> DoS on the shared hash primitive
PR #10 enforces STRICTLY SEQUENTIAL seq (seq must equal len(events)+1); verify()
checks `seq == i+1` BEFORE h(). A huge/crafted seq is rejected as "bad seq",
never reaches h(), and cannot crash. Confirmed in the merged verify().

### [4]  MEDIUM — correction events financially inert
PR #10 already implements correction semantics: loans.balances() subtracts a
correction from outstanding (clamped >= 0, over-repaid surfaced), and the
exporter adds an "orphan_correction" hint when a correction has no matching
prior (member, amount) entry. My earlier ref-based correction design was NOT
pursued because it would conflict with the merged model.

---

## Documented boundaries / owner decisions (NOT code changes in this PR)

### [2]  roots[] metadata (witness list, root_hash) is not hash-anchored
verify() recomputes only events; witness entries live in roots[] only. The
merged verify_receipt DOES cross-check root_hash against the recomputed close
hash (PR9/PR10), and enforces required member_events, but a witness-list SWAP
in roots[] is still invisible to plain verify()/audit_status().
Fix would require hashing witnesses into the close event, which conflicts with
the merged "close then sign" flow (add_witness attaches after the root exists).
Recommendation: if witness non-repudiation matters, adopt asymmetric keys
(witnesses hold private keys; chain stores public) — a roadmap item.

### [3]  Witness signature binds {root, meeting} only; crypto is optional
The witness signature does not name a member or amounts. It is mitigated by
required member_events (each hash-bound to the chain root) and by the
"close-hash recompute" tie, so a member's line items ARE transitively covered.
verify_receipt(..., witness_keys=...) performs crypto verification when the
caller holds the passphrase map; it is intentionally optional so an offline
member holding only a receipt can still verify the root against the recomputed
chain. Keeping it optional is a design choice, not a bug.

### GET-mutation endpoints, un-ANSWERED OPTIONS, unknown paths 200
PR #10's server.py routes mutations via GET (reverting the POST + X-BAHI CSRF
guard). The server binds loopback only, so cross-site reach is limited, but a
dedicated hardening pass should restore POST + a CSRF/origin gate. Not changed
here to avoid conflicting with the merged server wiring.

---

## Verification (all run live on this branch)

    python3 tests.py   -> 48/48 PASSED (41 inherited + 7 new regression tests)
    python3 demo.py    -> MATCH -> (edit) -> FORK-AT-EVENT-8 (event-hash-mismatch)
    server smoke       -> entry ok, close MATCH, state MATCH (4 member_events),
                          attack -> FORK; Host/Origin guard 403 on foreign hosts

Reproduction evidence for the findings was gathered against the merged
aa45fcb code (see probe output inline above) then re-run after the fix.