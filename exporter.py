#!/usr/bin/env python3
"""exporter.py - BAHI federation audit view: hint rules (deterministic, no ML)
and standardized export (JSON + CSV). Pure stdlib."""
import csv
import io
from chain import BahiChain

# Every declared rule is implemented in hint_flags() below. Keep this list in
# sync with the function -- it is the audited surface a federation can rely on.
HINT_RULES = [
    "arithmetic_mismatch",   # a member repaid more than they borrowed
    "missing_witness",       # meeting close signed by fewer than 2 witnesses
    "duplicate_identity",    # same member + same amount repeated in one meeting
    "reversal_burst",        # >= 4 correction events in one meeting
    "concentrated_lending",  # one member > 50% of meeting loan volume
]


def _meeting_of(chain, seq):
    """Map an event seq to its meeting id: the meeting whose MEETING-CLOSE
    seq is the smallest value >= seq. Fallback: the highest-root meeting."""
    best, best_seq = None, None
    for mid, meta in chain.roots.items():
        rs = meta.get("root_seq", 0)
        if rs >= seq and (best_seq is None or rs < best_seq):
            best, best_seq = mid, rs
    if best is None and chain.roots:
        best = max(chain.roots, key=lambda m: chain.roots[m].get("root_seq", 0))
    return best


def _events_for(chain, mid):
    """Events belonging to one meeting: those after the previous close and up
    to and including this meeting's close seq (exclusive of close events)."""
    meta = chain.roots[mid]
    hi = meta.get("root_seq", 0)
    lo = 0
    for other, m in chain.roots.items():
        rs = m.get("root_seq", 0)
        if rs < hi and rs > lo:
            lo = rs
    return [e for e in chain.events
            if e.get("type") != "MEETING-CLOSE" and lo < e.get("seq", 0) <= hi]


def _last_meeting(chain):
    if not chain.roots:
        return None
    return max(chain.roots, key=lambda m: chain.roots[m].get("root_seq", 0))


def hint_flags(chain):
    """Return list of {hint, meeting, evidence} dicts. Deterministic rules."""
    flags = []

    # missing_witness: per meeting, from the roots metadata
    for mid, meta in chain.roots.items():
        if len(meta.get("witnesses", [])) < 2:
            flags.append({"hint": "missing_witness", "meeting": mid,
                          "evidence": "close signed by %d witness(es)" % len(meta.get("witnesses", []))})

    # arithmetic_mismatch: cumulative repayments exceed borrowings per member.
    # Computed across the whole chain (loans repaid in a later meeting are legit).
    member_net = {}
    for e in chain.events:
        if e.get("type") == "loan":
            member_net[e["member"]] = member_net.get(e["member"], 0) + e["amount_paise"]
        elif e.get("type") == "repayment":
            member_net[e["member"]] = member_net.get(e["member"], 0) - e["amount_paise"]
    for member, net in member_net.items():
        if net < 0:
            flags.append({"hint": "arithmetic_mismatch", "meeting": _last_meeting(chain),
                          "evidence": "%s repaid Rs %d more than borrowed" % (member, -net // 100)})

    # Per-meeting rules: duplicate_identity, reversal_burst, concentrated_lending
    for mid in chain.roots:
        evs = _events_for(chain, mid)

        paired = {}
        for e in evs:
            key = (e["member"], e["amount_paise"])
            paired[key] = paired.get(key, 0) + 1
            if paired[key] == 2:
                flags.append({"hint": "duplicate_identity", "meeting": mid,
                              "evidence": "%s Rs %d repeated" % (e["member"], e["amount_paise"] // 100)})

        corrections = [e for e in evs if e["type"] == "correction"]
        if len(corrections) >= 4:
            flags.append({"hint": "reversal_burst", "meeting": mid,
                          "evidence": "%d correction events" % len(corrections)})

        loans = [e for e in evs if e["type"] == "loan"]
        if len(loans) >= 2:
            top = max(loans, key=lambda e: e["amount_paise"])
            total = sum(e["amount_paise"] for e in loans)
            if total > 0 and top["amount_paise"] * 2 > total:
                flags.append({"hint": "concentrated_lending", "meeting": mid,
                              "evidence": "%s took %d%% of loans" % (top["member"], round(100 * top["amount_paise"] / total))})

    return flags


def audit_report(chain):
    ok, bad_seq, why = chain.verify()
    meetings = [{"id": mid, "root_hash": m["root_hash"], "root_seq": m["root_seq"],
                 "witnesses": m.get("witnesses", [])} for mid, m in chain.roots.items()]
    return {"group": chain.group_id, "chain_ok": ok,
            "first_bad_seq": bad_seq, "why": why, "meetings": meetings,
            "hints": hint_flags(chain)}


def export_csv(chain):
    """RFC-4180 CSV via the stdlib csv module (handles commas in names)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["seq", "etype", "member", "amount_paise", "ts", "hash"])
    for e in chain.events:
        w.writerow([e["seq"], e["type"], e["member"], e["amount_paise"], e["ts"], e["hash"]])
    return buf.getvalue()
