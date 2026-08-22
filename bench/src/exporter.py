#!/usr/bin/env python3
"""exporter.py - BAHI federation audit view: hint rules (deterministic, no ML)
and standardized export (JSON + CSV). Pure stdlib.

v1.3 (hardening batch):
- _meetings_with_events buckets events in O(E log E) (single sort + two-pointer
  pass) instead of O(meetings * events); the quadratic scaling is gone.
- Events whose seq is not an integer (possible only in a hand-edited/corrupt
  chain, since add_event now validates) are flagged `invalid_seq` instead of
  crashing the audit path with a TypeError.
- hint_flags and audit_report never raise on any input.
"""
import csv, io
from chain import MIN_WITNESSES, audit_status

HINT_RULES = [
    "arithmetic_mismatch",
    "missing_witness",
    "duplicate_identity",
    "reversal_burst",
    "concentrated_lending",
    "corpus_insolvency",
    "repeat_borrower",
    "orphan_correction",
]


def _safe_seq(e):
    s = e.get("seq")
    return s if isinstance(s, int) and not isinstance(s, bool) else None


def _meetings_with_events(chain):
    """Return ([(meeting_id, [events])], [invalid_seq_events]).

    Every well-sequenced non-close event is attributed to exactly one meeting
    by root_seq ranges. Events with a non-integer seq are returned separately
    (never compared, so no TypeError)."""
    boundaries = sorted(
        (m.get("root_seq"), mid)
        for mid, m in chain.roots.items()
        if isinstance(m.get("root_seq"), int)
    )
    good, bad = [], []
    for e in chain.events:
        if e.get("type") == "MEETING-CLOSE":
            continue
        if _safe_seq(e) is not None:
            good.append(e)
        else:
            bad.append(e)
    good.sort(key=_safe_seq)
    out = []
    ei = 0
    lo = 0
    for hi, mid in boundaries:
        evs = []
        while ei < len(good) and _safe_seq(good[ei]) <= hi:
            if _safe_seq(good[ei]) > lo:
                evs.append(good[ei])
            ei += 1
        out.append((mid, evs))
        lo = hi
    return out, bad


def hint_flags(chain):
    """Return list of {hint, meeting, evidence} dicts. Deterministic rules."""
    flags = []
    if getattr(chain, "corrupt", False):
        return [{"hint": "corrupt_chain", "meeting": "-",
                 "evidence": "chain file is unreadable/incomplete"}]
    meetings, invalid_seq = _meetings_with_events(chain)
    for e in invalid_seq:
        flags.append({"hint": "invalid_seq", "meeting": "-",
                      "evidence": "event seq %r is not an integer" % (e.get("seq"),)})
    for mid, evs in meetings:
        meta = chain.roots.get(mid, {})
        ws = meta.get("witnesses") or []
        if len(ws) < MIN_WITNESSES:
            flags.append({"hint": "missing_witness", "meeting": mid,
                          "evidence": "close signed by %d witness(es)" % len(ws)})
        paired = {}
        dup_flagged = set()
        for e in evs:
            key = (e["member"], e["amount_paise"])
            paired[key] = paired.get(key, 0) + 1
            # advisory: 2 identical contributions is normal; fire on 3+ repeats,
            # once per (member, amount) key (O(1) dedup, not O(flags))
            if paired[key] >= 3 and key not in dup_flagged:
                dup_flagged.add(key)
                flags.append({"hint": "duplicate_identity", "meeting": mid,
                              "evidence": "%s Rs %d three or more times" % (e["member"], e["amount_paise"] // 100)})
        loans = [e for e in evs if e["type"] == "loan"]
        if len(loans) >= 2:
            top = max(loans, key=lambda e: e["amount_paise"])
            total = sum(e["amount_paise"] for e in loans)
            if total > 0 and top["amount_paise"] * 2 > total:
                flags.append({"hint": "concentrated_lending", "meeting": mid,
                              "evidence": "%s took %d%% of loans" % (top["member"], round(100 * top["amount_paise"] / total))})
        corrections = [e for e in evs if e["type"] == "correction"]
        if len(corrections) >= 4:
            flags.append({"hint": "reversal_burst", "meeting": mid,
                          "evidence": "%d correction events" % len(corrections)})
        repaid = sum(e["amount_paise"] for e in evs if e["type"] == "repayment")
        loaned = sum(e["amount_paise"] for e in evs if e["type"] == "loan")
        contributed = sum(e["amount_paise"] for e in evs if e["type"] == "contribution")
        if repaid > loaned:
            flags.append({"hint": "arithmetic_mismatch", "meeting": mid,
                          "evidence": "repayments Rs %d exceed loans Rs %d in meeting" % (repaid, loaned)})
        # B2: corpus insolvency - more money lent than was ever contributed
        if loaned > contributed:
            flags.append({"hint": "corpus_insolvency", "meeting": mid,
                          "evidence": "loans Rs %d exceed contributions Rs %d" % (loaned, contributed)})
        # B1: repeat borrower: a member takes >=2 loans with no repayment
        loan_counts = {}
        for e in evs:
            if e["type"] == "loan":
                loan_counts[e["member"]] = loan_counts.get(e["member"], 0) + 1
        repay_members = {e["member"] for e in evs if e["type"] == "repayment"}
        for member, cnt in loan_counts.items():
            if cnt >= 2 and member not in repay_members:
                flags.append({"hint": "repeat_borrower", "meeting": mid,
                              "evidence": "%s took %d loans with no repayment" % (member, cnt)})
        # B3: orphan correction: a correction with no matching prior event
        prior_amounts = {(e["member"], e["amount_paise"]) for e in evs
                         if e["type"] in ("loan", "repayment", "contribution")}
        for e in corrections:
            if (e["member"], e["amount_paise"]) not in prior_amounts:
                flags.append({"hint": "orphan_correction", "meeting": mid,
                              "evidence": "%s corrected Rs %d with no matching prior entry" % (e["member"], e["amount_paise"])})
    return flags


def audit_report(chain):
    st = audit_status(chain)
    meetings = [{"id": mid, "root_hash": m["root_hash"], "root_seq": m["root_seq"],
                 "witnesses": m.get("witnesses", [])} for mid, m in chain.roots.items()
                if isinstance(m, dict) and m.get("root_seq") is not None]  # PR9: partial roots crash
    return {"group": chain.group_id, "chain_ok": st["chain_ok"],
            "first_bad_seq": st["first_bad_seq"], "why": st["why"],
            "meetings": meetings, "hints": hint_flags(chain)}


def export_csv(chain):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "etype", "member", "amount_paise", "ts", "hash"])
    # CSV formula injection guard (PR9, extended): prefix dangerous cells with
    # a single quote so =,+,-,@,tab,CR cells export as text, never as formulas
    # or DDE payloads (OWASP CSV injection guidance).
    _DANGEROUS = ("=", "+", "-", "@", "\t", "\x0d")

    def safe(s):
        s = str(s)
        if s[:1] in _DANGEROUS or s.lstrip()[:1] in _DANGEROUS:
            return "'" + s
        return s
    for e in chain.events:
        w.writerow([e["seq"], safe(e["type"]), safe(e["member"]),
                    e["amount_paise"], safe(e["ts"]), e["hash"]])
    return buf.getvalue()
