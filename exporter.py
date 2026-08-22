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
    "invalid_event",
]

# Auditor-facing severity per hint. Rendered by server.py's auditor panel (and
# usable by any consumer) so the new business-logic flags (corpus_insolvency,
# repeat_borrower, orphan_correction) surface with the right visual weight.
HINT_SEVERITY = {
    "corrupt_chain": "critical",
    "invalid_seq": "critical",
    "invalid_event": "critical",
    "arithmetic_mismatch": "critical",
    "corpus_insolvency": "critical",
    "missing_witness": "warning",
    "concentrated_lending": "warning",
    "reversal_burst": "warning",
    "repeat_borrower": "warning",
    "orphan_correction": "warning",
    "duplicate_identity": "note",
}

# CSV formula-injection danger set (OWASP). Checked at both the first byte and
# after lstrip() so leading-whitespace/tab/CR payloads are also neutralized.
_DANGEROUS = ("=", "+", "-", "@", "\t", "\x0d")


def csv_safe_cell(value):
    """Neutralize CSV/Excel formula + DDE injection. Prefix dangerous cells with
    a single quote so =,+,-,@,tab,CR cells export as text, never as formulas."""
    s = str(value)
    if s[:1] in _DANGEROUS or s.lstrip()[:1] in _DANGEROUS:
        return "'" + s
    return s


def html_escape(s):
    """Escape & < > \" ' for safe interpolation into HTML text content.

    Server-side (defense-in-depth): server.py escapes hint fields before they
    reach the browser, and the client's esc() stays as a second layer.
    """
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _safe_seq(e):
    s = e.get("seq")
    return s if isinstance(s, int) and not isinstance(s, bool) else None


def _event_usable(e):
    """True if an event has the fields the arithmetic hint rules need.

    Corrupt/hand-edited chains can carry events missing `member`, `type`, or a
    numeric `amount_paise`; hint_flags must flag (not crash on) those.
    """
    if not isinstance(e.get("member"), str) or not e.get("member"):
        return False
    if not isinstance(e.get("type"), str):
        return False
    a = e.get("amount_paise")
    return (not isinstance(a, bool)) and isinstance(a, (int, float))


def _meetings_with_events(chain):
    """Return ([(meeting_id, [events])], [invalid_seq_events]).

    Every well-sequenced non-close event is attributed to exactly one meeting
    by root_seq ranges. Events with a non-integer seq are returned separately
    (never compared, so no TypeError)."""
    boundaries = sorted(
        (m.get("root_seq"), mid)
        for mid, m in chain.roots.items()
        if isinstance(m, dict) and isinstance(m.get("root_seq"), int)
    )
    good, bad = [], []
    for e in chain.events:
        if not isinstance(e, dict):
            bad.append(e)
            continue
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
                      "evidence": "event seq %r is not an integer" % (
                          e.get("seq") if isinstance(e, dict) else "<non-object>")})
    for mid, evs in meetings:
        meta = chain.roots.get(mid, {})
        ws = meta.get("witnesses") or []
        if len(ws) < MIN_WITNESSES:
            flags.append({"hint": "missing_witness", "meeting": mid,
                          "evidence": "close signed by %d witness(es)" % len(ws)})
        paired = {}
        dup_flagged = set()
        # split usable vs malformed events: corrupt/hand-edited events missing
        # member/type/numeric amount are FLAGGED, never fed into arithmetic
        # (hint_flags must not raise on any input).
        usable, malformed = [], []
        for e in evs:
            (usable if _event_usable(e) else malformed).append(e)
        for e in malformed:
            flags.append({"hint": "invalid_event", "meeting": mid,
                          "evidence": "event seq %r missing member/type/numeric amount" % (e.get("seq"),)})
        evs = usable
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
        # B2: corpus insolvency: more money lent than was ever contributed
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
    for e in chain.events:
        if not isinstance(e, dict):
            continue  # corrupt/hand-edited non-object event: never crash the export
        w.writerow([e.get("seq"), csv_safe_cell(e.get("type")), csv_safe_cell(e.get("member")),
                    e.get("amount_paise"), csv_safe_cell(e.get("ts")), e.get("hash")])
    return buf.getvalue()
