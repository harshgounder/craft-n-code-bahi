#!/usr/bin/env python3
"""exporter.py - BAHI federation audit view: hint rules (deterministic, no ML)
and standardized export (JSON + CSV). Pure stdlib.

v1.2 fixes from bug-hunter pass 1:
- hints scoped PER MEETING (meeting boundaries come from the chain roots
  structure: each root knows its root_seq, events between previous root and
  this root belong to this meeting)
- arithmetic_mismatch implemented (loan/repayment balance check)
- CSV quoted so member names with commas do not break rows
- never raises on corrupt chains (audit_status from chain.py)
"""
import csv, io
from chain import MIN_WITNESSES, audit_status

HINT_RULES = [
    "arithmetic_mismatch",
    "missing_witness",
    "duplicate_identity",
    "reversal_burst",
    "concentrated_lending",
]


def _meetings_with_events(chain):
    """returns list of (meeting_id, [events]) where every non-close event is
    attributed to exactly one meeting by root_seq ranges."""
    root_seqs = sorted((m["root_seq"], mid) for mid, m in chain.roots.items()
                       if m.get("root_seq") is not None)
    out = []
    events = [e for e in chain.events if e["type"] != "MEETING-CLOSE"]
    for i, (seq, mid) in enumerate(root_seqs):
        lo = 0 if i == 0 else root_seqs[i - 1][0] + 1
        hi = seq
        out.append((mid, [e for e in events if lo <= e["seq"] <= hi]))
    return out


def hint_flags(chain):
    flags = []
    if getattr(chain, "corrupt", False):
        return [{"hint": "corrupt_chain", "meeting": "-",
                 "evidence": "chain file is unreadable/incomplete"}]
    for mid, evs in _meetings_with_events(chain):
        meta = chain.roots.get(mid, {})
        ws = meta.get("witnesses") or []
        if len(ws) < MIN_WITNESSES:
            flags.append({"hint": "missing_witness", "meeting": mid,
                          "evidence": "close signed by %d witness(es)" % len(ws)})
        paired = {}
        for e in evs:
            key = (e["member"], e["amount_paise"])
            paired[key] = paired.get(key, 0) + 1
            # advisory only: 2 identical contributions is a normal SHG
            # pattern; fire only on 3+ repeats or on loan/repayment pairs
            if paired[key] >= 3 and not any(f["hint"] == "duplicate_identity" and f["meeting"] == mid
                                            and key[0] in f["evidence"] for f in flags):
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
        if repaid > loaned:
            flags.append({"hint": "arithmetic_mismatch", "meeting": mid,
                          "evidence": "repayments Rs %d exceed loans Rs %d in meeting" % (repaid, loaned)})
    return flags


def audit_report(chain):
    st = audit_status(chain)
    meetings = [{"id": mid, "root_hash": m["root_hash"], "root_seq": m["root_seq"],
                 "witnesses": m.get("witnesses", [])} for mid, m in chain.roots.items()]
    return {"group": chain.group_id, "chain_ok": st["chain_ok"],
            "first_bad_seq": st["first_bad_seq"], "why": st["why"],
            "meetings": meetings, "hints": hint_flags(chain)}


def export_csv(chain):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "etype", "member", "amount_paise", "ts", "hash"])
    for e in chain.events:
        w.writerow([e["seq"], e["type"], e["member"], e["amount_paise"], e["ts"], e["hash"]])
    return buf.getvalue()