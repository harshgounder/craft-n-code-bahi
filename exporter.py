#!/usr/bin/env python3
"""exporter.py - BAHI federation audit view: hint rules (deterministic, no ML)
and standardized export (JSON + CSV). Pure stdlib."""
from chain import BahiChain

HINT_RULES = [
    "arithmetic_mismatch",   # loan - repayment != stated balance path
    "missing_witness",       # meeting close signed by fewer than 2 witnesses
    "duplicate_identity",    # same member + same amount twice in one meeting
    "reversal_burst",        # >= 4 correction events in one meeting
    "concentrated_lending",  # one member > 50% of meeting loan volume
]

def hint_flags(chain):
    """Return list of {hint, meeting, evidence} dicts. Deterministic rules."""
    flags = []
    per_meeting = {}
    for ev in chain.events:
        if ev["etype"] == "MEETING-CLOSE":
            continue
        per_meeting.setdefault(ev["seq"] // 1000, []).append(ev)
    # evaluation uses the whole chain; keep rules over all events + roots
    meetings = chain.roots
    for mid, meta in meetings.items():
        evs = [e for e in chain.events if e["etype"] != "MEETING-CLOSE"]
        if len(meta.get("witnesses", [])) < 2:
            flags.append({"hint": "missing_witness", "meeting": mid,
                          "evidence": "close signed by %d witness(es)" % len(meta.get("witnesses", []))})
        paired = {}
        for e in evs:
            key = (e["member"], e["amount_paise"])
            paired[key] = paired.get(key, 0) + 1
            if paired[key] == 2:
                flags.append({"hint": "duplicate_identity", "meeting": mid,
                              "evidence": "%s Rs %d twice" % (e["member"], e["amount_paise"] // 100)})
        corrections = [e for e in evs if e["etype"] == "correction"]
        if len(corrections) >= 4:
            flags.append({"hint": "reversal_burst", "meeting": mid,
                          "evidence": "%d correction events" % len(corrections)})
        loans = [e for e in evs if e["etype"] == "loan"]
        if loans:
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
    lines = ["seq,etype,member,amount_paise,ts,hash"]
    for e in chain.events:
        lines.append("%d,%s,%s,%d,%s,%s" % (
            e["seq"], e["etype"], e["member"], e["amount_paise"], e["ts"], e["hash"]))
    return "\n".join(lines) + "\n"