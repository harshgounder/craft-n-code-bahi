#!/usr/bin/env python3
"""exporter.py - BAHI federation audit view: hint rules (deterministic, no ML)
and standardized export (JSON + CSV). Pure stdlib.

v1.3 (security-hardening pass):
- hint_flags() is defensive: it never raises on a malformed event (missing or
  mistyped fields are skipped rather than crashing the audit endpoint).
- export_csv() sanitizes cells that would otherwise be interpreted as a
  spreadsheet formula (= + - @ and tab/CR prefixes), closing the CSV-injection
  vector when an auditor opens the export in Excel/LibreOffice.
- arithmetic_mismatch is computed across the WHOLE chain (cumulative per-member
  net), so a loan taken in one meeting and repaid in a later meeting is no
  longer flagged as a false positive.
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


def _ev_amount(e):
    """Safe amount accessor: int paise or None if missing/mistyped/negative."""
    try:
        n = int(e.get("amount_paise"))
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def _safe_events(evs):
    """Drop malformed events (missing/mistyped member or amount) so analytics
    can never KeyError on a crafted chain file."""
    out = []
    for e in evs:
        if not isinstance(e, dict):
            continue
        if not isinstance(e.get("member"), str):
            continue
        amt = _ev_amount(e)
        if amt is None:
            continue
        e2 = dict(e)
        e2["amount_paise"] = amt
        out.append(e2)
    return out


def _meetings_with_events(chain):
    """returns list of (meeting_id, [events]) where every non-close event is
    attributed to exactly one meeting by root_seq ranges."""
    root_seqs = sorted((m["root_seq"], mid) for mid, m in chain.roots.items()
                       if isinstance(m, dict) and m.get("root_seq") is not None)
    out = []
    events = [e for e in chain.events if isinstance(e, dict) and e.get("type") != "MEETING-CLOSE"]
    for i, (seq, mid) in enumerate(root_seqs):
        lo = 0 if i == 0 else root_seqs[i - 1][0] + 1
        hi = seq
        out.append((mid, [e for e in events if lo <= e.get("seq", -1) <= hi]))
    return out


def _last_meeting(chain):
    if not chain.roots:
        return None
    return max(chain.roots, key=lambda m: (chain.roots[m].get("root_seq", 0) if isinstance(chain.roots[m], dict) else 0))


def hint_flags(chain):
    """Return list of {hint, meeting, evidence} dicts. Deterministic rules,
    and safe on malformed input (never raises)."""
    flags = []
    if getattr(chain, "corrupt", False):
        return [{"hint": "corrupt_chain", "meeting": "-",
                 "evidence": str(getattr(chain, "_corrupt", "unknown"))}]

    for mid, raw_evs in _meetings_with_events(chain):
        meta = chain.roots.get(mid, {})
        ws = meta.get("witnesses") or []
        # unique witnesses: a duplicated signature must not satisfy quorum
        if len(set(ws)) < MIN_WITNESSES:
            flags.append({"hint": "missing_witness", "meeting": mid,
                          "evidence": "close signed by %d distinct witness(es)" % len(set(ws))})

        evs = _safe_events(raw_evs)
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

    # arithmetic_mismatch: cumulative repayments exceed borrowings per member
    # across the WHOLE chain (a loan repaid in a later meeting is legitimate).
    member_net = {}
    for e in _safe_events([x for x in chain.events if isinstance(x, dict)]):
        if e.get("type") == "loan":
            member_net[e["member"]] = member_net.get(e["member"], 0) + e["amount_paise"]
        elif e.get("type") == "repayment":
            member_net[e["member"]] = member_net.get(e["member"], 0) - e["amount_paise"]
    for member, net in member_net.items():
        if net < 0:
            flags.append({"hint": "arithmetic_mismatch", "meeting": _last_meeting(chain),
                          "evidence": "%s repaid Rs %d more than borrowed overall" % (member, -net // 100)})

    return flags


def audit_report(chain):
    st = audit_status(chain)
    meetings = [{"id": mid, "root_hash": m["root_hash"], "root_seq": m["root_seq"],
                 "witnesses": m.get("witnesses", [])} for mid, m in chain.roots.items()
                if isinstance(m, dict)]
    return {"group": chain.group_id, "chain_ok": st["chain_ok"],
            "first_bad_seq": st["first_bad_seq"], "why": st["why"],
            "meetings": meetings, "hints": hint_flags(chain)}


def _sanitize_cell(v):
    """Neutralize spreadsheet formula injection (OWASP): cells beginning with
    = + - @ tab or CR are prefixed with a single quote so Excel/LibreOffice
    treat them as text, not a formula."""
    s = str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def export_csv(chain):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["seq", "etype", "member", "amount_paise", "ts", "hash"])
    for e in chain.events:
        if not isinstance(e, dict):
            continue
        w.writerow([_sanitize_cell(e.get("seq")), _sanitize_cell(e.get("type")),
                    _sanitize_cell(e.get("member")), _sanitize_cell(e.get("amount_paise")),
                    _sanitize_cell(e.get("ts")), _sanitize_cell(e.get("hash"))])
    return buf.getvalue()
