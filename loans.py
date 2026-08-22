#!/usr/bin/env python3
"""loans.py - BAHI internal loan tracker. Deterministic per-member
outstanding balances from the chain. Pure stdlib."""


def balances(chain):
    """Replay every event, derive per-member loan balances.

    Only loan and repayment events affect a member's balance:
    - loan: member takes money from the corpus (outstanding up).
    - repayment: member returns money (outstanding down).
    Contributions and corrections are intentionally excluded.

    Safe on malformed events (missing/mistyped fields are skipped, never crash).

    Returns dict member -> {loaned_paise, repaid_paise, outstanding_paise}.
    Note: outstanding can be negative (member repaid more than borrowed),
    which exporter.py surfaces as an arithmetic_mismatch hint."""
    b = {}
    for ev in chain.events:
        if not isinstance(ev, dict) or ev.get("type") not in ("loan", "repayment"):
            continue
        member = ev.get("member")
        if not isinstance(member, str):
            continue
        try:
            amt = int(ev.get("amount_paise"))
        except (TypeError, ValueError):
            continue
        if amt < 0:
            continue
        m = b.setdefault(member, {"loaned": 0, "repaid": 0})
        if ev["type"] == "loan":
            m["loaned"] += amt
        else:
            m["repaid"] += amt
    out = {}
    for member, m in b.items():
        outstanding = m["loaned"] - m["repaid"]
        out[member] = {
            "member": member,
            "loaned_paise": m["loaned"],
            "repaid_paise": m["repaid"],
            "outstanding_paise": outstanding,
        }
    return out


def format_rupees(paise):
    """Integer-exact rupees string: avoids float precision loss on large
    amounts (Rs 1234.56)."""
    paise = int(paise)
    return "Rs %d.%02d" % (paise // 100, paise % 100)
