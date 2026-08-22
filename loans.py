#!/usr/bin/env python3
"""loans.py - BAHI internal loan tracker. Deterministic per-member
outstanding balances from the chain. Pure stdlib."""
from chain import BahiChain

def balances(chain):
    """Replay every event, derive per-member loan balances.

    Only loan and repayment events affect a member's balance:
    - loan: member takes money from the corpus (outstanding up).
    - repayment: member returns money (outstanding down).
    Contributions and corrections are intentionally excluded.

    Returns dict member -> {loaned_paise, repaid_paise, outstanding_paise}.
    Note: outstanding can be negative (member repaid more than borrowed),
    which exporter.py surfaces as an arithmetic_mismatch hint."""
    b = {}
    for ev in chain.events:
        if ev["type"] not in ("loan", "repayment"):
            continue
        m = b.setdefault(ev["member"], {"loaned": 0, "repaid": 0})
        if ev["type"] == "loan":
            m["loaned"] += ev["amount_paise"]
        else:
            m["repaid"] += ev["amount_paise"]
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
    return "Rs %.2f" % (paise / 100.0)