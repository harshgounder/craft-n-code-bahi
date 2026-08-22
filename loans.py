#!/usr/bin/env python3
"""loans.py - BAHI internal loan tracker. Deterministic per-member
outstanding balances from the chain. Pure stdlib.

Semantics:
- loan:        member takes money from corpus (outstanding up).
- repayment:   member returns money (outstanding down).
- correction:  an append-only reversal of a previously-recorded amount; it
               reduces outstanding by its amount (see note below).
- contribution: money into the corpus; NOT part of per-member loan balances.

Invariants:
- outstanding_paise is always >= 0 (clamped). Over-repayment (repayment +
  corrections exceeding loans) is surfaced in `over_repaid_paise` rather than
  producing a negative balance.

Note on corrections: BAHI is append-only, so a mistake is fixed by APPENDING a
correction event rather than editing history. A correction reverses loan
balance; a correction of a *contribution* (corpus) is outside the scope of this
loan tracker and is left to the auditor view (exporter).
"""
from chain import BahiChain


def balances(chain):
    """Replay every event, derive per-member loan balances.
    Returns dict member -> {loaned, repaid, corrected, outstanding, over_repaid}."""
    b = {}
    for ev in chain.events:
        t = ev["type"]
        if t not in ("loan", "repayment", "correction"):
            continue
        m = b.setdefault(ev["member"], {"loaned": 0, "repaid": 0, "corrected": 0})
        if t == "loan":
            m["loaned"] += ev["amount_paise"]
        elif t == "repayment":
            m["repaid"] += ev["amount_paise"]
        else:  # correction
            m["corrected"] += ev["amount_paise"]
    out = {}
    for member, m in b.items():
        raw = m["loaned"] - m["repaid"] - m["corrected"]
        out[member] = {
            "member": member,
            "loaned_paise": m["loaned"],
            "repaid_paise": m["repaid"],
            "corrected_paise": m["corrected"],
            "outstanding_paise": max(0, raw),
            "over_repaid_paise": max(0, -raw),
        }
    return out


def format_rupees(paise):
    return "Rs %.2f" % (paise / 100.0)
