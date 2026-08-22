#!/usr/bin/env python3
"""chain.py - BAHI core: SHA-256 event chain, meeting roots, fork detection.
Pure stdlib. Deterministic: same files -> same bytes -> same verdict.

Design notes:
- Events form a pure hash chain (prev -> hash). No witness fields inside
  the hashed event (avoids circular hash<->signature dependency).
- Meeting close: a MEETING-CLOSE event terminates the meeting's segment.
  Its hash is the MEETING ROOT, stored as metadata in roots[].
- Witnesses sign the ROOT VALUE (outside the chain) and their signatures
  are stored as metadata, never inside a hashed event.
- Verification: recompute the ENTIRE chain from genesis; then compare the
  receipt root against the recomputed meeting root. Any internal break
  = FORK even if a stored root string still matches."""
import hashlib, json

def h(*parts):
    hsh = hashlib.sha256()
    for p in parts:
        if isinstance(p, str):
            hsh.update(p.encode("utf-8"))
        elif isinstance(p, (int, float)):
            hsh.update(str(p).encode("utf-8"))
        elif isinstance(p, bytes):
            hsh.update(p)
        else:
            hsh.update(json.dumps(p, sort_keys=True).encode("utf-8"))
    return hsh.hexdigest()

class BahiChain:
    def __init__(self, group_id=""):
        self.group_id = group_id
        self.events = []          # list of event dicts (hashed fields only)
        self.roots = {}           # meeting_id -> {"root_hash","root_seq","ts","witnesses":[]}

    def add_event(self, seq, etype, member, amount_paise, ts, prev_hash=""):
        prev = prev_hash or (self.events[-1]["hash"] if self.events else h("GENESIS", self.group_id))
        ev = {
            "seq": seq,
            "group": self.group_id,
            "type": etype,           # contribution | loan | repayment | correction | MEETING-CLOSE
            "member": member,
            "amount_paise": int(amount_paise),
            "ts": ts,
            "prev": prev,
        }
        ev["hash"] = h(prev, seq, etype, member, ev["amount_paise"], ts)
        self.events.append(ev)
        return ev

    def close_meeting(self, meeting_id, ts):
        # distinct seq: never collide with the last contribution event
        ev = self.add_event(len(self.events) + 1, "MEETING-CLOSE", "__root__", 0, ts)
        self.roots[meeting_id] = {
            "root_hash": ev["hash"],
            "root_seq": ev["seq"],
            "ts": ts,
            "witnesses": [],       # signatures over root_hash, added after close
        }
        return self.roots[meeting_id]

    def export(self):
        return {"group": self.group_id, "events": self.events, "roots": self.roots}

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.export(), f, indent=1)

    @staticmethod
    def load(path):
        c = BahiChain()
        with open(path) as f:
            d = json.load(f)
        c.group_id = d["group"]
        c.events = d["events"]
        c.roots = d.get("roots", {})
        return c

    def verify(self):
        """Recompute the whole chain. Returns (ok, first_bad_seq, detail).

        Robust to structurally malformed events: a missing or mistyped field
        is reported as a FORK (malformed-event), never as an unhandled crash,
        because a corrupted record is itself a tamper signal."""
        prev = h("GENESIS", self.group_id)
        for ev in self.events:
            try:
                recomputed = h(ev["prev"], ev["seq"], ev["type"], ev["member"],
                               ev["amount_paise"], ev["ts"])
            except (KeyError, TypeError):
                return False, ev.get("seq", "?"), "malformed-event"
            if ev.get("prev") != prev:
                return False, ev.get("seq", "?"), "prev-hash-mismatch"
            if ev.get("hash") != recomputed:
                return False, ev.get("seq", "?"), "event-hash-mismatch"
            prev = ev["hash"]
        return True, None, "chain-ok"

    def root_for(self, meeting_id):
        return self.roots.get(meeting_id)

def receipt_payload(group, meeting_id, root_meta, member, chain=None):
    """root_meta = chain.roots[meeting_id] after witnesses attached.

    When `chain` is supplied, the receipt also binds the member's OWN event
    hashes (member_events) so that a member can prove their specific line
    items are unchanged -- not just the meeting root. Without it the receipt
    only proves the meeting root, which is a weaker claim."""
    member_events = []
    if chain is not None:
        member_events = [
            {"seq": e["seq"], "hash": e["hash"]}
            for e in chain.events
            if e.get("member") == member and e.get("type") != "MEETING-CLOSE"
        ]
    return {
        "group": group,
        "meeting": meeting_id,
        "root": root_meta["root_hash"],
        "root_seq": root_meta["root_seq"],
        "member": member,
        "root_ts": root_meta["ts"],
        "witnesses": root_meta["witnesses"],
        "member_events": member_events,
    }

def _sig_values(entries):
    """Normalize witness entries to bare signature strings. Accepts both the
    legacy bare-string shape and the newer {"name":..,"sig":..} shape."""
    out = set()
    for w in entries or []:
        out.add(w["sig"] if isinstance(w, dict) else w)
    return out


def verify_receipt(chain, receipt, witness_keys=None):
    """Correct protocol:
    (1) recompute the ENTIRE chain from genesis; any internal break or
        malformed event = FORK even if a stored root string matches.
    (2) locate the meeting's MEETING-CLOSE event in the chain and require
        its hash to equal the receipt root (never trust a stored root alone).
    (3) MEETING-CLOSE must be the LAST event -- entries appended after close
        are not covered by this receipt.
    (4) the receipt member must exist and own the bound member_events.
    (5) witness signatures stored at close must be a superset of the
        receipt's, and (when witness_keys name->passphrase is supplied) each
        signature is cryptographically verified over {root, meeting}.
    Returns (ok, detail)."""
    chain_ok, bad_seq, why = chain.verify()
    if not chain_ok:
        return False, "FORK-AT-EVENT-%s (%s)" % (bad_seq, why)

    root_meta = chain.root_for(receipt.get("meeting"))
    if root_meta is None:
        return False, "meeting-root-missing"

    # (2) find the close event by seq in the live chain
    close_ev = None
    for ev in chain.events:
        if ev.get("type") == "MEETING-CLOSE" and ev.get("seq") == receipt.get("root_seq"):
            close_ev = ev
            break
    if close_ev is None:
        return False, "meeting-close-missing"
    if root_meta.get("root_hash") != close_ev.get("hash"):
        # stored roots[] metadata was tampered independently of the chain
        return False, "FORK-AT-MEETING-%s" % receipt.get("meeting")
    if close_ev.get("hash") != receipt.get("root"):
        return False, "FORK-AT-MEETING-%s" % receipt.get("meeting")

    # (3) terminality: nothing may follow the close event
    if chain.events[-1] is not close_ev:
        return False, "events-after-close"

    # (4) member binding
    member = receipt.get("member", "")
    seq_to_member = {e.get("seq"): e.get("member") for e in chain.events}
    member_events = receipt.get("member_events")
    if member_events is None:
        if not member or not any(e.get("member") == member for e in chain.events):
            return False, "member-not-in-chain"
    else:
        if not member or not member_events:
            return False, "member-no-events"
        chain_index = {(e.get("seq"), e.get("hash")) for e in chain.events}
        for me in member_events:
            if seq_to_member.get(me.get("seq")) != member:
                return False, "member-event-does-not-belong"
            if (me.get("seq"), me.get("hash")) not in chain_index:
                return False, "member-event-missing-or-tampered"

    # (5) witness signatures: superset, then optional cryptographic check
    sigs_now = _sig_values(root_meta.get("witnesses", []))
    sigs_then = _sig_values(receipt.get("witnesses", []))
    if not sigs_then.issubset(sigs_now):
        return False, "witness-signature-differs"
    if witness_keys is not None:
        from witness import verify as witness_verify
        payload = {"root": receipt["root"], "meeting": receipt["meeting"]}
        for entry in receipt.get("witnesses", []):
            name = entry["name"] if isinstance(entry, dict) else None
            sig = entry["sig"] if isinstance(entry, dict) else entry
            passphrase = witness_keys.get(name) if name else None
            if passphrase is None or not witness_verify(payload, sig, passphrase, name):
                return False, "witness-signature-invalid"
    return True, "MATCH"