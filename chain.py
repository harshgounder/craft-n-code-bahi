#!/usr/bin/env python3
"""chain.py - BAHI core: SHA-256 event chain, meeting roots, fork detection.
Pure stdlib. Deterministic: same files -> same bytes -> same verdict.

Protocol (v1.3, security-hardening pass):
- Events form a hash chain; recomputing from genesis detects any edit
  (event-hash-mismatch), delete (prev-hash-mismatch), reorder (same).
- h() is type-tagged AND length-prefixed: a field value can no longer be
  confused with another type (1 vs "1" vs True) or span a field boundary
  (a member name containing the old delimiter byte).
- add_event() validates its inputs: amount is a bounded integer, member is a
  stripped non-empty string with no control characters, type is a known enum,
  and seq is unique. A malformed record is rejected at the door rather than
  surviving until verification.
- Meeting close: at least 2 DISTINCT witness signatures (quorum) are REQUIRED;
  a duplicated signature does not inflate quorum.
- Receipts are bound to (group, meeting, root, member).
- Corrupt chain files NEVER crash: load()/verify() return structured verdicts.
  Corruption is tracked in a dedicated attribute, not a roots[] sentinel that a
  real meeting id could collide with.

Honest boundaries: full file-control by the bookkeeper (rewrite every hash
consistently) is undetectable by design; detection covers retroactive edits
AFTER witnessing, not mass collusion at entry time.
"""
import hashlib, json

MIN_WITNESSES = 2
MAX_AMOUNT_PAISE = 10 ** 12          # Rs 1,000 crore: far above any plausible SHG txn
VALID_EVENT_TYPES = {"contribution", "loan", "repayment", "correction", "MEETING-CLOSE"}
RESERVED_MEETING_IDS = {"__corrupt__"}


def h(*parts):
    """SHA-256 over type-tagged, length-prefixed parts.

    Type tags ("s"=str, "i"=int, "f"=float, "o"=bool, "b"=bytes, "j"=json)
    remove str/int/bool/float confusion (True vs 1 vs "1" vs 1.0); the
    length prefix removes delimiter ambiguity so a field containing any byte
    can no longer be made to collide with a field boundary. Deterministic on
    any Python 3 build."""
    m = hashlib.sha256()
    for p in parts:
        if isinstance(p, bool):
            tag, enc = b"o", (b"1" if p else b"0")
        elif isinstance(p, bytes):
            tag, enc = b"b", p
        elif isinstance(p, str):
            tag, enc = b"s", p.encode("utf-8")
        elif isinstance(p, int):
            tag, enc = b"i", str(p).encode("ascii")
        elif isinstance(p, float):
            tag, enc = b"f", repr(p).encode("ascii")
        else:
            tag, enc = b"j", json.dumps(p, sort_keys=True).encode("utf-8")
        m.update(tag)
        m.update(str(len(enc)).encode("ascii"))
        m.update(b":")
        m.update(enc)
    return m.hexdigest()


def _norm_amount(v):
    """Return int paise or None if invalid. Rejects bool, negatives, non-int,
    and amounts above MAX_AMOUNT_PAISE."""
    if isinstance(v, bool):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    if n < 0 or n > MAX_AMOUNT_PAISE:
        return None
    return n


def _clean_member(member):
    """Return a normalized member name, or None if unusable.

    Rejects control characters (including \\x1f) BEFORE stripping, so a
    trailing delimiter/control byte cannot be silently laundered by strip();
    then strips ordinary surrounding whitespace and rejects empty names."""
    if not isinstance(member, str):
        return None
    if any(ord(c) < 0x20 or c == "\x7f" for c in member):
        return None
    member = member.strip()
    if not member:
        return None
    return member


class BahiChain:
    def __init__(self, group_id=""):
        self.group_id = group_id
        self.events = []
        self.roots = {}
        self._corrupt = None            # set by load() on unreadable/invalid input

    def add_event(self, seq, etype, member, amount_paise, ts, prev_hash=""):
        amt = _norm_amount(amount_paise)
        if amt is None:
            raise ValueError("amount must be an integer paise value within [0, %d]" % MAX_AMOUNT_PAISE)
        member = _clean_member(member)
        if member is None:
            raise ValueError("member must be a non-empty string with no control characters")
        if etype not in VALID_EVENT_TYPES:
            raise ValueError("unknown event type %r (expected one of %s)" % (etype, sorted(VALID_EVENT_TYPES)))
        if any(e.get("seq") == seq for e in self.events):
            raise ValueError("duplicate seq %r" % seq)
        prev = prev_hash or (self.events[-1]["hash"] if self.events else h("GENESIS", self.group_id))
        ev = {
            "seq": seq,
            "group": self.group_id,
            "type": etype,
            "member": member,
            "amount_paise": amt,
            "ts": ts,
            "prev": prev,
        }
        ev["hash"] = h(prev, seq, etype, member, amt, ts)
        self.events.append(ev)
        return ev

    def close_meeting(self, meeting_id, ts, witnesses=None):
        """Close the meeting. witnesses: list of signature strings. Quorum is
        re-enforced at verification. meeting_id must be a non-empty,
        non-reserved string and must not already be closed."""
        if not isinstance(meeting_id, str) or not meeting_id:
            raise ValueError("meeting_id must be a non-empty string")
        if meeting_id in RESERVED_MEETING_IDS:
            raise ValueError("meeting_id %r is reserved" % meeting_id)
        if meeting_id in self.roots:
            raise ValueError("meeting %r already closed" % meeting_id)
        seq = max([e["seq"] for e in self.events], default=0) + 1
        ev = self.add_event(seq, "MEETING-CLOSE", "__root__", 0, ts)
        sigs = list(witnesses or [])
        self.roots[meeting_id] = {
            "root_hash": ev["hash"],
            "root_seq": ev["seq"],
            "ts": ts,
            "witnesses": sigs,
        }
        return self.roots[meeting_id]

    def root_for(self, meeting_id):
        return self.roots.get(meeting_id)

    def verify(self):
        """Recompute the whole chain. Returns (ok, bad_seq, why).
        NEVER raises on malformed data: returns (False, seq, 'corrupt-file: ...').
        The genesis is anchored: the first event must chain off h("GENESIS",
        group_id), and every event's group field must match the chain group."""
        if not self.events:
            return False, 0, "corrupt-file: empty chain"
        prev = h("GENESIS", self.group_id)
        for i, ev in enumerate(self.events):
            for field in ("seq", "type", "member", "amount_paise", "ts", "prev", "hash", "group"):
                if field not in ev:
                    return False, i + 1, "corrupt-file: missing field %r at event %d" % (field, i + 1)
            if ev.get("group") != self.group_id:
                return False, i + 1, "corrupt-file: event %d group mismatch" % (i + 1)
            amt = _norm_amount(ev["amount_paise"])
            if amt is None:
                return False, i + 1, "corrupt-file: bad amount at event %d" % (i + 1)
            recomputed = h(ev["prev"], ev["seq"], ev["type"], ev["member"], amt, ev["ts"])
            if recomputed != ev["hash"]:
                return False, i + 1, "event-hash-mismatch"
            if ev["prev"] != prev:
                return False, i + 1, "prev-hash-mismatch"
            prev = ev["hash"]
        return True, 0, "ok"

    def export(self):
        return {"group": self.group_id, "events": self.events, "roots": self.roots}

    def save(self, path):
        """Durable atomic write: temp file in the same dir, flush + fsync,
        atomic os.replace, plus a numbered .bak copy."""
        import os, tempfile
        data = json.dumps(self.export(), indent=1)
        d = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(prefix=".bahi-", suffix=".tmp", dir=d)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            try:
                with open(path + ".bak", "w") as b:
                    b.write(data)
            except OSError:
                pass  # backup is best-effort
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def load(path):
        c = BahiChain()
        try:
            with open(path) as f:
                d = json.load(f)
        except (OSError, ValueError) as e:
            c._corrupt = "load: %s" % e
            return c
        if not isinstance(d, dict) or "group" not in d or not isinstance(d.get("events"), list):
            c._corrupt = "load: no events array"
            return c
        c.group_id = d["group"]
        c.events = d["events"]
        c.roots = d.get("roots", {})
        return c

    @property
    def corrupt(self):
        return self._corrupt is not None or not isinstance(self.group_id, str) or self.group_id == ""


def receipt_payload(group, meeting_id, root_meta, member, chain=None):
    """Build a member receipt. When `chain` is supplied, the receipt also
    binds the member's own event hashes (member_events) so the receipt proves
    the member's line items, not just the meeting root. Without a chain the
    receipt carries member_events=None and verification falls back to a
    member-exists check."""
    member_events = None
    if chain is not None:
        member_events = [
            {"seq": e["seq"], "hash": e["hash"]}
            for e in chain.events
            if e.get("member") == member and e.get("type") != "MEETING-CLOSE"
            and e.get("seq", 0) <= root_meta.get("root_seq", 0)
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


def verify_receipt(chain, receipt):
    """(1) recompute chain (2) bind group (3) bind meeting+root + locate the
    MEETING-CLOSE event (4) terminality (5) bind member (6) DISTINCT-witness
    quorum (7) witness subset. Never crashes: corrupt input = fail with detail."""
    if chain.corrupt:
        return False, "corrupt-chain: %s" % (chain._corrupt or "unknown")
    chain_ok, bad_seq, why = chain.verify()
    if not chain_ok:
        return False, "FORK-AT-EVENT-%s (%s)" % (bad_seq, why)
    if receipt.get("group") != chain.group_id:
        return False, "group-mismatch"
    root_meta = chain.root_for(receipt.get("meeting", ""))
    if root_meta is None:
        return False, "meeting-root-missing"
    close_seqs = [e["seq"] for e in chain.events if e.get("type") == "MEETING-CLOSE"]
    if receipt.get("root_seq") not in close_seqs:
        return False, "meeting-close-missing"
    if root_meta["root_hash"] != receipt.get("root"):
        return False, "FORK-AT-MEETING-%s" % receipt.get("meeting")
    last_ev = chain.events[-1]
    if last_ev.get("type") != "MEETING-CLOSE" or last_ev.get("seq") != receipt.get("root_seq"):
        return False, "events-after-close"
    member = receipt.get("member", "")
    if not isinstance(member, str) or not member:
        return False, "member-missing"
    member_events = receipt.get("member_events")
    if member_events:
        chain_index = {(e.get("seq"), e.get("hash")) for e in chain.events}
        seq_to_member = {e.get("seq"): e.get("member") for e in chain.events}
        for me in member_events:
            if seq_to_member.get(me.get("seq")) != member:
                return False, "member-event-does-not-belong"
            if (me.get("seq"), me.get("hash")) not in chain_index:
                return False, "member-event-missing-or-tampered"
    elif not any(e.get("member") == member for e in chain.events):
        return False, "member-not-in-chain"
    # quorum must count DISTINCT signatures: a duplicated signature must not
    # let one real witness satisfy the two-witness requirement.
    sigs_now = root_meta.get("witnesses") or []
    sigs_then = receipt.get("witnesses") or []
    if len(set(sigs_then)) < MIN_WITNESSES:
        return False, "quorum-fail: %d unique witness" % len(set(sigs_then))
    if len(set(sigs_now)) < MIN_WITNESSES:
        return False, "quorum-fail: chain has %d unique witness" % len(set(sigs_now))
    if not set(sigs_then).issubset(set(sigs_now)):
        return False, "witness-signature-differs"
    return True, "MATCH"


def audit_status(chain):
    """For exporter: never raise on corrupt data."""
    if chain.corrupt:
        return {"chain_ok": False, "first_bad_seq": 0, "why": str(chain._corrupt or "unknown")}
    ok, bad_seq, why = chain.verify()
    return {"chain_ok": ok, "first_bad_seq": bad_seq if not ok else None, "why": why}
