#!/usr/bin/env python3
"""chain.py - BAHI core: SHA-256 event chain, meeting roots, fork detection.
Pure stdlib. Deterministic: same files -> same bytes -> same verdict.

Protocol (v1.3, hardening batch):
- Events form a hash chain; recomputing from genesis detects any edit
  (event-hash-mismatch), delete (prev-hash-mismatch), reorder (same).
  The FIRST event is anchored to h("GENESIS", group_id), and group_id is
  folded into every event hash, so group identity is cryptographically
  committed to the chain (rename -> verify fails).
- add_event validates its inputs: seq must be the next sequential integer
  (auto-assigned when omitted), type must be a known user type, member must be
  a non-empty, non-reserved string, amount must be a non-negative integral
  number of paise (float truncation and bool are rejected), ts must be a
  non-empty string. The prev_hash escape hatch is gone: prev is always derived.
- Meeting close: a MEETING-CLOSE event (member "__root__", amount 0) terminates
  a meeting; it is the ONLY path that can emit a close event. At least 2
  witness records are REQUIRED at verification (quorum). A meeting id cannot be
  closed twice.
- Witnesses are name-bound records: {"witness": name, "sig": hex-HMAC}. This
  makes the attestation "Meera and Laxmi signed root R" rather than "two opaque
  strings". verify_receipt cryptographically checks each signature when
  `witness_keys` (a {name: passphrase} map) is supplied; without it the check
  is structural (well-formed, quorum, subset).
- Receipts are bound to (group, meeting, root, member + the member's own event
  hashes). A receipt from another group/meeting/member FAILS. The receipt is a
  deep copy: mutating the chain afterwards cannot rewrite a held receipt.
- Corrupt chain files (missing fields, bad JSON, wrong types) NEVER crash:
  load() and verify() return structured corruption verdicts.

Honest boundaries: full file-control by the bookkeeper (rewrite every hash
consistently) is undetectable by design; detection covers retroactive edits
AFTER witnessing, not mass collusion at entry time. HMAC witness signatures are
verifiable only by a key holder (see witness.py).
"""
import hashlib, json
from witness import verify as _witness_verify, is_valid_sig, sign as _witness_sign

MIN_WITNESSES = 2

# user-facing event types; MEETING-CLOSE is reserved for close_meeting()
EVENT_TYPES = ("contribution", "loan", "repayment", "correction")
_RESERVED_MEMBERS = ("__root__",)


def h(*parts):
    m = hashlib.sha256()
    for p in parts:
        m.update(str(p).encode("utf-8"))
        m.update(b"\x1f")
    return m.hexdigest()


def _norm_amount(v):
    """Return a non-negative integer number of paise, or None if invalid.

    Rejects bool (A21), non-integral float (A08), negative (A09), and
    non-numeric strings. Integral floats (10000.0) are accepted; 10000.9 is not.
    """
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return None if v < 0 else v
    if isinstance(v, float):
        return None if (v < 0 or not v.is_integer()) else int(v)
    if isinstance(v, str):
        try:
            n = int(v.strip())
        except ValueError:
            return None
        return None if n < 0 else n
    return None


def _norm_witness(w):
    """Return (name, sig) for a well-formed witness record, else None."""
    if isinstance(w, dict):
        name = w.get("witness")
        sig = w.get("sig")
        if isinstance(name, str) and name and is_valid_sig(sig):
            return (name, sig)
    return None


def _norm_witnesses(ws):
    """Normalize a witness list, silently dropping malformed entries."""
    out = []
    for w in (ws or []):
        n = _norm_witness(w)
        if n is not None:
            out.append(n)
    return out


class BahiChain:
    def __init__(self, group_id=""):
        self.group_id = group_id
        self.events = []
        self.roots = {}

    # ------------------------------------------------------------------ write
    def _append(self, seq, etype, member, amt, ts):
        """Raw append (no validation); used by add_event and close_meeting."""
        prev = self.events[-1]["hash"] if self.events else h("GENESIS", self.group_id)
        ev = {
            "seq": seq,
            "group": self.group_id,
            "type": etype,
            "member": member,
            "amount_paise": amt,
            "ts": ts,
            "prev": prev,
        }
        ev["hash"] = h(prev, self.group_id, seq, etype, member, amt, ts)
        self.events.append(ev)
        return ev

    def add_event(self, seq, etype, member, amount_paise, ts):
        """Append a user event. seq may be None to auto-assign the next
        sequential integer; otherwise it must equal len(events)+1 (strictly
        increasing, no duplicates, no gaps)."""
        if not isinstance(self.group_id, str) or not self.group_id.strip():
            raise ValueError("group_id must be a non-empty string")
        if etype == "MEETING-CLOSE":
            raise ValueError("MEETING-CLOSE is reserved for close_meeting()")
        if etype not in EVENT_TYPES:
            raise ValueError("unknown event type: %r" % (etype,))
        if not isinstance(member, str) or not member:
            raise ValueError("member must be a non-empty string")
        if member in _RESERVED_MEMBERS:
            raise ValueError("member name %r is reserved" % (member,))
        if not isinstance(ts, str) or not ts:
            raise ValueError("ts must be a non-empty string")
        amt = _norm_amount(amount_paise)
        if amt is None:
            raise ValueError("amount must be a non-negative integer number of paise")
        expected = len(self.events) + 1
        if seq is None:
            seq = expected
        elif isinstance(seq, bool) or not isinstance(seq, int) or seq != expected:
            raise ValueError("seq must be %d (got %r)" % (expected, seq))
        return self._append(seq, etype, member, amt, ts)

    def close_meeting(self, meeting_id, ts, witnesses=None):
        """Close the meeting with a MEETING-CLOSE event and return its root.

        witnesses: optional list of {"witness", "sig"} records (already signed,
        e.g. via witness.sign_entry). A meeting id cannot be closed twice.
        NOTE: quorum (>= MIN_WITNESSES) is enforced at verification time, not
        here, because witnesses sign the root which only exists after close;
        pass witnesses here or attach them right after close."""
        if not isinstance(meeting_id, str) or not meeting_id:
            raise ValueError("meeting_id must be a non-empty string")
        if meeting_id in self.roots:
            raise ValueError("meeting %r is already closed" % (meeting_id,))
        if not isinstance(ts, str) or not ts:
            raise ValueError("ts must be a non-empty string")
        ev = self._append(len(self.events) + 1, "MEETING-CLOSE", "__root__", 0, ts)
        sigs = []
        for w in (witnesses or []):
            n = _norm_witness(w)
            if n is None:
                raise ValueError("invalid witness record: %r" % (w,))
            sigs.append({"witness": n[0], "sig": n[1]})
        self.roots[meeting_id] = {
            "root_hash": ev["hash"],
            "root_seq": ev["seq"],
            "ts": ts,
            "witnesses": sigs,
        }
        return self.roots[meeting_id]

    def add_witness(self, meeting_id, payload, passphrase, witness):
        """Sign and attach a witness record to a closed meeting (convenience
        for the "close then sign" flow). Returns the record."""
        root_meta = self.roots.get(meeting_id)
        if root_meta is None:
            raise ValueError("meeting %r not found" % (meeting_id,))
        rec = {"witness": witness, "sig": _witness_sign(payload, passphrase, witness)}
        root_meta["witnesses"].append(rec)
        return rec

    # ------------------------------------------------------------------- read
    def root_for(self, meeting_id):
        return self.roots.get(meeting_id)

    def verify(self):
        """Recompute the whole chain from genesis. Returns (ok, bad_seq, why).
        NEVER raises on malformed data: returns (False, seq, 'corrupt-file: ...')."""
        if not isinstance(self.group_id, str) or not self.group_id.strip():
            return False, 0, "corrupt-file: empty group"
        if not self.events:
            return False, 0, "corrupt-file: empty chain"
        prev = h("GENESIS", self.group_id)
        for i, ev in enumerate(self.events):
            seq = i + 1
            for field in ("seq", "type", "member", "amount_paise", "ts", "prev", "hash", "group"):
                if field not in ev:
                    return False, seq, "corrupt-file: missing field %r at event %d" % (field, seq)
            if ev.get("group") != self.group_id:
                return False, seq, "corrupt-file: group field mismatch at event %d" % seq
            amt = _norm_amount(ev["amount_paise"])
            if amt is None:
                return False, seq, "corrupt-file: bad amount at event %d" % seq
            if isinstance(ev["seq"], bool) or not isinstance(ev["seq"], int) or ev["seq"] != seq:
                return False, seq, "corrupt-file: bad seq at event %d (expected %d)" % (seq, seq)
            recomputed = h(ev["prev"], self.group_id, ev["seq"], ev["type"], ev["member"], amt, ev["ts"])
            if recomputed != ev["hash"]:
                return False, seq, "event-hash-mismatch"
            if ev["prev"] != prev:
                return False, seq, "prev-hash-mismatch"
            prev = ev["hash"]
        return True, 0, "ok"

    # --------------------------------------------------------------------- io
    def export(self):
        return {"group": self.group_id, "events": self.events, "roots": self.roots}

    def save(self, path):
        """Durable atomic write: temp file in the same dir, flush + fsync,
        atomic os.replace, plus a best-effort .bak copy."""
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
                pass
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
            c.events = []
            c.roots = {"__corrupt__": {"root_hash": "", "root_seq": 0, "ts": "", "witnesses": [], "corrupt": "load: %s" % e}}
            return c
        if not isinstance(d, dict) or "group" not in d or not isinstance(d.get("events"), list):
            c.events = []
            c.roots = {"__corrupt__": {"root_hash": "", "root_seq": 0, "ts": "", "witnesses": [], "corrupt": "load: no events array"}}
            return c
        c.group_id = d["group"]
        c.events = d["events"]
        c.roots = d.get("roots", {})
        return c

    @property
    def corrupt(self):
        return "__corrupt__" in self.roots or not isinstance(self.group_id, str) or not self.group_id.strip()


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------
def receipt_payload(group, meeting_id, root_meta, member, chain=None):
    """Build a member receipt. `chain` (optional) binds the member's own event
    hashes so the receipt proves the member's line items, not just the root.

    The returned receipt is a DEEP COPY of the witness records and member
    events: mutating the chain afterwards cannot rewrite an already-issued
    receipt (A04)."""
    member_events = None
    if chain is not None:
        member_events = [
            {"seq": e["seq"], "hash": e["hash"]}
            for e in chain.events
            if e.get("member") == member and e.get("type") != "MEETING-CLOSE"
            and e.get("seq", 0) <= root_meta.get("root_seq", 0)
        ]
    witnesses = [dict(w) for w in (root_meta.get("witnesses") or []) if isinstance(w, dict)]
    return {
        "group": group,
        "meeting": meeting_id,
        "root": root_meta["root_hash"],
        "root_seq": root_meta["root_seq"],
        "member": member,
        "root_ts": root_meta["ts"],
        "witnesses": witnesses,
        "member_events": member_events,
    }


def verify_receipt(chain, receipt, witness_keys=None):
    """Verify a member receipt against the chain.

    Checks (in order): chain not corrupt; full recompute; group binding; meeting
    root exists and its MEETING-CLOSE event is present in the chain and carries
    the receipt root; nothing follows the close (terminality); member binding;
    witness quorum; witness subset; and — when `witness_keys` (a {name:
    passphrase} map) is supplied — cryptographic verification of every witness
    signature (A02). Never crashes: corrupt input = fail with detail.
    """
    if chain.corrupt:
        return False, "corrupt-chain: %s" % (chain.roots.get("__corrupt__", {}).get("corrupt", "unknown"))
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

    # witnesses: normalize to (name, sig) pairs; malformed entries are dropped,
    # so arbitrary strings can never count toward quorum (A02)
    sigs_now = _norm_witnesses(root_meta.get("witnesses"))
    sigs_then = _norm_witnesses(receipt.get("witnesses"))
    if len(sigs_then) < MIN_WITNESSES:
        return False, "quorum-fail: %d valid witness record(s)" % len(sigs_then)
    if len(sigs_now) < MIN_WITNESSES:
        return False, "quorum-fail: chain has %d valid witness record(s)" % len(sigs_now)
    if not set(sigs_then).issubset(set(sigs_now)):
        return False, "witness-signature-differs"

    # cryptographic verification (optional but strongly recommended)
    if witness_keys is not None:
        payload = {"root": receipt.get("root"), "meeting": receipt.get("meeting")}
        for name, sig in sigs_then:
            key = witness_keys.get(name)
            if key is None:
                return False, "witness-key-missing: %s" % name
            if not _witness_verify(payload, sig, key, name):
                return False, "witness-signature-invalid: %s" % name
    return True, "MATCH"


def audit_status(chain):
    """For exporter: never raise on corrupt data."""
    if chain.corrupt:
        return {"chain_ok": False, "first_bad_seq": 0, "why": str(chain.roots.get("__corrupt__", {}).get("corrupt", ""))}
    ok, bad_seq, why = chain.verify()
    return {"chain_ok": ok, "first_bad_seq": bad_seq if not ok else None, "why": why}
