#!/usr/bin/env python3
"""t_stress.py - stress/scale/abuse tests on the CURRENT HEAD flow.
Concurrency, receipt bloat, reset cycles, export scale.
"""
import http.client, json, os, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain, receipt_payload, verify_receipt
from witness import sign
from http.server import HTTPServer
import server as srv

T = "2026-08-02T10:00:00"

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    srv.rebuild()
    httpd = HTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    def do(path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        conn.request("GET", path)
        res = conn.getresponse()
        body = res.read().decode("utf-8", "replace")
        conn.close()
        return res.status, body
    def st():
        return json.loads(do("/api/state")[1])

    # ---- concurrency: 8 threads x 50 entries (single-threaded HTTPServer serializes) ----
    srv.rebuild()
    n0 = len(st()["events"])
    errs = []
    def hammer(wid):
        for i in range(50):
            try:
                stc, b = do("/api/entry?type=contribution&paise=%d" % (wid * 100 + i))
                if stc != 200:
                    errs.append((wid, i, stc, b[:80]))
            except Exception as e:
                errs.append((wid, i, repr(e)))
    threads = [threading.Thread(target=hammer, args=(w,)) for w in range(8)]
    for th in threads: th.start()
    for th in threads: th.join()
    n1 = len(st()["events"])
    t("stress.conc.001 8x50 concurrent entries all recorded (serialized, no lost updates)",
      n1 == n0 + 400 and not errs, "n0=%d n1=%d errs=%d" % (n0, n1, len(errs)))
    seqs = [e["seq"] for e in st()["events"]]
    t("SAFE.stress.conc.002 seq allocator unique after 400 entries",
      len(set(seqs)) == len(seqs), "len(events)+1 allocation keeps seqs unique; no collision with seeded seq 8")
    t("stress.conc.003 chain verifies after hammer", st() and json.loads(do("/api/export")[1])["report"]["chain_ok"])

    # ---- 10k entries -> close -> bound receipt bloat ----
    srv.rebuild()
    CH = 10000
    chunk = 200
    for i in range(0, CH, chunk):
        for j in range(chunk):
            do("/api/entry?type=contribution&paise=1")
    t("stress.bloat.001 10000 entries accepted while open", len(st()["events"]) == 10008 and st()["verdict"] is None)
    t0 = time.perf_counter()
    stc, b = do("/api/close")
    dt_close = time.perf_counter() - t0
    s = st()
    rec = s["receipt"]
    n_me = len(rec["member_events"])
    t("stress.bloat.002 close at 10k events ok", stc == 200 and json.loads(b).get("ok") is True, b[:120])
    t("stress.bloat.003 member_events grows with member activity (10k entries, all Sita)",
      n_me >= 10000, "member_events=%d" % n_me)
    payload = json.dumps(s)
    t("stress.bloat.004 /api/state payload size with 10k member_events",
      len(payload) > 500 * 1024, "%.1f KB" % (len(payload) / 1024.0))
    t("VULN.stress.bloat.005 single-member 10k-entry meeting -> receipt ~%d event refs (%.0f KB state): unbounded receipt growth"
      % (n_me, len(payload) / 1024.0), n_me >= 10000,
      "every entry books to member Sita; receipts grow linearly with entry count; a 1e6-entry group -> ~70 MB receipts per member (QR impossible, /api/state MBs)")
    # verify_receipt still fast with 10k member events
    c = srv.STATE["chain"]
    t0 = time.perf_counter()
    ok, det = verify_receipt(c, rec)
    dt = time.perf_counter() - t0
    t("stress.bloat.006 verify_receipt @10k member_events %.0f ms" % (dt * 1000), ok and det == "MATCH" and dt < 2.0, det)
    # state payload time
    t0 = time.perf_counter()
    st()
    dt = time.perf_counter() - t0
    t("stress.bloat.007 /api/state latency @10k events < 500 ms", dt < 0.5, "%.0f ms" % (dt * 1000))

    # ---- reset cycle stability ----
    srv.rebuild()
    okc = 0
    for i in range(60):
        do("/api/entry?type=contribution&paise=1")
        stc, b = do("/api/close")
        if json.loads(b).get("ok") is True:
            okc += 1
        do("/api/reset")
    t("stress.reset.001 60 entry+close+reset cycles stable", okc == 60, "ok=%d" % okc)
    s = st()
    t("stress.reset.002 state consistent after cycles", len(s["events"]) == 8 and s["verdict"] is None and s["receipt"] is None)

    # ---- export scale ----
    srv.rebuild()
    for i in range(2000):
        do("/api/entry?type=contribution&paise=%d" % (i % 997))
    t0 = time.perf_counter()
    stc, b = do("/api/export")
    dt = time.perf_counter() - t0
    d = json.loads(b)
    t("stress.export.001 /api/export @2k events fast", stc == 200 and "report" in d and dt < 2.0, "%.0f ms" % (dt * 1000))
    t("stress.export.002 csv rows == events", d["csv_rows"].count("\n") == 2009, str(d["csv_rows"].count("\n")))
    # hint_flags do not crash at 2k
    t("stress.export.003 hints returned", isinstance(d["hints"], list))

    # ---- malformed param flood (server must not die) ----
    srv.rebuild()
    alive = True
    for q in ("paise=", "paise=abc", "paise=-5", "paise=9"*5000, "type=", "type=x"*2000,
              "paise=1&paise=2", "type=loan&paise=0", "paise=18446744073709551616"):
        try:
            stc, b = do("/api/entry?" + q)
            if stc != 200:
                alive = False
        except Exception:
            alive = False
    t("stress.fuzz.001 9 malformed param bombs: server stays up", alive and st()["verdict"] is None)

    httpd.shutdown()
    return R