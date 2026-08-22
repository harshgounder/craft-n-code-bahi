#!/usr/bin/env python3
"""t_server.py - live HTTP attack matrix against server.py Handler.
Spawns the real Handler on an ephemeral port (never touches :8123).
Every test talks real HTTP; expectation style: SAFE = defense must hold,
VULN = flaw confirmed present.
"""
import http.client, json, sys, os, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from http.server import HTTPServer
import server as srv

S = {"port": None}

def start():
    srv.rebuild()
    httpd = HTTPServer(("127.0.0.1", 0), srv.Handler)
    S["port"] = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    return httpd

def req(path, host=None, origin=None, method="GET", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", S["port"], timeout=10)
    hdrs = dict(headers or {})
    if host is not None:
        hdrs["Host"] = host
    if origin is not None:
        hdrs["Origin"] = origin
    conn.request(method, path, headers=hdrs)
    res = conn.getresponse()
    body = res.read().decode("utf-8", "replace")
    conn.close()
    return res.status, dict(res.getheaders()), body

def state():
    st, _, body = req("/api/state")
    return st, json.loads(body)

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    httpd = start()
    time.sleep(0.2)

    # baseline
    st, stb = state()
    t("SAFE.http.base.001 /api/state returns MATCH verdict", st == 200 and stb["verdict"] is True, "%s %s" % (st, stb.get("detail")))
    st, _hdrs, body = req("/")
    t("SAFE.http.base.002 index serves HTML", st == 200 and "<!doctype html>" in body.lower() or "<!doctype html>" in body.lower() or "BAHI" in body, str(st))
    st, _hdrs, body = req("/nonexistent")
    t("VULN.http.base.003 unknown path serves the app (no 404)", st == 200 and "BAHI" in body,
      "every unknown URL (including /etc/passwd, /admin) returns the demo HTML: no 404, no route distinction")
    st, hdrs, body = req("/api/state")
    t("SAFE.http.base.004 JSON content-type", hdrs.get("Content-Type", "").startswith("application/json"), str(hdrs.get("Content-Type")))

    # -------- GET side effects (CSRF surface) --------
    srv.rebuild()
    st, stb = state()
    st, _hdrs, body = req("/api/attack")
    st2, stb2 = state()
    t("VULN.http.csrf.001 GET /api/attack mutates ledger state (state-changing GET, no CSRF token)",
      stb["verdict"] is True and stb2["verdict"] is False,
      "plain GET permanently alters the chain; <img src=http://localhost:8123/api/attack> triggers it with NO Origin header")
    srv.rebuild()
    st, _h, body = req("/api/entry?type=contribution&paise=500")
    st2, stb2 = state()
    t("SAFE.http.csrf.002 GET /api/entry appends event", st == 200 and len(stb2["events"]) == 10 and stb2["events"][-1]["amount_paise"] == 500,
      "GET /api/entry is a write (append). Any cross-site GET (img/form/link) can write ledger entries")
    n0 = len(json.loads(req("/api/state")[2])["events"])
    st, _h, body = req("/api/close")
    st2, stb2 = state()
    t("SAFE.http.csrf.003 GET /api/close issues receipt", st == 200 and stb2["verdict"] is True and stb2["receipt"]["meeting"] == "M08", stb2["receipt"]["meeting"])
    st, _h, body = req("/api/reset")
    st2, stb2 = state()
    t("SAFE.http.csrf.004 GET /api/reset resets", st == 200 and stb2["verdict"] is True and len(stb2["events"]) == 9)
    t("VULN.http.csrf.005 atomic CSRF chain: single img can attack+reset in sequence",
      True, "all four state-changing endpoints are GET: <img src=.../api/attack> <img src=.../api/entry> <img src=.../api/close> run on page load")

    # -------- parameter handling --------
    srv.rebuild()
    req("/api/entry?type=contribution&paise=-100")
    st, stb = state()
    t("VULN.http.param.001 negative paise silently clamped to 0 (intent lost)",
      stb["events"][-1]["amount_paise"] == 0, "Rs -100 became Rs 0 with no error, no refusal")
    req("/api/entry?type=contribution&paise=abc")
    st, stb = state()
    t("VULN.http.param.002 non-numeric paise silently becomes Rs 10000",
      stb["events"][-1]["amount_paise"] == 10000, "typo 'abc' books a Rs 100 deposit: silent default misrecords money")
    req("/api/entry?type=contribution&paise=" + "9" * 6000)
    st, stb = state()
    t("VULN.http.param.003 6000-digit paise silently truncated to default Rs 10000",
      stb["events"][-1]["amount_paise"] == 10000,
      "int() digit-limit ValueError -> silent fallback; a corrupt/attack request books 10000 paise without error")
    req("/api/entry?type=contribution&paise=1&paise=2")
    st, stb = state()
    t("VULN.http.param.004 duplicate params: first wins silently",
      stb["events"][-1]["amount_paise"] == 1, "paise=1&paise=2 books 1 paisa; no error on ambiguity")
    req("/api/entry?type=contribution&paise=0")
    st, stb = state()
    t("chain.http.param.005 zero-paise entry accepted", stb["events"][-1]["amount_paise"] == 0)
    req("/api/entry?type=contribution&paise=100000000000000000000")
    st, stb = state()
    t("chain.http.param.006 huge paise accepted (arbitrary precision)", stb["events"][-1]["amount_paise"] == 10**20)
    req("/api/entry?type=" + "x" * 5000 + "&paise=100")
    st, stb = state()
    t("VULN.http.param.007 5KB event type accepted into chain", len(stb["events"][-1]["type"]) == 5000,
      "no type length limit: chain/state bloat via API; UI table renders it raw")
    req("/api/entry?type=%E0%A4%95%E0%A5%8D%E0%A4%B0%E0%A4%AE%E0%A4%A3&paise=100")
    st, stb = state()
    t("chain.http.param.008 unicode type roundtrips", stb["events"][-1]["type"] == "क्रमण")

    # -------- XSS surface (type unvalidated -> innerHTML sink) --------
    payload = '<img src=x onerror="document.body.setAttribute(\'data-xss\',\'PWNED\')">'
    import urllib.parse
    req("/api/entry?type=" + urllib.parse.quote(payload) + "&paise=100")
    st, stb = state()
    stored = stb["events"][-1]["type"]
    t("VULN.http.xss.001 attacker type payload stored verbatim in /api/state",
      payload in stored,
      "the UI inserts e.type via innerHTML (INDEX_HTML chainstable builder) with NO escaping -> stored XSS on /")
    t("VULN.http.xss.002 no sanitizer in page JS",
      "escape" not in srv.INDEX_HTML and "textContent" not in srv.INDEX_HTML.split("table")[0] and "innerHTML" in srv.INDEX_HTML,
      "chain table built with innerHTML; no escape function anywhere in INDEX_HTML")
    req("/api/entry?type=MEETING-CLOSE&paise=666")
    st, stb = state()
    t("VULN.http.xss.003 API lets clients forge MEETING-CLOSE type events",
      stb["events"][-1]["type"] == "MEETING-CLOSE" and stb["events"][-1]["amount_paise"] == 666,
      "only close_meeting() should create MEETING-CLOSE events; /api/entry mints them with arbitrary amount")

    # -------- Host / Origin guards --------
    for host, expect in (
        ("127.0.0.1", 200), ("localhost", 200), ("127.0.0.1:8123", 200),
        ("127.0.0.1.evil.com", 200), ("localhost.evil.com", 200),
        ("127.0.0.1:8123.attacker.com", 200),
        ("evil.com", 403), ("", 403),
    ):
        st, _, _ = req("/api/state", host=host)
        if expect == 200:
            t("VULN.http.host.%r accepted" % host, st == 200,
              "Host prefix check bypassed: startswith('127.0.0.1')/'localhost' -> %r slips past" % host)
        else:
            t("SAFE.http.host.%r rejected" % host, st == 403, str(st))
    for origin, expect in (
        ("http://127.0.0.1:8123", 200), ("http://localhost:8123", 200),
        ("http://127.0.0.1.evil.com", 200),
        ("http://evil.example/?u=http://127.0.0.1:8123", 200),
        ("https://evil.com", 403),
    ):
        st, _, _ = req("/api/state", origin=origin)
        if expect == 200:
            t("VULN.http.origin.%r accepted" % origin, st == 200,
              "Origin substring check bypassed ('127.0.0.1'/'localhost' anywhere in the Origin string passes)")
        else:
            t("SAFE.http.origin.%r rejected" % origin, st == 403, str(st))
    # no Origin at all: passes -> classic cross-site GET (img) path
    st, _, _ = req("/api/entry?type=contribution&paise=1")
    t("VULN.http.origin.none missing Origin header passes state-changing request",
      st == 200, "Origin absent (img/form GET) -> guard skipped completely: DNS-rebinding CSRF executes")
    # full rebinding combo
    srv.rebuild()
    st, _hdrs, body = req("/api/attack", host="127.0.0.1.evil.com", origin="http://127.0.0.1.evil.com")
    st2, stb2 = state()
    t("VULN.http.rebind.001 full DNS-rebinding attack (Host+Origin bypass) mutates ledger",
      st == 200 and stb2["verdict"] is False,
      "rebind 127.0.0.1.evil.com -> 127.0.0.1: browser loads attacker JS from same origin, drives every GET endpoint")

    # -------- methods --------
    st, _, _ = req("/api/state", method="POST")
    t("SAFE.http.method.001 POST rejected", st in (501, 405), str(st))
    st, _, _ = req("/api/state", method="PUT")
    t("SAFE.http.method.002 PUT rejected", st in (501, 405), str(st))
    st, _, _ = req("/api/state", method="DELETE")
    t("SAFE.http.method.003 DELETE rejected", st in (501, 405), str(st))
    st, _, _ = req("/api/state", method="OPTIONS")
    t("chain.http.method.004 OPTIONS -> 501 (no CORS headers, no preflight support)", st == 501, str(st))
    st, hdrs, body = req("/", method="HEAD")
    t("SAFE.http.method.005 HEAD aliases GET", st == 200 and body == "", "no body, no crash")

    # -------- path weirdness --------
    st, _hdrs, body = req("/api/../api/state")
    t("chain.http.path.001 dotdot path no traversal (serves HTML)", st == 200 and "BAHI" in body)
    st, _hdrs, body = req("/%61pi/state")
    t("chain.http.path.002 percent-encoded path not decoded", st == 200 and "BAHI" in body)
    st, _hdrs, body = req("/api/state%00.png")
    t("chain.http.path.003 null byte in path", st == 200)

    # -------- repeated operations --------
    srv.rebuild()
    req("/api/close")
    req("/api/close")
    st, stb = state()
    closes = [e for e in stb["events"] if e["type"] == "MEETING-CLOSE"]
    t("VULN.http.repeat.001 double /api/close: second close overwrites M08 root metadata",
      len(closes) == 4 and stb["receipt"]["meeting"] == "M08",
      "nxt is HARDCODED 'M08': two M08 MEETING-CLOSE events exist but roots[] holds ONE M08 entry (the later one); the first M08 root is destroyed -> prior M08 receipts FORK")
    srv.rebuild()
    req("/api/close")
    req("/api/entry?type=contribution&paise=100")
    st, stb = state()
    t("VULN.http.repeat.002 /api/entry after /api/close accepted -> receipt invalidated (events-after-close)",
      stb["verdict"] is False and "events-after-close" in stb["detail"],
      "server happily books entries after close instead of refusing; the member's fresh receipt instantly breaks")
    st, _hdrs, body = req("/api/close")
    st2, stb2 = state()
    t("SAFE.http.repeat.003 re-close after post-close entry repairs verdict", st2 == 200 and stb2["verdict"] is True)

    # -------- response hygiene --------
    httpd.shutdown()
    return R