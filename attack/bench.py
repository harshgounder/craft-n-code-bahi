#!/usr/bin/env python3
"""bench.py - BAHI benchmarks: throughput, verification cost at scale,
payload sizes, memory, server latency. Pure stdlib. Output: JSON + table.
"""
import json, os, sys, time, tracemalloc, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain, receipt_payload, verify_receipt, h
from loans import balances
from exporter import hint_flags, export_csv
import server as srv
from http.server import HTTPServer
import http.client

RESULTS = {}

def bench(name, fn, repeat=3):
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    RESULTS[name] = round(best, 6)
    return best

def chain_with(n, meetings=0):
    c = BahiChain("G-BENCH")
    t = "2026-08-02T10:00:00"
    types = ["contribution", "loan", "repayment"] * (n // 3 + 1)
    members = ["Sita", "Geeta", "Reema", "Kavita", "Asha"] * (n // 5 + 1)
    for i in range(n):
        c.add_event(None, types[i], members[i], (i * 137) % 100000, t)  # PR10: auto seq
        if meetings and i % (n // meetings) == 0 and i > 0:
            c.close_meeting("M%03d" % (i // (n // meetings)), t)
    return c

def run():
    # micro: h()
    bench("h_200k_hashes_sec", lambda: [h("a", "b", i, "Sita", 100, "t") for i in range(200000)], repeat=1)
    RESULTS["h_throughput_per_sec"] = round(200000 / RESULTS["h_200k_hashes_sec"])

    for n in (1000, 10000, 100000):
        c = chain_with(n)
        bench("add_%d" % n, lambda: chain_with(n), repeat=1)
        bench("verify_%d" % n, c.verify, repeat=1)
        bench("export_%d" % n, c.export, repeat=1)
        RESULTS["export_%d_bytes" % n] = len(json.dumps(c.export()))
        bench("csv_%d" % n, lambda: export_csv(c), repeat=1)
        RESULTS["csv_%d_bytes" % n] = len(export_csv(c))
        bench("balances_%d" % n, lambda: balances(c), repeat=1)
        if n == 1000:
            RESULTS["export_%d_events" % n] = len(c.events)

    # verify_receipt at 100k with real receipt
    c = chain_with(100000, meetings=20)
    mid = sorted(c.roots)[-1]
    rec = receipt_payload(c.group_id, mid, c.roots[mid], "Sita")
    bench("verify_receipt_100k", lambda: verify_receipt(c, rec), repeat=1)

    # hint_flags at 100k across meetings
    bench("hint_flags_100k", lambda: hint_flags(chain_with(100000, meetings=50)), repeat=1)

    # save/load roundtrip at 100k
    c100 = chain_with(100000)
    p = "/tmp/bahi-bench-chain.json"
    bench("save_100k", lambda: c100.save(p), repeat=1)
    bench("load_100k", lambda: BahiChain.load(p), repeat=1)
    RESULTS["save_100k_file_bytes"] = os.path.getsize(p)
    os.unlink(p)
    try:
        os.unlink(p + ".bak")
    except OSError:
        pass

    # memory: peak for 100k chain
    tracemalloc.start()
    c_mem = chain_with(100000)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    RESULTS["peak_mem_100k_events_bytes"] = peak

    # server latency: 100 sequential /api/state + /api/entry
    srv.rebuild()
    httpd = HTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)

    def hit(path):
        conn.request("GET", path)
        r = conn.getresponse()
        r.read()
        return r.status
    t0 = time.perf_counter()
    for _ in range(100):
        hit("/api/state")
    RESULTS["http_100x_state_sec"] = round(time.perf_counter() - t0, 4)
    t0 = time.perf_counter()
    for _ in range(100):
        hit("/api/entry?type=contribution&paise=100")
    RESULTS["http_100x_entry_sec"] = round(time.perf_counter() - t0, 4)
    RESULTS["http_state_ms_req"] = round(RESULTS["http_100x_state_sec"] * 10, 3)
    RESULTS["http_entry_ms_req"] = round(RESULTS["http_100x_entry_sec"] * 10, 3)
    conn.close()
    httpd.shutdown()

    print(json.dumps(RESULTS, indent=1))
    return RESULTS

if __name__ == "__main__":
    run()