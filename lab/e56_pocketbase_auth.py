"""E56: PocketBase's password sign-in, measured like bindings/node/e56_auth.js measures ours.

    python3 -I lab/e56_pocketbase_auth.py tools/pocketbase-0.40.5/pocketbase <scratch dir>

Creates 300 users through the built-in users collection, then: sign-in one at a time (p50, p99), failed sign-ins
(wrong password, unknown email), 200 sign-ins at once, and a request carrying the token against the same request
without one (the difference is what checking a token costs per request, plus the record rule).
"""
import json, os, shutil, socket, subprocess, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor

PB, SCRATCH = sys.argv[1], sys.argv[2]
shutil.rmtree(SCRATCH, ignore_errors=True); os.makedirs(SCRATCH)
with socket.socket() as s: s.bind(("127.0.0.1", 0)); PORT = s.getsockname()[1]
BASE = f"http://127.0.0.1:{PORT}"

def call(method, path, body=None, token=""):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json", **({"Authorization": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e: return e.code, {}

def pct(xs, p): s = sorted(xs); return s[min(len(s) - 1, int(len(s) * p))]

data = os.path.join(SCRATCH, "pb_data")
subprocess.run([PB, "superuser", "upsert", "admin@lab.test", "labpass12345", "--dir", data], capture_output=True, check=True)
proc = subprocess.Popen([PB, "serve", "--http", f"127.0.0.1:{PORT}", "--dir", data], stdout=open(os.path.join(SCRATCH, "pb.out"), "w"), stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try: urllib.request.urlopen(BASE + "/api/health", timeout=1); break
        except Exception: time.sleep(0.1)
    st, su = call("POST", "/api/collections/_superusers/auth-with-password", {"identity": "admin@lab.test", "password": "labpass12345"})
    admin = su["token"]
    N = 300; t = time.perf_counter(); ids = []
    for i in range(N):
        st, u = call("POST", "/api/collections/users/records", {"email": f"u{i}@example.com", "password": "the password", "passwordConfirm": "the password", "verified": True}, admin)
        assert st == 200, (st, u); ids.append(u["id"])
    print(f"{'sign-up (create a user), one at a time (' + str(N) + ')':64} {(time.perf_counter() - t) / N * 1000:.2f} ms each")
    lat = []; tokens = []
    for i in range(N):
        a = time.perf_counter(); st, r = call("POST", "/api/collections/users/auth-with-password", {"identity": f"u{i}@example.com", "password": "the password"}); lat.append((time.perf_counter() - a) * 1000)
        assert st == 200; tokens.append(r["token"])
    print(f"{'sign-in, one at a time':64} p50 {pct(lat, .5):.2f} ms, p99 {pct(lat, .99):.2f} ms")
    wrong = []; ghost = []
    for i in range(100):
        a = time.perf_counter(); call("POST", "/api/collections/users/auth-with-password", {"identity": f"u{i}@example.com", "password": "wrong password"}); wrong.append((time.perf_counter() - a) * 1000)
        a = time.perf_counter(); call("POST", "/api/collections/users/auth-with-password", {"identity": f"ghost{i}@example.com", "password": "the password"}); ghost.append((time.perf_counter() - a) * 1000)
    print(f"{'failed sign-in: wrong password / unknown login':64} p50 {pct(wrong, .5):.2f} ms / {pct(ghost, .5):.2f} ms")
    def one(i): return call("POST", "/api/collections/users/auth-with-password", {"identity": f"u{i}@example.com", "password": "the password"})[0]
    t = time.perf_counter()
    with ThreadPoolExecutor(64) as ex: codes = list(ex.map(one, range(200)))
    el = time.perf_counter() - t; assert all(c == 200 for c in codes), codes
    print(f"{'200 sign-ins at once (64 client threads)':64} {el * 1000:.0f} ms ({200 / el:.0f}/s)")
    R = 2000
    t = time.perf_counter()
    for i in range(R): call("GET", "/api/health")
    bare = (time.perf_counter() - t) / R * 1e6
    t = time.perf_counter()
    for i in range(R): st, _ = call("GET", f"/api/collections/users/records/{ids[i % N]}", token=tokens[i % N]); assert st == 200
    authed = (time.perf_counter() - t) / R * 1e6
    print(f"{'a request: /api/health / the user reading their own record':64} {bare:.0f} µs / {authed:.0f} µs")
finally:
    proc.terminate(); proc.wait()
    shutil.rmtree(SCRATCH, ignore_errors=True)
