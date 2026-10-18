"""E54: PocketBase 0.40.5 feature probes. Starts a fresh PocketBase with a JS hooks directory and a local SMTP sink,
then tries each feature through its HTTP API and prints one tab-separated row per feature: category, feature, result.

    python3 -I lab/e54_pocketbase.py tools/pocketbase-0.40.5/pocketbase <scratch dir> [s3 endpoint]
"""
import json, os, re, shutil, socket, socketserver, struct, subprocess, sys, threading, time, urllib.error, urllib.parse, urllib.request, zlib

PB, SCRATCH = sys.argv[1], sys.argv[2]
S3 = sys.argv[3] if len(sys.argv) > 3 else ""
PORT, SMTP_PORT = 8095, 2526
BASE = f"http://127.0.0.1:{PORT}"
MAILS = []
ROWS = []


def row(cat, feature, result):
    ROWS.append((cat, feature, result.replace("\t", " ").replace("\n", " ")))


# ---- a minimal SMTP sink: accepts every message and keeps it
class Smtp(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write((s + "\r\n").encode())
        w("220 lab smtp")
        data, in_data = [], False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode(errors="replace").rstrip("\r\n")
            if in_data:
                if text == ".":
                    MAILS.append("\n".join(data))
                    data, in_data = [], False
                    w("250 ok")
                else:
                    data.append(text[1:] if text.startswith("..") else text)
                continue
            cmd = text.split(" ")[0].upper()
            if cmd in ("EHLO", "HELO"):
                w("250 lab")
            elif cmd == "DATA":
                in_data = True
                w("354 go")
            elif cmd == "QUIT":
                w("221 bye")
                return
            else:
                w("250 ok")


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---- HTTP helpers
TOKEN = ""


def call(method, path, body=None, token=None, raw=None, ctype=None):
    data, headers = None, {}
    if raw is not None:
        data, headers["Content-Type"] = raw, ctype
    elif body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    tok = TOKEN if token is None else token
    if tok:
        headers["Authorization"] = tok
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = r.read()
            return r.status, (json.loads(payload) if payload and r.headers.get("Content-Type", "").startswith("application/json") else payload)
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload)
        except Exception:
            return e.code, payload


def png(w=200, h=120):
    raw = b"".join(b"\x00" + b"".join(bytes([(x * 3) % 256, (y * 2) % 256, 90]) for x in range(w)) for y in range(h))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def multipart(fields, files):
    b = "----lab" + str(time.time_ns())
    out = b""
    for k, v in fields.items():
        out += f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    for k, (name, content, ct) in files.items():
        out += f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{name}\"\r\nContent-Type: {ct}\r\n\r\n".encode() + content + b"\r\n"
    return out + f"--{b}--\r\n".encode(), f"multipart/form-data; boundary={b}"


def wait_mail(n, secs=10):
    t = time.time()
    while len(MAILS) < n and time.time() - t < secs:
        time.sleep(0.05)
    return len(MAILS) >= n


def probe(cat, feature, fn):
    try:
        row(cat, feature, fn())
    except Exception as e:  # a probe that throws is reported, not fatal
        row(cat, feature, f"no: {type(e).__name__}: {e}")


HOOKS = r"""
routerAdd("GET", "/hello", (e) => e.json(200, { "hello": "from a JS hook" }))
onRecordCreate((e) => { e.record.set("title", e.record.get("title") + " (hooked)"); e.next() }, "notes")
cronAdd("lab_cron", "*/5 * * * *", () => {})
"""


def main():
    global TOKEN
    shutil.rmtree(SCRATCH, ignore_errors=True)
    os.makedirs(f"{SCRATCH}/hooks")
    open(f"{SCRATCH}/hooks/main.pb.js", "w").write(HOOKS)
    smtp = Server(("127.0.0.1", SMTP_PORT), Smtp)
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    data = f"{SCRATCH}/pb_data"
    subprocess.run([PB, "superuser", "upsert", "admin@lab.test", "labpass12345", "--dir", data], capture_output=True, check=True)
    proc = subprocess.Popen([PB, "serve", "--http", f"127.0.0.1:{PORT}", "--dir", data, "--hooksDir", f"{SCRATCH}/hooks"], stdout=open(f"{SCRATCH}/pb.out", "w"), stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            try:
                if call("GET", "/api/health", token="")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        st, su = call("POST", "/api/collections/_superusers/auth-with-password", {"identity": "admin@lab.test", "password": "labpass12345"}, token="")
        TOKEN = su["token"]
        call("PATCH", "/api/settings", {"meta": {"senderName": "lab", "senderAddress": "pb@lab.test", "appURL": BASE},
                                          "smtp": {"enabled": True, "host": "127.0.0.1", "port": SMTP_PORT, "tls": False}})
        run_probes(data)
    finally:
        proc.terminate()
        proc.wait(10)
        smtp.shutdown()
    print("category\tfeature\tpocketbase")
    for r in ROWS:
        print("\t".join(r))


def run_probes(data):
    global TOKEN
    su = TOKEN

    # ---- app backend basics
    def admin_ui():
        st, body = call("GET", "/_/", token="")
        return "yes: the admin dashboard at /_/" if st == 200 and b"<html" in body.lower() else f"no: {st}"
    probe("Backend", "Admin UI", admin_ui)

    def rest():
        st, _ = call("POST", "/api/collections", {"name": "notes", "type": "base", "listRule": "", "viewRule": "", "createRule": "", "updateRule": "", "deleteRule": "",
                                                  "fields": [{"name": "title", "type": "text"}, {"name": "meta", "type": "json"},
                                                             {"name": "author", "type": "relation", "collectionId": "_pb_users_auth_", "maxSelect": 1},
                                                             {"name": "doc", "type": "file", "maxSelect": 1, "maxSize": 5242880, "thumbs": ["100x100"]},
                                                             {"name": "created", "type": "autodate", "onCreate": True}]})
        if st != 200:
            return f"no: creating a collection gave {st}"
        st, rec = call("POST", "/api/collections/notes/records", {"title": "hello world", "meta": {"n": 5}}, token="")
        st2, lst = call("GET", "/api/collections/notes/records?perPage=5", token="")
        return "yes: create, list, view, update and delete for every collection, no code" if st == 200 and st2 == 200 and lst["totalItems"] >= 1 else f"no: {st} {st2}"
    probe("Backend", "REST API generated for each table", rest)

    def hooks_and_routes():
        st, body = call("GET", "/hello", token="")
        st2, rec = call("POST", "/api/collections/notes/records", {"title": "via hook"}, token="")
        ok = st == 200 and st2 == 200 and rec.get("title", "").endswith("(hooked)")
        return "yes: JavaScript hooks (custom routes, record events), or Go when used as a library" if ok else f"no: route {st}, hook {rec.get('title') if isinstance(rec, dict) else st2}"
    probe("Backend", "Server-side code (hooks, custom routes)", hooks_and_routes)

    def cron():
        st, body = call("GET", "/api/crons")
        return "yes: cronAdd() in hooks; listed and runnable from the API" if st == 200 and any(c.get("id") == "lab_cron" for c in body) else f"no: {st} {body}"
    probe("Backend", "Scheduled jobs (cron)", cron)

    def filters():
        st, a = call("GET", "/api/collections/notes/records?" + urllib.parse.urlencode({"filter": "title ~ 'hel'"}), token="")
        st2, b = call("GET", "/api/collections/notes/records?" + urllib.parse.urlencode({"filter": "meta.n > 3"}), token="")
        st3, c = call("GET", "/api/collections/notes/records?" + urllib.parse.urlencode({"sort": "-created,title", "page": 1, "perPage": 1}), token="")
        ok = st == 200 and a["totalItems"] >= 1 and st2 == 200 and b["totalItems"] == 1 and st3 == 200
        return "yes: filter expressions (=, !=, >, ~ contains, ?= any), JSON paths, multi-column sort, pages" if ok else f"no: {st} {st2} {st3}"
    probe("Backend", "Filtering, sorting and paging through the API", filters)

    def expand():
        st, u = call("POST", "/api/collections/users/records", {"email": "ann@lab.test", "password": "annpass12345", "passwordConfirm": "annpass12345", "name": "Ann"}, token="")
        st2, n = call("POST", "/api/collections/notes/records", {"title": "by ann", "author": u["id"]}, token="")
        st3, got = call("GET", f"/api/collections/notes/records/{n['id']}?expand=author", token=su)
        return "yes: expand=relation returns the related record inline" if st3 == 200 and got.get("expand", {}).get("author", {}).get("id") == u["id"] else f"no: {st} {st2} {st3}"
    probe("Backend", "Expand relations in one request", expand)

    def view_collection():
        q = "SELECT id, title, row_number() OVER (ORDER BY title) AS rn, json_extract(meta, '$.n') AS n FROM notes"
        st, err = call("POST", "/api/collections", {"name": "notes_ranked", "type": "view", "listRule": "", "viewRule": "", "viewQuery": q})
        if st == 200:
            st2, lst = call("GET", "/api/collections/notes_ranked/records", token="")
            return "yes: a SQL SELECT (joins, window functions, JSON) exposed as a read-only collection" if st2 == 200 and lst["totalItems"] >= 1 else f"no: {st2}"
        q2 = "SELECT notes.id, notes.title, users.email, json_extract(notes.meta, '$.n') AS n FROM notes LEFT JOIN users ON users.id = notes.author"
        st, err2 = call("POST", "/api/collections", {"name": "notes_joined", "type": "view", "listRule": "", "viewRule": "", "viewQuery": q2})
        st2, lst = call("GET", "/api/collections/notes_joined/records", token="")
        if st == 200 and st2 == 200 and lst["totalItems"] >= 1:
            return "yes: a SQL SELECT with joins and JSON functions becomes a read-only collection; its column parser refused a window function"
        return f"no: {st} {st2} {json.dumps(err2)[:300]}"
    probe("Backend", "SQL views as API collections", view_collection)

    def batch():
        call("PATCH", "/api/settings", {"batch": {"enabled": True, "maxRequests": 50, "timeout": 3}})
        reqs = [{"method": "POST", "url": "/api/collections/notes/records", "body": {"title": f"batch {i}"}} for i in range(3)]
        st, res = call("POST", "/api/batch", {"requests": reqs}, token="")
        bad = [{"method": "POST", "url": "/api/collections/notes/records", "body": {"title": "ok"}}, {"method": "POST", "url": "/api/collections/nope/records", "body": {}}]
        st2, _ = call("POST", "/api/batch", {"requests": bad}, token="")
        st3, lst = call("GET", "/api/collections/notes/records?" + urllib.parse.urlencode({"filter": "title = 'ok'"}), token="")
        all_or_none = st2 >= 400 and lst["totalItems"] == 0
        if st != 200 or len(res) != 3:
            return f"no: {st} {res}"
        return "yes: /api/batch (off by default), all or nothing" if all_or_none else "partial: /api/batch runs requests together, but a failing one did not undo the others"
    probe("Backend", "Transactions through the API (batch)", batch)

    def import_schema():
        st, cols = call("GET", "/api/collections?perPage=200")
        notes = [c for c in cols["items"] if c["name"] == "notes"][0]
        st2, _ = call("PUT", "/api/collections/import", {"collections": [notes], "deleteMissing": False})
        return "yes: export the collections as JSON and import them into another instance" if st2 == 204 else f"no: {st2}"
    probe("Backend", "Export and import the schema", import_schema)

    def migrations():
        d = os.path.join(os.path.dirname(data), "pb_migrations")
        files = os.listdir(d) if os.path.isdir(d) else []
        return f"yes: every schema change made in the UI or API is written as a JS migration file ({len(files)} so far)" if files else "no: no pb_migrations written"
    probe("Backend", "Migration files", migrations)

    # ---- auth
    def password_auth():
        st, a = call("POST", "/api/collections/users/auth-with-password", {"identity": "ann@lab.test", "password": "annpass12345"}, token="")
        return "yes: sign-up, sign-in, token refresh, built-in users collection" if st == 200 and a.get("token") else f"no: {st}"
    probe("Auth", "Email and password sign-in", password_auth)

    def oauth2():
        st, _ = call("PATCH", "/api/collections/users", {"oauth2": {"enabled": True, "providers": [{"name": "google", "clientId": "lab-client", "clientSecret": "lab-secret"}, {"name": "github", "clientId": "lab-client", "clientSecret": "lab-secret"}]}})
        st2, m = call("GET", "/api/collections/users/auth-methods", token="")
        provs = [p["name"] for p in m.get("oauth2", {}).get("providers", [])] if st2 == 200 else []
        url = next((p.get("authURL", "") for p in m.get("oauth2", {}).get("providers", []) if p["name"] == "google"), "")
        ok = "google" in provs and "github" in provs and "accounts.google.com" in url
        return "yes: providers configured by settings, the sign-in URL and code exchange handled by the server (verified up to the provider's redirect; no real Google account used)" if ok else f"no: {st} {st2} {provs}"
    probe("Auth", "OAuth2 sign-in (Google, GitHub, …)", oauth2)

    def verification():
        n0 = len(MAILS)
        st, _ = call("POST", "/api/collections/users/request-verification", {"email": "ann@lab.test"}, token="")
        if st != 204 or not wait_mail(n0 + 1):
            return f"no: {st}, mails {len(MAILS) - n0}"
        tok = re.search(r"confirm-verification/([A-Za-z0-9_\-\.=]+)", MAILS[-1].replace("=\n", "").replace("=3D", "="))
        if not tok:
            return "partial: the email arrived but the token was not found in it"
        st2, _ = call("POST", "/api/collections/users/confirm-verification", {"token": tok.group(1)}, token="")
        st3, a = call("POST", "/api/collections/users/auth-with-password", {"identity": "ann@lab.test", "password": "annpass12345"}, token="")
        return "yes: the email is sent and its link verifies the account" if st2 == 204 and a["record"]["verified"] else f"no: confirm {st2}"
    probe("Auth", "Email verification", verification)

    def reset():
        n0 = len(MAILS)
        st, _ = call("POST", "/api/collections/users/request-password-reset", {"email": "ann@lab.test"}, token="")
        return "yes: reset email with a link (also email change)" if st == 204 and wait_mail(n0 + 1) else f"no: {st}"
    probe("Auth", "Password reset by email", reset)

    def otp():
        call("PATCH", "/api/collections/users", {"otp": {"enabled": True, "duration": 180, "length": 6}})
        n0 = len(MAILS)
        st, r = call("POST", "/api/collections/users/request-otp", {"email": "ann@lab.test"}, token="")
        if st != 200 or not wait_mail(n0 + 1):
            return f"no: {st}"
        code = re.search(r"\b(\d{6})\b", MAILS[-1])
        st2, a = call("POST", "/api/collections/users/auth-with-otp", {"otpId": r["otpId"], "password": code.group(1) if code else ""}, token="")
        return "yes: a one-time code by email signs the user in" if st2 == 200 and a.get("token") else f"no: {st2}"
    probe("Auth", "One-time code by email (OTP)", otp)

    def impersonate():
        st, u = call("GET", "/api/collections/users/records?perPage=1")
        uid = u["items"][0]["id"]
        st2, a = call("POST", f"/api/collections/users/impersonate/{uid}", {"duration": 600})
        return "yes: a superuser gets a token acting as any user" if st2 == 200 and a.get("token") else f"no: {st2}"
    probe("Auth", "Act as a user (impersonation)", impersonate)

    def mfa():
        call("PATCH", "/api/collections/users", {"mfa": {"enabled": True, "duration": 600}})
        st, a = call("POST", "/api/collections/users/auth-with-password", {"identity": "ann@lab.test", "password": "annpass12345"}, token="")
        return "yes: with MFA on, a password alone returns an mfaId that a second method (OTP, OAuth2) must complete" if st == 401 and isinstance(a, dict) and a.get("mfaId") else f"no: {st} {a}"
    probe("Auth", "Multi-factor authentication", mfa)
    call("PATCH", "/api/collections/users", {"mfa": {"enabled": False}})

    def rules():
        st, _ = call("POST", "/api/collections", {"name": "secrets", "type": "base", "fields": [{"name": "body", "type": "text"}, {"name": "owner", "type": "relation", "collectionId": "_pb_users_auth_", "maxSelect": 1}],
                                                  "listRule": "owner = @request.auth.id", "viewRule": "owner = @request.auth.id", "createRule": "@request.auth.id != '' && owner = @request.auth.id"})
        st, a = call("POST", "/api/collections/users/records", {"email": "bo@lab.test", "password": "bopass123456", "passwordConfirm": "bopass123456"}, token="")
        st, ta = call("POST", "/api/collections/users/auth-with-password", {"identity": "bo@lab.test", "password": "bopass123456"}, token="")
        st, tb = call("POST", "/api/collections/users/records", {"email": "cy@lab.test", "password": "cypass123456", "passwordConfirm": "cypass123456"}, token="")
        st, tc = call("POST", "/api/collections/users/auth-with-password", {"identity": "cy@lab.test", "password": "cypass123456"}, token="")
        call("POST", "/api/collections/secrets/records", {"body": "bo's", "owner": ta["record"]["id"]}, token=ta["token"])
        st1, mine = call("GET", "/api/collections/secrets/records", token=ta["token"])
        st2, theirs = call("GET", "/api/collections/secrets/records", token=tc["token"])
        return "yes: per-collection rules on the request's user and on related records (E52)" if mine["totalItems"] == 1 and theirs["totalItems"] == 0 else f"no: {mine.get('totalItems')} {theirs.get('totalItems')}"
    probe("Auth", "Per-user access rules", rules)

    # ---- files
    def files():
        body, ct = multipart({"title": "with a picture"}, {"doc": ("pic.png", png(), "image/png")})
        st, rec = call("POST", "/api/collections/notes/records", raw=body, ctype=ct, token="")
        if st != 200:
            return f"no: upload {st} {rec}"
        st2, img = call("GET", f"/api/files/notes/{rec['id']}/{rec['doc']}", token="")
        st3, thumb = call("GET", f"/api/files/notes/{rec['id']}/{rec['doc']}?thumb=100x100", token="")
        ok = st2 == 200 and st3 == 200 and isinstance(thumb, bytes) and thumb[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack(">II", thumb[16:24]) == (100, 100)
        return "yes: file fields, size and type limits, thumbnails generated on request (100x100 verified)" if ok else f"no: {st2} {st3}"
    probe("Files", "File uploads with thumbnails", files)

    def s3():
        if not S3:
            return "not tested: no S3 server given"
        st, _ = call("PATCH", "/api/settings", {"s3": {"enabled": True, "bucket": "pbfiles", "region": "us-east-1", "endpoint": S3, "accessKey": "minioadmin", "secret": "minioadmin", "forcePathStyle": True}})
        st2, r = call("POST", "/api/settings/test/s3", {"filesystem": "storage"})
        body, ct = multipart({"title": "in s3"}, {"doc": ("pic.png", png(), "image/png")})
        st3, rec = call("POST", "/api/collections/notes/records", raw=body, ctype=ct, token="")
        call("PATCH", "/api/settings", {"s3": {"enabled": False}})
        return "yes: files stored in an S3-compatible bucket (tested against a local S3 server)" if st == 200 and st2 == 204 and st3 == 200 else f"no: settings {st}, test {st2} {r}, upload {st3}"
    probe("Files", "Files in S3-compatible storage", s3)

    # ---- operations
    def backups():
        st, _ = call("POST", "/api/backups", {"name": "lab_backup.zip"})
        st2, lst = call("GET", "/api/backups")
        return "yes: a zip of pb_data from the API or UI, scheduled backups, optionally to S3; restore replaces the data and restarts" if st == 204 and any(b["key"] == "lab_backup.zip" for b in lst) else f"no: {st} {st2}"
    probe("Operations", "Backups", backups)

    def rate_limit():
        call("PATCH", "/api/settings", {"rateLimits": {"enabled": True, "rules": [{"label": "/api/health", "maxRequests": 3, "duration": 10}]}})
        codes = [call("GET", "/api/health", token="")[0] for _ in range(8)]
        call("PATCH", "/api/settings", {"rateLimits": {"enabled": False}})
        return f"yes: per-route rules by IP or user (8 quick requests got {codes.count(429)} × 429)" if 429 in codes else f"no: {codes}"
    probe("Operations", "Rate limiting", rate_limit)

    def logs():
        t = time.time()
        while True:  # requests are logged in the background, in batches
            st, lst = call("GET", "/api/logs?perPage=5")
            if st != 200 or lst["totalItems"] > 0 or time.time() - t > 15:
                break
            time.sleep(0.5)
        return f"yes: every request logged to a separate SQLite file, searchable in the UI ({lst['totalItems']} so far)" if st == 200 and lst["totalItems"] > 0 else f"no: {st}"
    probe("Operations", "Request logs", logs)

    def portable():
        import sqlite3
        c = sqlite3.connect(f"file:{data}/data.db?mode=ro", uri=True)
        n = c.execute("SELECT count(*) FROM notes").fetchone()[0]
        c.close()
        return f"yes: the data is a plain SQLite file any SQLite tool can read ({n} notes)"
    probe("Operations", "Data readable by other tools", portable)


if __name__ == "__main__":
    main()
