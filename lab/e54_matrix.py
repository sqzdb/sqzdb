"""E54: builds results/e54_features.md from the probe outputs (results/e54_features_*.tsv) and the product rows below.

    python3 -I lab/e54_matrix.py results
"""
import csv, sys

R = sys.argv[1]
PARTIAL = ["only", "after PRAGMA", "experimental", "not bare", "must be selected", "without a derived table", "needs a FROM", "ignores case",
           "not inside", "correlated only", "MVCC journal mode", "with CHECK", "no derived table", "declared maximum"]


def tsv(name):
    with open(f"{R}/{name}") as f:
        return list(csv.reader(f, delimiter="\t"))[1:]


def mark(cell):
    kind, _, note = cell.partition(": ")
    note = note.strip()
    if kind == "yes":
        if not note:
            return "✅"
        return ("⚠️ " if any(p in note for p in PARTIAL) else "✅ ") + note
    if kind == "wrong":
        return "⛔ " + note
    if kind == "partial":
        return "⚠️ " + note
    return "❌ " + (note[:90] + "…" if len(note) > 90 else note)


sql = tsv("e54_features_sql.tsv")
pb = {r[1]: r[2] for r in tsv("e54_features_pocketbase.tsv")}
extra = {r[1]: r[2:] for r in tsv("e54_features_extras.tsv")}


def tally(col):
    c = {"✅": 0, "⚠️": 0, "⛔": 0, "❌": 0}
    for r in sql:
        c[mark(r[col]).split(" ")[0]] += 1
    return c


def pbm(feature):
    return mark(pb[feature])


def ex(feature, i):
    return mark(extra[feature][i])


# product rows: (category, feature, pocketbase, sqzdb, sqlite, turso). Probed cells come from the TSVs; the rest cite
# the experiment that measured them, or are marked 📄 when only the documentation says so.
PRODUCT = [
    ("Backend", "Admin UI", pbm("Admin UI"), "✅ web console: SQL editor, tables, change feed, access, backup (E43, E51)", "❌ third-party tools", "❌ locally; 📄 Turso Cloud dashboard"),
    ("Backend", "REST API for each table, no code", pbm("REST API generated for each table"), "❌ the app writes its endpoints (the console's SQL endpoint is for admins)", "❌", "❌ locally; 📄 Turso Cloud has an HTTP SQL API"),
    ("Backend", "Server-side code (hooks, custom routes)", pbm("Server-side code (hooks, custom routes)"), "⚠️ the app embeds the database; no triggers or hooks inside it", "⚠️ triggers, functions registered by the app", "⚠️ triggers"),
    ("Backend", "Scheduled jobs (cron)", pbm("Scheduled jobs (cron)"), "❌", "❌", "❌"),
    ("Backend", "Filter, sort, page and expand relations over HTTP", pbm("Filtering, sorting and paging through the API") + "; " + pbm("Expand relations in one request").replace("✅ ", ""), "— SQL through a binding or TCP", "— SQL", "— SQL"),
    ("Backend", "SQL views", pbm("SQL views as API collections"), "❌ (E54 SQL)", "✅", "✅"),
    ("Backend", "Transactions", pbm("Transactions through the API (batch)"), "⚠️ BEGIN/COMMIT; no savepoints; only lookups by primary key see the transaction's own writes, other reads of a table it wrote are refused", "✅", "✅"),
    ("Backend", "Schema as code (migrations, export/import)", pbm("Migration files") + "; " + pbm("Export and import the schema").replace("✅ ", ""), "⚠️ online ALTER with writers running (E30); no migration files", "❌ external tools", "❌ external tools"),
    ("Auth", "Email and password sign-in", pbm("Email and password sign-in"), "❌ the app signs users in and passes their identity per request (E49)", "❌", "❌"),
    ("Auth", "OAuth2 (Google, GitHub, …)", pbm("OAuth2 sign-in (Google, GitHub, …)"), "❌", "❌", "❌"),
    ("Auth", "Email verification, password reset, one-time codes", "✅ verification link, reset link and OTP all received and completed through a local mail server", "❌", "❌", "❌"),
    ("Auth", "Multi-factor authentication", pbm("Multi-factor authentication"), "❌", "❌", "❌"),
    ("Auth", "Act as a user", pbm("Act as a user (impersonation)"), "⚠️ the app passes any identity per request (Assume)", "—", "—"),
    ("Auth", "Per-user access rules", pbm("Per-user access rules"), "⚠️ roles, grants and row policies enforced in the engine (E16, E49); a policy cannot follow a relation (E52)", "❌", "❌"),
    ("Files", "File uploads with thumbnails", pbm("File uploads with thumbnails"), "❌ BLOB columns need a declared maximum (≤ 64 KB); no file API", "⚠️ BLOBs up to 1 GB; no file API", "⚠️ BLOBs; no file API"),
    ("Files", "Files in S3-compatible storage", pbm("Files in S3-compatible storage"), "❌", "❌", "❌"),
    ("Realtime", "Push changes to browsers", "✅ SSE subscriptions with rules (E52)", "⚠️ subscriptions in the engine; the app relays them (E39 example, E52 demo)", "❌", "❌"),
    ("Realtime", "Change notifications in the process", "⚠️ record events in hooks", ex("Change notifications in the process", 0), ex("Change notifications in the process", 1), ex("Change notifications in the process", 2)),
    ("Realtime", "Resumable change feed", "❌", "✅ by log sequence (E32)", "❌", "⚠️ turso_cdc table (E54 SQL)"),
    ("Scale", "Many concurrent writers", "❌ one SQLite writer: 8–9k inserts/s (E52)", "✅ 132–166k durable commits/s at 256 writers (E50)", "❌ one writer at a time: 2.3k durable commits/s at any count (E50)", "✅ experimental MVCC: 107–118k at 256 (E50)"),
    ("Scale", "A database per tenant or agent", "⚠️ a process per tenant: 35 MB each (E53)", "✅ 100 KB per open database, 0.23 ms to create (E38, E53)", "✅ a file each: 188 KB open (E53)", "✅ a file each: 0.9–1.2 MB open (E53)"),
    ("Scale", "Access from other processes", "— over HTTP", "✅ through the owner process: Unix socket, shared memory, TCP (E40)", "✅ file locking", "📄 experimental multi-process WAL"),
    ("Scale", "Network access", "✅ HTTP", "✅ TCP with a token, and the console (E40)", "❌", "📄 Turso Cloud, or a server"),
    ("Search", "Full-text search", "⚠️ filter ~ is a LIKE '%…%' scan; no index or ranking", "❌ (E54 SQL)", "✅ FTS5 with bm25", "⚠️ experimental fts index with scores"),
    ("Search", "Vector similarity", "❌", "❌", "❌ without an extension; 📄 sqlite-vec", "✅ vector functions; ⚠️ only an experimental sparse index"),
    ("Operations", "Backups", pbm("Backups"), "✅ continuous to S3, compressed, optionally encrypted (E33, E35)", "⚠️ backup API; continuous only with Litestream (E33)", "⚠️ VACUUM INTO; 📄 continuous in Turso Cloud"),
    ("Operations", "Point-in-time restore", "❌ restore a whole backup", "✅ (E26)", "❌; 📄 Litestream", "📄 Turso Cloud"),
    ("Operations", "Read replicas", "❌", "✅ followers from a directory or a bucket (E26, E42)", "❌; 📄 LiteFS", "📄 embedded replicas synced with Turso Cloud"),
    ("Operations", "Online copy of a live database", "✅ backup zip", ex("Online copy of a live database", 0), ex("Online copy of a live database", 1), ex("Online copy of a live database", 2)),
    ("Operations", "Encryption of the database files", "❌ only its settings (--encryptionEnv)", ex("Encryption of the database files", 0), ex("Encryption of the database files", 1), ex("Encryption of the database files", 2)),
    ("Operations", "Rate limiting", pbm("Rate limiting"), "—", "—", "—"),
    ("Operations", "Request logs", pbm("Request logs"), "❌", "—", "—"),
    ("Operations", "Data readable by other tools", pbm("Data readable by other tools"), ex("Data readable by other tools", 0), ex("Data readable by other tools", 1), ex("Data readable by other tools", 2)),
    ("Platform", "Languages", "📄 JS and Dart SDKs; any HTTP client", "✅ Node, Python, Go, C, Rust (E36)", "📄 nearly every language", "✅ Rust (tested); 📄 JS, Python, Go, Java"),
    ("Platform", "Browser (WebAssembly)", "—", "❌", "📄 official WASM build", "📄 WASM build"),
    ("Platform", "Inside a mobile app", "—", "❌", "📄 built into iOS and Android", "📄 mobile SDKs"),
    ("Platform", "Operating systems", "📄 Linux, macOS, Windows, FreeBSD", "✅ Linux and macOS (x64, arm64); ❌ Windows", "📄 all", "📄 Linux, macOS, Windows"),
    ("Platform", "One binary to run a server", "✅", "✅ sqzdb serve", "❌", "📄 tursodb"),
]


def table(rows, head):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        out.append("| " + " | ".join(c.replace("|", "\\|") for c in r) + " |")
    return "\n".join(out)


def count(col):
    c = {"✅": 0, "⚠️": 0, "⛔": 0, "❌": 0, "📄": 0, "—": 0}
    for r in PRODUCT:
        c[r[col].split(" ")[0].rstrip(";")] = c.get(r[col].split(" ")[0].rstrip(";"), 0) + 1
    return c


ts = {n: tally(i) for n, i in (("sqzdb", 2), ("SQLite", 3), ("Turso", 4))}
pc = {n: count(i) for n, i in (("PocketBase", 2), ("sqzdb", 3), ("SQLite", 4), ("Turso", 5))}
WHY = {
    "Text longer than 64 KB": "`VARCHAR(100000)` is accepted, but a 100,000-byte value comes back different from what was inserted (its length is kept in two bytes).",
    "A JSON column rejects malformed JSON": "`CHECK (json_valid(doc))` is accepted and never enforced (the same cause as CHECK).",
    "CHECK constraint": "accepted by CREATE TABLE and never enforced: `age = -5` was inserted.",
    "Generated columns": "`GENERATED ALWAYS AS (a * 2)` is accepted; the column reads NULL.",
    "GROUP BY with HAVING": "HAVING is ignored: every group comes back.",
    "ORDER BY two columns": "only the first ORDER BY column sorts; the second is ignored.",
    "LIMIT with OFFSET": "OFFSET is ignored: the first rows come back.",
    "SELECT DISTINCT": "DISTINCT is ignored: 3 rows instead of 2.",
    "COUNT(DISTINCT …)": "duplicates are counted: 3 instead of 2.",
    "UPDATE … RETURNING": "RETURNING is ignored on UPDATE: no rows come back.",
    "A transaction sees its own writes": "a read inside a transaction does not see the rows the transaction wrote (documented in the README).",
}
wrong = [(r[0], r[1], WHY.get(r[1], r[2])) for r in sql if r[2].startswith("wrong")]
try:  # the first run, before unimplemented SQL was refused (H63)
    first = [(r[0], r[1], WHY.get(r[1], r[2])) for r in tsv("e54_features_sql_before_h63.tsv") if r[2].startswith("wrong")]
except FileNotFoundError:
    first = []

doc = f"""# Feature matrix: sqzdb, PocketBase 0.40.5, SQLite 3.53.4, Turso 0.8.3

Every cell comes from a probe run on the lab machine (E54), from an earlier experiment it names, or is marked 📄 when
only the product's documentation says so. ✅ works · ⚠️ partial, or only behind a setting · ⛔ runs but gives a wrong
answer · ❌ missing · 📄 documented, not tested here · — not applicable.

Sources: `src/bin/e54_features.rs` (SQL probes, each on a fresh database, and the engine extras), `lab/e54_pocketbase.py`
(PocketBase through its HTTP API, with a local mail server and S3 server), raw output in `results/e54_features_*.tsv`.
Turso is tried with its default build first, then with its experimental features switched on.

## In numbers

| SQL features ({len(sql)}) | ✅ | ⚠️ | ⛔ wrong | ❌ |
|---|---:|---:|---:|---:|
""" + "\n".join(f"| {n} | {c['✅']} | {c['⚠️']} | {c['⛔']} | {c['❌']} |" for n, c in ts.items()) + f"""

| Product features ({len(PRODUCT)}) | ✅ | ⚠️ | ❌ | 📄 | — |
|---|---:|---:|---:|---:|---:|
""" + "\n".join(f"| {n} | {c.get('✅', 0)} | {c.get('⚠️', 0)} | {c.get('❌', 0)} | {c.get('📄', 0)} | {c.get('—', 0)} |" for n, c in pc.items()) + """

PocketBase's SQL is SQLite's (it runs on SQLite), reachable through view collections and hooks rather than its REST API.

## Wrong answers without an error (sqzdb)

""" + ("These run and return a result, but not the right one.\n\n" + "\n".join(f"- **{f}**: {n}" for c, f, n in wrong) if wrong else
       "None now. The first run (`results/e54_features_sql_before_h63.tsv`) found the cases below. Each now fails with `SYNTAX` "
       "(\"unsupported: … is not implemented yet\") or, for the transaction, `TRANSACTION`, and SQL that is not implemented is "
       "refused rather than ignored.\n\n" + "\n".join(f"- ~~**{f}**: {n}~~ now an error" for c, f, n in first)) + """

## Product features

""" + table(PRODUCT, ["", "Feature", "PocketBase", "sqzdb", "SQLite", "Turso"]) + """

## SQL features

""" + table([(r[0], r[1], mark(r[2]), mark(r[3]), mark(r[4])) for r in sql], ["", "Feature", "sqzdb", "SQLite", "Turso"]) + "\n"

open(f"{R}/e54_features.md", "w").write(doc)
print(f"wrote {R}/e54_features.md: {len(sql)} SQL rows, {len(PRODUCT)} product rows")
for n, c in ts.items():
    print("SQL", n, c)
for n, c in pc.items():
    print("product", n, c)
