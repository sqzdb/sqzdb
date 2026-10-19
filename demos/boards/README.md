# Boards: a multi-tenant task board on sqzdb

A small Trello-style app in Go. Organizations sign in, each sees only its own boards and cards, and
changes show up live in every browser of the same organization.

The point of the demo is where the tenant rule lives. It is in the database, not in handler code:

```sql
CREATE ROLE member;
GRANT SELECT, INSERT, UPDATE, DELETE ON cards TO member;
CREATE POLICY org_cards ON cards FOR ALL TO member USING (org_id = SESSION.org);
```

Every request runs as the signed-in member (`session.Assume(["member"], {org, user})`), so a handler
that forgets a `WHERE org_id = ?` still cannot read or change another organization's rows. Live
updates are one change subscription per organization, fanned out to that organization's browsers
over server-sent events. The subscription runs under the same identity, so it carries the same rule.

## Run it

```sh
cargo build --release                       # builds target/release/libsqzdb.so, which the Go binding links
cd demos/boards
go run . -dir ./data -addr 127.0.0.1:8070   # then open http://127.0.0.1:8070
```

The first start creates the schema and three sample organizations. Sign in as two people from
different organizations in two windows to see the isolation, and as two people from the same
organization to see live updates.

Sign-in is a stand-in for OAuth: the server signs a short token with the user and organization. A
real app would put the same two values in the session after its OAuth callback.

## Benchmark against PocketBase

`bench/` runs the same workloads against this server and against PocketBase 0.40.5 set up the same
way: collections, `org = @request.auth.org` rules, indexes, 10 organizations × 20 members.

```sh
go build -o /tmp/boards . && go build -o /tmp/boards-bench ./bench
/tmp/boards -dir /tmp/boards-data -bench-seed 10,20 &
/tmp/boards-bench -target sqzdb -url http://127.0.0.1:8070 -pid $!      # -pid: the server, for its memory and CPU

pocketbase superuser upsert admin@bench.test benchpass123 --dir /tmp/pb_data
pocketbase serve --http 127.0.0.1:8090 --dir /tmp/pb_data &
/tmp/boards-bench -target pocketbase -url http://127.0.0.1:8090 -pid $! -setup [-no-request-log]
```

`-fill 200000` adds exactly that many cards instead of running the workloads, for the memory and disk
comparison.

Results on the lab machine (Ryzen 5 9600X, NVMe under btrfs). Each server ran twice from an empty
directory, and PocketBase also ran twice with its request log off. Neither server fsyncs each commit.
The full output is in [`results/e52_boards_vs_pocketbase.txt`](../../results/e52_boards_vs_pocketbase.txt).

| | sqzdb | PocketBase | PocketBase, request log off |
|---|---:|---:|---:|
| Add a card, 1 client | 21,500/s | 2,900–3,000/s | 3,130–3,170/s |
| Add a card, 64 clients | 100,300–100,700/s, p99 3.2 ms | 7,970–8,070/s, p99 35 ms | 9,070–9,190/s, p99 30–32 ms |
| List a 100-card board, 64 clients | 14,900–15,100/s, p99 16–17 ms | 5,180–5,360/s, p99 40–43 ms | 5,440–5,480/s, p99 44 ms |
| Live update to 200 browsers | p50 0.5 ms, p99 1.1–1.2 ms, CPU 6% | p50 8.3 ms, p99 19–21 ms, CPU 200% | p50 8.4–8.6 ms, p99 46 ms, CPU 195–198% |
| Live update to 1,000 browsers | p50 1.1–1.2 ms, p99 2.3–2.6 ms, CPU 13–14% | p50 32–33 ms, p99 73–80 ms, CPU 740% | p50 33 ms, p99 83–84 ms, CPU 720–730% |
| Cards actually written in the 1,000-browser test (target 1,600) | 1,600 | 1,113–1,125 | 1,109–1,111 |
| 200,000 cards: time to add, 16 clients | 1.9 s | 24.3 s | 21.3 s |
| 200,000 cards: server memory | 102 MB | 205 MB | 115 MB |
| 200,000 cards: disk | 63 MB after its snapshot (60 MB of log before) | 139 MB (45 MB data + 84 MB request log) | 50 MB |

Every live event reached every subscriber on both servers, and no subscriber ever saw another
organization's card.

What to keep in mind when reading this:

- The sqzdb side is a hand-written Go server with prepared statements. PocketBase is a whole
  framework (rule engine, request log, admin UI, generic REST), and that framework is part of what
  you measure.
- The live fan-out differs by design: one database subscription per organization here, against a rule
  check per connected client in PocketBase. That design difference is a large part of the gap.
- PocketBase's disk is smaller once its request log is off: 45 MB of SQLite data against 63 MB for the
  sqzdb snapshot.
- Something PocketBase does that sqzdb does not yet: a rule can follow a relation
  (`board.org = @request.auth.org`). A sqzdb policy compares a row's own columns with the session,
  so this server checks that the board is visible to the member before it inserts a card.
