# Agents: a database per AI agent on sqzdb

Each agent gets its own sqzdb database: a directory holding that agent's memories. An agent's
database is created on first use and stays open while the agent works. It is closed when the agent
goes idle or when too many are open, and opened again from disk when the agent wakes up. Forgetting
an agent deletes its directory, so nothing of it stays behind in a shared table.

This is the model Turso is now selling as "databases for AI agents" (one SQLite file per agent).
Here it runs in one Go process.

## Run it

```sh
cargo build --release                        # builds target/release/libsqzdb.so, which the Go binding links
cd demos/agents
go run . -dir ./agents -addr 127.0.0.1:8071  # then open http://127.0.0.1:8071
```

| Flag | Default | |
|---|---|---|
| `-max-open` | 2000 | Agents kept open at once; the least recently used beyond this are closed |
| `-idle` | 2m | Close an agent nobody has used for this long |
| `-body-max` | 2000 | Longest memory in bytes, for agents created from now on (see the costs below) |

The page lists agents (a green dot means open). It shows server memory, open agents and memories
written per second. **Spawn 1,000** creates a thousand agents with five memories each, and
**Run swarm** sets random agents writing and recalling for 15 seconds.

## API

| | |
|---|---|
| `POST /api/agents` `{name?}` | Create an agent (a new database directory); returns its name and how long that took |
| `POST /api/agents/{name}/memories` `{kind, body}` | Remember something |
| `GET /api/agents/{name}/memories?limit=10&q=word` | Recall the newest memories, optionally only those that mention a word |
| `GET /api/agents/{name}` | Memory count, bytes on disk, and whether this request had to open it from disk |
| `DELETE /api/agents/{name}` | Forget the agent: close its database and delete its directory |
| `GET /api/stats` | Agents on disk and open, opens, evictions, server memory |

Each database opens with `log.threadsIdleAfter = 300ms`, so an idle agent holds no threads, and
`log.syncDelay = 1s`, so one fsync per second covers an agent's writes. A crash of the machine (not
of this process) can lose at most the last second of memories.

## Benchmarks

Two benchmarks, both on the lab machine (Ryzen 5 9600X, NVMe under btrfs):

- **The engines** ([`src/bin/e53_agents.rs`](../../src/bin/e53_agents.rs),
  [`results/e53_agents.txt`](../../results/e53_agents.txt)): 10,000 agents in one process on
  sqzdb's tenant host, SQLite and Turso 0.8.3 (a file per agent), and PocketBase as one process per
  agent, the way PocketHost isolates tenants.
- **This server over HTTP** (`bench/`, [`results/e53_agents_http.txt`](../../results/e53_agents_http.txt)):
  against PocketBase 0.40.5 built the way you would build it there, with one shared `memories`
  collection and an indexed `agent` field.

```sh
cargo run --release --features lab --bin e53_agents          # the engines (PocketBase from tools/pocketbase-0.40.5)

go build -o /tmp/agents . && go build -o /tmp/agents-bench ./bench
/tmp/agents -dir /tmp/agents-data &
/tmp/agents-bench -target sqzdb -url http://127.0.0.1:8071 -pid $! -dir /tmp/agents-data
pocketbase superuser upsert admin@bench.test benchpass123 --dir /tmp/pb_data
pocketbase serve --http 127.0.0.1:8090 --dir /tmp/pb_data &
/tmp/agents-bench -target pocketbase -url http://127.0.0.1:8090 -pid $! -dir /tmp/pb_data -setup [-no-request-log]
```

### The engines: 10,000 agents in one process

Each agent creates its database, defines a table, writes 20 memories one at a time and reads back
the newest 10. Then every agent stays open while memory is measured. Then 8 threads pick random
agents to write one memory and read the newest 10 ("steps"). Finally closed agents are reopened. Two
runs each; every phase starts after a `sync()` and a pause. SQLite and Turso run with
`synchronous=OFF`, so they never fsync. sqzdb doesn't wait for fsync either, but by default it
fsyncs every write in the background at once; the second sqzdb column uses `log.syncDelay = 1s`.

| | sqzdb | sqzdb, `syncDelay 1s` | SQLite 3.53 | Turso 0.8.3 | PocketBase, a process per agent |
|---|---:|---:|---:|---:|---:|
| Create an agent | 232–243 µs | 274–284 µs | 251–253 µs | 1.8–1.9 ms | 43–44 ms to start |
| Memory per open agent | 99–101 KB | 149–154 KB | 188 KB | 865–1,201 KB | 35 MB idle, empty |
| Disk per agent, 20 memories | 16 KB | 16 KB | 128 KB while open | 96 KB | 1.1 MB, empty |
| Agent steps per second, 8 threads | 32,300–42,700 | **92,700–101,000** | 52,700–54,300 | 50,300–55,700 (each thread owns an eighth of the agents) | — |
| Reopen a closed agent and read 10 | 175–181 µs | 202–206 µs | **73–74 µs** | 195–812 µs | — |

PocketBase's row is what isolating each agent in its own PocketBase costs: 10,000 agents would need
about 340 GB of memory.

### This server over HTTP, against PocketBase

2,000 agents with 20 memories each, written by 16 clients. Then random agents write a memory and
recall their newest 10. Then 100 agents are forgotten. Forgetting means deleting a directory here;
in PocketBase it means listing the agent's records and deleting each one, because its API has no
delete by filter. Two runs each.

| | sqzdb | sqzdb, at most 200 open | sqzdb, `-body-max 256` | PocketBase | PocketBase, request log off |
|---|---:|---:|---:|---:|---:|
| Spawn 2,000 agents | 0.54–0.55 s | 0.57–0.59 s | 0.50–0.51 s | 2.7–3.5 s | 2.3 s |
| Steps per second, 8 clients | 21,100–21,500 | 5,300–5,400 | 24,500–24,600 | 6,800–7,000 | 7,000–8,400 |
| Steps per second, 64 clients | 25,700–30,500 | 6,600–7,200 | 33,200–38,500 | 3,800–7,100 | 8,600 |
| p99 of a step, 64 clients | 6–8 ms | 20–26 ms | 5–7 ms | 40–228 ms | 32 ms |
| Forget an agent (p50) | 0.3–0.8 ms | 0.6 ms | 0.2–0.7 ms | 7.4–10.6 ms | 8.5–9.0 ms |
| Server memory at the end | **1.8–1.9 GB** | 126–139 MB | 359–375 MB | 174–206 MB | 111–113 MB |
| Disk at the end | **782–859 MB** | 441–460 MB | 154–165 MB | 148–184 MB | 42–45 MB |

No agent ever got another agent's memories back, on either server.

### What this says, plainly

- **Isolation is cheap here.** Creating an agent takes a quarter of a millisecond, an open agent costs
  about 100 KB, and forgetting one is a directory delete that takes under a millisecond. In PocketBase
  the choice is a shared table, where forgetting means deleting records one at a time, or a process
  per agent at 35 MB each.
- **Memory text is expensive.** sqzdb rows are fixed width: a `VARCHAR(2000)` memory takes 2 KB in
  memory and in the log whatever its length. The end-of-run figures don't hold the same data: being
  faster, sqzdb wrote about 450,000 memories of about 90 bytes, PocketBase about 150,000. Per
  memory that is roughly 4 KB of server memory for sqzdb against 0.7–1.4 KB for PocketBase, and
  0.7 KB for sqzdb with `-body-max 256`. Variable-length text is the biggest gap for this use case.
- **There is no text search.** `LIKE` and full-text search don't exist yet, so recall by word scans the
  agent's newest 5,000 memories in Go. Turso pitches vector search for agents, and sqzdb has none.
- **Many small databases on one disk are bound by fsync.** By default every write gets its own
  background fsync, and with 10,000 agents those can't be shared. `log.syncDelay` lets one fsync
  cover a second of an agent's writes, which gives two to three times the throughput.
- **SQLite reopens a file faster:** 73 µs against 175 µs.
- **Opening is where the cost is when most agents sleep.** With at most 200 of 2,000 open, almost every
  step opens one agent and closes another, and every close is an fsync. That runs at PocketBase's speed, and
  each reopen leaves one small log file until a snapshot compacts them (46–53 per agent here).
