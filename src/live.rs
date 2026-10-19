//! Reactive layer (E37): filtered change subscriptions with the subscriber's row policies applied to every event, and
//! live queries kept fresh by invalidation. One reactor thread per database reads the in-process change ring, evaluates
//! compiled predicates on the raw row bytes, and pushes events into bounded per-subscriber queues. Writers never wait.
use crate::sql::{Access, Change, ChangeOp, Cmp, CPred, Expr, Plan, Pred, Prepared, Proj, SelectPlan, Session, Sql, P_SELECT};
use crate::table::{decode_col, read_key, ColType, Value, OP_DELETE, OP_INSERT, OP_UPDATE};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Event {
    /// One decoded change, shared by every subscriber it reaches.
    Change(Arc<Change>),
    /// A watched query's result changed: the whole new result, plus the rows that appeared and disappeared (by first column when it is the key).
    Live { seq: u64, rows: Vec<Vec<Value>>, added: Vec<Vec<Value>>, removed: Vec<Vec<Value>> },
    /// The subscriber fell more than `cap` events behind and was dropped; resubscribe (a feed from `last_seq` recovers everything).
    Overflow { last_seq: u64 },
}
pub struct Queue { items: Mutex<VecDeque<Event>>, cv: Condvar, cap: usize, pub closed: AtomicBool, pub delivered: AtomicU64, waker: Mutex<Option<Wake>> }
impl Queue {
    fn push(&self, e: Event) -> bool {
        { let mut q = self.items.lock().unwrap(); if q.len() >= self.cap { return false; } q.push_back(e); self.delivered.fetch_add(1, Ordering::Relaxed); self.cv.notify_one(); }
        if let Some(w) = self.waker.lock().unwrap().as_ref() { w(); }
        true
    }
    fn new(cap: usize) -> Queue { Queue { items: Mutex::new(VecDeque::new()), cv: Condvar::new(), cap, closed: AtomicBool::new(false), delivered: AtomicU64::new(0), waker: Mutex::new(None) } }
}
/// How long the reactor waits for writes it has read to finish publishing before re-running anyway (and again later).
const SETTLE_WAIT: Duration = Duration::from_micros(200);
const SETTLE_RETRY: Duration = Duration::from_millis(1);
/// Called on every event of the subscriptions it is set on: one waiter for many of them (a connection's live queries).
pub type Wake = Arc<dyn Fn() + Send + Sync>;
/// A subscriber's handle: pop events; dropping it unsubscribes.
pub struct Subscription { pub q: Arc<Queue> }
impl Subscription {
    /// Wake `w` on every event from now on (events already queued are found by the next `try_recv`).
    pub fn set_waker(&self, w: Wake) { *self.q.waker.lock().unwrap() = Some(w.clone()); if !self.q.items.lock().unwrap().is_empty() { w(); } }
    pub fn try_recv(&self) -> Option<Event> { self.q.items.lock().unwrap().pop_front() }
    pub fn recv_timeout(&self, d: Duration) -> Option<Event> { let mut q = self.q.items.lock().unwrap(); if q.is_empty() { let (g, _) = self.q.cv.wait_timeout(q, d).unwrap(); q = g; } q.pop_front() }
    pub fn pending(&self) -> usize { self.q.items.lock().unwrap().len() }
}
impl Drop for Subscription { fn drop(&mut self) { self.q.closed.store(true, Ordering::Relaxed); } }

/// `since`: the log position when the subscription was made; it receives exactly the changes committed after it.
struct Sub { table: u16, preds: Vec<CPred>, policies: Vec<CPred>, q: Arc<Queue>, key: Option<(usize, i64)>, since: u64,
    /// For a session from a sign-in token: its identity, checked again whenever sign-in state changes.
    ident: Option<Session> }
struct Live { prepared: Arc<Prepared>, sess: Session, params: Vec<Value>, tables: Vec<u16>, single: Option<(u16, Vec<CPred>, Vec<CPred>)>, key_col: Option<(usize, ColType)>, result: Vec<Vec<Value>>, keys: HashSet<crate::table::Key>, dirty_since: Option<Instant>, last_run: Option<Instant>,
    /// its last re-run started while writes were still publishing, so it runs again (at least SETTLE_RETRY later)
    retry: bool, q: Arc<Queue> }
impl Live {
    /// When a changed live query runs again: at once if it hasn't run within `debounce`, else `debounce` after its
    /// last run. A lone write is seen without waiting; a burst costs one re-run per `debounce`.
    fn due(&self, debounce: Duration) -> Option<Instant> {
        let d = self.dirty_since?; let gap = if self.retry { debounce.max(SETTLE_RETRY) } else { debounce };
        Some(self.last_run.map_or(d, |r| d.max(r + gap)))
    }
}
/// Subscriptions whose filter is `col = constant` on an INT column are indexed by (table, column, value): a record
/// reaches them through one hash lookup per indexed column instead of a scan over every subscriber.
#[derive(Default)] struct State { subs: Vec<Sub>, lives: Vec<Live>, keyed: HashMap<(u16, usize, i64), Vec<usize>>, key_cols: HashMap<u16, Vec<usize>>, general: HashMap<u16, Vec<usize>> }
impl State {
    fn reindex(&mut self) { self.keyed.clear(); self.key_cols.clear(); self.general.clear(); for (i, s) in self.subs.iter().enumerate() { match s.key { Some((c, v)) => { self.keyed.entry((s.table, c, v)).or_default().push(i); let cols = self.key_cols.entry(s.table).or_default(); if !cols.contains(&c) { cols.push(c); } } None => self.general.entry(s.table).or_default().push(i) } } }
}
/// Holds the database weakly: the database owns its reactor, and a reactor that owned the database back would keep
/// it alive forever after the first subscription (E44).
pub struct Reactor { sql: std::sync::Weak<Sql>, log: Arc<crate::table::GLog>, state: Arc<Mutex<State>>, pub debounce: Duration, pub reruns: AtomicU64, pub rerun_us: AtomicU64, pub events: AtomicU64, pub last_seq: AtomicU64, stop: Arc<AtomicBool>, thread: Mutex<Option<std::thread::JoinHandle<()>>> }

fn session_like(s: &Session) -> Session { Session { txn: None, user: s.user.clone(), roles: s.roles.clone(), attrs: s.attrs.clone(), assumed: s.assumed, last_seq: 0, last_insert_id: 0, last_insert_key: None, token: s.token.clone() } }
/// The predicates a single-table plan applies, including the ones hidden in its access path.
fn plan_preds(sql: &Sql, sess: &Session, sp: &SelectPlan, params: &[Value]) -> Result<Vec<CPred>, String> {
    let mut preds: Vec<Pred> = sp.preds.clone(); let sch = &sp.table.schema;
    match &sp.access {
        Access::Pk(e) => preds.push(Pred { col: sch.pk, cmp: Cmp::Eq, rhs: e.clone() }),
        Access::Unique(e) => { if let Some(u) = sch.unique { preds.push(Pred { col: u, cmp: Cmp::Eq, rhs: e.clone() }); } }
        Access::Range { lo, lo_excl, hi, hi_excl } => { preds.push(Pred { col: sch.pk, cmp: if *lo_excl { Cmp::Gt } else { Cmp::Ge }, rhs: lo.clone() }); preds.push(Pred { col: sch.pk, cmp: if *hi_excl { Cmp::Lt } else { Cmp::Le }, rhs: hi.clone() }); }
        Access::Index(ix, e) => preds.push(Pred { col: ix.col, cmp: Cmp::Eq, rhs: e.clone() }),
        Access::Scan => {}
    }
    preds.iter().map(|p| sql.compile(sess, &sp.table.schema, p, params)).collect()
}
fn tables_of(sp: &SelectPlan, out: &mut Vec<u16>) {
    out.push(sp.table.id);
    if let Some(j) = &sp.join { out.push(j.probe.id); for st in &j.steps { out.push(st.build.id); } }
    for (s, _) in &sp.subs { tables_of(s, out); }
    for p in &sp.preds { if let Expr::Set(s) | Expr::Scalar(s) = &p.rhs { tables_of(s, out); } }
    for x in sp.exprs.iter().chain(&sp.filters) { x.walk(&mut |n| if let crate::expr::SExpr::Sub(s) = n { tables_of(s, out); }); }
    out.sort_unstable(); out.dedup();
}
/// A result row's key, for telling added rows from removed ones: `key_col` is the key column and its type.
fn key_of(row: &[Value], key_col: &Option<(usize, ColType)>) -> Option<crate::table::Key> { let (c, ty) = key_col.as_ref()?; crate::table::value_key128(ty, row.get(*c)?) }

impl Reactor {
    pub fn start(sql: Arc<Sql>) -> Arc<Reactor> {
        sql.db.log.feeds.fetch_add(1, Ordering::Relaxed);  // keep the memory ring alive
        let r = Arc::new(Reactor { sql: Arc::downgrade(&sql), log: sql.db.log.clone(), thread: Mutex::new(None), state: Arc::new(Mutex::new(State::default())), debounce: sql.cfg.live.debounce, reruns: AtomicU64::new(0), rerun_us: AtomicU64::new(0), events: AtomicU64::new(0), last_seq: AtomicU64::new(0), stop: Arc::new(AtomicBool::new(false)) });
        // the feed starts where the log is now, decided here rather than on the new thread: a change committed right
        // after the first subscribe() returns must not slip in before the reactor begins reading
        let start = sql.current_seq();
        let r2 = r.clone(); let h = std::thread::spawn(move || r2.run(start)); *r.thread.lock().unwrap() = Some(h);
        r
    }
    /// Stop the reactor thread and wait for it (unless called from it). Subscriptions stop receiving events.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        let h = self.thread.lock().unwrap().take();
        if let Some(h) = h { if h.thread().id() != std::thread::current().id() { h.join().ok(); } }
    }
    fn run(&self, start: u64) {
        let (mut feed, durable_only) = { let Some(sql) = self.sql.upgrade() else { return }; (sql.subscribe(start), sql.db.durable) };
        let mut auth_seen = { let Some(sql) = self.sql.upgrade() else { return }; sql.auth_epoch() };
        loop {
            if self.stop.load(Ordering::Relaxed) { return; }
            // sleep until something is appended, or until a dirty query is due
            let due = { let st = self.state.lock().unwrap(); st.lives.iter().filter_map(|l| l.due(self.debounce)).map(|d| d.saturating_duration_since(Instant::now())).min() };
            self.log.wait_feed(feed.last_seq(), durable_only, due.unwrap_or(Duration::from_millis(20)).min(Duration::from_millis(20)));
            let Some(sql) = self.sql.upgrade() else { return };   // the database is gone
            let recs = feed.poll_raw(); let now = Instant::now();
            // sign-in state changed: a subscription or live query whose token no longer holds, or whose identity changed
            // (another role, other attributes), ends; the client sees it dropped and subscribes again
            let ep = sql.auth_epoch();
            if ep != auth_seen {
                auth_seen = ep; let last = self.last_seq.load(Ordering::Relaxed);
                let mut st = self.state.lock().unwrap();
                let changed = |s: &mut Session| { let before = (s.roles.clone(), s.attrs.clone()); sql.check_identity(s).is_err() || before != (s.roles.clone(), s.attrs.clone()) };
                for sub in st.subs.iter_mut() { if let Some(id) = sub.ident.as_mut() { if changed(id) { let _ = sub.q.push(Event::Overflow { last_seq: last }); sub.q.closed.store(true, Ordering::Relaxed); } } }
                for live in st.lives.iter_mut() { if live.sess.token.is_some() && changed(&mut live.sess) { let _ = live.q.push(Event::Overflow { last_seq: last }); live.q.closed.store(true, Ordering::Relaxed); } }
                let before = st.subs.len(); st.subs.retain(|s| !s.q.closed.load(Ordering::Relaxed)); if st.subs.len() != before { st.reindex(); } st.lives.retain(|l| !l.q.closed.load(Ordering::Relaxed));
            }
            if !recs.is_empty() {
                let mut st = self.state.lock().unwrap();
                for (seq, t, op, payload) in &recs {
                    self.last_seq.store(*seq, Ordering::Relaxed);
                    let is_row = payload.len() >= t.schema.row_size;   // a row, with any long values after it (not a key-only delete)
                    // candidates: keyed subscriptions matching this row's values on each indexed column, plus the general ones
                    let mut cands: Vec<usize> = Vec::new();
                    if is_row { if let Some(cols) = st.key_cols.get(&t.id) { for &c in cols { if let Some(v) = read_key(&t.schema, payload, c) { if let Some(ix) = st.keyed.get(&(t.id, c, v)) { cands.extend_from_slice(ix); } } } } }
                    else if *op == OP_DELETE { for ((tid, _, _), ix) in st.keyed.iter() { if *tid == t.id { cands.extend_from_slice(ix); } } }  // a key-only delete cannot be filtered: deliver to all
                    if let Some(g) = st.general.get(&t.id) { cands.extend_from_slice(g); }
                    if !cands.is_empty() {
                        let row = if is_row { Some((0..t.schema.columns.len()).map(|i| decode_col(&t.schema, payload, i)).collect()) } else { None };
                        let ch = Arc::new(Change { seq: *seq, table: t.schema.name.clone(), op: match *op { OP_INSERT => ChangeOp::Insert, OP_UPDATE => ChangeOp::Update, _ => ChangeOp::Delete }, pk: t.schema.delete_pk_value(payload), row });
                        for &i in &cands {
                            let sub = &st.subs[i]; if *seq <= sub.since { continue; }
                            let pass = if is_row { sub.preds.iter().all(|p| p.eval(payload)) && sub.policies.iter().all(|p| p.eval(payload)) } else { *op == OP_DELETE };
                            if !pass { continue; }
                            if !sub.q.push(Event::Change(ch.clone())) { let _ = sub.q.push(Event::Overflow { last_seq: *seq }); sub.q.closed.store(true, Ordering::Relaxed); }
                            self.events.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    for live in st.lives.iter_mut() {
                        if live.dirty_since.is_some() || !live.tables.contains(&t.id) { continue; }
                        // a row that matches now changes the result, and so does one that was in it (an update or delete
                        // may take it out). Without the key in its result, a query can't tell whether the row was: any
                        // update or key-only delete may have changed it (a full delete carries the row it removed)
                        let dirty = match &live.single {
                            Some((tid, preds, pols)) if *tid == t.id => { let pk = if is_row { t.pk_of(payload) } else { t.schema.delete_key(payload) }; (is_row && preds.iter().all(|p| p.eval(payload)) && pols.iter().all(|p| p.eval(payload))) || (live.key_col.is_some() && live.keys.contains(&pk)) || (live.key_col.is_none() && (!is_row || *op == OP_UPDATE)) }
                            _ => true,
                        };
                        if dirty { live.dirty_since = Some(now); }
                    }
                }
                let before = st.subs.len(); st.subs.retain(|s| !s.q.closed.load(Ordering::Relaxed)); if st.subs.len() != before { st.reindex(); } st.lives.retain(|l| !l.q.closed.load(Ordering::Relaxed));
            }
            // re-run the changed live queries that are due. A write is in the log before its rows are visible: a
            // re-run counts only if none was in between (it saw every write that changed it); else it runs again
            let mut st = self.state.lock().unwrap();
            let settled = st.lives.iter().any(|l| l.due(self.debounce).is_some_and(|d| now >= d)) && {
                let t = Instant::now(); loop { if self.log.settled() { break true; } if t.elapsed() > SETTLE_WAIT { break false; } std::thread::yield_now(); }
            };
            for live in st.lives.iter_mut() {
                let Some(due) = live.due(self.debounce) else { continue }; if now < due { continue; }
                let t0 = Instant::now(); live.last_run = Some(t0);
                let rows = match sql.execute_s(&mut live.sess, &live.prepared, &live.params) { Ok(r) => r, Err(_) => {
                    // a session from a token that no longer holds ends the live query (the client sees it dropped)
                    if live.sess.token.is_some() { let _ = live.q.push(Event::Overflow { last_seq: self.last_seq.load(Ordering::Relaxed) }); live.q.closed.store(true, Ordering::Relaxed); }
                    live.dirty_since = None; continue; } };
                self.reruns.fetch_add(1, Ordering::Relaxed); self.rerun_us.fetch_add(t0.elapsed().as_micros() as u64, Ordering::Relaxed);
                live.retry = !settled; if settled { live.dirty_since = None; }
                if rows != live.result {
                    let (added, removed) = match live.key_col.clone() { Some(kc) => { let kc = Some(kc); let old: HashSet<crate::table::Key> = live.keys.clone(); let new: HashSet<crate::table::Key> = rows.iter().filter_map(|r| key_of(r, &kc)).collect(); (rows.iter().filter(|r| key_of(r, &kc).map(|k| !old.contains(&k)).unwrap_or(true)).cloned().collect(), live.result.iter().filter(|r| key_of(r, &kc).map(|k| !new.contains(&k)).unwrap_or(true)).cloned().collect()) } None => (rows.clone(), live.result.clone()) };
                    live.keys = rows.iter().filter_map(|r| key_of(r, &live.key_col)).collect();
                    live.result = rows.clone();
                    if !live.q.push(Event::Live { seq: self.last_seq.load(Ordering::Relaxed), rows, added, removed }) { live.q.closed.store(true, Ordering::Relaxed); }
                    self.events.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    /// Subscribe to the changes a single-table SELECT would see: its WHERE becomes the filter, the session's row policies apply.
    pub fn subscribe(&self, sess: &Session, text: &str, params: &[Value]) -> Result<Subscription, String> {
        let sql = self.sql.upgrade().ok_or("database is closed")?; let p = sql.prepare(text)?;
        let Plan::Select(sp) = &p.plan else { return Err("subscribe needs a SELECT".into()) };
        if sp.join.is_some() || !sp.subs.is_empty() { return Err("subscribe needs a single-table SELECT (watch handles joins)".into()); }
        if !sp.filters.is_empty() { return Err("subscribe filters by columns compared with values (=, <, IN, IS NULL …); use watch for other conditions".into()); }
        let mut s0 = session_like(sess); sql.check_identity(&mut s0)?; let sess = &s0;
        let preds = plan_preds(&sql, sess, sp, params)?; let policies = sql.guard(sess, &sp.table, P_SELECT)?;
        // an equality on an INT column with a constant makes the subscription indexable
        let key = { let mut all: Vec<Pred> = sp.preds.clone(); match &sp.access { Access::Pk(e) => all.push(Pred { col: sp.table.schema.pk, cmp: Cmp::Eq, rhs: e.clone() }), Access::Index(ix, e) => all.push(Pred { col: ix.col, cmp: Cmp::Eq, rhs: e.clone() }), _ => {} }
            all.iter().find_map(|p| if p.cmp == Cmp::Eq && sp.table.schema.columns[p.col].ty == crate::table::ColType::Int { match &p.rhs { Expr::Lit(Value::Int(v)) => Some((p.col, *v)), Expr::Param(i) => match params.get(*i) { Some(Value::Int(v)) => Some((p.col, *v)), _ => None }, _ => None } } else { None }) };
        let q = Arc::new(Queue::new(sql.cfg.live.queue));
        { let mut st = self.state.lock().unwrap(); st.subs.push(Sub { table: sp.table.id, preds, policies, q: q.clone(), key, since: sql.current_seq(), ident: sess.token.as_ref().map(|_| session_like(sess)) }); st.reindex(); }
        Ok(Subscription { q })
    }
    /// Watch a query: returns its current result and a handle that receives `Event::Live` whenever the result changes.
    pub fn watch(&self, sess: &Session, text: &str, params: &[Value]) -> Result<(Subscription, Vec<Vec<Value>>), String> {
        let sql = self.sql.upgrade().ok_or("database is closed")?; let p = sql.prepare(text)?;
        let Plan::Select(sp) = &p.plan else { return Err("watch needs a SELECT".into()) };
        let mut tables = vec![]; tables_of(sp, &mut tables);
        let mut s0 = session_like(sess); sql.check_identity(&mut s0)?; let sess = &s0;
        let single = if sp.join.is_none() && sp.subs.is_empty() { Some((sp.table.id, plan_preds(&sql, sess, sp, params)?, sql.guard(sess, &sp.table, P_SELECT)?)) } else { None };
        let key_col = if sp.join.is_none() && sp.post.is_none() { sp.proj.iter().position(|pr| matches!(pr, Proj::Col(c) if *c == sp.table.schema.pk)).map(|i| (i, sp.table.schema.columns[sp.table.schema.pk].ty.clone())) } else { None };
        let mut s = session_like(sess); let result = sql.execute_s(&mut s, &p, params)?;
        let q = Arc::new(Queue::new(4096));
        let keys = result.iter().filter_map(|r| key_of(r, &key_col)).collect();
        self.state.lock().unwrap().lives.push(Live { prepared: p.clone(), sess: s, params: params.to_vec(), tables, single, key_col, result: result.clone(), keys, dirty_since: None, last_run: None, retry: false, q: q.clone() });
        Ok((Subscription { q }, result))
    }
    pub fn counts(&self) -> (usize, usize) { let st = self.state.lock().unwrap(); (st.subs.len(), st.lives.len()) }
}
impl Drop for Reactor { fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); self.log.feeds.fetch_sub(1, Ordering::Relaxed); } }

#[cfg(test)]
mod tests {
    use super::Event;
    use crate::config::Config;
    use crate::sql::{Session, Sql};
    use crate::table::{encode_row, Value, OP_INSERT};
    use super::Subscription;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    /// A write is in the log (where the reactor reads it) a moment before its row is visible. A re-run in that moment
    /// sees the old result; the live query must not count as fresh then, or the write never reaches it.
    #[test] fn a_live_query_sees_a_write_whose_row_appears_after_its_log_record() {
        let d = std::env::temp_dir().join(format!("sqzdb-live-{}-settle", std::process::id())); let _ = std::fs::remove_dir_all(&d);
        let mut cfg = Config::default(); cfg.live.debounce = Duration::ZERO;
        let s = Sql::open_with(&d, cfg).unwrap(); let mut sess = Session::default();
        s.exec_s(&mut sess, "CREATE TABLE t (id INT PRIMARY KEY, v INT)", &[]).unwrap();
        let (sub, _) = s.reactor().watch(&sess, "SELECT count(*) FROM t", &[]).unwrap();
        // a writer stopped between logging its row and publishing it
        let t = s.db.table("t").unwrap(); let row = encode_row(&t.schema, &[Value::Int(1), Value::Int(7)]).unwrap();
        let seq = s.db.log.append(OP_INSERT, t.id, &row);
        let waited = Instant::now(); while s.reactor().reruns.load(Ordering::Relaxed) == 0 { assert!(waited.elapsed() < Duration::from_secs(2), "the reactor never ran the query"); std::thread::yield_now(); }
        // the writer goes on: the row appears, with no other record to tell the reactor
        t.replay_record(seq, &row); s.db.log.published();
        let deadline = Instant::now() + Duration::from_secs(2); let mut n = 0;
        while n < 1 {
            match sub.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Some(Event::Live { rows, .. }) => if let Value::Int(c) = rows[0][0] { n = c },
                Some(_) => {}
                None => panic!("the live query still counts {n}"),
            }
        }
        drop(sub); drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    /// The rows a live query returns, once they are `want` (or it fails after 2 s).
    fn until(sub: &Subscription, want: &[Vec<Value>]) {
        let deadline = Instant::now() + Duration::from_secs(2); let mut last = None;
        loop {
            match sub.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Some(Event::Live { rows, .. }) => { if rows == want { return; } last = Some(rows); }
                Some(_) => {}
                None => panic!("the live query still has {last:?}, not {want:?}"),
            }
        }
    }
    /// A row that stops matching leaves the result, though the result has no key to say it was in it: a projection
    /// without the primary key, or a count by group.
    #[test] fn a_row_that_stops_matching_leaves_a_result_without_its_key() {
        let d = std::env::temp_dir().join(format!("sqzdb-live-{}-keyless", std::process::id())); let _ = std::fs::remove_dir_all(&d);
        let mut cfg = Config::default(); cfg.live.debounce = Duration::ZERO;
        let s = Sql::open_with(&d, cfg).unwrap(); let mut sess = Session::default();
        s.exec_s(&mut sess, "CREATE TABLE runs (id INT PRIMARY KEY, job INT, status TEXT, archived BOOL)", &[]).unwrap();
        s.exec_s(&mut sess, "INSERT INTO runs VALUES (1, 7, 'working', false), (2, 8, 'done', false)", &[]).unwrap();
        let (busy, rows) = s.reactor().watch(&sess, "SELECT job, status FROM runs WHERE status IN ('pending', 'working')", &[]).unwrap();
        assert_eq!(rows, vec![vec![Value::Int(7), Value::Text("working".into())]]);
        let (counts, _) = s.reactor().watch(&sess, "SELECT status, count(*) AS n FROM runs WHERE archived = false GROUP BY status ORDER BY status", &[]).unwrap();
        s.exec_s(&mut sess, "UPDATE runs SET status = 'canceled' WHERE id = 1", &[]).unwrap();
        until(&busy, &[]);
        s.exec_s(&mut sess, "UPDATE runs SET archived = true WHERE id = 2", &[]).unwrap();
        until(&counts, &[vec![Value::Text("canceled".into()), Value::Int(1)]]);
        drop(busy); drop(counts); drop(s); let _ = std::fs::remove_dir_all(&d);
    }
}
