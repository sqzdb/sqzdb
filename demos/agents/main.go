// Agents: a database per AI agent on sqzdb. Each agent's memory is its own database directory, created on first use,
// kept open while the agent is busy and closed when it goes idle or when too many are open; reopening a closed agent maps
// its files back in about a millisecond. Forgetting an agent is deleting its directory. A memory is a row; recall is the
// newest N, or the newest N that mention a word.
//
//	go run . -dir ./agents -addr 127.0.0.1:8071          # then open http://127.0.0.1:8071
package main

import (
	"container/list"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sqzdb/sqzdb/bindings/go/sqzdb"
)

//go:embed static
var static embed.FS

// The body's maximum length is fixed when an agent is created: sqzdb rows are fixed width, so every memory takes
// the full maximum in memory and in the log whatever its length (-body-max).
var bodyMax = 2000

func schema() []string {
	return []string{fmt.Sprintf("CREATE TABLE memories (id SERIAL PRIMARY KEY, kind VARCHAR(16) NOT NULL DEFAULT 'note', body VARCHAR(%d) NOT NULL, at TIMESTAMP DEFAULT now())", bodyMax)}
}

var memCols = []string{"id", "kind", "body", "at"}
var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var errNoAgent = errors.New("no such agent")
var errBusy = errors.New("agent is busy; try again")

// ---- the pool of open agents

type agent struct {
	name         string
	db           *sqzdb.DB
	ins, scan, n *sqzdb.Stmt
	recent       [3]*sqzdb.Stmt // newest 10, 50 and 200: LIMIT takes a literal
	refs         int
	last         time.Time
	elem         *list.Element
	ready        chan struct{} // closed once the database is open (or failed)
	err          error
}

type pool struct {
	root    string
	max     int
	idle    time.Duration
	mu      sync.Mutex
	open    map[string]*agent
	lru     *list.List               // front: most recently used
	closing map[string]chan struct{} // agents being closed or deleted; an open of the same name waits for it
	names   []string                 // every agent on disk, oldest first
	index   map[string]int

	opens, evictions, idled, created, forgot, steps atomic.Int64
	reopenNs                                        atomic.Int64 // time spent opening agents that already existed
}

func newPool(root string, max int, idle time.Duration) (*pool, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	p := &pool{root: root, max: max, idle: idle, open: map[string]*agent{}, lru: list.New(), closing: map[string]chan struct{}{}, index: map[string]int{}}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	type e struct {
		name string
		at   time.Time
	}
	var es []e
	for _, d := range ents {
		if d.IsDir() && validName.MatchString(d.Name()) {
			info, _ := d.Info()
			es = append(es, e{d.Name(), info.ModTime()})
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i].at.Before(es[j].at) })
	for _, x := range es {
		p.index[x.name] = len(p.names)
		p.names = append(p.names, x.name)
	}
	go p.reaper()
	return p, nil
}

// acquire returns the agent's open database, opening it (or, with create, creating it) if needed. Every acquire is
// paired with a release. opened reports a cold open and how long it took.
func (p *pool) acquire(name string, create bool) (a *agent, opened time.Duration, err error) {
	for {
		p.mu.Lock()
		if ch, ok := p.closing[name]; ok {
			p.mu.Unlock()
			<-ch
			continue
		}
		if a = p.open[name]; a != nil {
			a.refs++
			p.lru.MoveToFront(a.elem)
			p.mu.Unlock()
			<-a.ready
			if a.err != nil {
				p.release(a)
				return nil, 0, a.err
			}
			return a, 0, nil
		}
		_, exists := p.index[name]
		if !exists && !create {
			p.mu.Unlock()
			return nil, 0, errNoAgent
		}
		a = &agent{name: name, refs: 1, ready: make(chan struct{})}
		a.elem = p.lru.PushFront(a)
		p.open[name] = a
		victims := p.victims()
		p.mu.Unlock()
		p.closeAll(victims)

		t := time.Now()
		a.err = a.load(filepath.Join(p.root, name), !exists)
		opened = time.Since(t)
		close(a.ready)
		if a.err != nil {
			p.mu.Lock()
			delete(p.open, name)
			p.lru.Remove(a.elem)
			p.mu.Unlock()
			return nil, 0, a.err
		}
		if exists {
			p.opens.Add(1)
			p.reopenNs.Add(int64(opened))
		} else {
			p.mu.Lock()
			if _, ok := p.index[name]; !ok {
				p.index[name] = len(p.names)
				p.names = append(p.names, name)
			}
			p.mu.Unlock()
			p.created.Add(1)
		}
		return a, opened, nil
	}
}

func (p *pool) release(a *agent) {
	p.mu.Lock()
	a.refs--
	a.last = time.Now()
	p.mu.Unlock()
}

// victims picks least recently used idle agents beyond the limit and marks them closing. Called with p.mu held.
func (p *pool) victims() []*agent {
	var out []*agent
	for e := p.lru.Back(); e != nil && len(p.open) > p.max; {
		prev := e.Prev()
		if a := e.Value.(*agent); a.refs == 0 {
			p.detach(a)
			out = append(out, a)
			p.evictions.Add(1)
		}
		e = prev
	}
	return out
}

func (p *pool) detach(a *agent) {
	delete(p.open, a.name)
	p.lru.Remove(a.elem)
	p.closing[a.name] = make(chan struct{})
}

func (p *pool) closeAll(as []*agent) {
	for _, a := range as {
		a.close()
		p.mu.Lock()
		close(p.closing[a.name])
		delete(p.closing, a.name)
		p.mu.Unlock()
	}
}

// reaper closes agents nobody has used for the idle period: an idle agent costs nothing but its files.
func (p *pool) reaper() {
	for range time.Tick(time.Second) {
		p.mu.Lock()
		var out []*agent
		cut := time.Now().Add(-p.idle)
		for e := p.lru.Back(); e != nil; {
			prev := e.Prev()
			if a := e.Value.(*agent); a.refs == 0 && a.last.Before(cut) {
				p.detach(a)
				out = append(out, a)
				p.idled.Add(1)
			} else if a.refs == 0 {
				break // everything nearer the front was used more recently
			}
			e = prev
		}
		p.mu.Unlock()
		p.closeAll(out)
	}
}

// forget closes the agent and deletes its directory: all of its memory, gone in one step.
func (p *pool) forget(name string) (time.Duration, error) {
	t := time.Now()
	p.mu.Lock()
	if _, ok := p.index[name]; !ok {
		p.mu.Unlock()
		return 0, errNoAgent
	}
	if _, ok := p.closing[name]; ok {
		p.mu.Unlock()
		return 0, errBusy
	}
	a := p.open[name]
	if a != nil && a.refs > 0 {
		p.mu.Unlock()
		return 0, errBusy
	}
	done := make(chan struct{})
	if a != nil {
		delete(p.open, name)
		p.lru.Remove(a.elem)
	}
	p.closing[name] = done
	i := p.index[name]
	p.names = append(p.names[:i], p.names[i+1:]...)
	delete(p.index, name)
	for j := i; j < len(p.names); j++ {
		p.index[p.names[j]] = j
	}
	p.mu.Unlock()
	if a != nil {
		a.close()
	}
	err := os.RemoveAll(filepath.Join(p.root, name))
	p.mu.Lock()
	close(done)
	delete(p.closing, name)
	p.mu.Unlock()
	p.forgot.Add(1)
	return time.Since(t), err
}

func (p *pool) closeEverything() {
	p.mu.Lock()
	var out []*agent
	for _, a := range p.open {
		out = append(out, a)
	}
	p.open = map[string]*agent{}
	p.lru.Init()
	p.mu.Unlock()
	for _, a := range out {
		<-a.ready
		a.close()
	}
}

func (a *agent) load(dir string, fresh bool) error {
	// Log threads leave after 300 ms without writes, and one fsync per second covers an agent's writes: thousands of
	// agents share the disk, and a crash of the machine (not of this process) can lose at most the last second.
	db, err := sqzdb.OpenWith(dir, sqzdb.Options{Log: &sqzdb.Log{ThreadsIdleAfter: "300ms", SyncDelay: "1s"}})
	if err != nil {
		return err
	}
	a.db = db
	if fresh {
		s := db.Session()
		defer s.Close()
		for _, q := range schema() {
			if _, err := s.ExecText(q); err != nil {
				db.Close()
				os.RemoveAll(dir)
				return fmt.Errorf("%s: %w", q, err)
			}
		}
	}
	for _, x := range []struct {
		st **sqzdb.Stmt
		q  string
	}{
		{&a.ins, "INSERT INTO memories (kind, body) VALUES (?, ?) RETURNING id, kind, body, at"},
		{&a.recent[0], "SELECT id, kind, body, at FROM memories ORDER BY id DESC LIMIT 10"},
		{&a.recent[1], "SELECT id, kind, body, at FROM memories ORDER BY id DESC LIMIT 50"},
		{&a.recent[2], "SELECT id, kind, body, at FROM memories ORDER BY id DESC LIMIT 200"},
		{&a.scan, "SELECT id, kind, body, at FROM memories ORDER BY id DESC LIMIT 5000"},
		{&a.n, "SELECT count(*) FROM memories"},
	} {
		if *x.st, err = db.Prepare(x.q); err != nil {
			db.Close()
			return err
		}
	}
	return nil
}

func (a *agent) close() {
	if a.db == nil {
		return
	}
	for _, st := range []*sqzdb.Stmt{a.ins, a.recent[0], a.recent[1], a.recent[2], a.scan, a.n} {
		if st != nil {
			st.Close()
		}
	}
	a.db.Close()
	a.db = nil
}

// ---- what an agent does with its memory

func (a *agent) remember(kind, body string) (map[string]any, error) {
	s := a.db.Session()
	defer s.Close()
	rows, err := s.Exec(a.ins, kind, body)
	if err != nil {
		return nil, err
	}
	return table(memCols, rows)[0], nil
}

// recall returns the newest n memories, or the newest n that contain q (case-insensitive). sqzdb has no LIKE or full
// text search yet, so the word match runs here over the agent's newest 5,000 memories: one agent's memory is small.
func (a *agent) recall(n int, q string) ([]map[string]any, error) {
	s := a.db.Session()
	defer s.Close()
	st := a.recent[2]
	switch {
	case q != "":
		st = a.scan
	case n <= 10:
		st = a.recent[0]
	case n <= 50:
		st = a.recent[1]
	}
	rows, err := s.Exec(st)
	if err != nil {
		return nil, err
	}
	if q != "" {
		q = strings.ToLower(q)
		k := 0
		for _, r := range rows {
			if b, _ := r[2].(string); strings.Contains(strings.ToLower(b), q) {
				rows[k] = r
				k++
			}
		}
		rows = rows[:k]
	}
	if len(rows) > n {
		rows = rows[:n]
	}
	return table(memCols, rows), nil
}

func (a *agent) count() int64 {
	s := a.db.Session()
	defer s.Close()
	rows, err := s.Exec(a.n)
	if err != nil || len(rows) == 0 {
		return 0
	}
	n, _ := rows[0][0].(int64)
	return n
}

// ---- HTTP

type server struct {
	p     *pool
	swarm atomic.Bool
}

func main() {
	dir := flag.String("dir", "./agents", "directory that holds one database directory per agent")
	addr := flag.String("addr", "127.0.0.1:8071", "listen address")
	max := flag.Int("max-open", 2000, "agents kept open at once; the least recently used beyond this are closed")
	idle := flag.Duration("idle", 2*time.Minute, "close an agent nobody has used for this long")
	flag.IntVar(&bodyMax, "body-max", bodyMax, "longest memory, in bytes, for agents created from now on")
	flag.Parse()
	p, err := newPool(*dir, *max, *idle)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{p: p}
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/agents", s.list)
	mux.HandleFunc("POST /api/agents", s.create)
	mux.HandleFunc("GET /api/agents/{name}", s.detail)
	mux.HandleFunc("DELETE /api/agents/{name}", s.forget)
	mux.HandleFunc("POST /api/agents/{name}/memories", s.remember)
	mux.HandleFunc("GET /api/agents/{name}/memories", s.recall)
	mux.HandleFunc("POST /api/swarm/spawn", s.spawn)
	mux.HandleFunc("POST /api/swarm/run", s.run)
	log.Printf("agents on http://%s (%d agents in %s)", *addr, len(p.names), *dir)
	log.Fatal(http.ListenAndServe(*addr, guard(*addr, mux)))
}

// guard refuses what a web page open in the same browser could send to this demo, which has no sign-in: a write
// from another origin (CSRF; a browser sends a plain-text POST without asking first), and, while the demo listens on
// loopback, any request whose Host is not a loopback name (DNS rebinding, a page whose name points at 127.0.0.1).
// Tools without a browser, like the load generator in bench/, send neither header and pass.
func guard(addr string, h http.Handler) http.Handler {
	listenHost, _, _ := net.SplitHostPort(addr)
	loopback := isLoopback(listenHost)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if loopback && !isLoopback(host) {
			http.Error(w, "unknown host "+r.Host, http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			site := r.Header.Get("Sec-Fetch-Site")
			origin := r.Header.Get("Origin")
			if (site != "" && site != "same-origin" && site != "none") || (origin != "" && origin != "http://"+r.Host) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (s *server) with(w http.ResponseWriter, r *http.Request, create bool, f func(a *agent, opened time.Duration)) {
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		fail(w, 400, errors.New("agent names are lowercase letters, digits and dashes"))
		return
	}
	a, opened, err := s.p.acquire(name, create)
	if errors.Is(err, errNoAgent) {
		fail(w, 404, err)
		return
	} else if err != nil {
		fail(w, 500, err)
		return
	}
	defer s.p.release(a)
	f(a, opened)
}

func openInfo(opened time.Duration) map[string]any {
	if opened == 0 {
		return map[string]any{"cold": false}
	}
	return map[string]any{"cold": true, "ms": float64(opened.Microseconds()) / 1000}
}

func (s *server) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	if in.Name == "" {
		in.Name = newName()
	}
	if !validName.MatchString(in.Name) {
		fail(w, 400, errors.New("agent names are lowercase letters, digits and dashes"))
		return
	}
	s.p.mu.Lock()
	_, exists := s.p.index[in.Name]
	s.p.mu.Unlock()
	if exists {
		fail(w, 409, fmt.Errorf("agent %s already exists", in.Name))
		return
	}
	t := time.Now()
	a, _, err := s.p.acquire(in.Name, true)
	if err != nil {
		fail(w, 500, err)
		return
	}
	s.p.release(a)
	reply(w, map[string]any{"name": in.Name, "ms": float64(time.Since(t).Microseconds()) / 1000})
}

func (s *server) detail(w http.ResponseWriter, r *http.Request) {
	s.with(w, r, false, func(a *agent, opened time.Duration) {
		reply(w, map[string]any{"name": a.name, "memories": a.count(), "bytes": dirBytes(filepath.Join(s.p.root, a.name)), "open": openInfo(opened)})
	})
}

func (s *server) remember(w http.ResponseWriter, r *http.Request) {
	var in struct{ Kind, Body string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Body) == "" {
		fail(w, 400, errors.New("send {kind, body}"))
		return
	}
	if in.Kind == "" {
		in.Kind = "note"
	}
	s.with(w, r, r.URL.Query().Get("create") == "1", func(a *agent, opened time.Duration) {
		m, err := a.remember(in.Kind, in.Body)
		if err != nil {
			fail(w, 400, err)
			return
		}
		s.p.steps.Add(1)
		reply(w, map[string]any{"memory": m, "open": openInfo(opened)})
	})
}

func (s *server) recall(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 200 {
		n = 10
	}
	s.with(w, r, false, func(a *agent, opened time.Duration) {
		ms, err := a.recall(n, r.URL.Query().Get("q"))
		if err != nil {
			fail(w, 500, err)
			return
		}
		reply(w, map[string]any{"memories": ms, "open": openInfo(opened)})
	})
}

func (s *server) forget(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		fail(w, 400, errors.New("bad agent name"))
		return
	}
	took, err := s.p.forget(name)
	switch {
	case errors.Is(err, errNoAgent):
		fail(w, 404, err)
	case errors.Is(err, errBusy):
		fail(w, 409, err)
	case err != nil:
		fail(w, 500, err)
	default:
		reply(w, map[string]any{"forgot": name, "ms": float64(took.Microseconds()) / 1000})
	}
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 1000 {
		n = 200
	}
	q := r.URL.Query().Get("q")
	s.p.mu.Lock()
	total := len(s.p.names)
	out := []map[string]any{}
	for i := total - 1; i >= 0 && len(out) < n; i-- { // newest first
		name := s.p.names[i]
		if q != "" && !strings.Contains(name, q) {
			continue
		}
		_, open := s.p.open[name]
		out = append(out, map[string]any{"name": name, "open": open})
	}
	s.p.mu.Unlock()
	reply(w, map[string]any{"total": total, "agents": out})
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	p := s.p
	p.mu.Lock()
	total, open := len(p.names), len(p.open)
	p.mu.Unlock()
	opens := p.opens.Load() // reopens of existing agents; creating one is counted in created
	avg := 0.0
	if opens > 0 {
		avg = float64(p.reopenNs.Load()) / float64(opens) / 1e6
	}
	reply(w, map[string]any{
		"agents": total, "open": open, "maxOpen": p.max, "idleSecs": p.idle.Seconds(),
		"opens": opens, "openMsAvg": avg, "evictions": p.evictions.Load(), "idled": p.idled.Load(),
		"created": p.created.Load(), "forgot": p.forgot.Load(), "steps": p.steps.Load(),
		"rssMB": rssMB(), "threads": threads(), "goroutines": runtime.NumGoroutine(), "swarm": s.swarm.Load(),
	})
}

// ---- the swarm: load generated inside the server, so the page can show thousands of agents at work

func (s *server) spawn(w http.ResponseWriter, r *http.Request) {
	var in struct{ N int }
	json.NewDecoder(r.Body).Decode(&in)
	if in.N <= 0 || in.N > 20000 {
		in.N = 1000
	}
	t := time.Now()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var bad atomic.Int64
	for k := 0; k < 8; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				a, _, err := s.p.acquire(newName(), true)
				if err != nil {
					bad.Add(1)
					continue
				}
				for _, m := range starter(a.name) {
					a.remember(m[0], m[1])
				}
				s.p.release(a)
			}
		}()
	}
	for i := 0; i < in.N; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	reply(w, map[string]any{"spawned": int64(in.N) - bad.Load(), "failed": bad.Load(), "ms": time.Since(t).Milliseconds()})
}

func (s *server) run(w http.ResponseWriter, r *http.Request) {
	var in struct{ Secs, Workers, Rate int }
	json.NewDecoder(r.Body).Decode(&in)
	if in.Rate <= 0 || in.Rate > 1_000_000 {
		in.Rate = 2000 // memories per second across the swarm: agents think between steps
	}
	if in.Secs <= 0 || in.Secs > 120 {
		in.Secs = 10
	}
	if in.Workers <= 0 || in.Workers > 64 {
		in.Workers = 8
	}
	if !s.swarm.CompareAndSwap(false, true) {
		fail(w, 409, errors.New("a swarm is already running"))
		return
	}
	go func() {
		defer s.swarm.Store(false)
		end := time.Now().Add(time.Duration(in.Secs) * time.Second)
		var wg sync.WaitGroup
		for k := 0; k < in.Workers; k++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				every := time.Duration(float64(time.Second) * float64(in.Workers) / float64(in.Rate))
				next := time.Now()
				for time.Now().Before(end) {
					if d := time.Until(next); d > 0 {
						time.Sleep(d)
					}
					next = next.Add(every)
					s.p.mu.Lock()
					if len(s.p.names) == 0 {
						s.p.mu.Unlock()
						return
					}
					name := s.p.names[mrand.IntN(len(s.p.names))]
					s.p.mu.Unlock()
					a, _, err := s.p.acquire(name, false)
					if err != nil {
						continue
					}
					a.remember("step", thought())
					a.recall(10, "")
					s.p.release(a)
					s.p.steps.Add(1)
				}
			}()
		}
		wg.Wait()
	}()
	reply(w, map[string]any{"running": true, "secs": in.Secs, "workers": in.Workers, "rate": in.Rate})
}

var subjects = []string{"the quarterly report", "the flight to Lisbon", "the onboarding doc", "a refund request", "the API rate limit", "the team offsite", "a bug in checkout", "the vendor contract"}
var verbs = []string{"drafted", "checked", "summarized", "flagged", "scheduled", "answered", "reviewed", "updated"}

var endings = []string{"and noted the result", "for the user", "before the deadline", "with two open questions"}

// thought is a plausible line for an agent's working memory.
func thought() string {
	v := verbs[mrand.IntN(len(verbs))]
	return fmt.Sprintf("%s %s %s", strings.ToUpper(v[:1])+v[1:], subjects[mrand.IntN(len(subjects))], endings[mrand.IntN(len(endings))])
}

func starter(name string) [][2]string {
	return [][2]string{
		{"fact", "I am " + name + ", spawned " + time.Now().Format("Jan 2 15:04:05")},
		{"fact", "The user prefers short answers and metric units"},
		{"task", "Prepare " + subjects[mrand.IntN(len(subjects))] + " by Friday"},
		{"note", thought()},
		{"note", thought()},
	}
}

func newName() string {
	const abc = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = abc[int(b[i])%len(abc)]
	}
	return "agent-" + string(b)
}

// ---- helpers

func dirBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

func rssMB() float64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			f := strings.Fields(l)
			kb, _ := strconv.ParseFloat(f[1], 64)
			return kb / 1024
		}
	}
	return 0
}

func threads() int {
	ents, _ := os.ReadDir("/proc/self/task")
	return len(ents)
}

func table(cols []string, rows [][]any) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			if i < len(r) {
				m[c] = r[i]
			}
		}
		out = append(out, m)
	}
	return out
}
func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
