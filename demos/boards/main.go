// Boards: a multi-tenant task board on sqzdb. Every organization sees only its own boards and cards: the rule lives in
// the database as row policies, and each request runs as the signed-in member's identity (role "member", attribute org).
// Live updates are one change subscription per organization, fanned out to that organization's browsers as SSE.
//
//	go run . -dir ./data -addr 127.0.0.1:8070          # then open http://127.0.0.1:8070
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sqzdb/sqzdb/bindings/go/sqzdb"
)

//go:embed static
var static embed.FS

var schema = []string{
	"CREATE TABLE orgs (id UUID PRIMARY KEY DEFAULT uuid(), name VARCHAR(80) NOT NULL)",
	"CREATE TABLE users (id UUID PRIMARY KEY DEFAULT uuid(), org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, name VARCHAR(80) NOT NULL, email VARCHAR(120) UNIQUE)",
	"CREATE TABLE boards (id UUID PRIMARY KEY DEFAULT uuid(), org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, title VARCHAR(120) NOT NULL)",
	"CREATE TABLE cards (id UUID PRIMARY KEY DEFAULT uuid(), org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, board_id UUID NOT NULL REFERENCES boards(id) ON DELETE CASCADE, title VARCHAR(200) NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'todo', author_id UUID, created_at TIMESTAMP DEFAULT now())",
	"CREATE ROLE member",
	"GRANT SELECT ON orgs TO member",
	"GRANT SELECT ON users TO member",
	"GRANT SELECT, INSERT ON boards TO member",
	"GRANT SELECT, INSERT, UPDATE, DELETE ON cards TO member",
	"CREATE POLICY own_org ON orgs FOR ALL TO member USING (id = SESSION.org)",
	"CREATE POLICY org_users ON users FOR ALL TO member USING (org_id = SESSION.org)",
	"CREATE POLICY org_boards ON boards FOR ALL TO member USING (org_id = SESSION.org)",
	"CREATE POLICY org_cards ON cards FOR ALL TO member USING (org_id = SESSION.org)",
}

// cards columns in table order, as change events carry them
var cardCols = []string{"id", "org_id", "board_id", "title", "status", "author_id", "created_at"}

type server struct {
	db     *sqzdb.DB
	secret []byte
	stmts  map[string]*sqzdb.Stmt
	mu     sync.Mutex
	hubs   map[string]*hub // by org id
}

type identity struct {
	User string `json:"u"`
	Org  string `json:"o"`
	Name string `json:"n"`
	Exp  int64  `json:"e"`
}

func main() {
	dir := flag.String("dir", "./data", "database directory")
	addr := flag.String("addr", "127.0.0.1:8070", "listen address")
	orgs := flag.Int("seed-orgs", 3, "organizations to create on first start")
	users := flag.Int("seed-users", 4, "members per organization on first start")
	benchSeed := flag.String("bench-seed", "", "ORGS,USERS: deterministic load-test data instead (org<n>, u<i>@org<n>.test, boards work and read)")
	flag.Parse()

	db, err := sqzdb.Open(*dir, false)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{db: db, secret: make([]byte, 32), stmts: map[string]*sqzdb.Stmt{}, hubs: map[string]*hub{}}
	if _, err := rand.Read(s.secret); err != nil {
		log.Fatal(err)
	}
	app := db.Session()
	if _, err := app.ExecText("SELECT count(*) FROM orgs"); err != nil { // first start: schema and sample data
		for _, q := range schema {
			if _, err := app.ExecText(q); err != nil {
				log.Fatalf("%s: %v", q, err)
			}
		}
		if *benchSeed != "" {
			var no, nu int
			if _, err := fmt.Sscanf(*benchSeed, "%d,%d", &no, &nu); err != nil {
				log.Fatalf("-bench-seed: %v", err)
			}
			seedBench(app, no, nu)
		} else {
			seed(app, *orgs, *users)
		}
	}
	app.Close()
	for name, q := range map[string]string{
		"boards":     "SELECT id, title FROM boards",
		"board":      "SELECT id FROM boards WHERE id = ?",
		"cards":      "SELECT id, org_id, board_id, title, status, author_id, created_at FROM cards WHERE board_id = ?",
		"addCard":    "INSERT INTO cards (org_id, board_id, title, author_id) VALUES (?, ?, ?, ?) RETURNING id, org_id, board_id, title, status, author_id, created_at",
		"moveCard":   "UPDATE cards SET status = ? WHERE id = ?",
		"delCard":    "DELETE FROM cards WHERE id = ?",
		"members":    "SELECT id, name, email FROM users",
		"orgName":    "SELECT name FROM orgs",
		"userByMail": "SELECT id, org_id, name FROM users WHERE email = ?",
	} {
		st, err := db.Prepare(q)
		if err != nil {
			log.Fatalf("%s: %v", q, err)
		}
		s.stmts[name] = st
	}

	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	mux.HandleFunc("GET /api/demo-users", s.demoUsers)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("GET /api/me", s.auth(s.me))
	mux.HandleFunc("GET /api/boards", s.auth(s.boards))
	mux.HandleFunc("GET /api/boards/{id}/cards", s.auth(s.cards))
	mux.HandleFunc("POST /api/boards/{id}/cards", s.auth(s.addCard))
	mux.HandleFunc("PATCH /api/cards/{id}", s.auth(s.moveCard))
	mux.HandleFunc("DELETE /api/cards/{id}", s.auth(s.delCard))
	mux.HandleFunc("GET /api/events", s.auth(s.events))
	log.Printf("boards on http://%s (database %s)", *addr, *dir)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// ---- sample data (the application's own session: no policies)
func seed(app *sqzdb.Session, orgs, users int) {
	names := []string{"Acme", "Globex", "Initech", "Umbrella", "Hooli", "Stark", "Wayne", "Tyrell"}
	people := []string{"Ada", "Grace", "Alan", "Edsger", "Barbara", "Ken", "Margaret", "Donald", "Frances", "John", "Radia", "Linus"}
	tasks := []string{"Write the onboarding email", "Fix the login redirect", "Plan the Q3 roadmap", "Review the pricing page", "Interview candidates", "Ship the mobile build"}
	for o := 0; o < orgs; o++ {
		org := names[o%len(names)]
		if o >= len(names) {
			org = fmt.Sprintf("%s %d", org, o)
		}
		r, err := app.ExecText("INSERT INTO orgs (name) VALUES (?) RETURNING id", org)
		if err != nil {
			log.Fatal(err)
		}
		orgID := r[0][0].(string)
		var first string
		for u := 0; u < users; u++ {
			p := people[(o*users+u)%len(people)]
			email := fmt.Sprintf("%s@%s.test", strings.ToLower(p), strings.ToLower(strings.ReplaceAll(org, " ", "")))
			if o*users+u >= len(people) {
				email = fmt.Sprintf("%s%d@%s.test", strings.ToLower(p), o*users+u, strings.ToLower(strings.ReplaceAll(org, " ", "")))
			}
			r, err := app.ExecText("INSERT INTO users (org_id, name, email) VALUES (?, ?, ?) RETURNING id", orgID, p, email)
			if err != nil {
				log.Fatal(err)
			}
			if u == 0 {
				first = r[0][0].(string)
			}
		}
		r, err = app.ExecText("INSERT INTO boards (org_id, title) VALUES (?, ?) RETURNING id", orgID, org+" roadmap")
		if err != nil {
			log.Fatal(err)
		}
		board := r[0][0].(string)
		for i, t := range tasks {
			st := []string{"todo", "doing", "done"}[i%3]
			if _, err := app.ExecText("INSERT INTO cards (org_id, board_id, title, status, author_id) VALUES (?, ?, ?, ?, ?)", orgID, board, t, st, first); err != nil {
				log.Fatal(err)
			}
		}
	}
}

// The load test's data: the same shape is created in PocketBase by the bench tool.
func seedBench(app *sqzdb.Session, orgs, users int) {
	for o := 0; o < orgs; o++ {
		r, err := app.ExecText("INSERT INTO orgs (name) VALUES (?) RETURNING id", fmt.Sprintf("org%d", o))
		if err != nil {
			log.Fatal(err)
		}
		org := r[0][0].(string)
		for u := 0; u < users; u++ {
			if _, err := app.ExecText("INSERT INTO users (org_id, name, email) VALUES (?, ?, ?)", org, fmt.Sprintf("u%d", u), fmt.Sprintf("u%d@org%d.test", u, o)); err != nil {
				log.Fatal(err)
			}
		}
		if _, err := app.ExecText("INSERT INTO boards (org_id, title) VALUES (?, 'work')", org); err != nil {
			log.Fatal(err)
		}
		r, err = app.ExecText("INSERT INTO boards (org_id, title) VALUES (?, 'read') RETURNING id", org)
		if err != nil {
			log.Fatal(err)
		}
		app.ExecText("BEGIN")
		for i := 0; i < 100; i++ {
			if _, err := app.ExecText("INSERT INTO cards (org_id, board_id, title, status) VALUES (?, ?, ?, ?)", org, r[0][0], fmt.Sprintf("card %d", i), []string{"todo", "doing", "done"}[i%3]); err != nil {
				log.Fatal(err)
			}
		}
		if _, err := app.ExecText("COMMIT"); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("bench data: %d orgs x %d users, boards work and read (100 cards)", orgs, users)
}

// ---- sessions: HMAC-signed tokens, checked on every request; a request runs as the member's identity
func (s *server) sign(id identity) string {
	b, _ := json.Marshal(id)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func (s *server) verify(tok string) (identity, error) {
	var id identity
	p, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return id, errors.New("bad token")
	}
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(p))
	want := m.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return id, errors.New("bad token")
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(b, &id) != nil || time.Now().Unix() > id.Exp {
		return id, errors.New("expired token")
	}
	return id, nil
}

type handler func(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session)

func (s *server) auth(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.URL.Query().Get("token") // EventSource cannot set headers
		}
		id, err := s.verify(tok)
		if err != nil {
			fail(w, 401, err)
			return
		}
		sess := s.db.Session()
		defer sess.Close()
		if err := sess.Assume([]string{"member"}, map[string]any{"org": id.Org, "user": id.User}); err != nil {
			fail(w, 500, err)
			return
		}
		h(w, r, id, sess)
	}
}

func (s *server) demoUsers(w http.ResponseWriter, r *http.Request) {
	app := s.db.Session()
	defer app.Close()
	rows, err := app.ExecText("SELECT u.email, u.name, o.name FROM users u JOIN orgs o ON o.id = u.org_id")
	if err != nil {
		fail(w, 500, err)
		return
	}
	out := []map[string]any{}
	for _, r := range rows {
		out = append(out, map[string]any{"email": r[0], "name": r[1], "org": r[2]})
	}
	reply(w, out)
}

// Demo sign-in by email (no password): stands in for OAuth, which issues the same signed identity.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email string }
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Email == "" {
		fail(w, 400, errors.New("email required"))
		return
	}
	app := s.db.Session()
	defer app.Close()
	rows, err := app.Exec(s.stmts["userByMail"], body.Email)
	if err != nil || len(rows) == 0 {
		fail(w, 401, errors.New("no such user"))
		return
	}
	id := identity{User: rows[0][0].(string), Org: rows[0][1].(string), Name: rows[0][2].(string), Exp: time.Now().Add(12 * time.Hour).Unix()}
	reply(w, map[string]any{"token": s.sign(id), "user": id.User, "org": id.Org, "name": id.Name})
}

func (s *server) me(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session) {
	org, err := sess.Exec(s.stmts["orgName"])
	if err != nil || len(org) == 0 {
		fail(w, 500, fmt.Errorf("org: %v", err))
		return
	}
	members, err := sess.Exec(s.stmts["members"])
	if err != nil {
		fail(w, 500, err)
		return
	}
	reply(w, map[string]any{"user": id.User, "name": id.Name, "org": id.Org, "orgName": org[0][0], "members": table([]string{"id", "name", "email"}, members)})
}

func (s *server) boards(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session) {
	rows, err := sess.Exec(s.stmts["boards"])
	if err != nil {
		fail(w, 500, err)
		return
	}
	reply(w, table([]string{"id", "title"}, rows))
}

func (s *server) cards(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session) {
	rows, err := sess.Exec(s.stmts["cards"], r.PathValue("id"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	reply(w, table(cardCols, rows))
}

func (s *server) addCard(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session) {
	var body struct{ Title string }
	if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Title) == "" {
		fail(w, 400, errors.New("title required"))
		return
	}
	// The board must be one this member can see: the policy hides other orgs' boards. (A foreign key check alone only
	// asks whether the board exists anywhere; row policies cannot yet follow a relation, as PocketBase rules can.)
	if b, err := sess.Exec(s.stmts["board"], r.PathValue("id")); err != nil || len(b) == 0 {
		fail(w, 404, errors.New("no such board"))
		return
	}
	// org_id comes from the identity; the row policy refuses any other value, so a client cannot write into another org
	rows, err := sess.Exec(s.stmts["addCard"], id.Org, r.PathValue("id"), body.Title, id.User)
	if err != nil {
		fail(w, 400, err)
		return
	}
	reply(w, table(cardCols, rows)[0])
}

func (s *server) moveCard(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session) {
	var body struct{ Status string }
	if json.NewDecoder(r.Body).Decode(&body) != nil || (body.Status != "todo" && body.Status != "doing" && body.Status != "done") {
		fail(w, 400, errors.New("status must be todo, doing or done"))
		return
	}
	rows, err := sess.Exec(s.stmts["moveCard"], body.Status, r.PathValue("id"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	reply(w, map[string]any{"changed": rows})
}

func (s *server) delCard(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session) {
	rows, err := sess.Exec(s.stmts["delCard"], r.PathValue("id"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	reply(w, map[string]any{"changed": rows})
}

// ---- live updates: one subscription per organization, run as that organization's identity, fanned out to its browsers
type hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func (s *server) hubFor(org string) (*hub, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.hubs[org]; ok {
		return h, nil
	}
	sess := s.db.Session()
	if err := sess.Assume([]string{"member"}, map[string]any{"org": org}); err != nil {
		return nil, err
	}
	sub, err := sess.Subscribe("SELECT * FROM cards")
	if err != nil {
		return nil, err
	}
	h := &hub{clients: map[chan []byte]struct{}{}}
	s.hubs[org] = h
	go func() {
		ops := map[int64]string{1: "insert", 2: "update", 3: "delete"}
		for {
			ev, err := sub.Next(1000)
			if err != nil {
				log.Printf("org %s: %v; resubscribing", org, err)
				sub.Close()
				if sub, err = sess.Subscribe("SELECT * FROM cards"); err != nil {
					log.Printf("org %s: %v", org, err)
					return
				}
				continue
			}
			if ev == nil {
				continue
			}
			row := map[string]any{}
			for i, c := range cardCols {
				if 3+i < len(ev) {
					row[c] = ev[3+i]
				}
			}
			msg, _ := json.Marshal(map[string]any{"op": ops[ev[0].(int64)], "table": ev[1], "key": ev[2], "row": row})
			h.mu.Lock()
			for c := range h.clients {
				select {
				case c <- msg:
				default: // a browser that cannot keep up misses events rather than slowing the others
				}
			}
			h.mu.Unlock()
		}
	}()
	return h, nil
}

func (s *server) events(w http.ResponseWriter, r *http.Request, id identity, sess *sqzdb.Session) {
	fl, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, errors.New("streaming unsupported"))
		return
	}
	h, err := s.hubFor(id.Org)
	if err != nil {
		fail(w, 500, err)
		return
	}
	c := make(chan []byte, 256)
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.clients, c); h.mu.Unlock() }()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case msg := <-c:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			fl.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ---- helpers
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
