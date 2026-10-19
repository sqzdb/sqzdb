// Load test for the boards demo: the same workloads against the sqzdb server and PocketBase, through their HTTP APIs.
//
//	go run ./bench -target sqzdb -url http://127.0.0.1:8070 -pid <server pid>
//	go run ./bench -target pocketbase -url http://127.0.0.1:8090 -pid <pocketbase pid> -setup   # creates collections, rules, data
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	target   = flag.String("target", "sqzdb", "sqzdb or pocketbase")
	base     = flag.String("url", "http://127.0.0.1:8070", "server URL")
	pid      = flag.Int("pid", 0, "server process id, for its memory")
	setup    = flag.Bool("setup", false, "pocketbase: create collections, rules and the load-test data first")
	noLogs   = flag.Bool("no-request-log", false, "pocketbase: turn off its request log (on by default) during setup")
	orgs     = flag.Int("orgs", 10, "organizations in the data")
	users    = flag.Int("users", 20, "users per organization in the data")
	secs     = flag.Int("secs", 8, "seconds per timed phase")
	fill     = flag.Int("fill", 0, "instead of the workloads: add exactly this many cards (16 clients), then report memory")
	password = "benchpass123"
)

var hc = &http.Client{Transport: &http.Transport{MaxIdleConns: 4096, MaxIdleConnsPerHost: 4096, MaxConnsPerHost: 0}, Timeout: 30 * time.Second}

// ---- a client per signed-in user
type client struct {
	token, org, user string
	work, read       string // board ids
}

func call(method, path, token string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, *base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		if *target == "pocketbase" {
			req.Header.Set("Authorization", token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func login(email string) (*client, error) {
	c := &client{}
	if *target == "pocketbase" {
		var r struct {
			Token  string
			Record struct{ ID, Org string }
		}
		if err := call("POST", "/api/collections/users/auth-with-password", "", map[string]string{"identity": email, "password": password}, &r); err != nil {
			return nil, err
		}
		c.token, c.org, c.user = r.Token, r.Record.Org, r.Record.ID
		var b struct{ Items []struct{ ID, Title string } }
		if err := call("GET", "/api/collections/boards/records?perPage=50&skipTotal=1", c.token, nil, &b); err != nil {
			return nil, err
		}
		for _, x := range b.Items {
			if x.Title == "work" {
				c.work = x.ID
			} else if x.Title == "read" {
				c.read = x.ID
			}
		}
		return c, nil
	}
	var r struct{ Token, Org, User string }
	if err := call("POST", "/api/login", "", map[string]string{"email": email}, &r); err != nil {
		return nil, err
	}
	c.token, c.org, c.user = r.Token, r.Org, r.User
	var b []struct{ ID, Title string }
	if err := call("GET", "/api/boards", c.token, nil, &b); err != nil {
		return nil, err
	}
	for _, x := range b {
		if x.Title == "work" {
			c.work = x.ID
		} else if x.Title == "read" {
			c.read = x.ID
		}
	}
	return c, nil
}

func (c *client) addCard(title string) error {
	if *target == "pocketbase" {
		return call("POST", "/api/collections/cards/records", c.token, map[string]string{"title": title, "status": "todo", "org": c.org, "board": c.work, "author": c.user}, nil)
	}
	return call("POST", "/api/boards/"+c.work+"/cards", c.token, map[string]string{"title": title}, nil)
}

func (c *client) listRead() (int, error) {
	if *target == "pocketbase" {
		var r struct{ Items []json.RawMessage }
		err := call("GET", "/api/collections/cards/records?perPage=200&skipTotal=1&filter="+url.QueryEscape("board='"+c.read+"'"), c.token, nil, &r)
		return len(r.Items), err
	}
	var r []json.RawMessage
	err := call("GET", "/api/boards/"+c.read+"/cards", c.token, nil, &r)
	return len(r), err
}

// subscribe calls on(title, org of the card) for every card event this user is sent, until stop is closed.
func (c *client) subscribe(on func(title, org string), ready chan<- error, stop <-chan struct{}) {
	var req *http.Request
	if *target == "pocketbase" {
		req, _ = http.NewRequest("GET", *base+"/api/realtime", nil)
	} else {
		req, _ = http.NewRequest("GET", *base+"/api/events?token="+url.QueryEscape(c.token), nil)
	}
	sse := &http.Client{Transport: hc.Transport} // no timeout on a stream
	resp, err := sse.Do(req)
	if err != nil {
		ready <- err
		return
	}
	go func() { <-stop; resp.Body.Close() }()
	rd := bufio.NewReaderSize(resp.Body, 64<<10)
	event, signaled := "", false
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if !signaled {
				ready <- err
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, ":") && *target != "pocketbase" && !signaled:
			signaled = true
			ready <- nil // our server says ": connected" once the org's subscription exists
		case strings.HasPrefix(line, "data:"):
			data := strings.TrimSpace(line[5:])
			if *target == "pocketbase" {
				if event == "PB_CONNECT" {
					var m struct{ ClientID string }
					json.Unmarshal([]byte(data), &m)
					err := call("POST", "/api/realtime", c.token, map[string]any{"clientId": m.ClientID, "subscriptions": []string{"cards"}}, nil)
					signaled = true
					ready <- err
					continue
				}
				var m struct {
					Action string
					Record struct{ Title, Org string }
				}
				if json.Unmarshal([]byte(data), &m) == nil && m.Action == "create" {
					on(m.Record.Title, m.Record.Org)
				}
			} else {
				var m struct {
					Op  string
					Row struct {
						Title string
						Org   string `json:"org_id"`
					}
				}
				if json.Unmarshal([]byte(data), &m) == nil && m.Op == "insert" {
					on(m.Row.Title, m.Row.Org)
				}
			}
		}
	}
}

// ---- measurements
func pct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	return v[int(float64(len(v)-1)*p)]
}
func rss() string {
	if *pid == 0 {
		return "?"
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", *pid))
	if err != nil {
		return "?"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			f := strings.Fields(l)
			kb, _ := strconv.Atoi(f[1])
			return fmt.Sprintf("%d MB", kb/1024)
		}
	}
	return "?"
}
func cpuSecs() float64 {
	if *pid == 0 {
		return 0
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", *pid))
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+2:]))
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	return (ut + st) / 100
}
func say(f string, a ...any) { fmt.Printf("%-11s "+f+"\n", append([]any{*target}, a...)...) }

func main() {
	flag.Parse()
	if *setup {
		if err := setupPocketBase(); err != nil {
			fmt.Println("setup:", err)
			os.Exit(1)
		}
	}
	// sign everyone in
	all := make([][]*client, *orgs)
	t0 := time.Now()
	var wg sync.WaitGroup
	var lerr atomic.Value
	for o := 0; o < *orgs; o++ {
		all[o] = make([]*client, *users)
		for u := 0; u < *users; u++ {
			wg.Add(1)
			go func(o, u int) {
				defer wg.Done()
				c, err := login(fmt.Sprintf("u%d@org%d.test", u, o))
				if err != nil {
					lerr.Store(err)
					return
				}
				all[o][u] = c
			}(o, u)
		}
	}
	wg.Wait()
	if e := lerr.Load(); e != nil {
		fmt.Println("login:", e)
		os.Exit(1)
	}
	say("signed in %d users in %.2f s; server memory %s", *orgs**users, time.Since(t0).Seconds(), rss())
	flat := []*client{}
	for _, cs := range all {
		flat = append(flat, cs...)
	}
	if *fill > 0 {
		var next atomic.Int64
		t := time.Now()
		for w := 0; w < 16; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				c := flat[(w*7)%len(flat)]
				for next.Add(1) <= int64(*fill) {
					if err := c.addCard(fmt.Sprintf("a card title of ordinary length, number %d", next.Load())); err != nil {
						fmt.Println("fill:", err)
						return
					}
				}
			}(w)
		}
		wg.Wait()
		time.Sleep(3 * time.Second)
		say("filled %d cards in %.1f s; server memory %s", *fill, time.Since(t).Seconds()-3, rss())
		return
	}

	// 1. concurrent writes: each worker adds cards to its org's board as fast as answers come back
	for _, workers := range []int{1, 16, 64} {
		var n atomic.Int64
		var fails atomic.Int64
		lat := make([][]float64, workers)
		end := time.Now().Add(time.Duration(*secs) * time.Second)
		c0 := cpuSecs()
		t := time.Now()
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				c := flat[(w*7)%len(flat)]
				for i := 0; time.Now().Before(end); i++ {
					s := time.Now()
					if err := c.addCard(fmt.Sprintf("w%d-%d", w, i)); err != nil {
						if fails.Add(1) == 1 {
							fmt.Println("  first error:", err)
						}
						continue
					}
					lat[w] = append(lat[w], float64(time.Since(s).Microseconds())/1000)
					n.Add(1)
				}
			}(w)
		}
		wg.Wait()
		el := time.Since(t).Seconds()
		var l []float64
		for _, x := range lat {
			l = append(l, x...)
		}
		say("writes, %2d clients: %7.0f cards/s  p50 %6.2f ms  p99 %6.2f ms  errors %d  server CPU %.0f%%", workers, float64(n.Load())/el, pct(l, .5), pct(l, .99), fails.Load(), 100*(cpuSecs()-c0)/el)
	}

	// 2. reads: list the 100-card board
	for _, workers := range []int{1, 16, 64} {
		var n, bad atomic.Int64
		lat := make([][]float64, workers)
		end := time.Now().Add(time.Duration(*secs) * time.Second)
		t := time.Now()
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				c := flat[(w*11)%len(flat)]
				for time.Now().Before(end) {
					s := time.Now()
					k, err := c.listRead()
					if err != nil || k != 100 {
						if bad.Add(1) == 1 {
							fmt.Println("  first bad read:", k, err)
						}
						continue
					}
					lat[w] = append(lat[w], float64(time.Since(s).Microseconds())/1000)
					n.Add(1)
				}
			}(w)
		}
		wg.Wait()
		el := time.Since(t).Seconds()
		var l []float64
		for _, x := range lat {
			l = append(l, x...)
		}
		say("reads,  %2d clients: %7.0f lists/s  p50 %6.2f ms  p99 %6.2f ms  (100 cards each, %d bad)", workers, float64(n.Load())/el, pct(l, .5), pct(l, .99), bad.Load())
	}

	// 3. realtime fan-out: subscribers spread over the orgs; one writer per org; latency from send to receipt, and leaks
	for _, perUser := range []int{1, 5} {
		subs := *orgs * *users * perUser
		var got, leaks atomic.Int64
		var lmu sync.Mutex
		var lat []float64
		stop := make(chan struct{})
		ready := make(chan error, subs)
		for o := 0; o < *orgs; o++ {
			for u := 0; u < *users; u++ {
				c := all[o][u]
				for k := 0; k < perUser; k++ {
					go c.subscribe(func(title, org string) {
						parts := strings.Split(title, "|")
						if len(parts) != 3 || parts[0] != "rt" {
							return
						}
						if parts[2] != c.org {
							leaks.Add(1)
							return
						}
						ns, _ := strconv.ParseInt(parts[1], 10, 64)
						d := float64(time.Now().UnixNano()-ns) / 1e6
						got.Add(1)
						lmu.Lock()
						lat = append(lat, d)
						lmu.Unlock()
					}, ready, stop)
				}
			}
		}
		for i := 0; i < subs; i++ {
			if err := <-ready; err != nil {
				fmt.Println("subscribe:", err)
				os.Exit(1)
			}
		}
		time.Sleep(500 * time.Millisecond)
		rate := 20 // cards per second per org
		var sent atomic.Int64
		end := time.Now().Add(time.Duration(*secs) * time.Second)
		c0 := cpuSecs()
		t := time.Now()
		for o := 0; o < *orgs; o++ {
			wg.Add(1)
			go func(c *client) {
				defer wg.Done()
				tick := time.NewTicker(time.Second / time.Duration(rate))
				defer tick.Stop()
				for time.Now().Before(end) {
					<-tick.C
					if c.addCard(fmt.Sprintf("rt|%d|%s", time.Now().UnixNano(), c.org)) == nil {
						sent.Add(1)
					}
				}
			}(all[o][0])
		}
		wg.Wait()
		el := time.Since(t).Seconds()
		time.Sleep(2 * time.Second)
		cpu := 100 * (cpuSecs() - c0) / (el + 2)
		want := sent.Load() * int64(*users*perUser)
		lmu.Lock()
		say("realtime, %4d subscribers: %d cards -> %d of %d deliveries (%.2f%%), leaks %d, latency p50 %.1f ms p99 %.1f ms max %.1f ms, server CPU %.0f%%, memory %s",
			subs, sent.Load(), got.Load(), want, 100*float64(got.Load())/float64(want), leaks.Load(), pct(lat, .5), pct(lat, .99), pct(lat, 1), cpu, rss())
		lmu.Unlock()
		close(stop)
		time.Sleep(time.Second)
	}
}

// ---- PocketBase: collections, rules and data equivalent to the sqzdb server's -bench-seed
func setupPocketBase() error {
	var su struct{ Token string }
	if err := call("POST", "/api/collections/_superusers/auth-with-password", "", map[string]string{"identity": "admin@bench.test", "password": password}, &su); err != nil {
		return err
	}
	tok := su.Token
	if *noLogs {
		if err := call("PATCH", "/api/settings", tok, map[string]any{"logs": map[string]any{"maxDays": 0}}, nil); err != nil {
			return err
		}
	}
	var orgsCol struct{ ID string }
	if err := call("POST", "/api/collections", tok, map[string]any{"name": "orgs", "type": "base",
		"fields":   []map[string]any{{"name": "name", "type": "text", "required": true}},
		"listRule": "id = @request.auth.org", "viewRule": "id = @request.auth.org"}, &orgsCol); err != nil {
		return err
	}
	var usersCol struct {
		ID     string
		Fields []map[string]any
	}
	if err := call("GET", "/api/collections/users", tok, nil, &usersCol); err != nil {
		return err
	}
	fields := append(usersCol.Fields, map[string]any{"name": "org", "type": "relation", "collectionId": orgsCol.ID, "maxSelect": 1})
	if err := call("PATCH", "/api/collections/users", tok, map[string]any{"fields": fields}, nil); err != nil {
		return err
	}
	var boardsCol struct{ ID string }
	if err := call("POST", "/api/collections", tok, map[string]any{"name": "boards", "type": "base",
		"fields":   []map[string]any{{"name": "title", "type": "text", "required": true}, {"name": "org", "type": "relation", "collectionId": orgsCol.ID, "maxSelect": 1, "required": true, "cascadeDelete": true}},
		"listRule": "org = @request.auth.org", "viewRule": "org = @request.auth.org", "createRule": "org = @request.auth.org",
		"indexes": []string{"CREATE INDEX idx_boards_org ON boards (org)"}}, &boardsCol); err != nil {
		return err
	}
	rule := "org = @request.auth.org"
	if err := call("POST", "/api/collections", tok, map[string]any{"name": "cards", "type": "base",
		"fields": []map[string]any{{"name": "title", "type": "text", "required": true}, {"name": "status", "type": "text"},
			{"name": "org", "type": "relation", "collectionId": orgsCol.ID, "maxSelect": 1, "required": true, "cascadeDelete": true},
			{"name": "board", "type": "relation", "collectionId": boardsCol.ID, "maxSelect": 1, "required": true, "cascadeDelete": true},
			{"name": "author", "type": "relation", "collectionId": usersCol.ID, "maxSelect": 1},
			{"name": "created", "type": "autodate", "onCreate": true}},
		"listRule": rule, "viewRule": rule, "createRule": rule + " && board.org = @request.auth.org", "updateRule": rule, "deleteRule": rule,
		"indexes": []string{"CREATE INDEX idx_cards_board ON cards (board)", "CREATE INDEX idx_cards_org ON cards (org)"}}, nil); err != nil {
		return err
	}
	t := time.Now()
	for o := 0; o < *orgs; o++ {
		var org struct{ ID string }
		if err := call("POST", "/api/collections/orgs/records", tok, map[string]any{"name": fmt.Sprintf("org%d", o)}, &org); err != nil {
			return err
		}
		for u := 0; u < *users; u++ {
			if err := call("POST", "/api/collections/users/records", tok, map[string]any{"email": fmt.Sprintf("u%d@org%d.test", u, o), "password": password, "passwordConfirm": password, "name": fmt.Sprintf("u%d", u), "org": org.ID}, nil); err != nil {
				return err
			}
		}
		if err := call("POST", "/api/collections/boards/records", tok, map[string]any{"title": "work", "org": org.ID}, nil); err != nil {
			return err
		}
		var read struct{ ID string }
		if err := call("POST", "/api/collections/boards/records", tok, map[string]any{"title": "read", "org": org.ID}, &read); err != nil {
			return err
		}
		for i := 0; i < 100; i++ {
			if err := call("POST", "/api/collections/cards/records", tok, map[string]any{"title": fmt.Sprintf("card %d", i), "status": []string{"todo", "doing", "done"}[i%3], "org": org.ID, "board": read.ID}, nil); err != nil {
				return err
			}
		}
	}
	say("setup: collections, rules and %d orgs x %d users created in %.1f s", *orgs, *users, time.Since(t).Seconds())
	return nil
}
