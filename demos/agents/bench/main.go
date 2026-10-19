// Load test for the agents demo: agent memory through HTTP, on the sqzdb demo (a database per agent) and on
// PocketBase the way one would build it there (one shared memories collection, a field and an index per agent).
//
//	go run ./bench -target sqzdb -url http://127.0.0.1:8071 -pid <server pid> -dir <agents dir>
//	go run ./bench -target pocketbase -url http://127.0.0.1:8090 -pid <pocketbase pid> -dir <pb_data> -setup
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	target   = flag.String("target", "sqzdb", "sqzdb or pocketbase")
	base     = flag.String("url", "http://127.0.0.1:8071", "server URL")
	pid      = flag.Int("pid", 0, "server process id, for its memory and CPU")
	dataDir  = flag.String("dir", "", "server data directory, for disk use")
	setup    = flag.Bool("setup", false, "pocketbase: create the memories collection first")
	noLogs   = flag.Bool("no-request-log", false, "pocketbase: turn off its request log (on by default) during setup")
	agents   = flag.Int("agents", 2000, "agents to spawn")
	mems     = flag.Int("memories", 20, "memories each new agent writes")
	secs     = flag.Int("secs", 8, "seconds per timed phase")
	forgetN  = flag.Int("forget", 100, "agents to forget at the end")
	password = "benchpass123"
	suToken  string
)

var hc = &http.Client{Transport: &http.Transport{MaxIdleConns: 4096, MaxIdleConnsPerHost: 4096}, Timeout: 60 * time.Second}

func call(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, *base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if suToken != "" {
		req.Header.Set("Authorization", suToken)
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

// ---- the same four operations on both servers

func create(agent string) error {
	if *target == "pocketbase" {
		return nil // an agent is only a value in the agent field
	}
	return call("POST", "/api/agents", map[string]string{"name": agent}, nil)
}

func remember(agent, kind, body string) error {
	if *target == "pocketbase" {
		return call("POST", "/api/collections/memories/records", map[string]string{"agent": agent, "kind": kind, "body": body}, nil)
	}
	return call("POST", "/api/agents/"+agent+"/memories", map[string]string{"kind": kind, "body": body}, nil)
}

type memory struct {
	Agent string `json:"agent"`
	Body  string `json:"body"`
}

// recall returns the newest n memories; the bodies name their agent, so a memory from another agent is detectable.
func recall(agent string, n int) ([]memory, error) {
	if *target == "pocketbase" {
		var r struct{ Items []memory }
		q := url.Values{"filter": {fmt.Sprintf("agent = '%s'", agent)}, "sort": {"-created"}, "perPage": {strconv.Itoa(n)}, "skipTotal": {"1"}}
		err := call("GET", "/api/collections/memories/records?"+q.Encode(), nil, &r)
		return r.Items, err
	}
	var r struct{ Memories []memory }
	err := call("GET", fmt.Sprintf("/api/agents/%s/memories?limit=%d", agent, n), nil, &r)
	return r.Memories, err
}

// forget removes the agent and everything it remembered.
func forget(agent string) error {
	if *target == "pocketbase" { // no delete-by-filter in the API: list the agent's records, delete each
		for {
			var r struct{ Items []struct{ ID string } }
			q := url.Values{"filter": {fmt.Sprintf("agent = '%s'", agent)}, "fields": {"id"}, "perPage": {"500"}, "skipTotal": {"1"}}
			if err := call("GET", "/api/collections/memories/records?"+q.Encode(), nil, &r); err != nil {
				return err
			}
			if len(r.Items) == 0 {
				return nil
			}
			for _, it := range r.Items {
				if err := call("DELETE", "/api/collections/memories/records/"+it.ID, nil, nil); err != nil {
					return err
				}
			}
		}
	}
	return call("DELETE", "/api/agents/"+agent, nil, nil)
}

func gone(agent string) bool {
	if *target == "pocketbase" {
		m, err := recall(agent, 1)
		return err == nil && len(m) == 0
	}
	_, err := recall(agent, 1)
	return err != nil && strings.Contains(err.Error(), ": 404 ")
}

func body(agent string, i int) string {
	return fmt.Sprintf("[%s] step %d: the user prefers short answers and wants the report by Friday", agent, i)
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
func disk() string {
	if *dataDir == "" {
		return "?"
	}
	exec.Command("sync").Run()
	out, err := exec.Command("du", "-sh", *dataDir).Output()
	if err != nil {
		return "?"
	}
	return strings.Fields(string(out))[0]
}
func say(f string, a ...any) { fmt.Printf("%-11s "+f+"\n", append([]any{*target}, a...)...) }

func main() {
	flag.Parse()
	if *target == "pocketbase" {
		if err := pbAuth(); err != nil {
			fmt.Println("superuser login:", err)
			os.Exit(1)
		}
		if *setup {
			if err := setupPocketBase(); err != nil {
				fmt.Println("setup:", err)
				os.Exit(1)
			}
		}
		suToken = "" // the load runs without a superuser: the collection's rules are open, like the demo's API
	}
	names := make([]string, *agents)
	for i := range names {
		names[i] = fmt.Sprintf("bench-%05d", i)
	}

	// 1. spawn: create each agent and write its first memories, 16 clients
	{
		var next, bad atomic.Int64
		var wg sync.WaitGroup
		c0, t := cpuSecs(), time.Now()
		for k := 0; k < 16; k++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := int(next.Add(1)) - 1
					if i >= len(names) {
						return
					}
					if err := create(names[i]); err != nil {
						bad.Add(1)
						continue
					}
					for m := 1; m <= *mems; m++ {
						if err := remember(names[i], "note", body(names[i], m)); err != nil {
							bad.Add(1)
						}
					}
				}
			}()
		}
		wg.Wait()
		el := time.Since(t).Seconds()
		say("spawn %d agents x %d memories, 16 clients: %.2f s (%.0f agents/s, %.0f writes/s), errors %d, server CPU %.0f%%, memory %s, disk %s",
			*agents, *mems, el, float64(*agents)/el, float64(*agents**mems)/el, bad.Load(), (cpuSecs()-c0)/el*100, rss(), disk())
	}

	// 2. agents at work: write one memory and recall the newest 10, random agents
	for _, cl := range []int{8, 64} {
		var steps, bad, foreign atomic.Int64
		var mu sync.Mutex
		var lat []float64
		stop := make(chan struct{})
		var wg sync.WaitGroup
		c0, t := cpuSecs(), time.Now()
		for k := 0; k < cl; k++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var mine []float64
				for i := 0; ; i++ {
					select {
					case <-stop:
						mu.Lock()
						lat = append(lat, mine...)
						mu.Unlock()
						return
					default:
					}
					a := names[mrand.IntN(len(names))]
					s := time.Now()
					if err := remember(a, "step", body(a, 1000+i)); err != nil {
						bad.Add(1)
						continue
					}
					ms, err := recall(a, 10)
					if err != nil || len(ms) != 10 {
						bad.Add(1)
						continue
					}
					for _, m := range ms {
						if !strings.HasPrefix(m.Body, "["+a+"]") {
							foreign.Add(1)
						}
					}
					mine = append(mine, float64(time.Since(s).Microseconds())/1000)
					steps.Add(1)
				}
			}()
		}
		time.Sleep(time.Duration(*secs) * time.Second)
		close(stop)
		wg.Wait()
		el := time.Since(t).Seconds()
		say("agent steps (write + recall 10), %2d clients: %6.0f steps/s  p50 %6.2f ms  p99 %6.2f ms  errors %d  other agents' memories %d  server CPU %.0f%%, memory %s",
			cl, float64(steps.Load())/el, pct(lat, .5), pct(lat, .99), bad.Load(), foreign.Load(), (cpuSecs()-c0)/el*100, rss())
	}

	// 3. forget: delete agents with everything they remembered, one client, then check nothing is left
	{
		n := min(*forgetN, len(names))
		var lat []float64
		bad, left := 0, 0
		for _, a := range names[len(names)-n:] {
			s := time.Now()
			if err := forget(a); err != nil {
				bad++
				continue
			}
			lat = append(lat, float64(time.Since(s).Microseconds())/1000)
		}
		for _, a := range names[len(names)-n:] {
			if !gone(a) {
				left++
			}
		}
		say("forget %d agents (each with its memories), 1 client: p50 %.2f ms  p99 %.2f ms per agent, errors %d, agents with memories left %d, disk %s",
			n, pct(lat, .5), pct(lat, .99), bad, left, disk())
	}
}

func pbAuth() error {
	var su struct{ Token string }
	if err := call("POST", "/api/collections/_superusers/auth-with-password", map[string]string{"identity": "admin@bench.test", "password": password}, &su); err != nil {
		return err
	}
	suToken = su.Token
	return nil
}

func setupPocketBase() error {
	if *noLogs {
		if err := call("PATCH", "/api/settings", map[string]any{"logs": map[string]any{"maxDays": 0}}, nil); err != nil {
			return err
		}
	}
	return call("POST", "/api/collections", map[string]any{"name": "memories", "type": "base",
		"fields": []map[string]any{
			{"name": "agent", "type": "text", "required": true, "max": 64},
			{"name": "kind", "type": "text", "max": 16},
			{"name": "body", "type": "text", "required": true, "max": 2000},
			{"name": "created", "type": "autodate", "onCreate": true},
		},
		"indexes":  []string{"CREATE INDEX idx_memories_agent ON memories (agent, created)"},
		"listRule": "", "viewRule": "", "createRule": "", "deleteRule": ""}, nil)
}
