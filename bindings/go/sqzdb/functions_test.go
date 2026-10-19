package sqzdb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCall(t *testing.T) {
	dir := t.TempDir()
	fns := filepath.Join(dir, "functions")
	if err := os.MkdirAll(fns, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "import { fn } from 'sqzdb/functions'\nexport const add = fn({ args: { a: 'int', b: 'int' }, run: (_, { a, b }): number => a + b })\n"
	if err := os.WriteFile(filepath.Join(fns, "math.ts"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := OpenWith(filepath.Join(dir, "db"), Options{Functions: fns})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := db.Session()
	defer s.Close()
	v, err := s.Call("add", map[string]any{"a": 2, "b": 40})
	if err != nil || v.(json.Number).String() != "42" {
		t.Fatalf("add: %v %v", v, err)
	}
	if _, err := s.Call("add", map[string]any{"a": "x", "b": 1}); err == nil || !strings.HasPrefix(err.Error(), "ARGUMENTS: ") {
		t.Fatalf("a wrong argument: %v", err)
	}
}
