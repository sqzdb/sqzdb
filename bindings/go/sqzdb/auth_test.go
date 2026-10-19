package sqzdb

import (
	"os"
	"strings"
	"testing"
)

func TestAuth(t *testing.T) {
	dir := t.TempDir() + "/db"
	db, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app := db.Session()
	for _, q := range []string{
		"CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT DEFAULT 'member')",
		"CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, body TEXT)",
		"CREATE ROLE member", "GRANT SELECT, INSERT ON notes TO member",
		"CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id)",
		"ALTER TABLE users ENABLE AUTH (ROLE FROM role)",
	} {
		if _, err := app.ExecText(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	auth := db.Auth("users")
	ann, err := auth.SignUp(map[string]any{"email": "Ann@x.com", "name": "Ann"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ann.Token, "sqz_") || ann.User["email"] != "ann@x.com" || ann.User["id"] != int64(1) {
		t.Fatalf("sign-up gave %+v", ann)
	}
	s := db.Session()
	defer s.Close()
	if err := s.UseToken(ann.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecText("INSERT INTO notes (owner, body) VALUES (?, 'mine')", ann.User["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ExecText("INSERT INTO notes (owner, body) VALUES (99, 'not mine')"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ExecText("SELECT body FROM notes")
	if err != nil || len(rows) != 1 || rows[0][0] != "mine" {
		t.Fatalf("policy through the token: %v %v", rows, err)
	}
	if _, err := auth.SignIn("ann@x.com", "wrong"); err == nil || !strings.Contains(err.Error(), "wrong login or password") {
		t.Fatalf("a wrong password: %v", err)
	}
	again, err := auth.SignIn(" ANN@x.com", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SignOut(again.Token); err != nil {
		t.Fatal(err)
	}
	if err := db.Session().UseToken(again.Token); err == nil {
		t.Fatal("a signed-out token still works")
	}
	if err := auth.SetPassword(int64(1), "new password"); err != nil {
		t.Fatal(err)
	}
	if err := db.Session().UseToken(ann.Token); err == nil {
		t.Fatal("a session survived a password change")
	}
	if _, err := auth.SignIn("ann@x.com", "new password"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SignOutEverywhere(int64(1)); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(dir)
}

func TestOAuthStart(t *testing.T) {
	db, err := OpenWith(t.TempDir()+"/db", Options{Auth: &AuthOptions{OAuth: map[string]OAuthProvider{"github": {ClientID: "cid", ClientSecret: "sec"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app := db.Session()
	for _, q := range []string{"CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", "CREATE ROLE member", "ALTER TABLE users ENABLE AUTH (ROLE FROM role)"} {
		if _, err := app.ExecText(q); err != nil {
			t.Fatal(err)
		}
	}
	auth := db.Auth("users")
	url, state, cookie, err := auth.OAuthStart("github", "https://app.example/cb", "")
	if err != nil || !strings.HasPrefix(url, "https://github.com/login/oauth/authorize?") || !strings.Contains(url, "state="+state) || !strings.Contains(url, "code_challenge_method=S256") || len(cookie) != 64 {
		t.Fatalf("start: %q %q %v", url, state, err)
	}
	if _, err := auth.OAuthFinish("github", "code", state, "wrong cookie"); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("a wrong cookie: %v", err)
	}
	if _, err := auth.OAuthFinish("github", "code", "not-a-state", cookie); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("an unknown state: %v", err)
	}
	if _, _, _, err := auth.OAuthStart("google", "https://app.example/cb", ""); err == nil {
		t.Fatal("an unconfigured provider was accepted")
	}
}
