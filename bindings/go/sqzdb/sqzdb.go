// Package sqzdb is a thin Go binding over the C ABI of the sqzdb engine (one process owns a database directory).
package sqzdb

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -lsqzdb -Wl,-rpath,${SRCDIR}/../../../target/release
#include <stdlib.h>
#include <stddef.h>
typedef struct Db Db; typedef struct Stmt Stmt; typedef struct Sess Sess; typedef struct Rows Rows;
typedef struct { int tag; long long i; double f; const unsigned char* ptr; size_t len; } CValue;
Db* sqzdb_open(const char* path, int durable); long long sqzdb_last_insert_id(Sess*); Db* sqzdb_open_with(const char* path, const char* json); const char* sqzdb_open_error(); void sqzdb_close(Db*); const char* sqzdb_last_error(Db*);
Sess* sqzdb_session(Db*); void sqzdb_session_free(Sess*); int sqzdb_login(Db*, Sess*, const char*); int sqzdb_assume(Db*, Sess*, const char*);
char* sqzdb_sign_up(Db*, const char*, const char*, const char*); char* sqzdb_sign_in(Db*, const char*, const char*, const char*); int sqzdb_sign_out(Db*, const char*);
int sqzdb_set_password(Db*, const char*, const char*, const char*); int sqzdb_sign_out_everywhere(Db*, const char*, const char*); int sqzdb_use_token(Db*, Sess*, const char*); void sqzdb_free_string(char*);
char* sqzdb_call(Db*, Sess*, const char*, const char*);
char* sqzdb_oauth_start(Db*, const char*, const char*, const char*, const char*); char* sqzdb_oauth_finish(Db*, const char*, const char*, const char*, const char*, const char*);
Stmt* sqzdb_prepare(Db*, const char*); void sqzdb_finalize(Stmt*);
Rows* sqzdb_exec(Db*, Sess*, Stmt*, const CValue*, int); Rows* sqzdb_exec_text(Db*, Sess*, const char*, const CValue*, int);
int sqzdb_rows_count(Rows*); int sqzdb_rows_cols(Rows*); int sqzdb_rows_get(Rows*, int, int, CValue*); int sqzdb_rows_all(Rows*, CValue*, int); void sqzdb_rows_free(Rows*);
long long sqzdb_snapshot(Db*);
typedef struct Sub Sub; Sub* sqzdb_subscribe(Db*, Sess*, const char*, const CValue*, int); int sqzdb_sub_next(Sub*, int, Rows**); void sqzdb_sub_free(Sub*);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"unsafe"
)

type DB struct{ p *C.Db }
type Stmt struct{ p *C.Stmt }
type Session struct {
	db *DB
	p  *C.Sess
}

// Options mirror the engine's configuration keys (see src/config.rs). Durations are strings like "500ms", "1s", "2m";
// sizes like "256MB". Zero values are omitted, so an empty Options means the defaults.
type Options struct {
	ConfigFile string       `json:"configFile,omitempty"` // a TOML file with these keys, read first and overridden by the options
	Durable    any          `json:"durable,omitempty"`    // false, true, or "cloud"
	Create     *bool        `json:"create,omitempty"`
	Backup     *Backup      `json:"backup,omitempty"`
	Follow     *Follow      `json:"follow,omitempty"`
	Snapshot   *Snapshot    `json:"snapshot,omitempty"`
	Listen     *Listen      `json:"listen,omitempty"`
	Live       *Live        `json:"live,omitempty"`
	Log        *Log         `json:"log,omitempty"`
	Auth       *AuthOptions `json:"auth,omitempty"`
	Functions  any          `json:"functions,omitempty"` // the app's functions: a folder, or {"dir", "watch", "timeout", "memory", "instances"}
}

// AuthOptions configures sign-in: session length, the shortest password, and OAuth providers by name ("google",
// "github", or any OpenID Connect provider with its endpoints and issuer).
type AuthOptions struct {
	SessionTTL  string                   `json:"sessionTtl,omitempty"`
	PasswordMin int                      `json:"passwordMin,omitempty"`
	OAuth       map[string]OAuthProvider `json:"oauth,omitempty"`
}

// OAuthProvider is one provider's settings. google and github need only ClientID and ClientSecret.
type OAuthProvider struct {
	Kind         string `json:"kind,omitempty"` // "oidc" or "github"; implied for google and github
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	AuthURL      string `json:"authUrl,omitempty"`
	TokenURL     string `json:"tokenUrl,omitempty"`
	JwksURL      string `json:"jwksUrl,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	UserURL      string `json:"userUrl,omitempty"`
	EmailsURL    string `json:"emailsUrl,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
}
type Backup struct {
	Endpoint     string `json:"endpoint,omitempty"`
	Bucket       string `json:"bucket,omitempty"`
	Prefix       string `json:"prefix,omitempty"`
	Region       string `json:"region,omitempty"`
	AccessKey    string `json:"accessKey,omitempty"`
	SecretKey    string `json:"secretKey,omitempty"`
	Passphrase   string `json:"passphrase,omitempty"`
	Interval     string `json:"interval,omitempty"`
	Compress     *bool  `json:"compress,omitempty"`
	CompactAfter string `json:"compactAfter,omitempty"`
	CompactEvery string `json:"compactEvery,omitempty"`
	Bootstrap    bool   `json:"bootstrap,omitempty"`
}
type Follow struct {
	Dir    string  `json:"dir,omitempty"`
	Bucket *Backup `json:"bucket,omitempty"`
	Poll   string  `json:"poll,omitempty"`
}
type Snapshot struct {
	LogBytes  any `json:"logBytes,omitempty"`  // "256MB" or bytes; 0 disables
	IdleAfter any `json:"idleAfter,omitempty"` // "30s" or milliseconds; 0 disables
}
type Listen struct {
	Socket string `json:"socket,omitempty"`
	TCP    string `json:"tcp,omitempty"`
	HTTP   string `json:"http,omitempty"` // the web console, served from this process; needs Token
	Token  string `json:"token,omitempty"`
}
type Live struct {
	Debounce string `json:"debounce,omitempty"`
	Queue    int    `json:"queue,omitempty"`
}
type Log struct {
	ThreadsIdleAfter string `json:"threadsIdleAfter,omitempty"`
	SyncDelay        string `json:"syncDelay,omitempty"` // with durable off: hold the background fsync this long so it covers more writes
}

// Open opens or creates the database directory; durable waits for the disk on every commit.
func Open(path string, durable bool) (*DB, error) { return OpenWith(path, Options{Durable: durable}) }

// OpenWith opens or creates the database directory with the given options. If ConfigFile names a TOML file it is read
// first and the options win. Nothing is read from the data directory itself. An existing directory is never wiped.
func OpenWith(path string, opts Options) (*DB, error) {
	js, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	cpath := C.CString(path)
	cjson := C.CString(string(js))
	defer C.free(unsafe.Pointer(cpath))
	defer C.free(unsafe.Pointer(cjson))
	p := C.sqzdb_open_with(cpath, cjson)
	if p == nil {
		return nil, errors.New(C.GoString(C.sqzdb_open_error()))
	}
	return &DB{p: p}, nil
}
func (db *DB) Close()            { C.sqzdb_close(db.p) }
func (db *DB) Snapshot() int64   { return int64(C.sqzdb_snapshot(db.p)) }
func (db *DB) lastError() error  { return errors.New(C.GoString(C.sqzdb_last_error(db.p))) }
func (db *DB) Session() *Session { return &Session{db: db, p: C.sqzdb_session(db.p)} }
func (s *Session) Close()        { C.sqzdb_session_free(s.p) }
func (db *DB) Prepare(sql string) (*Stmt, error) {
	cs := C.CString(sql)
	defer C.free(unsafe.Pointer(cs))
	p := C.sqzdb_prepare(db.p, cs)
	if p == nil {
		return nil, db.lastError()
	}
	return &Stmt{p: p}, nil
}
func (st *Stmt) Close() { C.sqzdb_finalize(st.p) }

// LastInsertID is the primary key of the last row this session inserted (an automatic id, or the one given).
func (s *Session) LastInsertID() int64 { return int64(C.sqzdb_last_insert_id(s.p)) }

func (s *Session) Login(user string) error {
	cu := C.CString(user)
	defer C.free(unsafe.Pointer(cu))
	if C.sqzdb_login(s.db.p, s.p, cu) != 0 {
		return s.db.lastError()
	}
	return nil
}

// Assume binds the session to an identity your application vouches for, after its own login: the roles, and the
// attributes row policies read (USING (tenant_id = SESSION.tenant)). Nothing about the user is stored in the database.
// Attribute values are numbers, strings (a UUID as its text) or booleans.
//
//	s := db.Session(); s.Assume([]string{"customer"}, map[string]any{"tenant": 42})
func (s *Session) Assume(roles []string, attrs map[string]any) error {
	b, err := json.Marshal(map[string]any{"roles": roles, "attrs": attrs})
	if err != nil {
		return err
	}
	cj := C.CString(string(b))
	defer C.free(unsafe.Pointer(cj))
	if C.sqzdb_assume(s.db.p, s.p, cj) != 0 {
		return s.db.lastError()
	}
	return nil
}

// UseToken makes the session act as the user a session token belongs to (from Auth.SignIn or Auth.SignUp): their role,
// and their row's columns as the attributes row policies read (SESSION.id). It fails for an unknown, signed-out, ended
// or expired token.
func (s *Session) UseToken(token string) error {
	ct := C.CString(token)
	defer C.free(unsafe.Pointer(ct))
	if C.sqzdb_use_token(s.db.p, s.p, ct) != 0 {
		return s.db.lastError()
	}
	return nil
}

// Auth signs users of one table in: a table marked ALTER TABLE <table> ENABLE AUTH. A password hash takes a few
// milliseconds; call these from your request goroutines.
type Auth struct {
	db    *DB
	table string
}

// SignedIn is a new session: its token, the user's row by column name (integers as int64), and whether this
// sign-in made the user (a sign-up, or a first sign-in with a provider).
type SignedIn struct {
	Token   string
	User    map[string]any
	Created bool
}

// Call runs one of the app's functions (deployed from a folder of .ts/.js modules, see the README) as this session.
// args is encoded as a JSON object (nil: none); the result is what the function returned, decoded from JSON with
// numbers as json.Number. An error reads "CODE: message".
func (s *Session) Call(name string, args any) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	cn, ca := C.CString(name), C.CString(string(b))
	defer C.free(unsafe.Pointer(cn))
	defer C.free(unsafe.Pointer(ca))
	p := C.sqzdb_call(s.db.p, s.p, cn, ca)
	if p == nil {
		return nil, s.db.lastError()
	}
	defer C.sqzdb_free_string(p)
	d := json.NewDecoder(strings.NewReader(C.GoString(p)))
	d.UseNumber()
	var v any
	err = d.Decode(&v)
	return v, err
}

// Auth returns the sign-in functions for a table marked ALTER TABLE <table> ENABLE AUTH.
func (db *DB) Auth(table string) *Auth { return &Auth{db: db, table: table} }

func (a *Auth) result(p *C.char) (SignedIn, error) {
	if p == nil {
		return SignedIn{}, a.db.lastError()
	}
	defer C.sqzdb_free_string(p)
	var out struct {
		Token   string                     `json:"token"`
		User    map[string]json.RawMessage `json:"user"`
		Created bool                       `json:"created"`
	}
	if err := json.Unmarshal([]byte(C.GoString(p)), &out); err != nil {
		return SignedIn{}, err
	}
	user := make(map[string]any, len(out.User))
	for k, raw := range out.User {
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			if i, err := n.Int64(); err == nil {
				user[k] = i
			} else if f, err := n.Float64(); err == nil {
				user[k] = f
			}
			continue
		}
		var v any
		_ = json.Unmarshal(raw, &v)
		user[k] = v
	}
	return SignedIn{Token: out.Token, User: user, Created: out.Created}, nil
}

// OAuthStart begins a sign-in with an OAuth provider configured as auth.oauth.<provider> (google, github, or any
// OpenID Connect provider). Keep cookie in an HttpOnly cookie of the browser and send the browser to url; the
// provider redirects it to redirectURI with a code and the state. With linkToken (a session token, or ""), the
// provider account is linked to that signed-in user.
func (a *Auth) OAuthStart(provider, redirectURI, linkToken string) (url, state, cookie string, err error) {
	ct, cp, cr := C.CString(a.table), C.CString(provider), C.CString(redirectURI)
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cr))
	var cl *C.char
	if linkToken != "" {
		cl = C.CString(linkToken)
		defer C.free(unsafe.Pointer(cl))
	}
	p := C.sqzdb_oauth_start(a.db.p, ct, cp, cr, cl)
	if p == nil {
		return "", "", "", a.db.lastError()
	}
	defer C.sqzdb_free_string(p)
	var out struct {
		URL    string `json:"url"`
		State  string `json:"state"`
		Cookie string `json:"cookie"`
	}
	if err := json.Unmarshal([]byte(C.GoString(p)), &out); err != nil {
		return "", "", "", err
	}
	return out.URL, out.State, out.Cookie, nil
}

// OAuthFinish finishes it with the code and state from the provider's redirect and the cookie from OAuthStart, read
// back from the browser: only the browser that started a sign-in can finish it.
func (a *Auth) OAuthFinish(provider, code, state, cookie string) (SignedIn, error) {
	ct, cp, cc, cs, ck := C.CString(a.table), C.CString(provider), C.CString(code), C.CString(state), C.CString(cookie)
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ck))
	return a.result(C.sqzdb_oauth_finish(a.db.p, ct, cp, cc, cs, ck))
}

// SignUp inserts a user (fields must include the login column) and sets their password.
func (a *Auth) SignUp(fields map[string]any, password string) (SignedIn, error) {
	b, err := json.Marshal(fields)
	if err != nil {
		return SignedIn{}, err
	}
	ct, cf, cp := C.CString(a.table), C.CString(string(b)), C.CString(password)
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(cf))
	defer C.free(unsafe.Pointer(cp))
	return a.result(C.sqzdb_sign_up(a.db.p, ct, cf, cp))
}

// SignIn checks a login and password and starts a session.
func (a *Auth) SignIn(login, password string) (SignedIn, error) {
	ct, cl, cp := C.CString(a.table), C.CString(login), C.CString(password)
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(cl))
	defer C.free(unsafe.Pointer(cp))
	return a.result(C.sqzdb_sign_in(a.db.p, ct, cl, cp))
}

// SignOut ends one session; an unknown token is not an error.
func (a *Auth) SignOut(token string) error {
	ct := C.CString(token)
	defer C.free(unsafe.Pointer(ct))
	if C.sqzdb_sign_out(a.db.p, ct) != 0 {
		return a.db.lastError()
	}
	return nil
}

// SetPassword sets a user's password by primary key (an int64 or a string) and ends all their sessions.
func (a *Auth) SetPassword(key any, password string) error {
	b, err := json.Marshal(key)
	if err != nil {
		return err
	}
	ct, ck, cp := C.CString(a.table), C.CString(string(b)), C.CString(password)
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(ck))
	defer C.free(unsafe.Pointer(cp))
	if C.sqzdb_set_password(a.db.p, ct, ck, cp) != 0 {
		return a.db.lastError()
	}
	return nil
}

// SignOutEverywhere ends every session of a user, by primary key.
func (a *Auth) SignOutEverywhere(key any) error {
	b, err := json.Marshal(key)
	if err != nil {
		return err
	}
	ct, ck := C.CString(a.table), C.CString(string(b))
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(ck))
	if C.sqzdb_sign_out_everywhere(a.db.p, ct, ck) != 0 {
		return a.db.lastError()
	}
	return nil
}

// marshal Go arguments into CValues; strings and byte slices point at Go memory, pinned for the duration of the call.
func args(a []any, pin *runtime.Pinner) ([]C.CValue, []any) {
	vals := make([]C.CValue, len(a))
	for i, v := range a {
		switch x := v.(type) {
		case nil:
			vals[i].tag = 0
		case int:
			vals[i].tag, vals[i].i = 1, C.longlong(x)
		case int64:
			vals[i].tag, vals[i].i = 1, C.longlong(x)
		case float64:
			vals[i].tag, vals[i].f = 2, C.double(x)
		case bool:
			vals[i].tag = 5
			if x {
				vals[i].i = 1
			}
		case string:
			vals[i].tag, vals[i].len = 3, C.size_t(len(x))
			if len(x) > 0 {
				p := unsafe.StringData(x)
				pin.Pin(p)
				vals[i].ptr = (*C.uchar)(unsafe.Pointer(p))
			}
		case []byte:
			vals[i].tag, vals[i].len = 4, C.size_t(len(x))
			if len(x) > 0 {
				pin.Pin(&x[0])
				vals[i].ptr = (*C.uchar)(unsafe.Pointer(&x[0]))
			}
		}
	}
	return vals, a
}
func collect(r *C.Rows) [][]any {
	n, m := int(C.sqzdb_rows_count(r)), int(C.sqzdb_rows_cols(r))
	out := make([][]any, n)
	if n == 0 || m == 0 {
		C.sqzdb_rows_free(r)
		return out
	}
	flat := make([]C.CValue, n*m)
	C.sqzdb_rows_all(r, &flat[0], C.int(len(flat)))
	for i := 0; i < n; i++ {
		row := make([]any, m)
		for j := 0; j < m; j++ {
			cv := flat[i*m+j]
			switch cv.tag {
			case 1:
				row[j] = int64(cv.i)
			case 2:
				row[j] = float64(cv.f)
			case 3:
				row[j] = C.GoStringN((*C.char)(unsafe.Pointer(cv.ptr)), C.int(cv.len))
			case 4:
				row[j] = C.GoBytes(unsafe.Pointer(cv.ptr), C.int(cv.len))
			case 5:
				row[j] = cv.i != 0
			}
		}
		out[i] = row
	}
	C.sqzdb_rows_free(r)
	return out
}

// Exec runs a prepared statement and returns all rows (empty for writes).
func (s *Session) Exec(st *Stmt, a ...any) ([][]any, error) {
	var pin runtime.Pinner
	defer pin.Unpin()
	vals, keep := args(a, &pin)
	var vp *C.CValue
	if len(vals) > 0 {
		pin.Pin(&vals[0])
		vp = &vals[0]
	}
	r := C.sqzdb_exec(s.db.p, s.p, st.p, vp, C.int(len(vals)))
	runtime.KeepAlive(keep)
	if r == nil {
		return nil, s.db.lastError()
	}
	return collect(r), nil
}

// ExecText runs SQL text (DDL, admin statements, one-off queries).
func (s *Session) ExecText(sql string, a ...any) ([][]any, error) {
	cs := C.CString(sql)
	defer C.free(unsafe.Pointer(cs))
	var pin runtime.Pinner
	defer pin.Unpin()
	vals, keep := args(a, &pin)
	var vp *C.CValue
	if len(vals) > 0 {
		pin.Pin(&vals[0])
		vp = &vals[0]
	}
	r := C.sqzdb_exec_text(s.db.p, s.p, cs, vp, C.int(len(vals)))
	runtime.KeepAlive(keep)
	if r == nil {
		return nil, s.db.lastError()
	}
	return collect(r), nil
}

// Subscription delivers the changes a SELECT would see, as rows [op, table, key, columns...]; op is 1 insert, 2 update, 3 delete.
type Subscription struct {
	db *DB
	p  *C.Sub
}

func (s *Session) Subscribe(sql string, a ...any) (*Subscription, error) {
	cs := C.CString(sql)
	defer C.free(unsafe.Pointer(cs))
	var pin runtime.Pinner
	defer pin.Unpin()
	vals, keep := args(a, &pin)
	var vp *C.CValue
	if len(vals) > 0 {
		pin.Pin(&vals[0])
		vp = &vals[0]
	}
	p := C.sqzdb_subscribe(s.db.p, s.p, cs, vp, C.int(len(vals)))
	runtime.KeepAlive(keep)
	if p == nil {
		return nil, s.db.lastError()
	}
	return &Subscription{db: s.db, p: p}, nil
}

// Next blocks up to timeout for an event; it returns (nil, nil) on timeout and an error when the subscription was dropped.
func (sub *Subscription) Next(timeoutMs int) ([]any, error) {
	var r *C.Rows
	switch C.sqzdb_sub_next(sub.p, C.int(timeoutMs), &r) {
	case 0:
		rows := collect(r)
		return rows[0], nil
	case 1:
		return nil, nil
	default:
		return nil, errors.New("sqzdb: subscription fell behind and was dropped; resubscribe")
	}
}
func (sub *Subscription) Close() { C.sqzdb_sub_free(sub.p) }
