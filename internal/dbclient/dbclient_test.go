package dbclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ldc-dz/onecloud-cli/internal/sqlcmd"
)

const testPassword = "native-client-test-secret-not-for-logs"

// TestMain turns a copy of this test binary into a cross-platform native client.
// Recorded argv/env remain in process memory only; failure messages never dump
// the record (and thus never print the test password).
func TestMain(m *testing.M) {
	if os.Getenv("DBCLIENT_TEST_HELPER") == "1" {
		args := os.Args[1:]
		// The multi-call ClickHouse binary is started as `clickhouse client`.
		if len(args) > 0 && args[0] == "client" && strings.HasPrefix(filepath.Base(os.Args[0]), "clickhouse") &&
			!strings.HasPrefix(filepath.Base(os.Args[0]), "clickhouse-client") {
			args = args[1:]
		} else if os.Getenv("DBCLIENT_TEST_MULTICALL") == "1" {
			_, _ = io.WriteString(os.Stderr, "multi-call binary started without its client argument\n")
			os.Exit(64)
		}
		if len(args) == 1 && args[0] == "--version" {
			banner := "ClickHouse client version 26.10.4.207 (official build)."
			if v, ok := os.LookupEnv("DBCLIENT_TEST_VERSION"); ok {
				banner = v
			}
			if banner != "" {
				_, _ = io.WriteString(os.Stdout, banner+"\n")
			}
			os.Exit(0)
		}
		if len(args) == 1 && args[0] == "-?" {
			_, _ = io.WriteString(os.Stdout, "native test client 1.2.3\n")
			os.Exit(0)
		}
		if code, _ := strconv.Atoi(os.Getenv("DBCLIENT_TEST_EXIT")); code != 0 {
			_, _ = io.WriteString(os.Stderr, "test client failure\n")
			os.Exit(code)
		}
		input, _ := io.ReadAll(os.Stdin)
		env := make(map[string]string)
		for _, entry := range os.Environ() {
			key, value, _ := strings.Cut(entry, "=")
			if strings.HasPrefix(strings.ToUpper(key), "CLICKHOUSE_") || strings.HasPrefix(strings.ToUpper(key), "SQLCMD") || key == "DBCLIENT_TEST_KEEP" {
				env[key] = value
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(record{Args: args, Env: env, Input: string(input)})
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type record struct {
	Args  []string
	Env   map[string]string
	Input string
}

func fakeClient(t *testing.T, engine sqlcmd.Engine) string {
	t.Helper()
	list, err := candidates(engine)
	if err != nil {
		t.Fatal("invalid fake client engine")
	}
	return fakeClientNamed(t, list[0].name)
}

// fakeClientNamed installs the fake client under name as the only program on PATH.
func fakeClientNamed(t *testing.T, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate test executable")
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal("cannot load test executable")
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal("cannot prepare fake client")
	}
	t.Setenv("DBCLIENT_TEST_HELPER", "1")
	t.Setenv("PATH", dir)
	return path
}

func readRecord(t *testing.T, out *bytes.Buffer) record {
	t.Helper()
	var got record
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal("fake client did not return a valid argv/env record")
	}
	return got
}

func TestRunRecordsVerbatimArgsAndSanitizedEnvironment(t *testing.T) {
	path := fakeClient(t, sqlcmd.ClickHouseEngine)
	t.Setenv("CLICKHOUSE_PASSWORD", "inherited-test-password")
	t.Setenv("CLICKHOUSE_HOST", "untrusted.invalid")
	t.Setenv("CLICKHOUSE_CONFIG", "startup-config")
	t.Setenv("SQLCMDPASSWORD", "inherited-sql-password")
	t.Setenv("SQLCMDINI", "untrusted-startup.sql")
	t.Setenv("SQLCMDSERVER", "untrusted.invalid")
	t.Setenv("SQLCMDUSER", "unexpected-user")
	t.Setenv("DBCLIENT_TEST_KEEP", "keep me")
	inv, err := sqlcmd.ClickHouse(sqlcmd.Options{
		Port: 19200, User: "native user", Database: "app db", Password: testPassword,
		Extra: []string{"--query", "SELECT 'spaces; $unchanged'", "--format=JSON", ""},
	})
	if err != nil {
		t.Fatal("cannot build test client options")
	}
	var out, stderr bytes.Buffer
	if err := Run(context.Background(), path, inv.Args, inv.Env, strings.NewReader("test input"), &out, &stderr); err != nil {
		t.Fatal("fake client launch failed")
	}
	got := readRecord(t, &out)
	if !reflect.DeepEqual(got.Args, inv.Args) || got.Input != "test input" {
		t.Fatal("native argv or stdin changed")
	}
	if !reflect.DeepEqual(got.Env, map[string]string{"CLICKHOUSE_PASSWORD": testPassword, "DBCLIENT_TEST_KEEP": "keep me"}) {
		t.Fatal("child environment did not isolate managed credentials and startup configuration")
	}
	if stderr.Len() != 0 {
		t.Fatal("runner produced unexpected stderr")
	}
	for _, arg := range got.Args {
		if strings.Contains(arg, testPassword) {
			t.Fatal("managed password exposed in process argv")
		}
	}
}

func TestRunMSSQLPasswordOnlyEnvironment(t *testing.T) {
	path := fakeClient(t, sqlcmd.MSSQLEngine)
	t.Setenv("SQLCMDPASSWORD", "old-test-password")
	inv, err := sqlcmd.MSSQL(sqlcmd.Options{Port: 14330, User: "sa", Database: "app", Password: testPassword, Extra: []string{"-Q", "SELECT 1", "-b"}})
	if err != nil {
		t.Fatal("cannot build SQL Server options")
	}
	var out bytes.Buffer
	if err := Run(context.Background(), path, inv.Args, inv.Env, nil, &out, nil); err != nil {
		t.Fatal("fake SQL Server launch failed")
	}
	got := readRecord(t, &out)
	if !reflect.DeepEqual(got.Args, inv.Args) || !reflect.DeepEqual(got.Env, map[string]string{"SQLCMDPASSWORD": testPassword}) {
		t.Fatal("SQL Server argv/environment differ from expected values")
	}
}

func TestEnvironmentLastOverrideWinsAndValidationRedacts(t *testing.T) {
	t.Setenv("SQLCMDPASSWORD", "old-test-password")
	env, err := environment([]string{"SQLCMDPASSWORD=first-test-password", "SQLCMDPASSWORD=" + testPassword})
	if err != nil {
		t.Fatal("valid environment rejected")
	}
	count := 0
	for _, entry := range env {
		if strings.HasPrefix(entry, "SQLCMDPASSWORD=") {
			count++
			if entry != "SQLCMDPASSWORD="+testPassword {
				t.Fatal("last override did not win")
			}
		}
	}
	if count != 1 {
		t.Fatal("password environment key was not unique")
	}
	for _, overrides := range [][]string{{testPassword}, {"=" + testPassword}, {"SECRET=" + testPassword + "\x00"}} {
		if _, err := environment(overrides); err == nil || strings.Contains(err.Error(), testPassword) {
			t.Fatal("invalid environment not safely rejected")
		}
	}
}

func TestDiscoveryMissingClientIsActionable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, engine := range []sqlcmd.Engine{sqlcmd.ClickHouseEngine, sqlcmd.MSSQLEngine} {
		_, err := Discover(engine)
		var missing *MissingClientError
		if !errors.As(err, &missing) || !strings.Contains(err.Error(), "install") || !strings.Contains(err.Error(), "PATH") {
			t.Fatal("missing client did not provide actionable installation guidance")
		}
	}
}

func TestDiscoverAndVersion(t *testing.T) {
	for _, engine := range []sqlcmd.Engine{sqlcmd.ClickHouseEngine, sqlcmd.MSSQLEngine} {
		t.Run(string(engine), func(t *testing.T) {
			path := fakeClient(t, engine)
			found, err := Discover(engine)
			if err != nil || found.Path != path || len(found.Prefix) != 0 {
				t.Fatal("fake native client discovery failed")
			}
			want := "native test client 1.2.3"
			if engine == sqlcmd.ClickHouseEngine {
				want = "ClickHouse client version 26.10.4.207 (official build)."
			}
			version, err := Version(context.Background(), engine, found)
			if err != nil || version != want {
				t.Fatal("fake native client version probe failed")
			}
		})
	}
}

func TestNativeExitCodeAndStderrArePreservedWithoutErrorLeak(t *testing.T) {
	path := fakeClient(t, sqlcmd.MSSQLEngine)
	t.Setenv("DBCLIENT_TEST_EXIT", "23")
	var stderr bytes.Buffer
	err := Run(context.Background(), path, []string{testPassword}, []string{"SQLCMDPASSWORD=" + testPassword}, nil, nil, &stderr)
	var exit *ExitCodeError
	if !errors.As(err, &exit) || exit.Code != 23 || exit.ExitCode() != 23 || err.Error() != "client exited with code 23" {
		t.Fatal("native exit status was not mapped to the exported safe error")
	}
	if strings.Contains(err.Error(), testPassword) || stderr.String() != "test client failure\n" {
		t.Fatal("runner leaked details or changed native stderr")
	}
}

func TestMissingExecutableAndCancellation(t *testing.T) {
	err := Run(context.Background(), filepath.Join(t.TempDir(), testPassword), nil, nil, nil, nil, nil)
	if err == nil || strings.Contains(err.Error(), testPassword) {
		t.Fatal("missing executable failure was not safe")
	}
	path := fakeClient(t, sqlcmd.ClickHouseEngine)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, path, nil, nil, nil, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled runner did not return the context error")
	}
}

type fakeTunnel struct {
	port   int
	closed bool
}

func (t *fakeTunnel) Port() int    { return t.port }
func (t *fakeTunnel) Close() error { t.closed = true; return nil }

func TestConnectNoticePortAndCleanup(t *testing.T) {
	fakeClient(t, sqlcmd.ClickHouseEngine)
	tun := &fakeTunnel{port: 19888}
	var out, notice bytes.Buffer
	open := func(context.Context) (Tunnel, error) { return tun, nil }
	err := Connect(context.Background(), sqlcmd.ClickHouseEngine,
		sqlcmd.Options{User: "default", Password: testPassword, Port: 9000}, open,
		Streams{Stdout: &out, Notice: &notice})
	if err != nil || !tun.closed {
		t.Fatal("connection failed or left its tunnel open")
	}
	got := readRecord(t, &out)
	if !reflect.DeepEqual(got.Args, []string{"--host", "127.0.0.1", "--port", "19888", "--user", "default"}) {
		t.Fatal("native client did not use allocated tunnel port")
	}
	if notice.String() != "" {
		t.Fatal("ClickHouse emitted an unwanted compatibility notice")
	}
	// The fake client records Env, including CLICKHOUSE_PASSWORD, in its
	// stdout; that's the point of the fixture, not a leak. Assert on the
	// parsed record rather than scanning the raw JSON.
	if _, hasPassword := got.Env["CLICKHOUSE_PASSWORD"]; !hasPassword {
		t.Fatal("managed password was not forwarded to the native client")
	}
}

func TestConnectMissingClientNoTunnelSideEffect(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	opened := false
	err := Connect(context.Background(), sqlcmd.ClickHouseEngine, sqlcmd.Options{User: "default"},
		func(context.Context) (Tunnel, error) { opened = true; return nil, nil }, Streams{Notice: io.Discard})
	var missing *MissingClientError
	if !errors.As(err, &missing) || opened {
		t.Fatal("missing native client caused a tunnel side effect")
	}
}

func TestConnectRequiresVisibleNoticeAndClosesOnFailures(t *testing.T) {
	fakeClient(t, sqlcmd.MSSQLEngine)
	for _, mode := range []string{"bad-port", "client-exit"} {
		t.Run(mode, func(t *testing.T) {
			tun := &fakeTunnel{port: 14330}
			opened := false
			streams := Streams{Notice: io.Discard}
			switch mode {
			case "bad-port":
				tun.port = 0
			case "client-exit":
				t.Setenv("DBCLIENT_TEST_EXIT", "17")
			}
			err := Connect(context.Background(), sqlcmd.MSSQLEngine, sqlcmd.Options{User: "sa", Database: "app", Password: testPassword},
				func(context.Context) (Tunnel, error) { opened = true; return tun, nil }, streams)
			if err == nil || strings.Contains(err.Error(), testPassword) {
				t.Fatal("connection failure was not safely propagated")
			}
			if !opened || !tun.closed {
				t.Fatal("connection failure left tunnel open")
			}
		})
	}
}

// UAT 2026-11 CH-PORTAL-02: `curl https://clickhouse.com/ | sh` installs only
// the multi-call binary, which is the ClickHouse client as `clickhouse client`.
func TestDiscoverAcceptsMultiCallClickHouseBinary(t *testing.T) {
	path := fakeClientNamed(t, "clickhouse")
	t.Setenv("DBCLIENT_TEST_MULTICALL", "1")
	found, err := Check(context.Background(), sqlcmd.ClickHouseEngine)
	if err != nil {
		t.Fatalf("the multi-call clickhouse binary was not accepted: %v", err)
	}
	if found.Path != path || !reflect.DeepEqual(found.Prefix, []string{"client"}) {
		t.Fatalf("got %q with prefix %q, want %q started as `clickhouse client`", found.Path, found.Prefix, path)
	}
	tun := &fakeTunnel{port: 19777}
	var out bytes.Buffer
	err = Connect(context.Background(), sqlcmd.ClickHouseEngine,
		sqlcmd.Options{User: "default", Password: testPassword, Extra: []string{"--query", "SELECT 1"}},
		func(context.Context) (Tunnel, error) { return tun, nil }, Streams{Stdout: &out})
	if err != nil {
		t.Fatalf("connect through the multi-call binary: %v", err)
	}
	// The fake strips the leading "client" exactly as the real binary does.
	got := readRecord(t, &out)
	if !reflect.DeepEqual(got.Args, []string{"--host", "127.0.0.1", "--port", "19777", "--user", "default", "--query", "SELECT 1"}) {
		t.Fatal("the multi-call binary did not get the managed arguments after `client`")
	}
}

func TestDiscoverPrefersClickHouseClientOverMultiCall(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"clickhouse-client", "clickhouse"} {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	found, err := Discover(sqlcmd.ClickHouseEngine)
	if err != nil || !strings.HasPrefix(filepath.Base(found.Path), "clickhouse-client") || len(found.Prefix) != 0 {
		t.Fatalf("got %+v, %v; want clickhouse-client with no prefix", found, err)
	}
}

func TestIsClickHouseClient(t *testing.T) {
	for banner, want := range map[string]bool{
		// Official Linux and macOS builds, and the multi-call binary.
		"ClickHouse client version 26.10.4.207 (official build).":  true,
		"ClickHouse client version 24.5.1.117 (official build).\n": true,
		// Altinity and distribution builds.
		"ClickHouse client version 23.8.8.21.altinitystable (altinity build).": true,
		"ClickHouse client version 18.16.1.":                                   true,
		"ClickHouse client version 22.2.2.1.\r\n":                              true,
		// Not the client: the third-party client of the UAT, other programs
		// of the same family, an error text, nothing.
		"chcli 0.2.0": false,
		"ClickHouse local version 26.10.4.207 (official build).":  false,
		"ClickHouse server version 26.10.4.207 (official build).": false,
		"clickhouse-cli, version 0.3.9":                           false,
		"ClickHouse client version unknown":                       false,
		"usage: clickhouse client version --help":                 false,
		"error: ClickHouse client version 1.2 missing":            false,
		"": false,
	} {
		if got := IsClickHouseClient(banner); got != want {
			t.Errorf("IsClickHouseClient(%q) = %v, want %v", banner, got, want)
		}
	}
}

// UAT 2026-11 CH-PORTAL-02 (Windows): a third-party client put on PATH as
// clickhouse-client ignored CLICKHOUSE_PASSWORD and the server answered
// "Authentication failed". It must be refused before any tunnel is opened.
func TestCheckRejectsNonOfficialClickHouseClient(t *testing.T) {
	for _, banner := range []string{"chcli 0.2.0", ""} {
		t.Run("banner="+banner, func(t *testing.T) {
			path := fakeClient(t, sqlcmd.ClickHouseEngine)
			t.Setenv("DBCLIENT_TEST_VERSION", banner)
			_, err := Check(context.Background(), sqlcmd.ClickHouseEngine)
			var wrong *WrongClientError
			if !errors.As(err, &wrong) {
				t.Fatalf("a program that is not the ClickHouse client was accepted: %v", err)
			}
			if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "not the official ClickHouse client") {
				t.Fatalf("the message must name the program found: %v", err)
			}
			if banner != "" && !strings.Contains(err.Error(), banner) {
				t.Fatalf("the message must quote what the program printed: %v", err)
			}
			opened := false
			err = Connect(context.Background(), sqlcmd.ClickHouseEngine, sqlcmd.Options{User: "default", Password: testPassword},
				func(context.Context) (Tunnel, error) { opened = true; return &fakeTunnel{port: 1}, nil }, Streams{})
			if !errors.As(err, &wrong) || opened {
				t.Fatal("a non official client must stop the connection before the tunnel opens")
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Fatal("the refusal leaked the password")
			}
		})
	}
}

func TestCheckDoesNotProbeSQLCmdIdentity(t *testing.T) {
	path := fakeClient(t, sqlcmd.MSSQLEngine)
	found, err := Check(context.Background(), sqlcmd.MSSQLEngine)
	if err != nil || found.Path != path {
		t.Fatalf("sqlcmd check: %+v, %v", found, err)
	}
}

// UAT 2026-11 CH-ANY-CLI-03: the guidance depends on the OS, and on Windows
// it must not send the user to a client that does not exist.
func TestMissingClickHouseClientMessagePerOS(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for goos, want := range map[string][]string{
		"windows": {"no native Windows client", "WSL 2", "OneCloud Shell", "DBeaver", "curl https://clickhouse.com/ | sh"},
		"linux":   {"curl https://clickhouse.com/ | sh", "clickhouse client", "clickhouse-client package", "https://clickhouse.com/docs/install"},
		"darwin":  {"curl https://clickhouse.com/ | sh", "clickhouse client", "https://clickhouse.com/docs/install"},
	} {
		t.Run(goos, func(t *testing.T) {
			old := hostOS
			hostOS = goos
			t.Cleanup(func() { hostOS = old })
			_, err := Check(context.Background(), sqlcmd.ClickHouseEngine)
			var missing *MissingClientError
			if !errors.As(err, &missing) {
				t.Fatalf("want a missing client error, got %v", err)
			}
			if !strings.HasPrefix(err.Error(), "clickhouse-client not found on PATH: ") {
				t.Fatalf("message must start with what is missing: %v", err)
			}
			for _, w := range want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%s message lacks %q: %v", goos, w, err)
				}
			}
			if goos == "windows" && strings.Contains(err.Error(), "install the ClickHouse native client") {
				t.Errorf("the Windows message still asks for a native client: %v", err)
			}
			if goos != "windows" && (strings.Contains(err.Error(), "WSL") || strings.Contains(err.Error(), "Windows")) {
				t.Errorf("%s message talks about Windows: %v", goos, err)
			}
			if strings.ContainsAny(err.Error(), "\u2013\u2014") {
				t.Errorf("dash in message: %v", err)
			}
		})
	}
	if hint := InstallHint(sqlcmd.MSSQLEngine, "windows"); !strings.Contains(hint, "sqlcmd") || strings.Contains(hint, "ClickHouse") {
		t.Fatalf("sqlcmd guidance changed: %s", hint)
	}
}

func TestWrongClientMessageGivesWindowsRoute(t *testing.T) {
	path := fakeClient(t, sqlcmd.ClickHouseEngine)
	t.Setenv("DBCLIENT_TEST_VERSION", "chcli 0.2.0")
	old := hostOS
	hostOS = "windows"
	t.Cleanup(func() { hostOS = old })
	_, err := Check(context.Background(), sqlcmd.ClickHouseEngine)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "WSL 2") || !strings.Contains(err.Error(), `"chcli 0.2.0"`) {
		t.Fatalf("got %v", err)
	}
}
