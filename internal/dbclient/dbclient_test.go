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
		if len(args) == 1 && (args[0] == "--version" || args[0] == "-?") {
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
	self, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate test executable")
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal("cannot load test executable")
	}
	name, _, err := client(engine)
	if err != nil {
		t.Fatal("invalid fake client engine")
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
			if err != nil || found != path {
				t.Fatal("fake native client discovery failed")
			}
			version, err := Version(context.Background(), engine, found)
			if err != nil || version != "native test client 1.2.3" {
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
