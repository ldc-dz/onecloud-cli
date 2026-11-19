// Package dbclient discovers and runs native SQL clients, and coordinates their
// lifetime with a caller-owned Pomerium tunnel. It never logs command arguments,
// environment variables, or native-client output.
package dbclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/sqlcmd"
)

// MissingClientError gives actionable installation guidance without exposing
// command arguments or environment values.
type MissingClientError struct {
	Client      string
	InstallHint string
}

func (e *MissingClientError) Error() string {
	return e.Client + " not found on PATH: " + e.InstallHint
}

// WrongClientError reports a program that has the native client's name but
// is not that client (for example a third-party ClickHouse client renamed to
// clickhouse-client). Such a program ignores the options and environment ocd
// passes, so the database answers with a misleading authentication error.
type WrongClientError struct {
	Path        string
	Reported    string
	InstallHint string
}

func (e *WrongClientError) Error() string {
	reported := "it printed no version"
	if e.Reported != "" {
		reported = fmt.Sprintf("its --version output starts with %q", e.Reported)
	}
	return fmt.Sprintf("%s is not the official ClickHouse client (%s, expected \"ClickHouse client version ...\"): %s",
		e.Path, reported, e.InstallHint)
}

// ExitCodeError preserves a native client's exit status without retaining its
// stderr, argv, environment, or *exec.ExitError.
type ExitCodeError struct{ Code int }

func (e *ExitCodeError) Error() string { return fmt.Sprintf("client exited with code %d", e.Code) }
func (e *ExitCodeError) ExitCode() int { return e.Code }

// Native is a discovered native client: the executable and the arguments
// that select the client inside it. The official ClickHouse multi-call
// binary is run as `clickhouse client ...`, so its Prefix is ["client"].
type Native struct {
	Path   string
	Prefix []string
}

// Replaced in tests: the OS decides the guidance, and PATH the discovery.
var (
	hostOS   = runtime.GOOS
	lookPath = exec.LookPath
)

// candidate is one way to start a native client.
type candidate struct {
	name   string
	prefix []string
}

func candidates(engine sqlcmd.Engine) ([]candidate, error) {
	switch engine {
	case sqlcmd.ClickHouseEngine:
		// clickhouse-client is what the deb/rpm packages and
		// `clickhouse install` provide; `curl https://clickhouse.com/ | sh`
		// leaves only the multi-call binary, started as `clickhouse client`.
		return []candidate{{name: "clickhouse-client"}, {name: "clickhouse", prefix: []string{"client"}}}, nil
	case sqlcmd.MSSQLEngine:
		return []candidate{{name: "sqlcmd"}}, nil
	default:
		return nil, errors.New("unsupported SQL client engine (use clickhouse or mssql)")
	}
}

// InstallHint tells how to get the native client of engine on goos
// (a runtime.GOOS value). The ClickHouse commands are the ones of the
// official documentation (https://clickhouse.com/docs/install).
func InstallHint(engine sqlcmd.Engine, goos string) string {
	if engine == sqlcmd.MSSQLEngine {
		return "install Microsoft sqlcmd (mssql-tools18 or the Go sqlcmd client) and add it to PATH"
	}
	switch goos {
	case "windows":
		return "ClickHouse publishes no native Windows client. Use one of these routes: " +
			"(1) WSL 2: inside your Linux distribution install ocd and the ClickHouse client (curl https://clickhouse.com/ | sh), then run ocd clickhouse there; " +
			"(2) OneCloud Shell, opened from the portal, where ocd and the ClickHouse client are preinstalled; " +
			"(3) DBeaver with the OneCloud plugin"
	case "darwin":
		return "install the official ClickHouse client: run `curl https://clickhouse.com/ | sh`, which downloads the `clickhouse` program into the current folder, " +
			"then move it to a folder on PATH (for example /usr/local/bin); ocd runs it as `clickhouse client`. See https://clickhouse.com/docs/install"
	default:
		return "install the official ClickHouse client: run `curl https://clickhouse.com/ | sh`, which downloads the `clickhouse` program into the current folder, " +
			"then move it to a folder on PATH (for example ~/.local/bin); ocd runs it as `clickhouse client`. " +
			"On Debian/Ubuntu and RHEL you can instead add the ClickHouse package repository and install the clickhouse-client package. See https://clickhouse.com/docs/install"
	}
}

// Discover finds the supported native client before callers open a tunnel or
// reveal credentials. Neither discovery nor version probing needs a password.
func Discover(engine sqlcmd.Engine) (Native, error) {
	list, err := candidates(engine)
	if err != nil {
		return Native{}, err
	}
	for _, c := range list {
		if path, err := lookPath(c.name); err == nil {
			return Native{Path: path, Prefix: c.prefix}, nil
		}
	}
	return Native{}, &MissingClientError{Client: list[0].name, InstallHint: InstallHint(engine, hostOS)}
}

// Check discovers the native client and, for ClickHouse, proves with the
// version probe that the program found really is the ClickHouse client.
// Callers run it before any sign-in, tunnel or credential reveal.
func Check(ctx context.Context, engine sqlcmd.Engine) (Native, error) {
	native, err := Discover(engine)
	if err != nil {
		return Native{}, err
	}
	if engine != sqlcmd.ClickHouseEngine {
		return native, nil
	}
	// A probe that fails or prints nothing identifies nothing: report what
	// was found instead of handing it the database password.
	version, _ := Version(ctx, engine, native)
	if !IsClickHouseClient(version) {
		return Native{}, &WrongClientError{Path: native.Path, Reported: firstLine(version), InstallHint: InstallHint(engine, hostOS)}
	}
	return native, nil
}

// IsClickHouseClient reports whether version is the --version output of the
// ClickHouse client. Every build of it prints "ClickHouse client version
// <number>" first: official builds add " (official build).", Altinity ones
// " (altinity build).", distribution packages only a final dot. Other
// programs (chcli, usql, a server binary) do not start that way.
func IsClickHouseClient(version string) bool {
	const banner = "clickhouse client version "
	line := strings.ToLower(firstLine(version))
	if !strings.HasPrefix(line, banner) {
		return false
	}
	rest := line[len(banner):]
	return rest != "" && rest[0] >= '0' && rest[0] <= '9'
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// Version probes the native client's self-reported version/help, with a five
// second deadline and bounded output. SQL Server's ODBC and Go clients both
// support -?; clickhouse-client supports --version. No minimum version is
// imposed here. The output is informational, not database readiness evidence.
func Version(ctx context.Context, engine sqlcmd.Engine, native Native) (string, error) {
	if _, err := candidates(engine); err != nil {
		return "", err
	}
	arg := "--version"
	if engine == sqlcmd.MSSQLEngine {
		arg = "-?"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var output limitedBuffer
	args := append(append([]string{}, native.Prefix...), arg)
	if err := Run(ctx, native.Path, args, nil, nil, &output, &output); err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(output.data))
	if version == "" {
		return "", errors.New("native client returned no version information; verify its installation")
	}
	return version, nil
}

type limitedBuffer struct{ data []byte }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	const max = 64 * 1024
	n := len(p)
	if remaining := max - len(b.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

// Run executes a native path directly, never through a shell. Args are passed
// unchanged. Env supplies overrides, not a complete environment. Inherited
// CLICKHOUSE_* and SQLCMD* variables are removed first to avoid password
// collisions, endpoint/config overrides, and SQLCMDINI startup scripts.
// Nil streams discard output/use an empty input; no implicit logging occurs.
func Run(ctx context.Context, path string, args, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if path == "" || strings.ContainsRune(path, '\x00') {
		return errors.New("native client executable path is invalid")
	}
	for _, arg := range args {
		if strings.ContainsRune(arg, '\x00') {
			return errors.New("native client arguments must not contain NUL")
		}
	}
	childEnv, err := environment(env)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = childEnv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &ExitCodeError{Code: exit.ExitCode()}
		}
		// Do not retain the exec error: supplied paths/arguments may be
		// sensitive, and some system errors include them in their text.
		return errors.New("cannot start native SQL client; verify its executable path and permissions")
	}
	return nil
}

func environment(overrides []string) ([]string, error) {
	keys := make(map[string]bool, len(overrides))
	for _, entry := range overrides {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.ContainsRune(entry, '\x00') {
			return nil, errors.New("native client environment override is invalid")
		}
		keys[strings.ToUpper(key)] = true
	}
	result := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if strings.HasPrefix(key, "CLICKHOUSE_") || strings.HasPrefix(key, "SQLCMD") || keys[key] {
			continue
		}
		result = append(result, entry)
	}
	// Last override wins, with exactly one entry per key. The values never
	// appear in errors or logs.
	for i, entry := range overrides {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		last := true
		for _, later := range overrides[i+1:] {
			laterKey, _, _ := strings.Cut(later, "=")
			if strings.EqualFold(key, laterKey) {
				last = false
				break
			}
		}
		if last {
			result = append(result, entry)
		}
	}
	return result, nil
}

// Tunnel is the local endpoint supplied by an existing access-gateway helper.
// Close must stop the listener and release its resources.
type Tunnel interface {
	Port() int
	Close() error
}

// OpenTunnel starts a loopback-only Pomerium tunnel. Implementations must bind
// 127.0.0.1, not a wildcard interface. Connect does not select routes, authenticate
// to the portal, or reveal credentials; those remain caller responsibilities.
type OpenTunnel func(context.Context) (Tunnel, error)

// Streams are the native client's input/output and the separate compatibility
// notice destination. Notice may be nil for engines with no notice to show.
// It is never given environment variables or passwords.
type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Notice io.Writer
}

// Connect checks the client, opens a tunnel, shows any compatibility
// notice, and runs the native client. Tunnel closure is guaranteed on success,
// build/notice failures, cancellation, and native exit errors. The listener's
// actual Port replaces Options.Port. Use Build/Discover/Run separately when a
// CLI needs to perform additional work before revealing credentials.
func Connect(ctx context.Context, engine sqlcmd.Engine, o sqlcmd.Options, open OpenTunnel, streams Streams) (err error) {
	if open == nil {
		return errors.New("SQL tunnel opener is required")
	}
	// Validate the managed values before creating any tunnel side effect.
	validation := o
	validation.Port = 1
	if _, err := sqlcmd.Build(engine, validation); err != nil {
		return err
	}
	native, err := Check(ctx, engine)
	if err != nil {
		return err
	}
	tun, err := open(ctx)
	if err != nil {
		// The opener's error says what failed and what to do; it carries no
		// credential (none has been handed to it).
		return fmt.Errorf("cannot open the SQL tunnel: %w", err)
	}
	if tun == nil {
		return errors.New("SQL tunnel opener returned no listener")
	}
	defer func() {
		if closeErr := tun.Close(); closeErr != nil && err == nil {
			err = errors.New("cannot close the SQL tunnel")
		}
	}()
	o.Port = tun.Port()
	invocation, err := sqlcmd.Build(engine, o)
	if err != nil {
		return err
	}
	if invocation.Notice != "" {
		if streams.Notice == nil {
			return errors.New("SQL compatibility notice output is required")
		}
		if _, err := fmt.Fprintln(streams.Notice, invocation.Notice); err != nil {
			return errors.New("cannot display the SQL compatibility notice")
		}
	}
	args := append(append([]string{}, native.Prefix...), invocation.Args...)
	return Run(ctx, native.Path, args, invocation.Env, streams.Stdin, streams.Stdout, streams.Stderr)
}
