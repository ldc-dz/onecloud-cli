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

// ExitCodeError preserves a native client's exit status without retaining its
// stderr, argv, environment, or *exec.ExitError.
type ExitCodeError struct{ Code int }

func (e *ExitCodeError) Error() string { return fmt.Sprintf("client exited with code %d", e.Code) }
func (e *ExitCodeError) ExitCode() int { return e.Code }

func client(engine sqlcmd.Engine) (name, hint string, err error) {
	switch engine {
	case sqlcmd.ClickHouseEngine:
		return "clickhouse-client", "install the ClickHouse native client (clickhouse-client) and add it to PATH", nil
	case sqlcmd.MSSQLEngine:
		return "sqlcmd", "install Microsoft sqlcmd (mssql-tools18 or the Go sqlcmd client) and add it to PATH", nil
	default:
		return "", "", errors.New("unsupported SQL client engine (use clickhouse or mssql)")
	}
}

// Discover finds the supported native client before callers open a tunnel or
// reveal credentials. Neither discovery nor version probing needs a password.
func Discover(engine sqlcmd.Engine) (string, error) {
	name, hint, err := client(engine)
	if err != nil {
		return "", err
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", &MissingClientError{Client: name, InstallHint: hint}
	}
	return path, nil
}

// Version probes the native client's self-reported version/help, with a five
// second deadline and bounded output. SQL Server's ODBC and Go clients both
// support -?; clickhouse-client supports --version. No minimum version is
// imposed here. The output is informational, not database readiness evidence.
func Version(ctx context.Context, engine sqlcmd.Engine, path string) (string, error) {
	if _, _, err := client(engine); err != nil {
		return "", err
	}
	arg := "--version"
	if engine == sqlcmd.MSSQLEngine {
		arg = "-?"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var output limitedBuffer
	if err := Run(ctx, path, []string{arg}, nil, nil, &output, &output); err != nil {
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

// Connect discovers the client, opens a tunnel, shows any compatibility
// notice, and runs the native client. Tunnel closure is guaranteed on success,
// build/notice failures, cancellation, and native exit errors. The listener's
// actual Port replaces Options.Port. Use Build/Discover/Run separately when a
// CLI needs to perform additional work before revealing credentials.
func Connect(ctx context.Context, engine sqlcmd.Engine, o sqlcmd.Options, open OpenTunnel, streams Streams) (err error) {
	if open == nil {
		return errors.New("Pomerium tunnel opener is required")
	}
	// Validate the managed values before creating any tunnel side effect.
	validation := o
	validation.Port = 1
	if _, err := sqlcmd.Build(engine, validation); err != nil {
		return err
	}
	path, err := Discover(engine)
	if err != nil {
		return err
	}
	tun, err := open(ctx)
	if err != nil {
		return errors.New("cannot open the Pomerium SQL tunnel")
	}
	if tun == nil {
		return errors.New("Pomerium SQL tunnel opener returned no listener")
	}
	defer func() {
		if closeErr := tun.Close(); closeErr != nil && err == nil {
			err = errors.New("cannot close the Pomerium SQL tunnel")
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
	return Run(ctx, path, invocation.Args, invocation.Env, streams.Stdin, streams.Stdout, streams.Stderr)
}
