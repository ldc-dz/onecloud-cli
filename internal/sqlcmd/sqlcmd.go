// Package sqlcmd builds native SQL client invocations for loopback connections
// carried by the OneCloud Pomerium tunnel. It never puts managed passwords in
// argv, logs them, or persists them.
package sqlcmd

import (
	"errors"
	"strconv"
	"strings"
)

// Engine identifies a supported native client.
type Engine string

const (
	ClickHouseEngine Engine = "clickhouse"
	MSSQLEngine      Engine = "mssql"

	// MSSQLTrustServerCertificate deliberately skips database certificate
	// verification (-C). It is not full server-identity verification.
	MSSQLTrustServerCertificate = "mssql-trust-server-certificate-compatibility"
)

// Options contains process-memory connection information. Port must be the
// loopback listener's port, not the remote database's service port. Extra is
// forwarded verbatim after the managed arguments; callers must not log it or
// populate it from portal/catalog data. User-supplied native options can override
// managed connection arguments and send the credential to that chosen target.
// Password is provided to the native client only through its environment. The
// child environment remains readable to the same OS user and root.
// Never log Options, its fields, or wrappers containing it: formatting methods
// are defensive only, and fmt bypasses them for unexported wrapper fields.
type Options struct {
	Port     int
	User     string
	Password string
	Database string
	Extra    []string
}

// String and GoString keep accidental formatting from exposing credentials or
// forwarded arguments (which may themselves contain user-supplied secrets).
func (Options) String() string     { return "sqlcmd.Options{connection details redacted}" }
func (o Options) GoString() string { return o.String() }

// Invocation is a prepared native-client launch. Env holds only overrides;
// dbclient.Run merges them into a sanitized inherited environment. Policy
// records an engine compatibility decision. Notice is optional and shown
// before launch only when nonempty.
// Args and Env must never be logged. All fields are retained in memory only.
// Never format wrappers containing Invocation; fmt can bypass its defensive
// redaction methods when it is held in an unexported field.
type Invocation struct {
	Name   string
	Args   []string
	Env    []string
	Policy string
	Notice string
}

func (Invocation) String() string     { return "sqlcmd.Invocation{arguments and environment redacted}" }
func (i Invocation) GoString() string { return i.String() }

// Build constructs an invocation without discovering or executing the client.
func Build(engine Engine, o Options) (Invocation, error) {
	switch engine {
	case ClickHouseEngine:
		return ClickHouse(o)
	case MSSQLEngine:
		return MSSQL(o)
	default:
		return Invocation{}, errors.New("unsupported SQL client engine (use clickhouse or mssql)")
	}
}

// ClickHouse uses clickhouse-client's native TCP protocol, not its HTTP
// interface. It adds no --secure flag and emits no compatibility notice.
func ClickHouse(o Options) (Invocation, error) {
	if err := validate(o); err != nil {
		return Invocation{}, err
	}
	args := []string{"--host", "127.0.0.1", "--port", strconv.Itoa(o.Port), "--user", o.User}
	if o.Database != "" {
		args = append(args, "--database", o.Database)
	}
	args = append(args, o.Extra...)
	return Invocation{
		Name: "clickhouse-client", Args: args,
		Env: []string{"CLICKHOUSE_PASSWORD=" + o.Password},
	}, nil
}

// MSSQL deliberately trusts the SQL Server certificate (-C), as approved for
// the Pomerium tunnel compatibility path. Notice discloses the trust bypass.
func MSSQL(o Options) (Invocation, error) {
	if err := validate(o); err != nil {
		return Invocation{}, err
	}
	if o.Database == "" {
		return Invocation{}, errors.New("SQL Server database is required")
	}
	args := []string{"-S", "127.0.0.1," + strconv.Itoa(o.Port), "-U", o.User, "-d", o.Database, "-C"}
	args = append(args, o.Extra...)
	return Invocation{
		Name: "sqlcmd", Args: args,
		Env:    []string{"SQLCMDPASSWORD=" + o.Password},
		Policy: MSSQLTrustServerCertificate,
	}, nil
}

func validate(o Options) error {
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("SQL client loopback port must be between 1 and 65535")
	}
	if strings.TrimSpace(o.User) == "" {
		return errors.New("SQL client username is required")
	}
	for _, value := range []string{o.User, o.Password, o.Database} {
		if strings.ContainsRune(value, '\x00') {
			return errors.New("SQL connection values must not contain NUL")
		}
	}
	for _, arg := range o.Extra {
		if strings.ContainsRune(arg, '\x00') {
			return errors.New("SQL client arguments must not contain NUL")
		}
	}
	return nil
}
