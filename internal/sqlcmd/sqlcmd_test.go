package sqlcmd

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const secret = "unit-test-password-do-not-log"

func TestClickHouseNativeArgsAndEnvironment(t *testing.T) {
	extra := []string{"--query", "SELECT 'space and ; shell text'", "--format=JSONEachRow", ""}
	o := Options{Port: 19000, User: "report user", Password: secret, Database: "my database", Extra: extra}
	inv, err := ClickHouse(o)
	if err != nil {
		t.Fatal("valid ClickHouse options rejected")
	}
	want := []string{"--host", "127.0.0.1", "--port", "19000", "--user", "report user", "--database", "my database"}
	want = append(want, extra...)
	if inv.Name != "clickhouse-client" || !reflect.DeepEqual(inv.Args, want) {
		t.Fatal("ClickHouse native argv differs from expected loopback arguments")
	}
	if !reflect.DeepEqual(inv.Env, []string{"CLICKHOUSE_PASSWORD=" + secret}) {
		t.Fatal("ClickHouse password environment is incorrect")
	}
	if inv.Notice != "" || inv.Policy != "" {
		t.Fatal("ClickHouse emits an unwanted compatibility notice")
	}
	assertNoSecret(t, inv.Args)
	if !reflect.DeepEqual(extra, o.Extra) {
		t.Fatal("forwarded arguments were mutated")
	}
	// Changes to a result must not alias the caller's slice.
	inv.Args[len(inv.Args)-1] = "changed"
	if extra[len(extra)-1] != "" {
		t.Fatal("result arguments alias input arguments")
	}
}

func TestClickHouseDatabaseOptionalAndEmptyPassword(t *testing.T) {
	inv, err := Build(ClickHouseEngine, Options{Port: 1, User: "default"})
	if err != nil {
		t.Fatal("optional database and empty password rejected")
	}
	if !reflect.DeepEqual(inv.Args, []string{"--host", "127.0.0.1", "--port", "1", "--user", "default"}) {
		t.Fatal("unexpected optional database arguments")
	}
	if !reflect.DeepEqual(inv.Env, []string{"CLICKHOUSE_PASSWORD="}) {
		t.Fatal("empty managed password must override any inherited password")
	}
}

func TestMSSQLArgsAndTrustBypassNotice(t *testing.T) {
	extra := []string{"-Q", "SELECT 'keep spaces'", "-b", "-v", "name=a=b"}
	inv, err := MSSQL(Options{Port: 14330, User: "sql user", Password: secret, Database: "app db", Extra: extra})
	if err != nil {
		t.Fatal("valid SQL Server options rejected")
	}
	want := []string{"-S", "127.0.0.1,14330", "-U", "sql user", "-d", "app db", "-C"}
	want = append(want, extra...)
	if inv.Name != "sqlcmd" || !reflect.DeepEqual(inv.Args, want) {
		t.Fatal("SQL Server argv differs from expected loopback arguments")
	}
	if !reflect.DeepEqual(inv.Env, []string{"SQLCMDPASSWORD=" + secret}) {
		t.Fatal("SQL Server password environment is incorrect")
	}
	if inv.Policy != MSSQLTrustServerCertificate || inv.Notice != "" {
		t.Fatal("SQL Server trust bypass policy is not clearly disclosed")
	}
	assertNoSecret(t, inv.Args)
}

func TestValidationDoesNotDiscloseInput(t *testing.T) {
	cases := []Options{
		{Port: 0, User: "user", Password: secret},
		{Port: 65536, User: "user", Password: secret},
		{Port: 1234, User: " ", Password: secret},
		{Port: 1234, User: "user", Password: secret + "\x00"},
		{Port: 1234, User: "user\x00", Password: secret},
		{Port: 1234, User: "user", Password: secret, Database: "db\x00"},
		{Port: 1234, User: "user", Password: secret, Extra: []string{secret + "\x00"}},
	}
	for _, o := range cases {
		if _, err := ClickHouse(o); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatal("invalid ClickHouse options not safely rejected")
		}
	}
	if _, err := MSSQL(Options{Port: 1433, User: "user", Password: secret}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("missing SQL Server database not safely rejected")
	}
	if _, err := Build(Engine(secret), Options{}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("unknown engine not safely rejected")
	}
}

func TestFormattingRedactsCredentialsAndExtra(t *testing.T) {
	o := Options{Port: 1234, User: "user", Password: secret, Extra: []string{secret}}
	inv, err := ClickHouse(o)
	if err != nil {
		t.Fatal("valid options rejected")
	}
	for _, value := range []any{o, &o, inv, &inv} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, value), secret) {
				t.Fatal("formatted connection details exposed a credential")
			}
		}
	}
}

func assertNoSecret(t *testing.T, args []string) {
	t.Helper()
	for _, arg := range args {
		if strings.Contains(arg, secret) {
			t.Fatal("managed credential found in argv")
		}
	}
}
