package browser

import (
	"reflect"
	"testing"
	"time"
)

func TestCommandArgs(t *testing.T) {
	got := CommandArgs("firefox --new-tab", "https://x/y?a=1&b=2")
	want := []string{"firefox", "--new-tab", "https://x/y?a=1&b=2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("append: %v", got)
	}
	got = CommandArgs("hyprctl dispatch exec [workspace 9 silent] brave {url}", "https://u")
	if got[len(got)-1] != "https://u" || len(got) != 8 {
		t.Fatalf("template: %v", got)
	}
}

func TestNewPrefersEnv(t *testing.T) {
	t.Setenv(EnvCommand, "none")
	if o := New("firefox"); !o.Disabled() {
		t.Fatalf("OCD_BROWSER must win over the config: %+v", o)
	}
}

func TestParseHyprActive(t *testing.T) {
	if a := parseHyprActive([]byte(`{"address":"0x55d1","class":"kitty"}`)); a != "0x55d1" {
		t.Fatalf("got %q", a)
	}
	if a := parseHyprActive([]byte("Invalid")); a != "" {
		t.Fatalf("got %q", a)
	}
}

func TestRestoreGivesFocusBack(t *testing.T) {
	active := "term"
	steps := 0
	var restored []string
	f := focus{
		active: func() string {
			steps++
			if steps == 2 { // the browser raises itself once
				active = "browser"
			}
			return active
		},
		focus: func(w string) { restored = append(restored, w); active = w },
	}
	start := time.Now()
	f.restore("term", 3*time.Second)
	if !reflect.DeepEqual(restored, []string{"term"}) || active != "term" {
		t.Fatalf("restored %v, active %s", restored, active)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("restore must return once the focus is stable")
	}
}

func TestHelperMainIgnoresNormalArgs(t *testing.T) {
	t.Setenv(HelperEnv, "1")
	if ok, _ := HelperMain([]string{"ssh", "x/y"}, ""); ok {
		t.Fatal("a normal command must not be taken as a helper call")
	}
	t.Setenv(HelperEnv, "")
	if ok, _ := HelperMain([]string{"https://x"}, ""); ok {
		t.Fatal("without the helper marker a URL argument is a normal command")
	}
}
