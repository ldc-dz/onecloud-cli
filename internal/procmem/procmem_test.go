package procmem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestValuesNeverPrintOrSerialise(t *testing.T) {
	v := New(map[string]string{"password": "s3cr3t-value"})
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("reveal", "values", v)
	js, _ := json.Marshal(map[string]any{"v": v})
	txt, _ := v.MarshalText()
	for _, out := range []string{
		fmt.Sprint(v), fmt.Sprintf("%+v %#v %s %q", v, v, v, v), logs.String(), string(js), string(txt),
	} {
		if strings.Contains(out, "s3cr3t") || !strings.Contains(out, Redacted) {
			t.Fatalf("value leaked or not redacted: %q", out)
		}
	}
}

func TestUseStringAndWipe(t *testing.T) {
	v := New(map[string]string{"b": "2", "a": "1"})
	if got := v.Keys(); len(got) != 2 || got[0] != "a" {
		t.Fatalf("keys %v", got)
	}
	var held []byte
	if err := v.Use("a", func(b []byte) error { held = b; return nil }); err != nil {
		t.Fatal(err)
	}
	if s, err := v.String("b"); err != nil || s != "2" {
		t.Fatalf("String = %q, %v", s, err)
	}
	if _, err := v.String("zz"); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing key: %v", err)
	}
	v.Wipe()
	if held[0] != 0 {
		t.Fatal("Wipe did not zero the stored bytes")
	}
	if _, err := v.String("a"); !errors.Is(err, ErrWiped) || v.Len() != 0 {
		t.Fatalf("after wipe: %v len %d", err, v.Len())
	}
	v.Wipe() // idempotent
	var nilValues *Values
	nilValues.Wipe()
}

func TestSetCopiesInput(t *testing.T) {
	var v Values
	in := []byte("abc")
	v.Set("k", in)
	Zero(in)
	if s, _ := v.String("k"); s != "abc" {
		t.Fatalf("Set kept the caller's slice: %q", s)
	}
}
