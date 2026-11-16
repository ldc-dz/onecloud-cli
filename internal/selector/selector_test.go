package selector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// script feeds bytes; "\xff" stands for a read timeout with no input.
func script(s string) nextByte {
	i := 0
	return func() (byte, bool, error) {
		if i >= len(s) {
			return 0, false, io.ErrUnexpectedEOF
		}
		b := s[i]
		i++
		if b == 0xff {
			return 0, false, nil
		}
		return b, true, nil
	}
}

var items = []Item{{Label: "a"}, {Label: "b", Disabled: true}, {Label: "c"}, {Label: "d"}}

func TestRunNavigation(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want int
	}{
		"enter first":         {"\r", 0},
		"down skips disabled": {"\x1b[B\r", 2},
		"down twice":          {"\x1b[B\x1b[B\r", 3},
		"clamped at end":      {"jjjjj\r", 3},
		"up from end":         {"\x1b[F\x1b[A\r", 2},
		"home":                {"jj\x1b[H\n", 0},
		"ss3 arrows":          {"\x1bOB\r", 2},
		"timeouts ignored":    {"\xff\xffj\xff\r", 2},
		"unknown seq ignored": {"\x1b[3~x\r", 0},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := run(context.Background(), script(c.in), &out, "Pick", items)
			if err != nil || got != c.want {
				t.Fatalf("run(%q) = %d, %v; want %d", c.in, got, err, c.want)
			}
		})
	}
}

func TestRunCancelHasNoSelection(t *testing.T) {
	for _, in := range []string{"\x1b\xff", "\x1bx", "q", "\x03", "\x04", "j\x03"} {
		var out bytes.Buffer
		got, err := run(context.Background(), script(in), &out, "Pick", items)
		if !errors.Is(err, ErrCanceled) || got != -1 {
			t.Fatalf("cancel %q = %d, %v", in, got, err)
		}
		// The menu is erased and the cursor shown again.
		if s := out.String(); !strings.HasSuffix(s, "\x1b[J\x1b[?25h") {
			t.Fatalf("menu not cleaned up: %q", s)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := run(ctx, script("\r"), io.Discard, "", items); !errors.Is(err, ErrCanceled) {
		t.Fatalf("context cancel = %v", err)
	}
	if _, err := run(context.Background(), script(""), io.Discard, "", items); !errors.Is(err, ErrCanceled) {
		t.Fatalf("input error = %v", err)
	}
}

func TestNoChoiceAndLabelSanitising(t *testing.T) {
	if _, err := Select(context.Background(), "x", []Item{{Label: "a", Disabled: true}}); !errors.Is(err, ErrNoChoice) {
		t.Fatalf("all disabled = %v", err)
	}
	if _, err := Select(context.Background(), "x", nil); !errors.Is(err, ErrNoChoice) {
		t.Fatalf("empty = %v", err)
	}
	var out bytes.Buffer
	_, _ = run(context.Background(), script("\r"), &out, "t\x1b]0;evil\x07", []Item{{Label: "x\x1b[2Jy", Detail: "\u009b31m"}})
	if s := out.String(); strings.Contains(s, "\x1b]") || strings.Contains(s, "\x07") || strings.Contains(s, "\x1b[2Jy") || strings.Contains(s, "\u009b") || !strings.Contains(s, "x[2Jy") {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
}

// Without a controlling terminal Select must refuse rather than block or
// pick something. The opener is forced to fail so the result does not
// depend on whether the test runner has a terminal attached.
func TestSelectWithoutTTY(t *testing.T) {
	orig := openTerminal
	t.Cleanup(func() { openTerminal = orig })
	openTerminal = func() (*tty, error) { return nil, errors.New("no /dev/tty") }
	if _, err := Select(context.Background(), "x", items); !errors.Is(err, ErrNotInteractive) {
		t.Fatalf("no tty = %v", err)
	}
}
