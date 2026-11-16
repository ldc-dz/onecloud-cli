package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestCopyFilteredHidesPomeriumNotice(t *testing.T) {
	in := "Your browser has been opened to visit:\n\nhttps://access.example/.pomerium/sign_in?x=1\n\nreal error\n"
	var out bytes.Buffer
	copyFiltered(bytes.NewBufferString(in), &out, "vm-ssh-1.tcp.example:443")
	want := "Authorizing access to vm-ssh-1.tcp.example:443 (in your browser)\nreal error\n"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}

func TestLibOutputQuietUnlessVerbose(t *testing.T) {
	t.Setenv(VerboseEnv, "")
	if verbose() {
		t.Fatal("verbose without OCD_VERBOSE")
	}
	t.Setenv(VerboseEnv, "1")
	if !verbose() {
		t.Fatal("OCD_VERBOSE=1 must enable verbose")
	}
}

func TestCopyFilteredKeepsDrainingAfterOverlongLine(t *testing.T) {
	long := strings.Repeat("x", 2<<20)
	r, w := io.Pipe()
	var out bytes.Buffer
	done := make(chan struct{})
	go func() { copyFiltered(r, &out, "h"); close(done) }()
	wrote := make(chan error, 1)
	go func() {
		_, err := io.WriteString(w, "before\n"+long+"\nafter\n")
		_ = w.Close()
		wrote <- err
	}()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer blocked: the filter stopped reading")
	}
	<-done
	if !strings.HasPrefix(out.String(), "before\n") || !strings.HasSuffix(out.String(), "after\n") {
		t.Fatalf("lines around the long one lost: %q...%q", out.String()[:20], out.String()[len(out.String())-20:])
	}
}

func TestDisplayEscapesTerminalControls(t *testing.T) {
	cases := map[string]string{
		"reports/jan.pdf":            "reports/jan.pdf",
		"a\x1b]0;PWNED\x07":          `a\x1b]0;PWNED\x07`,
		"x\r\x1b[2K":                 `x\x0d\x1b[2K`,
		"c1\u009b31m":                `c1\x9b31m`,
		"bidi\u202egpj.exe":          `bidi\u202egpj.exe`,
		`back\x1b`:                   `back\\x1b`,
		"caf\u00e9/\u6587\u4ef6.txt": "caf\u00e9/\u6587\u4ef6.txt",
	}
	for in, want := range cases {
		if got := display(in); got != want {
			t.Errorf("display(%q) = %q, want %q", in, got, want)
		}
		for _, r := range display(in) {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
				t.Errorf("display(%q) still has control %U", in, r)
			}
		}
	}
}
