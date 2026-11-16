package cli

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"unicode/utf8"
)

// VerboseEnv carries -v to the ocd processes ssh starts (ocd tunnel).
const VerboseEnv = "OCD_VERBOSE"

func verbose() bool { return os.Getenv(VerboseEnv) == "1" }

// say prints a progress line for the user.
func say(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

// debugf prints a detail line only with -v.
func debugf(format string, a ...any) {
	if verbose() {
		fmt.Fprintf(os.Stderr, "debug: "+format+"\n", a...)
	}
}

// libOutput is where embedded libraries (opkssh, openpubkey) write their own
// messages: stderr with -v, nowhere otherwise.
func libOutput() io.Writer {
	if verbose() {
		return prefixWriter{w: os.Stderr, prefix: "debug: "}
	}
	return io.Discard
}

// prefixWriter prefixes every line written to it.
type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (p prefixWriter) Write(b []byte) (int, error) {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return len(b), nil
	}
	for _, line := range strings.Split(s, "\n") {
		if _, err := fmt.Fprintln(p.w, p.prefix+line); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// quietStdout runs fn with os.Stdout (and the standard logger) sent to
// libOutput: opkssh prints its progress straight to stdout.
func quietStdout(fn func() error) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fn()
	}
	orig := os.Stdout
	os.Stdout = w
	log.SetOutput(w)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(libOutput(), r)
		close(done)
	}()
	defer func() {
		os.Stdout = orig
		log.SetOutput(os.Stderr)
		_ = w.Close()
		<-done
		_ = r.Close()
	}()
	return fn()
}

// filterPomeriumNotice replaces pomerium-cli's "Your browser has been opened
// to visit: <long URL>" block (written straight to os.Stderr) with one short
// line, unless -v is set. It returns a function that restores os.Stderr.
func filterPomeriumNotice(host string) func() {
	if verbose() {
		return func() {}
	}
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyFiltered(r, orig, host)
	}()
	return func() {
		os.Stderr = orig
		_ = w.Close()
		<-done
		_ = r.Close()
	}
}

// copyFiltered copies lines from r to out, swallowing the pomerium-cli notice
// (its header line, the blank lines and the URL that follow). It always reads
// r to EOF: a writer behind the pipe (psql stderr) must never block because
// one line is too long to filter.
func copyFiltered(r io.Reader, out io.Writer, host string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	skipping := false
	defer func() {
		if sc.Err() != nil {
			// The over-long line was consumed into the buffer and dropped;
			// pass the rest through unfiltered.
			fmt.Fprintln(out, "ocd: (one over-long stderr line omitted)")
			_, _ = io.Copy(out, r)
		}
	}()
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Your browser has been opened to visit:") {
			fmt.Fprintf(out, "Authorizing access to %s (in your browser)\n", host)
			skipping = true
			continue
		}
		if skipping {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "http") {
				continue
			}
			skipping = false
		}
		fmt.Fprintln(out, line)
	}
}

// display escapes a server-supplied string (S3 key, portal label, error
// text) before it reaches the terminal: C0/C1 controls, DEL and bidi
// overrides become visible escapes, so a remote value can neither drive the
// terminal nor make two different keys print alike.
func display(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteString(`\ufffd`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		case (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
