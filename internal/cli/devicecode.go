package cli

import (
	"bytes"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// issuerHost returns the host[:port] of an OAuth issuer URL, "" if invalid.
func issuerHost(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" {
		return ""
	}
	return u.Host
}

// libpq (PostgreSQL 18) prints the OAuth device prompt on stderr and never
// opens a browser itself. The completed URI (code pre-filled) is not printed,
// so ocd builds it the way Keycloak accepts it: <verification_uri>?user_code=.
var devicePrompt = regexp.MustCompile(`Visit (https?://\S+) and enter the code: (\S+)`)

// deviceCodeWriter passes psql's stderr through unchanged and opens the
// sign-in page, code pre-filled, the first time the device prompt appears
// (like aws sso login). open is nil when the browser is disabled.
//
// psql's stderr also carries server messages (NOTICE, RAISE), so a prompt-like
// line is not trusted on its own: only an https page on allowedHost (the
// configured OAuth issuer) is opened. With allowedHost empty nothing opens.
type deviceCodeWriter struct {
	out         io.Writer
	open        func(string)
	allowedHost string
	mu          sync.Mutex
	line        []byte
	opened      bool
}

func (w *deviceCodeWriter) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.open == nil || w.opened {
		return n, err
	}
	w.line = append(w.line, p...)
	for {
		i := bytes.IndexByte(w.line, '\n')
		if i < 0 {
			break
		}
		w.scan(w.line[:i])
		w.line = w.line[i+1:]
	}
	// Only whole lines are matched, so a code split across writes is never
	// opened truncated (libpq ends the prompt with a newline).
	if len(w.line) > 4096 {
		w.line = nil
	}
	return n, err
}

func (w *deviceCodeWriter) scan(line []byte) {
	if w.opened {
		return
	}
	if m := devicePrompt.FindSubmatch(line); m != nil {
		if u := deviceURL(string(m[1]), string(m[2]), w.allowedHost); u != "" {
			w.opened = true
			w.open(u)
		}
	}
}

// deviceURL adds user_code to the verification URI; "" when it is not an
// https URL on allowedHost.
func deviceURL(verification, code, allowedHost string) string {
	u, err := url.Parse(verification)
	if err != nil || u.Scheme != "https" || u.Host == "" || allowedHost == "" || !strings.EqualFold(u.Host, allowedHost) {
		return ""
	}
	q := u.Query()
	q.Set("user_code", code)
	u.RawQuery = q.Encode()
	return u.String()
}
