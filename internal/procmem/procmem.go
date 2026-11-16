// Package procmem holds secret values revealed by the portal in process
// memory only. A Values never prints, logs or serialises its content: every
// fmt verb, slog and JSON/text marshalling yields a redacted placeholder.
// Wipe zeroes the stored bytes once the caller no longer needs them.
//
// This is best effort: Go may keep transient copies (the decoded JSON
// string, a string returned by String) until the garbage collector reuses
// that memory. Nothing in this package ever writes a value to disk.
package procmem

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
)

// Redacted is what every printing or marshalling path shows instead of a value.
const Redacted = "[redacted]"

// ErrMissing means the key was not returned by the portal.
var ErrMissing = errors.New("value not returned by the portal")

// ErrWiped means the values were already wiped.
var ErrWiped = errors.New("revealed values already wiped")

// Values is a set of named secret values. The zero value is empty and usable.
type Values struct {
	mu    sync.Mutex
	m     map[string][]byte
	wiped bool
}

// New copies m into a fresh Values. The caller should drop its own map.
func New(m map[string]string) *Values {
	v := &Values{m: make(map[string][]byte, len(m))}
	for k, s := range m {
		v.m[k] = []byte(s)
	}
	return v
}

// Set stores a copy of b under key; the caller may zero b afterwards.
func (v *Values) Set(key string, b []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.m == nil {
		v.m = map[string][]byte{}
	}
	if old, ok := v.m[key]; ok {
		Zero(old)
	}
	v.m[key] = append([]byte(nil), b...)
	v.wiped = false
}

// Keys returns the sorted value names (names are not secret).
func (v *Values) Keys() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	keys := make([]string, 0, len(v.m))
	for k := range v.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Len is the number of stored values.
func (v *Values) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.m)
}

// Has reports whether key was returned.
func (v *Values) Has(key string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.m[key]
	return ok
}

// Use calls fn with the stored bytes of key. fn must not retain the slice.
func (v *Values) Use(key string, fn func([]byte) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.wiped {
		return ErrWiped
	}
	b, ok := v.m[key]
	if !ok {
		return fmt.Errorf("%w: %s", ErrMissing, key)
	}
	return fn(b)
}

// String returns a copy of key as a string, for APIs that only take strings
// (for example an environment variable of a child process). Prefer Use.
func (v *Values) String(key string) (string, error) {
	var s string
	err := v.Use(key, func(b []byte) error { s = string(b); return nil })
	return s, err
}

// Wipe zeroes and drops every value. Safe to call more than once.
func (v *Values) Wipe() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, b := range v.m {
		Zero(b)
		delete(v.m, k)
	}
	v.wiped = true
}

// Format redacts every fmt verb (%v, %+v, %#v, %s, %q, ...).
func (v *Values) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "procmem.Values{%s}", Redacted)
}

// LogValue redacts slog output.
func (v *Values) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalJSON never serialises a value.
func (v *Values) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText never serialises a value.
func (v *Values) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// Zero overwrites b with zero bytes.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
