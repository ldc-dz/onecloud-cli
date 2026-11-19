package s3cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func noBackoff(t *testing.T) {
	t.Helper()
	old := getBackoff
	getBackoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() { getBackoff = old })
}

// cutServer serves object like a gateway that dies mid-transfer: the first
// `cuts` responses announce the full length, send part of it and drop the
// connection. Ranged requests are honoured.
type cutServer struct {
	mu       sync.Mutex
	object   []byte
	etag     string
	cuts     int
	requests []http.Header
}

func (s *cutServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Header.Clone())
	cut := len(s.requests) <= s.cuts
	s.mu.Unlock()
	start := 0
	if rng := r.Header.Get("Range"); rng != "" {
		start, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rng, "bytes="), "-"))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(s.object)-1, len(s.object)))
	}
	if s.etag != "" {
		w.Header().Set("ETag", s.etag)
	}
	body := s.object[start:]
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if start > 0 {
		w.WriteHeader(http.StatusPartialContent)
	}
	if cut {
		w.Write(body[:len(body)/3])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	w.Write(body)
}

func (s *cutServer) seen() []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.requests...)
}

func testObject() []byte {
	object := make([]byte, 3<<20)
	for i := range object {
		object[i] = byte(i*7 + i>>11)
	}
	return object
}

// UAT S3-ANY-CLI-05: the gateway restarted during a 100 MiB download and the
// command failed although the same command passed seconds later.
func TestGetResumesTransferCutByTheGateway(t *testing.T) {
	noBackoff(t)
	server := &cutServer{object: testObject(), etag: `"v1"`, cuts: 2}
	c := testClient(t, server.handle)
	dir := t.TempDir()
	dest := filepath.Join(dir, "download")
	if err := c.Get(context.Background(), "big.bin", dest, false); err != nil {
		t.Fatalf("interrupted transfer was not resumed: %v", err)
	}
	content, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(content, server.object) {
		t.Fatalf("resumed download differs from the object (len %d, err %v)", len(content), err)
	}
	requests := server.seen()
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want 3", len(requests))
	}
	if requests[0].Get("Range") != "" || requests[0].Get("If-Match") != "" {
		t.Errorf("first request must be a plain GET: %v", requests[0])
	}
	for _, h := range requests[1:] {
		if !strings.HasPrefix(h.Get("Range"), "bytes=") || h.Get("Range") == "bytes=0-" || h.Get("If-Match") != `"v1"` {
			t.Errorf("resume must be a ranged request bound to the first ETag: Range=%q If-Match=%q", h.Get("Range"), h.Get("If-Match"))
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("leaked temporary downloads: %v", entries)
	}
}

func TestGetGivesUpAfterBoundedAttemptsAndNamesTheTransfer(t *testing.T) {
	noBackoff(t)
	server := &cutServer{object: testObject(), etag: `"v1"`, cuts: 1000}
	c := testClient(t, server.handle)
	dir := t.TempDir()
	dest := filepath.Join(dir, "download")
	err := c.Get(context.Background(), "big.bin", dest, false)
	if err == nil || !strings.Contains(err.Error(), "transfer interrupted after") || strings.Contains(err.Error(), "local write") {
		t.Fatalf("error must name the interrupted transfer only: %v", err)
	}
	if n := len(server.seen()); n != getAttempts {
		t.Errorf("requests = %d, want %d", n, getAttempts)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("failed download left files: %v", entries)
	}
}

func TestGetDoesNotResumeWithoutETag(t *testing.T) {
	noBackoff(t)
	server := &cutServer{object: testObject(), cuts: 1}
	c := testClient(t, server.handle)
	if err := c.Get(context.Background(), "big.bin", filepath.Join(t.TempDir(), "download"), false); err == nil {
		t.Fatal("transfer without ETag reported success")
	}
	if n := len(server.seen()); n != 1 {
		t.Errorf("requests = %d: a resume without ETag cannot prove the object is unchanged", n)
	}
}

func TestGetResumeRefusesAChangedObject(t *testing.T) {
	noBackoff(t)
	server := &cutServer{object: testObject(), etag: `"v1"`, cuts: 1}
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Match") != "" {
			server.mu.Lock()
			server.requests = append(server.requests, r.Header.Clone())
			server.mu.Unlock()
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		server.handle(w, r)
	})
	dir := t.TempDir()
	err := c.Get(context.Background(), "big.bin", filepath.Join(dir, "download"), false)
	if err == nil || !strings.Contains(err.Error(), "changed during the download") {
		t.Fatalf("changed object must stop the download: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("mixed download left files: %v", entries)
	}
}

func TestGetResumeRefusesAnAnswerThatIsNotTheRequestedRange(t *testing.T) {
	noBackoff(t)
	server := &cutServer{object: testObject(), etag: `"v1"`, cuts: 1}
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("Range") // a gateway that ignores Range sends the whole object again
		server.handle(w, r)
	})
	dir := t.TempDir()
	err := c.Get(context.Background(), "big.bin", filepath.Join(dir, "download"), false)
	if err == nil || !strings.Contains(err.Error(), "did not resume") {
		t.Fatalf("full body appended to a partial file: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("failed download left files: %v", entries)
	}
}

func TestGetRetriesWhileTheGatewayIsUnavailable(t *testing.T) {
	noBackoff(t)
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("complete object"))
	})
	dest := filepath.Join(t.TempDir(), "download")
	if err := c.Get(context.Background(), "key", dest, false); err != nil {
		t.Fatalf("503 from a restarting gateway was not retried: %v", err)
	}
	if content, _ := os.ReadFile(dest); string(content) != "complete object" {
		t.Fatalf("content=%q", content)
	}
}

func TestGetDoesNotRetryRefusals(t *testing.T) {
	noBackoff(t)
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		calls := 0
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) })
		err := c.Get(context.Background(), "key", filepath.Join(t.TempDir(), "download"), false)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) || calls != 1 {
			t.Errorf("status %d: err=%v calls=%d", status, err, calls)
		}
	}
}

func TestGetNamesALocalWriteFailure(t *testing.T) {
	noBackoff(t)
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("complete object"))
	})
	file, err := os.Create(filepath.Join(t.TempDir(), "closed"))
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	err = c.download(context.Background(), "key", file)
	if err == nil || !strings.HasPrefix(err.Error(), "write downloaded file:") || strings.Contains(err.Error(), "S3") {
		t.Fatalf("local write failure reported as a transfer problem: %v", err)
	}
	if calls != 1 {
		t.Errorf("local write failure retried %d time(s)", calls-1)
	}
}
