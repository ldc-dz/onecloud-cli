package s3cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const testBucket = "published.bucket"

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	c, err := New(Config{EndpointURL: server.URL, Region: "test-region-1", Bucket: testBucket, AccessKey: "synthetic-access", SecretKey: "synthetic-secret", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func listXML(keys []string, truncated bool, token string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>%t</IsTruncated>`, truncated)
	for _, key := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>3</Size></Contents>", key)
	}
	if token != "" {
		fmt.Fprintf(&b, "<NextContinuationToken>%s</NextContinuationToken>", token)
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

func TestConfigRequiresManagedHTTPS(t *testing.T) {
	for _, endpoint := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test/path", "https://example.test?token=x", "https://example.test#secret", "file:///tmp/file", ""} {
		_, err := New(Config{EndpointURL: endpoint, Region: "r", Bucket: "b", AccessKey: "a", SecretKey: "s"})
		if err == nil {
			t.Errorf("accepted unsafe endpoint %q", endpoint)
		}
	}
	_, err := New(Config{EndpointURL: "https://example.test", Region: "r", Bucket: "b", AccessKey: "a"})
	if err == nil {
		t.Fatal("accepted missing in-memory credentials")
	}
}

func TestListPaginationLiteralPrefixAndSigning(t *testing.T) {
	calls := 0
	prefix := "docs/a b+#%/"
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/"+testBucket {
			t.Errorf("not path style: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("prefix") != prefix || r.URL.Query().Get("list-type") != "2" {
			t.Error("literal prefix/list type not preserved")
		}
		if !strings.Contains(r.Header.Get("Authorization"), "/test-region-1/s3/aws4_request") || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("missing SigV4 region signing")
		}
		w.Header().Set("Content-Type", "application/xml")
		if calls == 1 {
			io.WriteString(w, listXML([]string{prefix + "a.txt"}, true, "p2+/="))
			return
		}
		if r.URL.Query().Get("continuation-token") != "p2+/=" {
			t.Error("opaque continuation token changed")
		}
		io.WriteString(w, listXML([]string{prefix + "sub/b.txt"}, false, ""))
	})
	objects, err := c.List(context.Background(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(objects) != 2 || objects[0].Key != prefix+"a.txt" {
		t.Fatalf("bad listing: calls=%d objects=%v", calls, objects)
	}
}

func TestListFailureDiscardsPartialManifest(t *testing.T) {
	for _, mode := range []string{"malformed", "repeated", "missing-token", "missing-status", "http403", "outside", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			calls, deletes := 0, 0
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					deletes++
					return
				}
				calls++
				w.Header().Set("Content-Type", "application/xml")
				if calls == 1 {
					io.WriteString(w, listXML([]string{"docs/a"}, true, "same"))
					return
				}
				switch mode {
				case "malformed":
					io.WriteString(w, "<ListBucketResult><")
				case "repeated":
					io.WriteString(w, listXML([]string{"docs/b"}, true, "same"))
				case "missing-token":
					io.WriteString(w, listXML([]string{"docs/b"}, true, ""))
				case "missing-status":
					io.WriteString(w, "<ListBucketResult/>")
				case "http403":
					w.WriteHeader(403)
					io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>synthetic-secret</Message></Error>")
				case "outside":
					io.WriteString(w, listXML([]string{"docs-old/x"}, false, ""))
				case "duplicate":
					io.WriteString(w, listXML([]string{"docs/a"}, false, ""))
				}
			})
			plan, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true, Yes: true})
			if err == nil || plan != nil || deletes != 0 {
				t.Fatalf("failed listing allowed deletion: err=%v deletes=%d", err, deletes)
			}
			if strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("service error leaked credentials")
			}
		})
	}
}

func TestGetLiteralKeyPrivateAtomicDestination(t *testing.T) {
	key := "folder/../a b+#%.txt"
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/"+testBucket+"/"+key {
			t.Errorf("literal key changed: %q", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("method %s", r.Method)
		}
		io.WriteString(w, "complete object")
	})
	dir := t.TempDir()
	dest := filepath.Join(dir, "download")
	if err := c.Get(context.Background(), key, dest, false); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(dest)
	if err != nil || string(content) != "complete object" {
		t.Fatalf("content=%q err=%v", content, err)
	}
	info, _ := os.Stat(dest)
	if info.Mode().Perm() != 0600 {
		t.Errorf("download mode %o", info.Mode().Perm())
	}
	if err := c.Get(context.Background(), key, dest, false); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite allowed: %v", err)
	}
	if calls != 1 {
		t.Error("existing destination caused network request")
	}
	if err := c.Get(context.Background(), key, dest, true); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leaked temporary downloads: %v", entries)
	}
}

func TestGetFailureLeavesDestinationAndCleansTemp(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999")
		io.WriteString(w, "incomplete")
	})
	dir := t.TempDir()
	dest := filepath.Join(dir, "download")
	os.WriteFile(dest, []byte("old"), 0600)
	if err := c.Get(context.Background(), "key", dest, true); err == nil {
		t.Fatal("partial download reported success")
	}
	content, _ := os.ReadFile(dest)
	if string(content) != "old" {
		t.Fatal("failed get destroyed existing file")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Error("partial temporary file remained")
	}
}

func TestGetNoOverwriteRace(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "download")
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := os.WriteFile(dest, []byte("concurrent"), 0600); err != nil {
			t.Error(err)
		}
		io.WriteString(w, "remote")
	})
	if err := c.Get(context.Background(), "key", dest, false); !errors.Is(err, ErrExists) {
		t.Fatalf("concurrent destination overwritten: %v", err)
	}
	content, _ := os.ReadFile(dest)
	if string(content) != "concurrent" {
		t.Fatal("concurrent destination not preserved")
	}
}

func TestGetDoesNotFollowDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	dest := filepath.Join(dir, "output")
	os.WriteFile(victim, []byte("untouched"), 0600)
	mustSymlink(t, victim, dest)
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "new") })
	if err := c.Get(context.Background(), "key", dest, false); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), "key", dest, true); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(victim)
	if string(content) != "untouched" {
		t.Fatal("symlink victim modified")
	}
	content, _ = os.ReadFile(dest)
	if string(content) != "new" {
		t.Fatal("symlink not replaced with downloaded file")
	}
}

func TestPutAtomicNoOverwrite(t *testing.T) {
	source := filepath.Join(t.TempDir(), "input")
	os.WriteFile(source, []byte("upload"), 0600)
	key := "literal/../a b+#%"
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "PUT" || r.URL.Path != "/"+testBucket+"/"+key {
			t.Errorf("bad literal PUT: %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "upload" {
			t.Error("body changed")
		}
		if calls == 1 {
			if r.Header.Get("If-None-Match") != "*" {
				t.Error("missing atomic overwrite precondition")
			}
			w.WriteHeader(412)
			io.WriteString(w, "<Error><Code>PreconditionFailed</Code><Message>synthetic-secret</Message></Error>")
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			t.Error("explicit overwrite was conditional")
		}
	})
	if err := c.Put(context.Background(), key, source, false); !errors.Is(err, ErrExists) {
		t.Fatalf("existing key not refused: %v", err)
	}
	if err := c.Put(context.Background(), key, source, true); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected PUT only, got %d calls", calls)
	}
}

func TestPutDoesNotFollowSymlinksOrDirectories(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	os.WriteFile(source, []byte("private"), 0600)
	link := filepath.Join(dir, "link")
	mustSymlink(t, source, link)
	parentLink := filepath.Join(dir, "parent-link")
	mustSymlink(t, dir, parentLink)
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	for _, path := range []string{link, filepath.Join(parentLink, "source"), dir} {
		if err := c.Put(context.Background(), "key", path, false); err == nil {
			t.Errorf("unsafe source accepted: %s", path)
		}
	}
	if calls != 0 {
		t.Fatal("unsafe source reached network")
	}
}

func TestPutPermissionDeniedFailsClosed(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	os.WriteFile(source, []byte("data"), 0600)
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(403)
		io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>synthetic-secret</Message></Error>")
	})
	err := c.Put(context.Background(), "key", source, false)
	if err == nil || calls != 1 {
		t.Fatalf("403 did not fail closed: calls=%d err=%v", calls, err)
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("server error leaked secret")
	}
}

func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	calls := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer target.Close()
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+"/stolen", 307) })
	_, err := c.List(context.Background(), "")
	if err == nil || calls != 0 {
		t.Fatalf("redirect followed: calls=%d err=%v", calls, err)
	}
}

func TestRemovalValidation(t *testing.T) {
	invalid := []RemoveOptions{
		{}, {Key: "/", Yes: true}, {Key: ".", Yes: true}, {Key: "..", Yes: true}, {Key: "folder/", Yes: true}, {Key: "key", Recursive: true, Yes: true},
		{Key: "key", Prefix: "docs/", Recursive: true, Yes: true}, {Prefix: "docs/", Yes: true},
		{Prefix: "docs", Recursive: true, Yes: true}, {Prefix: "/", Recursive: true, Yes: true},
		{Prefix: "///", Recursive: true, Yes: true}, {Prefix: "../", Recursive: true, Yes: true},
		{Key: "key"}, {Prefix: "docs/", Recursive: true},
	}
	for _, o := range invalid {
		if err := ValidateRemoval(o); err == nil {
			t.Errorf("accepted unsafe removal %+v", o)
		}
	}
	for _, o := range []RemoveOptions{{Key: "literal ../* key", Yes: true}, {Key: "key", DryRun: true}, {Prefix: "docs/", Recursive: true, Yes: true}, {Prefix: "docs/a b+#%/", Recursive: true, DryRun: true}} {
		if err := ValidateRemoval(o); err != nil {
			t.Errorf("literal safe removal refused %+v: %v", o, err)
		}
	}
}

func TestRecursiveRemovalFrozenManifest(t *testing.T) {
	var mu sync.Mutex
	events := []string{}
	deleted := []string{}
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "DELETE" {
			if r.URL.Query().Has("versionId") {
				t.Error("version/history purge requested")
			}
			key := strings.TrimPrefix(r.URL.Path, "/"+testBucket+"/")
			deleted = append(deleted, key)
			events = append(events, "delete:"+key)
			return
		}
		if r.Method != "GET" || r.URL.Query().Has("versions") {
			t.Error("unexpected bulk/history operation")
		}
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Get("continuation-token") == "" {
			events = append(events, "list1")
			io.WriteString(w, listXML([]string{"docs/a"}, true, "p2+/="))
			return
		}
		events = append(events, "list2")
		io.WriteString(w, listXML([]string{"docs/b"}, false, ""))
	})
	plan, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true, Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	keys := plan.Keys()
	keys[0] = "outside/mutated"
	if len(deleted) != 0 {
		t.Fatal("prepare performed deletion")
	}
	result, err := plan.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, []string{"docs/a", "docs/b"}) || !reflect.DeepEqual(deleted, result) {
		t.Fatalf("manifest mutated: %v %v", result, deleted)
	}
	if !reflect.DeepEqual(events, []string{"list1", "list2", "delete:docs/a", "delete:docs/b"}) {
		t.Fatalf("delete before frozen enumeration: %v", events)
	}
	if _, err := plan.Execute(context.Background()); err == nil {
		t.Fatal("plan reusable")
	}
}

func TestDryRunAndUnconfirmedNeverDelete(t *testing.T) {
	calls, deletes := 0, 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "DELETE" {
			deletes++
			return
		}
		io.WriteString(w, listXML([]string{"docs/a"}, false, ""))
	})
	if _, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true}); !errors.Is(err, ErrConfirmation) {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("unconfirmed removal accessed network")
	}
	plan, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true, DryRun: true, Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if deletes != 0 {
		t.Fatal("dry-run deleted objects")
	}
}

func TestDeletionFailureReportsPartialNotSuccess(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			io.WriteString(w, listXML([]string{"docs/a", "docs/b", "docs/c"}, false, ""))
			return
		}
		calls++
		if calls == 2 {
			w.WriteHeader(403)
			io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>synthetic-secret</Message></Error>")
		}
	})
	plan, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true, Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := plan.Execute(context.Background())
	if err == nil || !reflect.DeepEqual(deleted, []string{"docs/a"}) || calls != 2 {
		t.Fatalf("partial delete reported success: %v %v", deleted, err)
	}
}

func TestListMoreThanOneThousandObjects(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		keys := []string{}
		if calls == 1 {
			for i := 0; i < 1000; i++ {
				keys = append(keys, fmt.Sprintf("docs/%d", i))
			}
			io.WriteString(w, listXML(keys, true, url.QueryEscape("opaque+/=")))
			return
		}
		io.WriteString(w, listXML([]string{"docs/1000"}, false, ""))
	})
	plan, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true, DryRun: true})
	if err != nil || len(plan.Keys()) != 1001 || calls != 2 {
		t.Fatalf("pagination incomplete: err=%v calls=%d", err, calls)
	}
}

func TestPromptConfirmationReusesFrozenManifest(t *testing.T) {
	lists, deletes := 0, 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deletes++
			return
		}
		lists++
		io.WriteString(w, listXML([]string{"docs/a"}, false, ""))
	})
	plan, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan.ExecuteConfirmed(context.Background(), false); !errors.Is(err, ErrConfirmation) {
		t.Fatal(err)
	}
	if deletes != 0 {
		t.Fatal("negative answer deleted objects")
	}
	result, err := plan.ExecuteConfirmed(context.Background(), true)
	if err != nil || len(result) != 1 || deletes != 1 || lists != 1 {
		t.Fatalf("confirmation did not use frozen manifest: lists=%d deletes=%d err=%v", lists, deletes, err)
	}
}

func TestListURLKeyEncodingIsNotFormOrPathNormalization(t *testing.T) {
	key := "docs/a b+#%/../control\x01"
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("encoding-type") != "url" {
			t.Error("not requesting safe XML key encoding")
		}
		io.WriteString(w, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>`+url.PathEscape(key)+`</Key><Size>0</Size></Contents></ListBucketResult>`)
	})
	objects, err := c.List(context.Background(), "docs/")
	if err != nil || len(objects) != 1 || objects[0].Key != key {
		t.Fatalf("literal key decoding failed: objects=%v err=%v", objects, err)
	}
}

func TestConfigFormattingRedactsCredentials(t *testing.T) {
	c := Config{EndpointURL: "https://synthetic-endpoint-secret", Region: "synthetic-region-secret", Bucket: "synthetic-bucket-secret", AccessKey: "synthetic-access-secret", SecretKey: "synthetic-secret-key"}
	for _, value := range []any{c, &c} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, "synthetic-") || !strings.Contains(output, "redacted") {
				t.Fatalf("Config formatting did not redact using %s", format)
			}
		}
	}
}

func TestDryRunPreviewDoesNotConsumeFrozenPlan(t *testing.T) {
	lists, deletes := 0, 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deletes++
			return
		}
		lists++
		io.WriteString(w, listXML([]string{"docs/a"}, false, ""))
	})
	plan, err := c.PrepareRemoval(context.Background(), RemoveOptions{Prefix: "docs/", Recursive: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := plan.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if deletes != 0 {
		t.Fatal("preview deleted objects")
	}
	result, err := plan.ExecuteConfirmed(context.Background(), true)
	if err != nil || len(result) != 1 || deletes != 1 || lists != 1 {
		t.Fatalf("preview consumed frozen manifest: lists=%d deletes=%d err=%v", lists, deletes, err)
	}
	if _, err := plan.ExecuteConfirmed(context.Background(), true); err == nil {
		t.Fatal("destructive plan reused")
	}
}
