package accounts

import (
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "sub", "accounts.json")}
	if _, ok := s.Get("h"); ok {
		t.Fatal("empty store returned a value")
	}
	if err := s.Set("h", "anis-fathallah"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("h2", "bob"); err != nil {
		t.Fatal(err)
	}
	if a, ok := s.Get("h"); !ok || a != "anis-fathallah" {
		t.Fatalf("got %q %v", a, ok)
	}
	if err := s.Forget("h"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("h"); ok {
		t.Fatal("forget did not remove")
	}
	if a, _ := s.Get("h2"); a != "bob" {
		t.Fatal("forget removed the wrong host")
	}
}
