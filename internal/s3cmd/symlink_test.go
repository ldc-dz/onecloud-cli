package s3cmd

import (
	"os"
	"runtime"
	"testing"
)

// mustSymlink creates a symlink or fails the test. Only Windows without
// Developer Mode or the SeCreateSymbolicLink privilege cannot create one;
// there the symlink-safety tests cannot run and are skipped explicitly.
func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks need Developer Mode on Windows: %v", err)
		}
		t.Fatalf("symlink %s -> %s: %v", newname, oldname, err)
	}
}
