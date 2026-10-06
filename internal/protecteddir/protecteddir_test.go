package protecteddir

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Mode assertions are skipped on Windows, matching the existing tests in
// internal/membership: only the owner-writable bit is meaningful there, so a
// chmod to 0700 still reports 0777 and the assertion would be about the platform
// rather than about this function.

// The container runtime creates a bind-mount directory as root 0755, so the
// interesting case is an existing permissive directory, not a missing one.
func TestEnsureTightensAnExistingPermissiveDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Ensure(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %o, want 700", info.Mode().Perm())
	}
}

func TestEnsureCreatesAMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state")

	if err := Ensure(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("path is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %o, want 700", info.Mode().Perm())
	}
}

// A symlink would make chmod tighten whatever it points at, so it is refused
// instead of followed.
func TestEnsureRejectsASymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}

	if err := Ensure(link); err == nil {
		t.Fatal("symlink was accepted")
	}
	info, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
		t.Fatalf("target mode changed to %o", info.Mode().Perm())
	}
}

// A relative NM_DATABASE_PATH such as "registry.db" gives filepath.Dir the value
// ".", so this path reaches Ensure whenever nobody configured a directory. It must
// not narrow the working directory, which creating a directory never did.
func TestEnsureRejectsTheCurrentDirectory(t *testing.T) {
	for _, path := range []string{".", "./", "registry.db/.."} {
		if err := Ensure(path); err == nil {
			t.Fatalf("%q was accepted", path)
		}
	}
}

// "/registry.db" gives filepath.Dir the filesystem root. Narrowing that would be
// far worse than the working directory, so it is refused as well. The check itself
// is platform independent; this only exercises the branch that can run here.
func TestEnsureRejectsTheRootDirectory(t *testing.T) {
	root := string(filepath.Separator)
	if err := Ensure(root); err == nil {
		t.Fatalf("%q was accepted", root)
	}
}
