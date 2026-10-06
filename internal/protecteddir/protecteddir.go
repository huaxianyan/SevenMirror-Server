// Package protecteddir creates a directory when missing and narrows it to 0700.
//
// It exists because the container runtime creates bind-mount directories as root
// with mode 0755, so os.MkdirAll alone leaves an existing directory world
// readable. Both callers handle local state that another account on the host has
// no reason to read: the registry directory and the workspace backup directory.
package protecteddir

import (
	"fmt"
	"os"
	"path/filepath"
)

// Ensure makes path exist as a directory owned by the caller and readable only by
// the caller. A symlink is rejected, because chmod would otherwise follow it and
// tighten a different directory.
//
// A root or relative-self path is rejected too. Both are reachable by accident: a
// relative NM_DATABASE_PATH such as "registry.db" yields ".", and
// "/registry.db" yields the filesystem root. Narrowing either would change a
// directory the deployment does not own, which creating a directory with 0700
// never did.
func Ensure(path string) error {
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return fmt.Errorf(
			"refuse to narrow %q: it resolves to the current or root directory, not a state directory",
			path)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a directory, not a symbolic link", path)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect %s: %w", path, err)
	}
	return nil
}
