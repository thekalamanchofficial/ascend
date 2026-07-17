package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemBackend_StoreRetrieveDelete(t *testing.T) {
	dir := t.TempDir()
	b, err := NewFilesystemBackend(dir)
	if err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}

	data := []byte("sealed opaque bytes")
	if err := b.Store("blob_abc", data); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := b.Retrieve("blob_abc")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("Retrieve mismatch: got %q, want %q", got, data)
	}

	if !b.SupportsPhysicalDelete() {
		t.Fatalf("FilesystemBackend must report SupportsPhysicalDelete() == true")
	}

	// Prove physical presence on disk before delete.
	onDisk := filepath.Join(dir, "blob_abc")
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("expected file to exist on disk before delete: %v", err)
	}

	if err := b.Delete("blob_abc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Prove the file is genuinely, physically gone — not merely
	// unreachable through this package's API.
	if _, err := os.Stat(onDisk); !os.IsNotExist(err) {
		t.Fatalf("expected file to be physically removed from disk after Delete, stat err: %v", err)
	}

	if _, err := b.Retrieve("blob_abc"); err == nil {
		t.Fatalf("expected Retrieve to fail after Delete")
	}
}

func TestFilesystemBackend_DeleteIsIdempotent(t *testing.T) {
	b, err := NewFilesystemBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}
	if err := b.Delete("never_stored"); err != nil {
		t.Fatalf("expected Delete on a never-stored key to be a no-op, got: %v", err)
	}
}

func TestFilesystemBackend_LocationIsHumanReadable(t *testing.T) {
	dir := t.TempDir()
	b, err := NewFilesystemBackend(dir)
	if err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}
	loc := b.Location("blob_xyz")
	if loc == "" {
		t.Fatalf("expected a non-empty human-readable location")
	}
}

func TestNewFilesystemBackend_CreatesRootDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "does", "not", "exist", "yet")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("test setup invariant broken: dir should not exist yet")
	}
	if _, err := NewFilesystemBackend(dir); err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("expected NewFilesystemBackend to create rootDir: %v", err)
	}
}
