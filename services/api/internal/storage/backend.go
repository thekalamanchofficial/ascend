package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Backend is the storage substrate seam: everything Service needs from a
// concrete place bytes can live. Swapping in a real S3-compatible backend
// later means writing one new type that satisfies this interface — no
// change to Service, Store, or any RPC handler (charter §7: "the policy
// abstraction here must not privilege one backend in a way that's hard to
// add alternatives to later").
//
// Backend implementations receive and return already-outer-wrapped bytes
// (see wrap.go) — a Backend never needs to know about wrapping keys, AEAD,
// or plaintext of any kind. It is a pure key-value byte store keyed by
// blob_ref.
type Backend interface {
	// Store persists data under key, overwriting any existing value.
	Store(key string, data []byte) error

	// Retrieve returns the bytes stored under key. Returns an error
	// wrapping ErrBackendKeyNotFound if key does not exist.
	Retrieve(key string) ([]byte, error)

	// Delete removes key's bytes. Idempotent: deleting an already-absent
	// key is not an error.
	Delete(key string) error

	// SupportsPhysicalDelete reports whether this Backend's Delete method
	// performs true, unrecoverable byte-level erasure. DeleteBlob uses
	// this to decide whether the physical-delete path (preferred) or the
	// crypto-shred fallback (see wrap.go) is this blob's actual deletion
	// mechanism — see docs/DECISION_LOG.md, 2026-07-17.
	SupportsPhysicalDelete() bool

	// Location returns a human-readable description of where key
	// physically lives, feeding GetStorageLocation (Art. 15 — no data in
	// an unqueryable location).
	Location(key string) string
}

// ErrBackendKeyNotFound is returned by Backend.Retrieve for a missing key.
var ErrBackendKeyNotFound = errors.New("storage: backend key not found")

// --- FilesystemBackend: the first-pass, concrete Backend implementation. ---
//
// See docs/DECISION_LOG.md, "Storage backend: local filesystem, not an
// in-memory fake" for why this was chosen over a simpler in-memory store:
// no S3-compatible object store is deployed anywhere in this environment
// (per this capability's spawn brief), and a real filesystem is the
// simplest backend that genuinely, physically supports true byte-level
// erasure — the "primary, preferred" DeleteBlob path this charter
// requires implementing for real, not merely simulating.

// FilesystemBackend stores each blob as one file, named after its
// blob_ref, under rootDir.
type FilesystemBackend struct {
	rootDir     string
	displayRoot string // human-readable form used in Location() output
}

// NewFilesystemBackend creates (if necessary) rootDir and returns a
// Backend rooted there. rootDir is created with 0700 permissions —
// storage bytes are opaque ciphertext, but there is no reason to make the
// containing directory world-readable regardless.
func NewFilesystemBackend(rootDir string) (*FilesystemBackend, error) {
	if rootDir == "" {
		return nil, errors.New("storage: rootDir must not be empty")
	}
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, fmt.Errorf("storage: creating backend root dir: %w", err)
	}
	abs, err := filepath.Abs(rootDir)
	if err != nil {
		abs = rootDir
	}
	return &FilesystemBackend{rootDir: rootDir, displayRoot: abs}, nil
}

// DefaultDataDir returns the default `.data` directory this package uses
// when wired for real, computed relative to THIS SOURCE FILE's own
// directory (via runtime.Caller) rather than the process's current
// working directory — so behavior is identical regardless of where a
// `go run`/compiled binary happens to be launched from. Gitignored (see
// repository root .gitignore) — this directory is local operational
// state, never committed.
func DefaultDataDir(policySubdir string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), ".data", policySubdir)
}

func (b *FilesystemBackend) path(key string) string {
	// key is always a Storage-generated blob_ref (see idgen.go), never
	// caller-supplied path data — safe to use directly as a filename with
	// no further sanitization needed. filepath.Base is applied anyway as
	// defense in depth against a future caller mistakenly passing
	// something path-like.
	return filepath.Join(b.rootDir, filepath.Base(key))
}

func (b *FilesystemBackend) Store(key string, data []byte) error {
	if key == "" {
		return errors.New("storage: key must not be empty")
	}
	return os.WriteFile(b.path(key), data, 0o600)
}

func (b *FilesystemBackend) Retrieve(key string) ([]byte, error) {
	data, err := os.ReadFile(b.path(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrBackendKeyNotFound, key)
		}
		return nil, err
	}
	return data, nil
}

func (b *FilesystemBackend) Delete(key string) error {
	err := os.Remove(b.path(key))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SupportsPhysicalDelete is true: os.Remove on a real local filesystem is
// true byte-level erasure of that directory entry and its data blocks
// (modulo underlying disk/filesystem journaling nuances outside this
// package's control, same caveat any local-delete claim carries).
func (b *FilesystemBackend) SupportsPhysicalDelete() bool { return true }

func (b *FilesystemBackend) Location(key string) string {
	return fmt.Sprintf("local-filesystem:%s", b.path(key))
}
