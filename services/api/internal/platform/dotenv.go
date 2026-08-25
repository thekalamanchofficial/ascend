package platform

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// LoadDotEnv is a local-dev convenience only: it searches upward from the
// current working directory for a .env file (so `go run .` behaves the same
// whether invoked from services/api/ or from the repo root, or anywhere in
// between) and, for each KEY=VALUE line found, sets that variable in the
// process environment -- but ONLY if the process doesn't already have a
// value for that key. A real environment variable (CI, a real deployment, a
// shell export) always wins over .env; .env only fills gaps a developer
// hasn't set another way.
//
// In any real deployment there is no .env file at all -- it's gitignored,
// see .env.example's header comment -- so this is a silent no-op there.
// ConfigFromEnv's required-variable check remains the single source of
// truth for what configuration is actually required; this just saves a
// local developer from re-exporting the same values into every shell.
//
// Errors reading a found .env file are logged, not fatal: a malformed or
// unreadable .env should surface as ConfigFromEnv's missing-variable error
// (naming exactly what's still missing), not an opaque crash from this
// convenience step.
func LoadDotEnv() {
	path, err := findDotEnv()
	if err != nil || path == "" {
		return // no .env found above cwd -- fine, e.g. in any real deployment.
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("platform: found %s but could not open it: %v", path, err)
		return
	}
	defer f.Close()

	loaded := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)

		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue // a real environment variable always wins over .env.
		}
		if err := os.Setenv(key, value); err == nil {
			loaded++
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("platform: error reading %s: %v", path, err)
		return
	}
	if loaded > 0 {
		log.Printf("platform: loaded %d variable(s) from %s", loaded, path)
	}
}

// findDotEnv walks upward from the current working directory looking for a
// file named .env, stopping as soon as one is found or once it reaches the
// filesystem root -- the same way tools like git locate a repo root. This
// is what makes `go run .` work unchanged from services/api/ (where the Go
// module lives) even though .env sits at the repo root.
func findDotEnv() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, ".env")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil // reached filesystem root without finding one.
		}
		dir = parent
	}
}
