// Package detect resolves the ssh, mosh, and et binaries a host has installed.
package detect

import (
	"fmt"
	"os/exec"
	"sync"
)

// Binary identifies one of the three client programs warp can drive.
type Binary string

const (
	SSH  Binary = "ssh"
	Mosh Binary = "mosh"
	ET   Binary = "et"
)

var All = []Binary{SSH, Mosh, ET}

// Result is the outcome of resolving a single binary.
type Result struct {
	Binary Binary
	Path   string // absolute path if found
	Err    error  // non-nil if not found/resolvable
}

// Resolver resolves binary paths, honoring config overrides and caching
// each lookup so repeated calls don't re-touch $PATH.
type Resolver struct {
	// Overrides maps a binary name to an explicit path from config
	// (the [binaries] table). An empty/missing entry falls back to $PATH.
	Overrides map[Binary]string

	mu    sync.Mutex
	cache map[Binary]Result
}

// NewResolver builds a Resolver with the given config overrides.
func NewResolver(overrides map[Binary]string) *Resolver {
	return &Resolver{
		Overrides: overrides,
		cache:     make(map[Binary]Result),
	}
}

// Resolve returns the resolved path for bin, using the cache if present.
func (r *Resolver) Resolve(bin Binary) Result {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cached, ok := r.cache[bin]; ok {
		return cached
	}

	res := r.resolveUncached(bin)
	r.cache[bin] = res
	return res
}

func (r *Resolver) resolveUncached(bin Binary) Result {
	if override, ok := r.Overrides[bin]; ok && override != "" {
		path, err := exec.LookPath(override)
		if err != nil {
			return Result{Binary: bin, Err: fmt.Errorf("configured path %q for %s: %w", override, bin, err)}
		}
		return Result{Binary: bin, Path: path}
	}

	path, err := exec.LookPath(string(bin))
	if err != nil {
		return Result{Binary: bin, Err: fmt.Errorf("%s: not found in $PATH: %w", bin, err)}
	}
	return Result{Binary: bin, Path: path}
}

// ResolveAll resolves every known binary, for diagnostics (`warp detect`).
func (r *Resolver) ResolveAll() []Result {
	results := make([]Result, 0, len(All))
	for _, bin := range All {
		results = append(results, r.Resolve(bin))
	}
	return results
}
