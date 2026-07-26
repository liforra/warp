// Command gendocs generates warp's man pages straight from the real cobra
// command tree (internal/cli), so they can't drift out of sync with actual
// flags/subcommands. Run via `go run ./tools/gendocs`; wired into
// .goreleaser.yaml as a before-hook so packages always ship current pages.
//
// Not part of the warp binary itself -- this is a build-time-only tool.
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"

	"github.com/liforra/warp/internal/cli"
	"github.com/spf13/cobra/doc"
)

const outDir = "man"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := os.RemoveAll(outDir); err != nil {
		return fmt.Errorf("clearing %s: %w", outDir, err)
	}
	tmpDir, err := os.MkdirTemp("", "warp-gendocs")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	header := &doc.GenManHeader{
		Title:   "WARP",
		Section: "1",
		Source:  "warp",
		Manual:  "warp Manual",
	}
	if err := doc.GenManTree(cli.NewRootCmd(), header, tmpDir); err != nil {
		return fmt.Errorf("generating man pages: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := gzipFile(filepath.Join(tmpDir, e.Name()), filepath.Join(outDir, e.Name()+".gz")); err != nil {
			return fmt.Errorf("compressing %s: %w", e.Name(), err)
		}
	}

	fmt.Printf("gendocs: wrote %d man page(s) to %s/\n", len(entries), outDir)
	return nil
}

func gzipFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}

	return os.WriteFile(dst, buf.Bytes(), 0o644)
}
