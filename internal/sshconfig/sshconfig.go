// Package sshconfig parses the subset of OpenSSH's ssh_config format warp
// needs to auto-import hosts: literal (non-wildcard) `Host` blocks and the
// HostName/User/Port/IdentityFile/ProxyJump keys within them, following
// `Include` directives.
//
// This intentionally is not a full ssh_config implementation. Wildcard/
// pattern Host lines (containing *, ?, or !) apply to many hosts at once
// and can't be imported as a single connectable name, so they're skipped
// rather than guessed at. Global (outside any Host block) options are
// skipped too, since they're not tied to a specific importable host.
package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Host is one literal Host block's connection-relevant fields.
type Host struct {
	Name         string // the literal Host pattern itself
	HostName     string
	User         string
	Port         int
	IdentityFile string
	ProxyJump    string
}

// maxIncludeDepth guards against an Include cycle turning into infinite
// recursion.
const maxIncludeDepth = 8

// Parse reads path (expanding a leading ~) and any files it Include's,
// returning one Host per literal Host pattern found.
func Parse(path string) ([]Host, error) {
	abs, err := expandPath(path)
	if err != nil {
		return nil, err
	}
	return parseFile(abs, 0, make(map[string]bool))
}

func parseFile(path string, depth int, visited map[string]bool) ([]Host, error) {
	if depth > maxIncludeDepth {
		return nil, fmt.Errorf("include depth exceeded (possible cycle) at %s", path)
	}
	if visited[path] {
		return nil, nil
	}
	visited[path] = true

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var hosts []Host
	var cur *Host
	dir := filepath.Dir(path)

	flush := func() {
		if cur != nil {
			hosts = append(hosts, *cur)
			cur = nil
		}
	}

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitConfigLine(line)
		if !ok {
			continue
		}

		switch strings.ToLower(key) {
		case "host":
			flush()
			name := firstLiteralPattern(val)
			if name != "" {
				cur = &Host{Name: name}
			}
		case "include":
			for _, pattern := range strings.Fields(val) {
				p, err := expandPath(pattern)
				if err != nil {
					continue
				}
				if !filepath.IsAbs(p) {
					p = filepath.Join(dir, p)
				}
				matches, err := filepath.Glob(p)
				if err != nil {
					continue
				}
				for _, m := range matches {
					sub, err := parseFile(m, depth+1, visited)
					if err == nil {
						hosts = append(hosts, sub...)
					}
				}
			}
		case "hostname":
			if cur != nil {
				cur.HostName = val
			}
		case "user":
			if cur != nil {
				cur.User = val
			}
		case "port":
			if cur != nil {
				if p, err := strconv.Atoi(val); err == nil {
					cur.Port = p
				}
			}
		case "identityfile":
			// ssh_config allows repeated IdentityFile lines (tried in
			// order); we only import one, so keep the first.
			if cur != nil && cur.IdentityFile == "" {
				cur.IdentityFile = val
			}
		case "proxyjump":
			if cur != nil {
				cur.ProxyJump = val
			}
		}
	}
	flush()

	return hosts, nil
}

// firstLiteralPattern returns the first non-wildcard name in a Host line's
// pattern list, or "" if every pattern is a wildcard (e.g. "Host *" or
// "Host *.example.com"). Extra literal names on the same line are dropped
// rather than duplicating the block under multiple names.
func firstLiteralPattern(val string) string {
	for _, name := range strings.Fields(val) {
		if !isWildcardPattern(name) {
			return name
		}
	}
	return ""
}

func isWildcardPattern(s string) bool {
	return strings.ContainsAny(s, "*?!")
}

// splitConfigLine splits an ssh_config line into its key and value.
// ssh_config accepts "Key value", "Key=value", and quoted values; this
// handles the common forms without being a full tokenizer.
func splitConfigLine(line string) (key, val string, ok bool) {
	line = strings.TrimSpace(strings.Replace(line, "=", " ", 1))
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return "", "", false
	}
	key = line[:i]
	val = strings.TrimSpace(line[i+1:])
	val = strings.Trim(val, `"`)
	if key == "" || val == "" {
		return "", "", false
	}
	return key, val, true
}

func expandPath(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
}
