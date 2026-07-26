// Package netrc parses just enough of the .netrc format (see netrc(5)) for
// warp's purposes: knowing whether a machine has an autologin entry, and
// its login name.
//
// The password token is deliberately never retained anywhere -- it's
// tokenized (so the parser doesn't misinterpret it as a keyword) and
// discarded immediately. warp only needs to know an entry *exists* to
// decide whether to hand off to a program's own .netrc-based autologin
// (e.g. `telnet -a`, which reads the file itself at connection time); warp
// itself has no reason to ever hold a credential in memory.
package netrc

import (
	"os"
	"strings"
)

// Entry is what warp keeps from one "machine" block.
type Entry struct {
	Login string
}

// Parse reads a .netrc-format file and returns its machine entries, keyed
// by machine name. "default" entries (matching any machine) aren't
// returned as a keyed entry, since there's no single host name to key them
// under; "macdef" macro bodies are recognized and skipped so they don't
// confuse the tokenizer.
func Parse(path string) (map[string]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(string(data)), nil
}

func parse(data string) map[string]Entry {
	entries := make(map[string]Entry)

	var machine, login string
	haveMachine := false
	inMacro := false

	flush := func() {
		if haveMachine && machine != "" {
			e := entries[machine]
			if login != "" {
				e.Login = login
			}
			entries[machine] = e
		}
	}

	for _, line := range strings.Split(data, "\n") {
		if inMacro {
			if strings.TrimSpace(line) == "" {
				inMacro = false
			}
			continue
		}

		fields := strings.Fields(line)
		for i := 0; i < len(fields); i++ {
			switch strings.ToLower(fields[i]) {
			case "machine":
				flush()
				haveMachine = true
				login = ""
				machine = ""
				if i+1 < len(fields) {
					machine = fields[i+1]
					i++
				}
			case "default":
				flush()
				haveMachine = false
				machine = ""
				login = ""
			case "login":
				if i+1 < len(fields) {
					login = fields[i+1]
					i++
				}
			case "password", "account":
				// Consume the value token without ever storing it -- see
				// package doc.
				i++
			case "macdef":
				inMacro = true
				i = len(fields)
			}
		}
	}
	flush()

	return entries
}
