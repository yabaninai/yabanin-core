package harness

import (
	"bytes"
	"strings"
)

const blockHead = "# >>> yabanin:"
const blockTail = "# <<< yabanin:"

// RemoveManagedBlocks drops every managed block whose id is listed.
func RemoveManagedBlocks(content []byte, ids []string) []byte {
	if len(ids) == 0 {
		return content
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	lines := bytes.Split(content, []byte("\n"))
	var out [][]byte
	skip := false
	for _, line := range lines {
		text := string(line)
		if !skip && strings.HasPrefix(text, blockHead) {
			id := blockID(text)
			if want[id] {
				skip = true
				continue
			}
		}
		if skip {
			if strings.HasPrefix(text, blockTail) {
				skip = false
			}
			continue
		}
		out = append(out, line)
	}
	return bytes.Join(out, []byte("\n"))
}

func blockID(line string) string {
	rest := strings.TrimPrefix(line, blockHead)
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}

// RestoreDisabled uncomments lines this harness commented.
func RestoreDisabled(content []byte, lines []string) []byte {
	if len(lines) == 0 {
		return content
	}
	want := map[string]bool{}
	for _, line := range lines {
		want[line] = true
	}
	rows := bytes.Split(content, []byte("\n"))
	for i, row := range rows {
		text := string(row)
		const prefix = "# yabanin-disabled: "
		if rest, ok := strings.CutPrefix(text, prefix); ok && want[rest] {
			rows[i] = []byte(rest)
		}
	}
	return bytes.Join(rows, []byte("\n"))
}
