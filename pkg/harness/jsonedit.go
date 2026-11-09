package harness

import "strings"

// SetPath writes value at a dotted path and returns the previous value.
func SetPath(doc map[string]any, path string, value any) (prev any, existed bool) {
	parts := strings.Split(path, ".")
	cur := doc
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	leaf := parts[len(parts)-1]
	prev, existed = cur[leaf]
	cur[leaf] = value
	return prev, existed
}

// RestorePath puts a previous value back or deletes the leaf.
func RestorePath(doc map[string]any, path string, prev any, existed bool) {
	parts := strings.Split(path, ".")
	cur := doc
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
	leaf := parts[len(parts)-1]
	if !existed {
		delete(cur, leaf)
		return
	}
	cur[leaf] = prev
}
