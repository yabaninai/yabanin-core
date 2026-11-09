package mcpserver

// jsonMaxDepth reports the maximum nesting depth of a JSON document, or -1
// when the input is not valid JSON at the structural level. Strings and
// escapes are handled so brace bytes inside strings never count. The limit
// is abuse protection (a 10k-deep document burns decoder stack/allocations
// on every hop); valid MCP messages nest at most a handful of levels.

const defaultMaxJSONDepth = 64

func jsonMaxDepth(raw []byte) int {
	depth, max := 0, 0
	inString, escaped := false, false
	for _, c := range raw {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
			if depth > max {
				max = depth
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	if depth != 0 || inString {
		return -1
	}
	return max
}
