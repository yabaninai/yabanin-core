package consumer

import "github.com/google/uuid"

// nsRequestLogs freezes the namespace that maps client-supplied non-UUID
// identifiers (session_id, team_id, agent_id) onto RFC 4122 v5 UUIDs before
// they reach the uuid columns of request_logs. OpenCode sends its native
// session ids (e.g. "ses_...") in X-Session-Id; storing them verbatim wedged
// every INSERT with SQLSTATE 22P02 and silently dropped all rows for that
// traffic (LG-U1).
//
// This value MUST NEVER change after first release: stored hashes depend on
// it, and rotating it would silently regroup all session analytics. The
// golden vectors in uuidfield_test.go fail if it is ever edited.
const nsRequestLogs = "6f9d2c1e-8b47-4a9b-9d3a-5e2f7c4b1a00"

var nsRequestLogsUUID = uuid.MustParse(nsRequestLogs)

// uuidField maps an event string field onto a value safe for a uuid column:
//
//   - ""            -> nil (absent stays NULL; hashing "" would merge all
//     session-less traffic into one group)
//   - valid UUID    -> canonical form (uuid.Parse also accepts urn:/braces/
//     no-dash spellings; canonicalize so Postgres always accepts the value)
//   - anything else -> deterministic v5 UUID (uuid.NewSHA1). The same input
//     maps to the same UUID, so sessions still group; the mapping is one-way,
//     the same principle as prompt_hash. A bad producer can never wedge the
//     INSERT — fail-open to a stable key, never a crash.
//
// To map a client id to its stored UUID while debugging (e.g. an OpenCode
// "ses_..." id), compute the same v5 UUID with the namespace above:
//
//	python3 -c "import uuid; print(uuid.uuid5(uuid.UUID('6f9d2c1e-8b47-4a9b-9d3a-5e2f7c4b1a00'), 'ses_...'))"
//
// strictUUID stores a uuid column that must already be a UUID. An empty
// string is NULL. Anything else is NULL and ok=false so the caller can warn
// without turning a junk value into a v5 UUID (that would hide a bad id).
func strictUUID(s string) (any, bool) {
	if s == "" {
		return nil, true
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return nil, false
	}
	return u.String(), true
}

func uuidField(s string) any {
	if s == "" {
		return nil
	}
	if u, err := uuid.Parse(s); err == nil {
		return u.String()
	}
	return uuid.NewSHA1(nsRequestLogsUUID, []byte(s)).String()
}

// eventString reads a stream field as a string; non-string values (or missing
// keys) become "", mirroring the typed field reads in the handlers. Wrong
// types therefore take the same NULL path as absent values.
func eventString(fields map[string]interface{}, key string) string {
	s, _ := fields[key].(string)
	return s
}
