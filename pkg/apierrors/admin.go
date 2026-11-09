package apierrors

// AdminError is the admin-surface error envelope: {"error":"…"}. Extra keys
// (conflict bodies, analytics codes) are handler concerns and stay there; the
// plain consolidated path must not grow fields silently.
type AdminError struct {
	Error string `json:"error"`
}

// Admin renders e in the admin envelope.
func Admin(e *E) AdminError {
	if e == nil {
		return AdminError{}
	}
	return AdminError{Error: e.Message}
}
