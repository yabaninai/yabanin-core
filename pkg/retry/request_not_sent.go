package retry

import "errors"

// RequestNotSentError is the typed proof that a request never reached the
// transport: it is produced when the request fails at the translate layer —
// before any dial, any sent byte and any chargeable side effect (N07-P01-T05,
// I51: modeled-unsupported fields are rejected with the precise reason
// instead of being silently dropped).
//
// The distinction matters for two consumers:
//   - the fallback chain: a not-sent refusal may advance to the next
//     candidate (the request provably never happened, unlike an unknown
//     outcome where a second provider call could double-execute);
//   - the client-facing render: the refusal is a request problem (400 with
//     the exact reason), not an upstream availability problem, so it must
//     not be masked as a generic gateway/upstream failure.
//
// The wrap lives at the transport seam (pkg/upstream), so Err keeps the
// translate layer's exact reason visible in Error().
type RequestNotSentError struct {
	Err error
}

func (e *RequestNotSentError) Error() string {
	if e == nil || e.Err == nil {
		return "request not sent"
	}
	return e.Err.Error()
}

func (e *RequestNotSentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsRequestNotSent reports whether err (or any error it wraps) is the typed
// request-not-sent proof.
func IsRequestNotSent(err error) bool {
	var ns *RequestNotSentError
	return errors.As(err, &ns)
}
