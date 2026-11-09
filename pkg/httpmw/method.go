package httpmw

import (
	"net/http"
	"strings"
)

// MethodGuard returns a middleware that lets through only the listed HTTP
// methods and answers 405 Method Not Allowed (with the Allow header, RFC 9110
// §15.5.5) for everything else, before the request reaches the wrapped handler.
//
// It exists so read-only routes mounted with r.Handle (which accepts every
// method, unlike the method-specific chi helpers) can be narrowed without
// re-registering them: e.g. /metrics is a scrape endpoint and only GET/HEAD
func MethodGuard(allowed ...string) func(http.Handler) http.Handler {
	set := make(map[string]struct{}, len(allowed))
	for _, m := range allowed {
		set[m] = struct{}{}
	}
	allow := strings.Join(allowed, ", ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := set[r.Method]; !ok {
				w.Header().Set("Allow", allow)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
