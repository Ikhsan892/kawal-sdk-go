package kawal

import (
	"context"
	"net/http"
)

type ctxKey struct{}

type ARNFunc func(*http.Request) (string, error)

func FromContext(ctx context.Context) *Result {
	res, _ := ctx.Value(ctxKey{}).(*Result)
	return res
}

func Require(c *Client, actions []string, principal, resource ARNFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := principal(r)
			if err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			res, err := resource(r)
			if err != nil {
				http.Error(w, "unknown resource", http.StatusBadRequest)
				return
			}

			out, err := c.Authorize(r.Context(), Request{Principal: p, Resource: res, Actions: actions})
			if err != nil {
				http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
				return
			}
			if !out.AllAllowed() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, out)))
		})
	}
}
