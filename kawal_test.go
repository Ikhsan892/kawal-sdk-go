package kawal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func server(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(srv.URL, WithRetry(2))
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func req(actions ...string) Request {
	return Request{Principal: "arn:kawal:user:main:default:profile/u-1", Resource: "arn:kawal:doc:main:default:doc/d-1", Actions: actions}
}

func TestAuthorize_SendsTheWireBodyAndReadsDecisions(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != authorizePath || r.Method != http.MethodPost {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["principal_arn"] != "arn:kawal:user:main:default:profile/u-1" {
			t.Errorf("principal_arn = %v", body["principal_arn"])
		}
		reply(w, 200, map[string]any{"request_id": "rq-1", "data": []map[string]any{
			{"action": "read", "effect": "allow", "policies": []string{"p1"}},
			{"action": "delete", "effect": "deny"},
		}})
	})

	res, err := c.Authorize(context.Background(), req("read", "delete"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed("read") || res.Allowed("delete") || res.Allowed("approve") || res.AllAllowed() {
		t.Fatalf("unexpected verdicts: %+v", res.Decisions)
	}
	if res.RequestID != "rq-1" || res.Decisions[0].Policies[0] != "p1" {
		t.Fatalf("lost fields: %+v", res)
	}
}

func TestAuthorize_SingleDecisionWithoutActionCoversTheRequest(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 200, map[string]any{"data": []map[string]any{{"effect": "allow"}}})
	})

	res, err := c.Authorize(context.Background(), req("read"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed("read") || !res.AllAllowed() || res.Allowed("delete") {
		t.Fatal("single decision should cover exactly the requested actions")
	}
}

func TestAuthorize_MapsErrors(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{400, ErrInvalidRequest},
		{422, ErrNotAuthorizable},
		{500, ErrServer},
	}
	for _, tc := range cases {
		var calls atomic.Int32
		c := server(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			reply(w, tc.status, map[string]any{"message": "nope", "request_id": "rq-err"})
		})

		res, err := c.Authorize(context.Background(), req("read"))
		if !errors.Is(err, tc.want) {
			t.Fatalf("%d: got %v", tc.status, err)
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.RequestID != "rq-err" || apiErr.Message != "nope" {
			t.Fatalf("%d: api error not kept: %v", tc.status, err)
		}
		if res.Allowed("read") {
			t.Fatalf("%d: a nil result must deny", tc.status)
		}
		if calls.Load() != 1 {
			t.Fatalf("%d: retried %d times", tc.status, calls.Load())
		}
	}
}

func TestAuthorize_RetriesUnavailable(t *testing.T) {
	var calls atomic.Int32
	c := server(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			reply(w, 503, map[string]any{"message": "busy"})
			return
		}
		reply(w, 200, map[string]any{"data": []map[string]any{{"action": "read", "effect": "allow"}}})
	})

	res, err := c.Authorize(context.Background(), req("read"))
	if err != nil || !res.Allowed("read") || calls.Load() != 2 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestAuthorize_RefusesAnEmptyRequestWithoutCalling(t *testing.T) {
	c := server(t, func(http.ResponseWriter, *http.Request) {
		t.Error("server should not be called")
	})

	if _, err := c.Authorize(context.Background(), Request{Principal: "p", Resource: "r"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("got %v", err)
	}
}

func TestAuthorize_StopsOnCancel(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 503, map[string]any{"message": "busy"})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := c.Authorize(ctx, req("read"))
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestARN(t *testing.T) {
	c := New("http://x", WithARNPrefix("myerp", "id", "acme"))
	if got := c.ARN("invoice", "doc/INV-1"); got != "arn:myerp:invoice:id:acme:doc/INV-1" {
		t.Fatal(got)
	}
}

func TestRequire(t *testing.T) {
	effect := "allow"
	status := 200
	c := server(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, status, map[string]any{"data": []map[string]any{{"action": "read", "effect": effect}}})
	})

	arn := func(string) ARNFunc {
		return func(*http.Request) (string, error) { return "arn:x", nil }
	}
	h := Require(c, []string{"read"}, arn("p"), arn("r"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if FromContext(r.Context()) == nil {
			t.Error("result not in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, tc := range []struct {
		effect string
		status int
		want   int
	}{
		{"allow", 200, http.StatusNoContent},
		{"deny", 200, http.StatusForbidden},
		{"allow", 500, http.StatusServiceUnavailable},
	} {
		effect, status = tc.effect, tc.status
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != tc.want {
			t.Fatalf("%s/%d: got %d want %d", tc.effect, tc.status, rec.Code, tc.want)
		}
	}
}
