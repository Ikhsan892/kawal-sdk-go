package kawal

import (
	"errors"
	"fmt"
)

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

type Request struct {
	Principal string
	Resource  string
	Actions   []string
}

type Decision struct {
	Action   string     `json:"action,omitempty"`
	Effect   Effect     `json:"effect"`
	Reason   string     `json:"reason,omitempty"`
	Policies []string   `json:"policies,omitempty"`
	Results  []Decision `json:"results,omitempty"`
}

type Result struct {
	Decisions []Decision
	RequestID string
	requested []string
}

func (r *Result) Allowed(action string) bool {
	if r == nil {
		return false
	}
	if len(r.Decisions) == 1 && r.Decisions[0].Action == "" {
		return r.Decisions[0].Effect == Allow && contains(r.requested, action)
	}
	found := false
	for _, d := range r.Decisions {
		if d.Action != action {
			continue
		}
		if d.Effect != Allow {
			return false
		}
		found = true
	}
	return found
}

func (r *Result) AllAllowed() bool {
	if r == nil || len(r.requested) == 0 {
		return false
	}
	for _, action := range r.requested {
		if !r.Allowed(action) {
			return false
		}
	}
	return true
}

var (
	ErrInvalidRequest  = errors.New("kawal: invalid request")
	ErrNotAuthorizable = errors.New("kawal: request cannot be authorized")
	ErrServer          = errors.New("kawal: server error")
	ErrTransport       = errors.New("kawal: transport error")
)

type APIError struct {
	Status      int
	Message     string
	RequestID   string
	Validations []string
	kind        error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kawal: %d %s (request %s)", e.Status, e.Message, e.RequestID)
}

func (e *APIError) Unwrap() error { return e.kind }

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
