package kawal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const authorizePath = "/api/v1/authorize"

type Client struct {
	baseURL   string
	http      *http.Client
	token     string
	partition string
	region    string
	account   string
	retries   int
}

type Option func(*Client)

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.http = hc
		}
	}
}

func WithToken(token string) Option {
	return func(c *Client) { c.token = token }
}

func WithARNPrefix(partition, region, account string) Option {
	return func(c *Client) {
		c.partition, c.region, c.account = partition, region, account
	}
}

func WithRetry(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.retries = n
		}
	}
}

func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		http:      &http.Client{Timeout: 5 * time.Second},
		partition: "kawal",
		region:    "main",
		account:   "default",
		retries:   1,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) ARN(service, resource string) string {
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s", c.partition, service, c.region, c.account, resource)
}

func (c *Client) Authorize(ctx context.Context, req Request) (*Result, error) {
	actions := make([]string, 0, len(req.Actions))
	for _, a := range req.Actions {
		if a = strings.TrimSpace(a); a != "" {
			actions = append(actions, a)
		}
	}
	if strings.TrimSpace(req.Principal) == "" || strings.TrimSpace(req.Resource) == "" || len(actions) == 0 {
		return nil, fmt.Errorf("%w: principal, resource and at least one action are required", ErrInvalidRequest)
	}

	body, err := json.Marshal(map[string]any{
		"principal_arn": req.Principal,
		"resource_arn":  req.Resource,
		"actions":       actions,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTransport, err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			wait := time.Duration(100<<(attempt-1)) * time.Millisecond
			if wait > 2*time.Second {
				wait = 2 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: %w", ErrTransport, ctx.Err())
			case <-time.After(wait):
			}
		}

		res, retry, err := c.do(ctx, body, actions)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

type envelope struct {
	Data        []Decision `json:"data"`
	Message     string     `json:"message"`
	RequestID   string     `json:"request_id"`
	Validations []string   `json:"validations"`
}

func (c *Client) do(ctx context.Context, body []byte, actions []string) (*Result, bool, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+authorizePath, bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrTransport, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrTransport, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrTransport, err)
	}

	var env envelope
	decodeErr := json.Unmarshal(raw, &env)

	if resp.StatusCode != http.StatusOK {
		apiErr := &APIError{
			Status:      resp.StatusCode,
			Message:     env.Message,
			RequestID:   env.RequestID,
			Validations: env.Validations,
		}
		if apiErr.Message == "" {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		switch {
		case resp.StatusCode == http.StatusBadRequest:
			apiErr.kind = ErrInvalidRequest
		case resp.StatusCode == http.StatusUnprocessableEntity:
			apiErr.kind = ErrNotAuthorizable
		case resp.StatusCode >= 500:
			apiErr.kind = ErrServer
		default:
			apiErr.kind = ErrTransport
		}
		retry := resp.StatusCode == http.StatusBadGateway ||
			resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusGatewayTimeout
		return nil, retry, apiErr
	}

	if decodeErr != nil {
		return nil, false, fmt.Errorf("%w: decode response: %w", ErrTransport, decodeErr)
	}

	return &Result{Decisions: env.Data, RequestID: env.RequestID, requested: actions}, false, nil
}
