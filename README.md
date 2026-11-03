# kawal Go SDK

Client for Kawal's `POST /api/v1/authorize`. Standard library only.

```sh
go get github.com/Ikhsan892/kawal-sdk-go@latest
```

```go
import kawal "github.com/Ikhsan892/kawal-sdk-go"

c := kawal.New("http://kawal:3999", kawal.WithARNPrefix("kawal", "main", "default"))

res, err := c.Authorize(ctx, kawal.Request{
	Principal: c.ARN("example_user", "profile/u-example"),
	Resource:  c.ARN("example_doc", "doc/doc-001"),
	Actions:   []string{"read", "approve"},
})
if err != nil {
	// errors.Is(err, kawal.ErrInvalidRequest | ErrNotAuthorizable | ErrServer | ErrTransport)
}
if res.Allowed("approve") { /* ... */ }
```

`Allowed` fails closed: a nil result, an error, or an action with no decision is a deny.

## net/http middleware

```go
mux.Handle("/docs/{id}", kawal.Require(c, []string{"read"},
	func(r *http.Request) (string, error) { return c.ARN("example_user", "profile/"+userID(r)), nil },
	func(r *http.Request) (string, error) { return c.ARN("example_doc", "doc/"+r.PathValue("id")), nil },
)(handler))
```

Deny returns 403. If Kawal is unreachable it returns 503. The handler reads the result with `kawal.FromContext(r.Context())`.

## Options

| Option                                      | Default                                    |
| ------------------------------------------- | ------------------------------------------ |
| `WithHTTPClient(hc)`                        | 5s timeout                                 |
| `WithToken(t)`                              | none (sent as `Authorization: Bearer`)     |
| `WithARNPrefix(partition, region, account)` | `kawal`, `main`, `default`                 |
| `WithRetry(n)`                              | 1 (only on network errors and 502/503/504) |

## Releasing

Tag with the module prefix: `git tag sdk/go/v1.0.0 && git push origin sdk/go/v1.0.0`.
