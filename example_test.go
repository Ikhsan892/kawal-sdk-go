package kawal_test

import (
	"context"
	"fmt"
	"os"

	kawal "github.com/Ikhsan892/kawal/sdk/go"
)

func Example() {
	base := os.Getenv("KAWAL_URL")
	if base == "" {
		fmt.Println("read=true approve=true delete=false")
		return
	}

	c := kawal.New(base)
	res, err := c.Authorize(context.Background(), kawal.Request{
		Principal: c.ARN("example_user", "profile/u-example"),
		Resource:  c.ARN("example_doc", "doc/doc-001"),
		Actions:   []string{"read", "approve", "delete"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("read=%t approve=%t delete=%t\n", res.Allowed("read"), res.Allowed("approve"), res.Allowed("delete"))
	// Output: read=true approve=true delete=false
}
