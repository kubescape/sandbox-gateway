// Command httpget fetches one URL over plain HTTP and prints the status code
// and the body on one line. It exits 1 when there is no HTTP answer at all,
// which is how the integration test tells a refused connection from a status.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: httpget <url>")
		os.Exit(2)
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(os.Args[1])
	if err != nil {
		fmt.Println("000", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	fmt.Println(resp.StatusCode, string(b))
}
