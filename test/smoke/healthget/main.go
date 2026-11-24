// Command healthget asks the processor's health socket for
// GET /healthz/processor and prints the status code and the body on one
// line. With "idle" it waits forever, so a pod can keep it as a container to
// exec into.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: healthget <socket path> | healthget idle")
		os.Exit(2)
	}
	if os.Args[1] == "idle" {
		select {}
	}
	sock := os.Args[1]
	c := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}
	resp, err := c.Get("http://processor/healthz/processor")
	if err != nil {
		fmt.Println("000", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	fmt.Println(resp.StatusCode, string(b))
}
