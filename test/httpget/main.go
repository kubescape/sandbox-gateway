// Command httpget makes one plain HTTP request and prints the status code and
// the body on one line. It exits 1 when there is no HTTP answer at all, which
// is how the integration test tells a refused connection from a status.
//
//	httpget http://host:port/path
//	httpget -unix /path/to.sock http://name/path     over a unix socket
//	httpget -post '{"json":true}' ...                POST that body
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	unix := flag.String("unix", "", "connect to this unix socket instead of the URL's host")
	post := flag.String("post", "", "POST this body as application/json instead of a GET")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: httpget [-unix socket] [-post body] <url>")
		os.Exit(2)
	}
	c := http.Client{Timeout: 3 * time.Second}
	if *unix != "" {
		c.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *unix)
		}}
	}
	var resp *http.Response
	var err error
	if *post != "" {
		resp, err = c.Post(flag.Arg(0), "application/json", strings.NewReader(*post))
	} else {
		resp, err = c.Get(flag.Arg(0))
	}
	if err != nil {
		fmt.Println("000", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	fmt.Println(resp.StatusCode, strings.TrimSpace(string(b)))
}
