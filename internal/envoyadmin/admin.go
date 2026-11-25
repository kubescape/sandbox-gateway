// Package envoyadmin reads Envoy's admin interface over its unix socket.
//
// The admin interface has no authentication and can stop Envoy. On the host
// network a loopback port is reachable by every process on the node, so the
// gateway serves admin on a socket in its own run directory and nothing else.
package envoyadmin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one Envoy.
type Client struct{ http *http.Client }

// New returns a client for the admin socket at path.
func New(path string) *Client {
	return &Client{http: &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
			MaxIdleConns: 2,
		},
	}}
}

func (c *Client) get(ctx context.Context, path string, query url.Values, into any) error {
	u := url.URL{Scheme: "http", Host: "envoy-admin", Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("envoyadmin: %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(into)
}

// Stats returns the integer stats whose name matches the regular expression
// filter (RE2, as Envoy applies it).
func (c *Client) Stats(ctx context.Context, filter string) (map[string]int64, error) {
	var doc struct {
		Stats []struct {
			Name  string      `json:"name"`
			Value json.Number `json:"value"`
		} `json:"stats"`
	}
	if err := c.get(ctx, "/stats", url.Values{"format": {"json"}, "filter": {filter}}, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(doc.Stats))
	for _, s := range doc.Stats {
		if s.Name == "" {
			continue // histograms come as a nested object with no name
		}
		if v, err := s.Value.Int64(); err == nil {
			out[s.Name] = v
		}
	}
	return out, nil
}

// Info is what /server_info says about the process.
type Info struct {
	// Version is the release, for example "1.40.2".
	Version string
	// Live is true once Envoy has initialized and is serving.
	Live bool
}

// ServerInfo asks Envoy for its version and state.
func (c *Client) ServerInfo(ctx context.Context) (Info, error) {
	var doc struct {
		Version string `json:"version"` // "<commit>/<release>/<status>/<build>/<tls library>"
		State   string `json:"state"`
	}
	if err := c.get(ctx, "/server_info", nil, &doc); err != nil {
		return Info{}, err
	}
	info := Info{Live: doc.State == "LIVE"}
	if parts := strings.Split(doc.Version, "/"); len(parts) >= 2 {
		info.Version = parts[1]
	}
	return info, nil
}

// InstalledChains returns the names of the filter chains Envoy holds for the
// listener named listener, in every state Envoy reports it in: active,
// warming and draining. Nil when Envoy has no such listener.
func (c *Client) InstalledChains(ctx context.Context, listener string) ([]string, error) {
	var raw struct {
		Configs []map[string]json.RawMessage `json:"configs"`
	}
	if err := c.get(ctx, "/config_dump", url.Values{"resource": {"dynamic_listeners"}}, &raw); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, cfg := range raw.Configs {
		var name string
		if err := json.Unmarshal(cfg["name"], &name); err != nil || name != listener {
			continue
		}
		for key, state := range cfg {
			if !strings.HasSuffix(key, "_state") {
				continue
			}
			var st struct {
				Listener struct {
					FilterChains []struct {
						Name string `json:"name"`
					} `json:"filter_chains"`
				} `json:"listener"`
			}
			if err := json.Unmarshal(state, &st); err != nil {
				return nil, fmt.Errorf("envoyadmin: config_dump %s.%s: %w", listener, key, err)
			}
			for _, fc := range st.Listener.FilterChains {
				if fc.Name != "" && !seen[fc.Name] {
					seen[fc.Name] = true
					out = append(out, fc.Name)
				}
			}
		}
	}
	return out, nil
}
