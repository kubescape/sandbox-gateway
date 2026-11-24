// Package xds builds the listeners Envoy runs and serves them over LDS.
//
// The redirect listener has one filter chain per decrypted hostname and one
// passthrough chain, which forwards to the connection's original destination. Which chain a connection gets is decided by the
// listener's matcher from the pod's address and the SNI together, so a pod
// is decrypted only for the names its own policy asks for.
//
// Pod addresses live in the matcher and never in a chain. A change to the
// matcher is applied in place and drains nothing; a change to a chain
// replaces the chain and cuts the streams on it.
package xds

import (
	"bytes"
	"embed"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"text/template"

	xdscorev3 "github.com/cncf/xds/go/xds/core/v3"
	matcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	networkinputsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"sigs.k8s.io/yaml"

	// The chain templates name these extensions by type URL.
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	originaldstv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/original_dst/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

//go:embed templates/*.yaml
var templates embed.FS

var chainTemplates = template.Must(template.ParseFS(templates, "templates/*.yaml"))

// Names of the listener and of the chain every undecrypted connection gets.
const (
	EgressListener   = "egress_tls"
	PassthroughChain = "passthrough"
)

// Config holds what is the same for every build of the listener. These are
// listener-wide settings: changing one means a new listener and a restart.
type Config struct {
	// Port the redirect listener binds on every IPv4 address. Default 18443.
	Port uint32
	// Clusters defined in Envoy's bootstrap.
	XDSCluster, ExtProcCluster, DecryptCluster, PassthroughCluster string
}

func (c Config) withDefaults() Config {
	if c.Port == 0 {
		c.Port = 18443
	}
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&c.XDSCluster, "xds")
	def(&c.ExtProcCluster, "ext_proc")
	def(&c.DecryptCluster, "dfp")
	def(&c.PassthroughCluster, "orig_dst")
	return c
}

// PodNames is one pod's addresses and the names it is decrypted for.
type PodNames struct {
	Addrs []netip.Addr
	Names []string
}

// Input is what changes between builds.
type Input struct {
	// Names get a decrypt chain each: the node's host set.
	Names []string
	// Pods are the pods that reach a chain. A pod with no names is passed
	// through for everything. A source address that is no pod's gets no
	// chain and is reset.
	Pods []PodNames
}

// DecryptChain is the name of the filter chain for a hostname.
func DecryptChain(name string) string { return "decrypt/" + name }

// StatPrefix is the connection manager stat prefix of a hostname's chain.
// The gauge http.<prefix>.downstream_cx_active says whether the name has
// open connections. Hostnames have no underscore, so the mapping is one to
// one.
func StatPrefix(name string) string { return "egress_" + strings.ReplaceAll(name, ".", "_") }

// hostname is what may be written into a chain template.
var hostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// clusterName is what a cluster flag may hold.
var clusterName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Egress builds the redirect listener. The same input always gives an equal
// listener, so an unchanged node pushes nothing.
func (c Config) Egress(in Input) (*listenerv3.Listener, error) {
	c = c.withDefaults()
	for _, cl := range []string{c.XDSCluster, c.ExtProcCluster, c.DecryptCluster, c.PassthroughCluster} {
		if !clusterName.MatchString(cl) {
			return nil, fmt.Errorf("xds: %q is not a cluster name", cl)
		}
	}
	names := append([]string(nil), in.Names...)
	sort.Strings(names)
	hasChain := map[string]bool{}
	var chains []*listenerv3.FilterChain
	for _, name := range names {
		if hasChain[name] {
			continue
		}
		if !hostname.MatchString(name) || len(name) > 253 {
			return nil, fmt.Errorf("xds: %q is not a hostname", name)
		}
		fc, err := c.chain("decrypt_chain.yaml", name)
		if err != nil {
			return nil, err
		}
		hasChain[name] = true
		chains = append(chains, fc)
	}
	pt, err := c.chain("passthrough_chain.yaml", "")
	if err != nil {
		return nil, err
	}
	chains = append(chains, pt)

	tlsInspector, err := anypb.New(&tlsinspectorv3.TlsInspector{})
	if err != nil {
		return nil, err
	}
	originalDst, err := anypb.New(&originaldstv3.OriginalDst{})
	if err != nil {
		return nil, err
	}
	m, err := podMatcher(in.Pods, hasChain)
	if err != nil {
		return nil, err
	}
	return &listenerv3.Listener{
		Name: EgressListener,
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address: "0.0.0.0", PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: c.Port},
		}}},
		// No proxy_protocol filter, on purpose: it would replace the remote address with
		// one the pod writes, and the pod's identity is keyed on that address.
		ListenerFilters: []*listenerv3.ListenerFilter{
			// Restores the address the pod was connecting to, which the kernel answers
			// from the connection table. The passthrough chain forwards there. It does
			// not hand the connection to another listener (use_original_dst is unset).
			{
				Name:       "envoy.filters.listener.original_dst",
				ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: originalDst},
			},
			{
				Name:       "envoy.filters.listener.tls_inspector",
				ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: tlsInspector},
			},
		},
		FilterChains:       chains,
		FilterChainMatcher: m,
	}, nil
}

func (c Config) chain(file, name string) (*listenerv3.FilterChain, error) {
	var buf bytes.Buffer
	err := chainTemplates.ExecuteTemplate(&buf, file, struct {
		Name, StatPrefix                                               string
		XDSCluster, ExtProcCluster, DecryptCluster, PassthroughCluster string
	}{name, StatPrefix(name), c.XDSCluster, c.ExtProcCluster, c.DecryptCluster, c.PassthroughCluster})
	if err != nil {
		return nil, fmt.Errorf("xds: %s: %w", file, err)
	}
	js, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("xds: %s: %w", file, err)
	}
	fc := &listenerv3.FilterChain{}
	if err := protojson.Unmarshal(js, fc); err != nil {
		return nil, fmt.Errorf("xds: %s: %w", file, err)
	}
	if err := fc.ValidateAll(); err != nil {
		return nil, fmt.Errorf("xds: %s: %w", file, err)
	}
	return fc, nil
}

func input(name string, msg proto.Message) (*xdscorev3.TypedExtensionConfig, error) {
	a, err := anypb.New(msg)
	if err != nil {
		return nil, err
	}
	return &xdscorev3.TypedExtensionConfig{Name: name, TypedConfig: a}, nil
}

func chainAction(chain string) (*matcherv3.Matcher_OnMatch, error) {
	a, err := anypb.New(wrapperspb.String(chain))
	if err != nil {
		return nil, err
	}
	return &matcherv3.Matcher_OnMatch{OnMatch: &matcherv3.Matcher_OnMatch_Action{
		Action: &xdscorev3.TypedExtensionConfig{Name: "chain", TypedConfig: a},
	}}, nil
}

// podMatcher builds the tree: source address, then SNI. A pod's name that
// has no chain is left out, so it falls to passthrough with the rest.
func podMatcher(pods []PodNames, hasChain map[string]bool) (*matcherv3.Matcher, error) {
	source, err := input("source-ip", &networkinputsv3.SourceIPInput{})
	if err != nil {
		return nil, err
	}
	passthrough, err := chainAction(PassthroughChain)
	if err != nil {
		return nil, err
	}
	byAddr := map[string]*matcherv3.Matcher_OnMatch{}
	for _, pod := range pods {
		onPod := passthrough
		byName := map[string]*matcherv3.Matcher_OnMatch{}
		for _, name := range pod.Names {
			if !hasChain[name] {
				continue
			}
			if byName[name], err = chainAction(DecryptChain(name)); err != nil {
				return nil, err
			}
		}
		if len(byName) > 0 {
			sni, err := input("sni", &networkinputsv3.ServerNameInput{})
			if err != nil {
				return nil, err
			}
			onPod = &matcherv3.Matcher_OnMatch{OnMatch: &matcherv3.Matcher_OnMatch_Matcher{Matcher: &matcherv3.Matcher{
				MatcherType: &matcherv3.Matcher_MatcherTree_{MatcherTree: &matcherv3.Matcher_MatcherTree{
					Input:    sni,
					TreeType: &matcherv3.Matcher_MatcherTree_ExactMatchMap{ExactMatchMap: &matcherv3.Matcher_MatcherTree_MatchMap{Map: byName}},
				}},
				OnNoMatch: passthrough,
			}}}
		}
		for _, a := range pod.Addrs {
			key := a.Unmap().String()
			if _, dup := byAddr[key]; dup {
				// Two pods never share an address. If the API shows it for a
				// moment, neither is decrypted until it settles.
				byAddr[key] = passthrough
				continue
			}
			byAddr[key] = onPod
		}
	}
	if len(byAddr) == 0 {
		// An exact map needs an entry. This one is the unspecified address,
		// which is never a connection's source.
		byAddr["0.0.0.0"] = passthrough
	}
	return &matcherv3.Matcher{
		MatcherType: &matcherv3.Matcher_MatcherTree_{MatcherTree: &matcherv3.Matcher_MatcherTree{
			Input:    source,
			TreeType: &matcherv3.Matcher_MatcherTree_ExactMatchMap{ExactMatchMap: &matcherv3.Matcher_MatcherTree_MatchMap{Map: byAddr}},
		}},
		// No on_no_match: a source that is no pod on this node gets no chain.
	}, nil
}
