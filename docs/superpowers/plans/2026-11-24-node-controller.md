---
type: intent
status: active
owner: amirmalka
scope: repo
---

# Node controller and Envoy config implementation plan (SUB-9949)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Grow the seeded SDS server into the node controller the gateway ships. It keeps the node's host set, serves Envoy its listeners (LDS) and leaf certificates (SDS), takes DNS sightings, answers the certificate health path and writes the gateway node status. The Envoy config around it decrypts a host only for the pods whose policy names it and passes everything else to where the pod was going.

**Architecture:** `cmd/node-controller` wires small packages with one job each: the node view (pods and policy objects from informers), the host set (cap, learned names, width check), the certificate authority (intermediate and leaves), the xDS server (listener builder, LDS, SDS), the sightings and health socket, and the status writer. Envoy's bootstrap holds only what never changes: the clusters, the admin socket, the overload manager. Both listeners come over LDS.

**Tech stack:** Go 1.27 toolchain, `envoyproxy/go-control-plane` protos (listener v3, matcher v3, secret v3), `k8s.io/client-go` informers, `kubescape/storage` v0.0.418 for the policy and status types, Envoy 1.40.2 in the integration job.

**Spec:** the L7 egress gateway design (section "Gateway DaemonSet", design decisions 5, 6 and 11) and ticket T7 of its implementation plan, with the shared contracts C1, C3, C4 and C5.

## Global constraints

- Envoy floor 1.40. The integration job runs v1.40.2. `node.id` and `node.cluster` are always set.
- One filter chain per decrypted host. Never a wildcard chain. A leaf is minted only for a name in the host set; the SNI alone never mints one.
- A listener update only adds or removes filter chains or changes the chain matcher. Listener-wide settings change only on a pod restart.
- A chain with open connections is never removed.
- Defaults, all flags: 256 minted names per node, one-hour leaves renewed at 30 minutes, intermediate 24 hours renewed at 12, listener port 18443, health port 18444.
- Envoy never parses PROXY protocol on the redirect listener.
- The node controller does not edit the processor packages (`internal/extproc`, `internal/app`, `internal/policysource`, `internal/stale`, `internal/lookup`, `internal/conntable`, `pkg/`).
- Commits are signed off, and every code commit updates `docs/features/node-controller.md`.

## Spike result (2026-11-24)

The ticket starts with one spike on two questions. Both have an answer on stock Envoy 1.40.2, so no custom listener filter is needed. The runs used Docker on a 7.0 kernel, file-based LDS, `--drain-time-s 4` so that a drain shows within seconds, and a 12-second streamed response as the live stream.

### How a decrypt chain matches the pod and the SNI together

The listener's `filter_chain_matcher` (the unified matcher API) picks a chain by name. The tree is: source address (`SourceIPInput`, exact map of pod addresses), then SNI (`ServerNameInput`, exact map of that pod's decrypted names), with `on_no_match` on the pod's entry sending it to the `passthrough` chain. A source address that is not in the map matches nothing and Envoy resets the connection.

| Case | Result |
|---|---|
| Pod A, SNI in A's list | chain `decrypt/<name>`, leaf from the gateway CA |
| Pod B, same SNI, not in B's list | `passthrough` chain |
| Pod A, SNI no policy names | `passthrough` chain |
| Source address of no bound pod | reset, `no_filter_chain_match` counts it |
| Matcher changed during a live stream (pod added to a name) | `listener_in_place_updated` +1, 0 chains draining, stream completed, the new mapping applied to the next connection |
| Chain added during a live stream | in place, 0 draining, stream completed |
| Idle chain removed during a live stream on another chain | only the removed chain drained, stream completed |
| The pod of a live stream removed from the matcher | stream completed; the matcher is read at accept only |
| Chain removed while it carried the stream | stream reset at the drain time |

The form the design proposed first, source addresses in each chain's `filter_chain_match` beside `server_names`, was run for comparison. A source miss does fall through to `default_filter_chain`. Changing a chain's source list replaces the chain, though, and the stream on it was cut at the drain time (`unexpected EOF`). So pod addresses go in the matcher and never in the chain.

### How Envoy forwards a passthrough connection to the original destination

Envoy's `original_dst` listener filter asks the kernel for `SO_ORIGINAL_DST`, and the `ORIGINAL_DST` cluster connects to the address it restored. A connect-time rewrite leaves no NAT entry, so by default the kernel has no answer. A `cgroup/getsockopt` BPF program can give one: for a socket whose local port is the gateway listener's, it looks the peer address and port up in `conns` and writes the recorded original destination into the option value.

| Case | Result |
|---|---|
| Pod with a `conns` entry, passthrough SNI | connected to the address in `conns` (`upstream_host` and the restored local address both showed it) |
| Pod with no `conns` entry, passthrough SNI | reset; the cluster refuses a connection whose address was not restored, so nothing loops back to the listener |
| Decrypt chain with the filter in place | unchanged |

The other stock form was run too: a network `ext_authz` filter that returns the destination as dynamic metadata, `set_filter_state`, then `tcp_proxy`. It does not work. `tcp_proxy` picks its upstream when the connection opens, before `ext_authz` has been called (`ext_authz` total stayed 0).

The program is about 30 lines of C. Its source lands with PR 5 under `test/origdst/`. It has to be loaded by whatever owns the redirect, because it reads the same `conns` map. That is open item 1.

### Per-chain SDS secret against `on_demand_secret`

A chain that names its leaf through `tls_certificate_sds_secret_configs` works. Envoy subscribes when the chain is added, so the fetch is off the handshake path without `prefetch_secret_names`. A renewed leaf pushed on the stream replaced the old one with no listener update (40-second leaves, call still verified at 55 seconds). With the SDS server stopped, existing chains kept handshaking. A chain added while SDS was down did not go live: the listener update stayed warming and the name kept passing through until the leaf arrived. The plain form replaces `on_demand_secret`, which takes the alpha extension off the data path.

## Decisions this plan makes

Each is stated so a reviewer can reject it.

1. Chain match: the matcher tree above. Chains are named `decrypt/<host>` and `passthrough`. Pod addresses come from the API (pods scheduled on this node), not from `bindings`. A pod on the host network shares the node's address and is never matched for decryption.
2. A pod's decrypted names are computed per pod: the exact hosts of the objects that select it, plus the learned names that match one of those objects' own patterns, minus its passthrough entries. The host set stays node-wide for minting and for the cap. This is what keeps pod A from being decrypted for a host only pod B's policy names (review focus 2).
3. An object applies to a pod when its selector matches, it has an `http` section and `spec.mode` is not `off`. Whether node-agent has bound the pod is not checked here: an unbound pod is never redirected, and if it dials the listener itself the processor rejects it for having no `conns` entry.
4. C3's `bindingIds` are accepted and logged, not used for scoping. Scoping by the pod's own patterns (decision 2) gives the same result without mapping binding ids back to pods.
5. Open connections per name are read from Envoy's stats (`http.<prefix>.downstream_cx_active`, one stat prefix per chain) over the admin socket. The node controller therefore does not read `conns` or `bindings` at all. The plan's "T7 reads `conns` and `bindings`" is covered by the kernel hook in the spike.
6. Envoy's admin interface moves from `127.0.0.1:9901` to the unix socket `/run/sandbox-gateway/envoy-admin.sock`. On the host network a loopback port is reachable by every process on the node, and admin can stop Envoy. The directory is private to the gateway pod (an emptyDir). It is not `/run/kubescape-sandbox`, because node-agent mounts that one too.
7. LDS and SDS are served on one gRPC socket, `/run/kubescape-sandbox/xds.sock` (was `sds.sock`). LDS is state of the world: two resources, `egress_tls` and `health`. Its `initial_fetch_timeout` is 0, so an Envoy that starts while the node controller is down opens no listener, the health probe fails and the gate opens. With the default it would open the health listener after 15 seconds with no redirect listener behind it.
8. The SDS config also gets `initial_fetch_timeout: 0s`. A chain whose leaf has not arrived never goes live, so its name keeps passing through instead of failing handshakes. The node controller mints a name's leaf before it adds the chain.
9. The decrypt upstream stays the dynamic forward proxy cluster. Each chain's route has one virtual host whose domains are the chain's name and `name:443`, so a `Host` that differs from the SNI gets a 404 and the upstream name is the chain's. No CDS.
10. C3 and the `certs` half of C4 share one HTTP server on `/run/kubescape-sandbox/gateway.sock`: `POST /v1/sightings` and `GET /healthz/certs`.
11. On-node sources. The health listener uses the same matcher on source address: every pod address on this node, the node's own addresses and loopback. On EKS pod addresses come from the VPC and there is no per-node range, so the list is built from the pod informer.
12. The stand-in intermediate. Until the operator issues one, the node controller creates a root and an intermediate in memory at start (24 hours, replaced at 12) behind an interface the operator client will implement. `rootFingerprint` is the SHA-256 of the root certificate in hex. `--ca-cert`, `--ca-key` and `--gen-ca` stay for tests that need the client to trust a root on disk.
13. Over the cap, existing names keep their place. A new exact host takes a free slot, then the slot of an idle learned name. When neither exists it passes through and is counted. `passedThroughOverCap` is the number of names wanted now and not in the set.
14. No name leaves in one step. A name nobody wants, or one evicted for room, is retired first: its chain stays and no pod maps to it. It is removed only when it is idle and Envoy has accepted the listener that unmapped it. Checking the connection count and removing the chain in the same update would leave a window in which a new connection lands on a chain about to go.

## Open items that need an answer

1. Who loads the `getsockopt` program. It belongs with the redirect loader in node-agent (T4, SUB-9947), attached at the cgroup root and filtered on the listener port, since it reads `conns`. That adds one program to T4's list and one line to C1. Until T4 lands, the integration job loads the spike's program from `test/origdst/`. Needs the contract owner's yes.
2. Overload and C4. Measured on 1.40.2 with an injected resource monitor: while `envoy.overload_actions.stop_accepting_requests` is active, the health listener answers `503 envoy overloaded` on every path (the admin interface still answers 200). The action applies to every connection manager and has no per-listener exemption. So global request shedding would fail C4 and open the gate, which the ticket forbids. No overload config ships until this is decided. The options:
   - (recommended) No global request shedding. Bound the decrypted path alone: circuit breakers on the decrypt and `ext_proc` clusters (a cap on concurrent decrypted requests), with a fixed JSON body through the decrypt chains' `local_reply_config`. The health listener has its own connection manager and is not touched. `shrink_heap` stays as the only global action.
   - Keep global shedding and accept that overload opens the gate for `allow` pods. That is fail-open under load, a change to the design's posture.
   - Serve C4 without a connection manager. Not possible with three routed paths on one port.
3. "Sheds with the plugin's provider-shaped error". Envoy sheds before `ext_proc` runs, so the evaluator is never asked. Task 5.4 ships a fixed JSON error from Envoy through `local_reply_config`. A provider-shaped body needs the processor to shed, which is a change in the processor packages and is not made here.
4. Passthrough entries. The CRD does not say whether `decrypt.passthrough` takes patterns. This plan treats an entry with `*` as a pattern in the host set's syntax and anything else as an exact name.

## Pull requests

Each PR is a draft with SUB-9949 in the title. They stack in this order; a later branch contains the earlier ones until those merge.

| PR | Branch | Contents |
|---|---|---|
| 1 | `docs/SUB-9949-node-controller-plan` | This plan and the spike record |
| 2 | `feat/SUB-9949-host-set` | Width check with the shared vectors, total cap, eviction that skips busy names, per-pod names |
| 3 | `feat/SUB-9949-node-view` | Informers on pods, namespaces and both policy kinds; the per-node snapshot |
| 4 | `feat/SUB-9949-xds` | Intermediate holder, listener builder, LDS, SDS rework, sightings socket, new bootstrap, integration stack on LDS |
| 5 | `feat/SUB-9949-passthrough` | Passthrough to the original destination, with the test's BPF stand-in |
| 6 | `feat/SUB-9949-health` | Health listener. Overload waits for open item 2 |
| 7 | `feat/SUB-9949-node-status` | `SandboxGatewayNodeStatus` writer |
| 8 | `test/SUB-9949-integration` | The remaining integration tests and the SigV4 check |

## PR 2: host set

Files: `internal/hostset/width.go`, `width_test.go`, `testdata/host_pattern_vectors.json`, `hostset.go`, `hostset_test.go`, `docs/features/node-controller.md`.

- [ ] 2.1 Copy the width vectors. Write `TestWidthVectors` over them, failing.
- [ ] 2.2 `CheckWidth(pattern string) error`: at most one label carries `*`, the last two labels are literal, a letter or digit stands outside the last two labels; lower case, no trailing dot, no doubled `*`. `Match` and the processor's use of it do not change.
- [ ] 2.3 Tests first for the new set: 300 exact hosts with cap 256 admit 256 and report 44 over the cap; an exact host evicts an idle learned name; a busy learned name is not evicted and the newcomer is counted; a rejected pattern learns nothing and is listed once; a name leaves when no object wants it and it is idle, and stays while busy.
- [ ] 2.4 `Set`: `New(cap int, busy func(name string) bool)`, `Apply(Wanted)` (the node's exact hosts and patterns), `Observe(name)`, `Contains`, `Names`, `Counts`, `RejectedPatterns`.
- [ ] 2.5 `NamesFor(exact, patterns, passthrough []string) []string`: the per-pod list of decision 2. Tests: a learned name reaches only the pod whose pattern matches; a passthrough entry removes a name; a name over the cap is in no pod's list.

## PR 3: node view

Files: `internal/nodeview/view.go`, `informers.go`, `static.go`, tests.

- [ ] 3.1 Tests first with fake clients: a namespaced policy selects by pod labels; a cluster policy also by namespace labels; `mode: off` and an object with no `http` section apply to nothing; a pod on another node, a pod with no address and a host-network pod are left out; two pods with different policies get different lists.
- [ ] 3.2 `Snapshot{Pods []Pod, OnNode []netip.Addr}` with `Pod{Namespace, Name, Addrs, Exact, Patterns, Passthrough}`. `Source` interface with `Snapshot()`, `Synced()` and a change channel.
- [ ] 3.3 Informers: pods with the field selector `spec.nodeName`, namespaces, and dynamic informers on `sandboxpolicies` and `clustersandboxpolicies`. Changes are coalesced (100 ms) before a rebuild.
- [ ] 3.4 `static.go`: a snapshot from a YAML file, for the integration stack.

RBAC this needs, for the chart: `list` and `watch` on pods, namespaces and both policy kinds.

## PR 4: xDS

Files: `internal/ca/authority.go`, `internal/xds/listener.go`, `lds.go`, `internal/sds/server.go`, `internal/gatewaysock/`, `cmd/node-controller/main.go`, `deploy/envoy/envoy.yaml`, `test/integration/`.

- [ ] 4.1 `ca.Authority`: holds the intermediate, mints leaves, `Replace(cert, key, root)` drops every cached leaf. Tests: a leaf verifies against the root through the intermediate and not against another node's; a replaced intermediate changes every leaf and the root fingerprint; `ValidUntil` is the earlier of the intermediate and the oldest leaf handed out.
- [ ] 4.2 `ca.SelfSigned`: decision 12, with a renewal timer.
- [ ] 4.3 Listener builder, golden-file tests first: the matcher tree; one chain per name with the per-chain SDS secret; resumption off; `use_remote_address`, `skip_xff_append`; `ext_proc` in `FULL_DUPLEX_STREAMED` with `failure_mode_allow: false`; `accept-encoding: identity` at the route; `alt-svc` removed; WebSocket upgrade; one virtual host per chain. Output is deterministic (sorted), so an unchanged input gives a byte-equal listener.
- [ ] 4.4 LDS server, state of the world, with ACK and NACK handling. A NACK is logged and counted, and the last accepted version stays in force.
- [ ] 4.5 The reconcile loop: snapshot and sightings in, `Set.Apply`, mint missing leaves, build, push. A name the set dropped keeps its chain until Envoy reports it idle.
- [ ] 4.6 SDS: serve only names in the set, version from the leaf's serial, push on renewal and on a replaced intermediate.
- [ ] 4.7 `gatewaysock`: `POST /v1/sightings` (C3).
- [ ] 4.8 Bootstrap: admin on the socket, LDS over gRPC, the static clusters. Remove the explicit-proxy and internal listeners.
- [ ] 4.9 Integration stack on LDS: the existing checks pass unchanged, plus a second client address that is passed through for a name the first is decrypted for.

## PRs 5 and 6: passthrough, then health and overload

- [ ] 5.1 `test/origdst/`: the program and a loader that fills `conns`, built in the test image. The integration job runs it privileged.
- [ ] 5.2 `original_dst` listener filter and the `ORIGINAL_DST` cluster on the passthrough chain. Tests: a passthrough connection reaches the address in `conns`; one with no entry is reset; a pod's passthrough host is not decrypted when another pod's policy names it.
- [ ] 5.3 Health listener (C4): `/healthz/envoy` as a direct response, `/healthz/processor` to the processor's health socket, `/healthz/certs` to `gateway.sock` with `canDecrypt`, `decryptValidUntil` and `rootFingerprint`. Tests: each path answers from its own process and survives the other two being stopped; an address that is not on the node is reset; with the node controller down at Envoy's start nothing listens.
- [ ] 5.4 Overload manager: measure open item 2 first, then heap and connection monitors, request shedding with a fixed JSON body, never `stop_accepting_connections`.
- [ ] 5.5 Upstream TLS checks the SAN; a `Host` that differs from the SNI is refused.

## PR 7: node status

- [ ] 6.1 Tests first with a fake dynamic client: the object is created with an owner reference to the Node, then `/status` is updated with the resource version from the read; every field of C5 is written; `rejectedPatterns` is capped at 64.
- [ ] 6.2 Sources: Envoy's admin socket (up, version, overload), the processor's health body (up, evaluator, degraded decisions), the host set, the authority.
- [ ] 6.3 Written every 30 seconds and on a change, with a floor of 5 seconds between writes.

## PR 8: remaining integration tests

- [ ] 7.1 A 1,500-name SNI flood mints nothing and Envoy's memory stays flat.
- [ ] 7.2 Adding a chain does not drain a live stream; an idle chain is removed and a busy one kept.
- [ ] 7.3 A renewed leaf is served without a restart; `decryptValidUntil` moves with it.
- [ ] 7.4 SDS down, first call still works.
- [ ] 7.5 `rootFingerprint` changes when the intermediate moves to a new root.
- [ ] 7.6 `accept-encoding: identity` with a SigV4-signed Bedrock request from the AWS SDK for Go and from boto3, against a mock that verifies the signature.

## What the operator ticket builds on

The interface in 4.1 and 4.2 is where the operator's signing client plugs in. The sockets, flags and RBAC the chart needs are listed in `docs/features/node-controller.md` as each PR lands.
