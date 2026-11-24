---
type: reality
status: active
owner: amirmalka
scope: repo
---

# Node controller

The node controller is the gateway's control process on one node. It decides which hostnames Envoy decrypts there and for which pods, serves Envoy its listeners and certificates, and holds the node's intermediate CA. The program is `cmd/node-controller`; the loop is `internal/controller`.

The plan for what is not built yet (overload settings) is `docs/superpowers/plans/2026-11-24-node-controller.md`.

## What runs where

Envoy's bootstrap (`deploy/envoy/envoy.yaml`) holds only the clusters and the admin socket. The listeners come from the node controller, because the decrypted names and the pods allowed to reach each one keep changing.

| Socket | Served by | Used by | For |
|---|---|---|---|
| `/run/kubescape-sandbox/xds.sock` | node controller (gRPC) | Envoy | listeners (LDS) and leaf certificates (SDS) |
| `/run/kubescape-sandbox/gateway.sock` | node controller (HTTP) | node-agent, Envoy | `POST /v1/sightings`; `GET /healthz/certs` for the health listener |
| `/run/kubescape-sandbox/processor-health.sock` | processor (HTTP) | Envoy | `GET /healthz/processor` for the health listener |
| `/run/kubescape-sandbox/extproc.sock` | processor | Envoy | `ext_proc` |
| `/run/sandbox-gateway/envoy-admin.sock` | Envoy | node controller | stats: open connections per hostname |

Envoy's admin interface has no authentication and can stop Envoy. On the host network a loopback port is open to every process on the node, so admin is a unix socket (mode 0660, the node controller is in Envoy's group). Its directory, `/run/sandbox-gateway`, is private to the gateway pod. It is not `/run/kubescape-sandbox`, which node-agent mounts too.

Envoy waits for its first listeners without a timeout (`initial_fetch_timeout: 0s`). An Envoy that starts while the node controller is down serves nothing until the node controller answers; it never comes up looking healthy with no redirect listener.

## The redirect listener

`internal/xds` builds the listener `egress_tls` on port 18443 (`-listener-port`). It has:

- one filter chain per name in the host set, `decrypt/<name>`, rendered from `internal/xds/templates/decrypt_chain.yaml`. There is never a wildcard chain;
- one `passthrough` chain (`passthrough_chain.yaml`);
- a matcher (`filter_chain_matcher`) that picks the chain from the connection's source address and then its SNI.

| Connection | Chain |
|---|---|
| from a pod, SNI is a name that pod is decrypted for | that name's decrypt chain |
| from a pod, any other SNI, or none | `passthrough` |
| from an address that is no selected pod's on this node | none: Envoy resets it |

A pod is "selected" when a policy object with an `http` section applies to it (see "Node view"). Pod addresses are in the matcher and never in a chain. Envoy applies a matcher change in place and drains nothing. A change to a chain replaces the chain and cuts the streams on it at the drain time, so chains only ever get added or removed.

### Passthrough

A passthrough connection goes where the pod was connecting to, and nowhere else. The SNI is the workload's to choose, so it never picks the destination: forwarding by it would let a pod reach any host through the gateway.

Envoy does not know that destination by itself. The redirect rewrites the address at connect time, so there is no NAT entry for the kernel to answer `SO_ORIGINAL_DST` from. The pieces:

1. A `cgroup/getsockopt` BPF program answers `getsockopt(SOL_IP, SO_ORIGINAL_DST)` for sockets on the listener's port. It looks the socket's peer address and port up in `conns` and returns the original destination recorded there.
2. The listener's first filter is Envoy's stock `original_dst`, which asks that question and restores the address on the connection. It does not hand the connection to another listener.
3. The passthrough chain is a `tcp_proxy` to the `orig_dst` cluster (type `ORIGINAL_DST`), which connects to the restored address.

A connection with no `conns` entry gets no answer, so nothing is restored. The cluster refuses such a connection and Envoy resets it; it cannot loop back into the listener.

The program has to be loaded by whatever owns `conns`, which is the redirect loader. This repo carries a copy for the integration test only: `test/origdst/` (the C source, a loader that also fills `conns`, and its image). The listener is IPv4, so only `SOL_IP` is handled.

A decrypt chain:

- terminates TLS with the name's leaf, a plain SDS secret named after the host. Session resumption is off. The SDS config has `initial_fetch_timeout: 0s`: a chain whose leaf has not arrived does not go live, and the name keeps passing through until it does;
- runs `ext_proc` in `FULL_DUPLEX_STREAMED` mode with `failure_mode_allow: false`, passing `source.address`;
- routes only its own name. The virtual host's domains are the name and `name:443`; a `Host` that differs from the SNI gets a 404. The dynamic forward proxy resolves the `Host`, so this also pins the upstream to the chain's name, and the upstream certificate is checked against it;
- sets `accept-encoding: identity` on the upstream request, after `ext_proc`, and removes `alt-svc` from responses;
- takes the remote address from the socket (`use_remote_address`, `skip_xff_append`) and allows WebSocket upgrades;
- has its own stat prefix, `egress_<name with dots as underscores>`.

The listener never parses PROXY protocol: the pod writes the first bytes of the connection, and the pod's identity is keyed on the remote address.

## The health listener

node-agent probes the gateway to decide whether to keep redirecting. `internal/xds` builds a second listener, `health`, on port 18444 (`-health-port`). It has three paths, each answered by a different process, so one of them dying does not hide the others:

| Path | Answered by | Answer |
|---|---|---|
| `GET /healthz/envoy` | Envoy itself | `200 ok` |
| `GET /healthz/processor` | the processor, on `/run/kubescape-sandbox/processor-health.sock` | 503 until its policy informers have synced, then 200 with `evaluator`, `degradedDecisions`, `stuckEvaluatorCalls` |
| `GET /healthz/certs` | the node controller, on `gateway.sock` | `200 {"canDecrypt": true, "decryptValidUntil": "<RFC 3339>", "rootFingerprint": "<sha256, hex>"}` |

Any other path is a 404. A process that is down gives a 503 on its own path only. The two routed paths time out at 300 ms, under the probe's own 400 ms.

`/healthz/certs` answers 200 whenever the node controller is up. The body says whether the node can decrypt: `canDecrypt` is false with no intermediate, or when the one held has less than one leaf lifetime left. `decryptValidUntil` is left out when there is no intermediate.

The listener takes connections from this node only. Its matcher lists the address of every pod on the node (node-agent is one of them), the node's own interface addresses and `127.0.0.1`; any other source gets no chain and is reset. On EKS pod addresses come from the VPC and a node has no pod range of its own, so the list is built from the pods and kept current by the same in-place matcher updates as the redirect listener.

Both listeners arrive in one LDS response. An Envoy that starts while the node controller is down opens neither: the probe gets a refused connection, not a healthy answer with no redirect listener behind it.

Overload settings are not configured yet. Envoy's global request shedding also answers 503 on this listener, which would make a loaded gateway look dead; the plan's open item 2 has the measurement and the options.

## Reconcile

`internal/controller` rebuilds the listener when the node view changes, when a sighting arrives, when the intermediate is replaced, and every 5 seconds. One run:

1. Reads `http.egress_*.downstream_cx_active` from Envoy's admin socket. When Envoy cannot be asked, every name counts as busy.
2. If Envoy has accepted the last listener sent, sweeps the retired names that are idle (see "Names with open connections").
3. Applies the node view to the host set.
4. Mints a leaf for every name in the set. A name whose leaf cannot be minted gets no chain. With no intermediate there are no decrypt chains and everything passes through.
5. Computes each pod's names, builds the listener and hands it to the LDS server, which pushes only when it differs from the last one.

Nothing is built before the node view has synced: a listener from half a view would drop chains in use.

LDS is state of the world over one gRPC stream. A listener Envoy rejects (NACK) is logged and counted, and Envoy keeps the last one it accepted.

## Certificates

`internal/ca.Authority` holds the node's intermediate and the leaves signed with it. The intermediate's key stays in the process's memory.

- A leaf lives one hour (`-leaf-ttl`) and is re-minted once it is past half of that. The SDS server checks each stream's names every minute (`-renew-every`) and pushes a leaf that changed. Envoy never asks again on its own.
- A leaf's chain is the leaf and the intermediate. Pods trust the root.
- A leaf is minted only for a name in the host set (`sds.Gated`).
- Replacing the intermediate drops every leaf. The next reconcile mints them again and the SDS server pushes them at once.
- `Authority.State` reports `CanDecrypt` (false when there is no intermediate, or the one held has less than one leaf lifetime left), `ValidUntil` (the earliest expiry among the leaves held and the intermediate) and the root's SHA-256 fingerprint.

Until the operator issues node intermediates, `ca.SelfSigned` stands in: the process signs its own intermediate (24 hours, `-intermediate-ttl`, replaced at half) from a root it creates in memory. `-ca-cert`, `-ca-key` and `-gen-ca` put that root on disk, for test stacks whose client has to trust it.

## Sightings

node-agent posts a hostname it saw in a workload's DNS answers:

```
POST /v1/sightings   on /run/kubescape-sandbox/gateway.sock
{"name": "myres.openai.azure.com", "addresses": ["20.0.0.1"], "bindingIds": [7]}
200 {"changed": true}
```

The name joins the host set when a valid pattern on the node covers it. `addresses` and `bindingIds` are accepted and not used: node-agent keeps the address set, and a learned name reaches a pod when one of that pod's own patterns covers it. A body over 64 KiB is refused.

## Node status

`internal/nodestatus` writes one `SandboxGatewayNodeStatus` object per node (`kubescape.io/v1alpha1`, cluster-scoped, named after the node). It is a snapshot: every field is written each time, and `observedAt` says how old it is. A reader must check `observedAt` and not only that the object exists.

| Field | From |
|---|---|
| `envoy.up`, `envoy.version` | Envoy's admin socket (`/server_info`); down when it does not answer or is not live |
| `processor.up`, `processor.evaluator` | the processor's health path; `unavailable` unless it answers 200 and says `available` |
| `overloaded` | true when any of Envoy's `overload.*.active` gauges is set |
| `hosts.exact`, `hosts.learned`, `hosts.cap` | the host set |
| `rejectedPatterns` | the host set's refused entries, at most 64 |
| `passedThroughOverCap` | names wanted now and left out by the cap |
| `evictions` | learned names evicted since the node controller started |
| `degradedDecisions` | the processor's count; while the processor is down, the last one it reported |
| `decryptValidUntil` | the authority; absent with no intermediate |

The object is written when it changes and at least every 30 seconds, never more often than every 5.

The writer creates the object if it is missing, with an owner reference to the Node so it is collected when the node goes. The reference does not block the Node's deletion. If the Node cannot be read the object is created without an owner. The status goes through the `status` subresource with the resource version just read.

RBAC it needs: `get` and `create` on `sandboxgatewaynodestatuses`, `update` on `sandboxgatewaynodestatuses/status`, and `get` on `nodes` for the owner reference.

With `-view-file` there is no API server and no status object is written.

## Flags

| Flag | Default | |
|---|---|---|
| `-listen` | `unix:///run/kubescape-sandbox/xds.sock` | LDS and SDS |
| `-gateway-socket` | `unix:///run/kubescape-sandbox/gateway.sock` | sightings |
| `-envoy-admin` | `/run/sandbox-gateway/envoy-admin.sock` | Envoy's admin socket |
| `-node-name` | `$NODE_NAME` | the node whose pods are watched |
| `-name-cap` | 256 | names with a certificate and a chain |
| `-leaf-ttl`, `-renew-every` | 1h, 1m | leaves |
| `-intermediate-ttl` | 24h | the stand-in intermediate |
| `-listener-port`, `-health-port` | 18443, 18444 | the redirect and health listeners |
| `-decrypt-cluster`, `-passthrough-cluster` | `dfp`, `orig_dst` | bootstrap clusters the chains route to |
| `-processor-health-socket` | `/run/kubescape-sandbox/processor-health.sock` | read for the node status |
| `-view-file` | | pods and policy objects from a YAML file, for test stacks; no status object is written |
| `-debug-addr` | off | `/stats` and `/debug/vars`, no authentication |

Sockets are created with mode 0660. `SANDBOX_GATEWAY_SOCKET_GID` sets their group, so Envoy can connect.

## Host set

`internal/hostset.NodeSet` is the set of names that get a certificate and a filter chain on the node.

Policy objects give two lists. An exact host is in the set as soon as an object on the node asks for it. A host pattern never reaches Envoy as a pattern: a name under it joins only after node-agent has seen it in a workload's DNS answers (`Observe`). The SNI a client sends is never enough to join.

### The cap

One cap covers every name, exact and learned together (default 256). It bounds how many certificates the node mints whatever the policies say.

- An exact host takes a free slot. With none free, the learned name seen longest ago that has no open connections is retired for it, and the host joins once that name has been swept.
- A sighted name does the same. node-agent posts a sighting once, so the set remembers a name that is waiting.
- While a name waits, and when the set is full of exact hosts or busy names, its traffic passes through undecrypted and it is counted in `Counts().OverCap`.
- Names already in the set keep their place. A new exact host that sorts earlier does not displace one that has a chain.

### Names with open connections

Removing a chain cuts the streams on it, so a name with open connections is never removed, and no name leaves in one step. A name no object wants any more, or a learned name evicted to make room, is first retired: it keeps its chain, its certificate and its slot, and no pod's list contains it, so no new connection is decrypted for it. `Sweep` removes a retired name once it is idle. The reconcile loop sweeps only after Envoy has accepted the listener that stopped mapping pods to the name. From that point no new connection can reach the chain, so a count of zero stays zero.

### Pattern width

Every `hostPatterns` entry goes through `CheckWidth` before anything is learned under it. A pattern passes when at most one label carries `*`, its last two labels are literal, and a letter or digit stands outside the last two labels. `*.openai.azure.com` and `bedrock-runtime.*.amazonaws.com` pass; `*.amazonaws.com` does not. The rule reads the pattern alone, with no public-suffix list, so `*.foo.co.uk` passes.

The policy compiler applies the same rule, and the test vectors in `internal/hostset/testdata/host_pattern_vectors.json` are shared with it. The node checks again because an object can be written by hand.

A pattern that fails learns nothing, and `RejectedPatterns` lists it. An exact host that is not a plain hostname is listed there too.

### Per pod

The set is node-wide. Who is decrypted for a name is decided per pod. `NamesFor` takes the lists of the policy objects that select one pod and returns:

- its exact hosts that are in the set,
- the learned names one of its own patterns covers,
- minus its `passthrough` entries. An entry with `*` is a pattern, any other is an exact name.

So a pod is never decrypted for a host that only another pod's policy names, even when both hosts share an address.

## Node view

`internal/nodeview` is where the per-pod lists come from. It watches four resources and needs `list` and `watch` on each:

| Resource | Why |
|---|---|
| `pods`, with the field selector `spec.nodeName` | the pods on this node, their labels and addresses |
| `namespaces` | a `ClusterSandboxPolicy` selects namespaces by label |
| `sandboxpolicies`, `clustersandboxpolicies` (`kubescape.io`) | selectors and the `http.decrypt` lists |

A policy object applies to a pod when its selector matches the pod, it has an `http` section, and `spec.mode` is not `off`. A `SandboxPolicy` selects pods in its own namespace. A `ClusterSandboxPolicy` also needs its namespace selector to match the pod's namespace; the empty selector matches every namespace, and an object with no namespace selector selects nothing. When several objects apply to one pod, their exact hosts, patterns and passthrough entries are each merged as a union.

The view does not check whether node-agent has bound the pod. An unbound pod is never redirected, so its entry is not used.

Pods the view leaves out:

- a pod on another node, a pod with no address yet, and a pod that has finished (its address may already belong to another pod);
- a pod on the host network. Its connections carry the node's address, which every host process shares, so it is never matched for decryption.

`Snapshot.OnNode` lists the address of every pod on the node, selected or not. The health listener uses it to accept on-node sources only.

`LoadStatic` builds the same view from a YAML file of `Pod`, `Namespace` and policy objects, for test programs with no API server.
