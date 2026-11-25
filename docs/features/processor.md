---
type: reality
status: active
owner: amirmalka
scope: repo
---

# Processor

The processor is the gateway's Envoy external processor (`ext_proc`). Envoy sends it every decrypted request and response in `FULL_DUPLEX_STREAMED` mode, so the processor sees each body chunk and returns the bytes Envoy forwards. It works out which pod sent the request, hands the request to the evaluator and enforces its verdict, parses the streamed response, and writes one record per transaction.

The program is `pkg/processor.Main()`; `cmd/processor` calls it and registers no evaluator. The wiring is `internal/app`, the server `internal/extproc`.

## Who sent the request

Identity comes from two tables node-agent pins under `/sys/fs/bpf/kubescape-sandbox/http/` (`internal/conntable`), and from node-agent's workload lookup (`internal/lookup`). Nothing the client sends is used.

1. Envoy passes the downstream remote address as the `source.address` request attribute. That is the pod socket's own address and port. An IPv4 address in its IPv6-mapped form is the same key.
2. `conns`, keyed on that address and port, gives the cgroup, the pid, the binding and the original destination. It is read on every request and never cached by address, because the kernel reuses an address and port for another pod's connection once the first one closes.
3. `bindings`, keyed on the cgroup, gives the pod's fail posture (`allow` or `deny`) and its health-gate state. Its binding id must equal the one in the `conns` entry.
4. `GET /v1/workload?cgroup=<id>` on `/run/kubescape-sandbox/lookup.sock` names the namespace, pod, container, controller and the policy objects that cover the pod.

The kernel tables decide the binding. The binding id on the record is the one in `conns`, and it must equal the one in `bindings` (otherwise `binding_mismatch`, below); the posture and the gate come from that same `bindings` entry. The lookup only names the workload, and its answer is used only when its `bindingId` is that same binding. When it names another binding, because node-agent's view or the cache lags a rebinding, the request is not refused, but none of the lookup's fields go on the record: it carries the kernel half of the identity and a `lookup_error` that starts with `binding_mismatch`.

A request is refused with a 403 from the processor, before anything reaches the provider, when:

| `reject_reason` | Cause |
|---|---|
| `no_source_address` | Envoy sent no usable `source.address` |
| `no_connection_entry` | the connection is not in `conns` |
| `not_bound` | the cgroup has no `bindings` entry, or node-agent answers that it is not bound |
| `binding_mismatch` | the binding id in the `conns` entry differs from the one in the cgroup's `bindings` entry, so the connection was made under another binding |
| `connection_table_error` | reading a map failed |
| `no_connection_table` | the processor has no tables (a build or wiring error) |

A PROXY protocol identity that arrives in the `kubescape.sandbox.attribution` metadata is never used. The record notes it as `ppv2_ignored`.

When node-agent's socket does not answer, the last answer for that cgroup is served from a cache, and the record carries `lookup_failing_since`. With no cached answer the record carries `lookup_error` and only the kernel half of the identity. Neither case is refused.

The lookup runs while the request headers wait, so it is kept short. One request per cgroup is in flight at a time; while it is, other requests for that cgroup get the cached answer at once. After a failed request the cgroup is not asked about again for one second, counted from when the failure came back (a request can take up to the two-second client timeout to fail). A request the client abandoned does not count as a failure.

The pod's namespace, pod name, container, binding id, fail posture and original destination are also written to the `kubescape.sandbox.audit` metadata, so Envoy's access log shows them.

### What the Envoy config must do

The identity is only as good as `source.address`, so the listener must report the socket's own address. The decrypting chain the node controller serves (`internal/xds/templates/decrypt_chain.yaml`) does two things for that, and a config that drops either lets a pod be taken for another pod:

- It has no `proxy_protocol` listener filter. That filter replaces the remote address with the one in the PROXY header, which the pod writes.
- The HTTP connection manager sets `use_remote_address: true`. Without it Envoy takes the remote address from an `X-Forwarded-For` header.

`test/integration/run.sh` sends both a forged `X-Forwarded-For` header and a PROXY protocol line and fails if the processor sees the forged address.

The proof of concept's explicit-proxy listener (port 3128) is gone from the gateway's Envoy config. A connection that arrived through it had no socket address to look up and no `conns` entry, so the processor refused every request on it with `no_source_address`.

### Request position

The verdict record's join key ends in `request_position`. The C7 contract defines it as the HTTP/2 stream id, or the request's ordinal on an HTTP/1.1 connection. The processor sends neither, so the record has no `request_position`, and the backend uses the contract's fallback join: the connection plus method, path and a time window. The record keeps the method and path (as `gateway.method` and `gateway.path`) and its timestamp for that join.

We checked the stream id against Envoy v1.40.2, with an ext_proc server that printed every attribute it received. The client opened three HTTP/2 streams on one connection, then sent three HTTP/1.1 requests on another. Envoy has no stream id attribute and drops unknown attribute names without a word. The `%STREAM_ID%` access-log field is Envoy's own id for the stream, not the HTTP/2 one. The three HTTP/2 streams reached the processor in the order a, c, b, so a count of them gives the order they reached the processor, not the order the client opened them.

The HTTP/1.1 ordinal looks easy, since `connection.id` arrives with every request and the requests on a connection run one after another. But a count is only right if the processor saw the connection's first request, and nothing Envoy sends says so: there is no connection start time and no request count per connection. After a processor restart, a connection that was already open looks like a new one, and the next request would be numbered 1. A wrong position that looks valid would join a verdict to another request's capture, which is worse than no position.

### Map layout

Integers are in host byte order. Addresses are 16 bytes, IPv4 in its IPv6-mapped form. The structs use natural C alignment:

| Map | Key | Value |
|---|---|---|
| `conns` | address (16), port `u16`: 18 bytes | cgroup `u64`, pid `u32`, binding `u32`, original destination address (16) and port `u16`, padded to 40 bytes |
| `bindings` | cgroup `u64`: 8 bytes | binding `u32`, posture `u8` (0 allow, 1 deny), gate `u8` (0 redirecting, 1 failing open, 2 recovering), padded to 8 bytes |

The processor opens both maps read-only at start and exits if either is missing or has another key or value size. It needs `CAP_BPF` and the bpffs mount.

## The evaluator

The processor decides nothing itself. An evaluator does, through the interface in `pkg/plugin` (contract C6): `Classify` names the provider and model from the host, the path and the body; `Evaluate` returns a verdict; `DenyResponse` and `StreamError` give the provider-shaped answers for a blocked request and for a stream ended by the watchdog.

A build registers its evaluator with `plugin.Register`, from an `init` function of the evaluator's package, and then calls `processor.Main()`. A build that registers none passes every request: nothing is held, classified or evaluated, and the start-up log and `/stats` on the debug server report `"evaluator":"unavailable"`.

With an evaluator, one request goes like this:

1. At the request headers the processor starts `Classify` with the read end of a pipe. A request with no body, and a WebSocket upgrade, get an empty body and are decided at the headers; WebSocket frames are never fed to the evaluator.
2. Each body chunk is written to the pipe and forwarded one chunk behind, so the newest chunk waits for the verdict. A blocked request therefore never reaches the provider whole.
3. At the end of the body, or at the trailers, the pipe is closed, `Classify` returns, and `Evaluate` gets the `Request`: the workload (with the fail posture from the `bindings` table and the policy references from the lookup), host, method, path, headers, model, the cached policy sections and whether the decision is degraded (see "Policies and degraded decisions").
4. A verdict of `deny` in `enforce` mode blocks the request with the evaluator's `DenyResponse`. A `deny` in `audit` mode passes and the record has `would_deny`. Anything else passes and the held chunk is released.

Every call into the evaluator is bounded, because Go cannot stop a function that ignores its context:

- Each call runs in its own goroutine and holds one of `-max-evaluator-calls` slots until it returns. A call past its deadline keeps its slot and counts as stuck; `/stats` shows `stuckEvaluatorCalls`.
- `Classify`, each write of a body chunk to it, and `Evaluate` get `-chunk-budget` each. `DenyResponse` and `StreamError` get 200 ms. The context `Evaluate` gets ends at its budget, so an evaluator that honours it gives the slot back in time. The same deadline decides whether its answer counts: a verdict that comes back after it is refused, and the request gets the timeout denial.
- A `Classify` still running when a body write times out counts as stuck until it returns.
- When `Classify` or `Evaluate` stalls, panics, or `Evaluate` finds no slot, the request is refused with `DenyResponse`, rule `framework.evaluator-timeout`.
- When `DenyResponse` itself finds no slot, stalls or panics, the processor sends its own 403, `{"error":{"type":"gateway_error","message":"request blocked by the gateway"}}`. A deny verdict stands even then, on any pod.
- When no slot is free to start `Classify`, the request cannot begin evaluation and the pod's fail posture decides: an `allow` pod passes, a `deny` pod gets the processor's 403 with rule `framework.evaluator-saturated`. Both records are `degraded`.
- On every way a transaction ends (verdict, timeout, client reset, stream error), the pipe is closed, which unblocks `Classify` and any writer.

The watchdog ends a response whose chunk takes longer than `-chunk-budget` with the evaluator's `StreamError` frame and end of stream. With no evaluator, or a `StreamError` that cannot answer in 200 ms, the stream ends with no frame.

The record carries `provider`, `model`, the `verdict` (action, mode, rule, origin, policy uid and revision), `would_deny`, `degraded` and `evaluator_error`, which says which call failed and how. The access log shows `rule_id`, `action`, `mode`, `would_deny`, `degraded` and `model`.

## Policies and degraded decisions

The processor runs its own informers on `SandboxPolicy` and `ClusterSandboxPolicy` (`internal/policysource`, contract C11), with the pod's service account, which needs `list` and `watch` on both kinds across all namespaces. For each request it resolves the policy references the lookup names by UID in the informer cache, and hands the evaluator the `http` section of each, unmerged, as `Request.Sections`. A reference cached at another generation yields the cached copy; a UID the cache does not hold is missing.

The pod's fail posture never comes from those sections, because the section that is missing can be the one that says `deny`. It comes from the `bindings` table.

A workload's policy is stale from the earliest of: node-agent's lookup serving from its cache, either informer losing the API server (each informer keeps its own outage clock), or a referenced policy not resolving. After `-stale-after` (5m) its decisions are degraded (`internal/stale`). A workload keeps its clock while it is idle. It leaves the tracker only when its policy resolves or when its removal is confirmed: a request finds its cgroup unbound, or the once-a-minute sweep of the kernel bindings table does not find it. The tracker times at most 65,536 workloads and never drops a live one to make room. A newly unresolved workload that arrives while it is full gets an entry of unknown age, up to 65,536 more, and is degraded at once; it stays degraded when a slot opens later. If even those run out, the tracker can no longer tell which workload it turned away, so until the processor restarts every workload it newly admits starts with an unknown age. A sweep removes an entry only if no request observed it after the sweep read the bindings table.

The informers index the objects by UID themselves, so an object deleted and created again under the same name no longer resolves under its old UID. Every list and watch call is counted where it is made: a failure starts that informer's outage clock, a success or any event ends it. Each request gets its own copy of the sections.

Before any body is read, a decision table (`internal/extproc/decide.go`) settles what does not need the evaluator. The first matching row wins:

| Condition | Result |
|---|---|
| No covering policy cached, evaluator present, posture `deny` | the processor's own 403 at the headers, rule `framework.no-cached-policy`, degraded; the evaluator is not called |
| No covering policy cached, otherwise | passes, degraded, nothing evaluated |
| Host not in the decrypt list, decision fresh or posture `deny` | the processor's own 403 at the headers, rule `framework.host-not-decrypted` |
| Host not in the decrypt list, degraded, posture `allow` | passes, degraded |
| No evaluator | passes |

Otherwise `Evaluate` runs, and an enforce-mode deny blocks unless the decision is degraded on an `allow` pod, which passes and is recorded as `would_deny`. The decrypt list is the union over the cached sections of `decrypt.exactHosts` and the names matching `decrypt.hostPatterns`, minus `decrypt.passthrough`. The decrypt-list guard runs without an evaluator too.

Both blocks above happen at the request headers, so none of the request reaches the provider; the provider is not known yet, so the answer is the processor's own 403. `GET /healthz/processor` on `-health-socket` answers 503 until both informers have synced once and delivered that list to their handlers, then 200 with `{"evaluator":"available|unavailable","degradedDecisions":N,"stuckEvaluatorCalls":N}`.

## Streams

| Package | What it does |
|---|---|
| `pkg/jsonscan` | reads named top-level string fields, such as `model`, from a JSON request body in constant memory |
| `internal/sse` | splits a server-sent event stream into events, whatever the chunk boundaries |
| `internal/streamfmt` | recognises Anthropic Messages, OpenAI Chat Completions and OpenAI Responses events, and tracks the items, the stop reason and the end of the stream |
| `internal/renumber` | removes items from a stream and renumbers the ones after them |
| `internal/eventstream` | AWS event-stream frames (Bedrock) |
| `internal/wsframe` | WebSocket frames after an upgrade |

The record's `stop_reason` comes from `streamfmt`: Anthropic's `stop_reason`, OpenAI's `finish_reason`, or the status of a Responses stream's closing event.

Removal has no policy rule yet. `extproc.Config.Remove` (`app.Config.Remove`) turns it on: once per SSE response it gives the filter that picks the items to remove, and the processor runs `internal/renumber` over what it forwards. Only `test/processor-it -remove-first-tool` sets it. The record still counts the stream the provider sent. If the editor meets an event too large to edit once it knows the stream's format, it ends the stream with the evaluator's `StreamError` and the record ends `edit_error`, because forwarding that event unedited could leak a removed item.

## The record

Every transaction ends in one record, whatever ended it: an allowed request, a blocked one, a rejected connection, or the stall watchdog. The JSON log line (and `-records`) carries the full transaction. OTLP gets the verdict record of contract C7: one log record per transaction, family `R-L7-GW` (the instrumentation scope name), with no request or response bytes (`internal/record`).

Its attributes use the C7 names as they are:

| Attribute | Value |
|---|---|
| `crd_uid`, `crd_revision`, `rule`, `origin`, `verdict`, `mode` | from the verdict. A connection refused before any policy applied is `deny` in `enforce` mode, with rule `framework.` plus the reject reason (`framework.no-connection-entry`, for one) |
| `would_deny`, `degraded` | as on the log line |
| `tier` | always `gateway` |
| `fail_posture`, `namespace`, `pod`, `container`, `controller_kind`, `controller_name` | the identity |
| `provider`, `model` | what `Classify` returned |
| `destination_state` | `blocked` for a denied or rejected request, otherwise `inspected`. The processor never sees passthrough traffic |
| `fail_open_window` | the pod's health gate was failing open or recovering when the request arrived |
| `upstream_content_encoding` | only when the upstream answered with an encoding other than `identity` |
| `conn_local_addr`, `conn_local_port`, `orig_dst` | the join key. `request_position` is never sent (above) |

Everything else the processor measured goes under `gateway.`: the transaction id, authority, method, path and protocol, status, how the transaction ended, byte and event counts, timings, the reject reason, and the kernel half of the identity.

## Flags

| Flag | Default | |
|---|---|---|
| `-listen` | `unix:///run/kubescape-sandbox/extproc.sock` | gRPC address for Envoy |
| `-maps-dir` | `/sys/fs/bpf/kubescape-sandbox/http` | where `conns` and `bindings` are pinned |
| `-lookup-socket` | `/run/kubescape-sandbox/lookup.sock` | node-agent's workload lookup |
| `-lookup-refresh` | `5s` | ask node-agent again once a cached answer is this old |
| `-chunk-budget` | `3s` | the stall watchdog, and the budget of each evaluator call and body write; `0` turns the watchdog off |
| `-max-evaluator-calls` | `64` | evaluator calls in flight, stuck ones included |
| `-stale-after` | `5m` | how long a workload's policy may go without a source before its decisions are degraded |
| `-health-socket` | `unix:///run/kubescape-sandbox/processor-health.sock` | where `GET /healthz/processor` is served |
| `-otlp-endpoint`, `-records` | empty | where records go besides the log |
| `-debug-addr` | `127.0.0.1:9102` | debug server, no authentication |

## Testing

`go test -race ./...` covers the packages. `internal/extproc` tests the evaluator seam against a fake evaluator whose calls can be made to stall or panic. The pinned-map test in `internal/conntable` needs root and runs as root in CI.

`TestThirtyMiBPromptUnder16MiB` sends a 30 MiB prompt in 64 KiB chunks through an enforce-mode evaluator that scans the whole body with `jsonscan`. The processor runs in a child process, so the test client's own allocations are not counted, and samples its heap every millisecond. Its live heap (what each GC finds still reachable) must grow by less than 16 MiB. The 16 MiB budget is a budget for live heap, the memory the processor holds on to. On a laptop it grows by about 11 MiB, most of it gRPC's buffer pool, and by 10 to 12 MiB for prompts from 10 to 60 MiB, so the body is streamed, not held. The peak `HeapAlloc` is about 22 MiB over a 1 MiB base and is only logged: it also counts each chunk's short-lived copies (gRPC's receive buffer and protobuf's copy of the body) until the next GC, so it measures GC pacing, which `GOGC` and `GOMEMLIMIT` set, rather than what the processor keeps.

`test/integration/run.sh` runs Envoy with `test/processor-it`, which is the same server against an in-memory table that names one fixed pod, because the stack has no eBPF redirect. The fixture runs with `-evaluator`, a test evaluator that denies the model `denied-model`, and with `-policies test/integration/policies.yaml` instead of an API server. It checks a streamed call end to end, that the record names the pod, that no record carries a `request_position`, for three HTTP/1.1 requests on one connection or for an HTTP/2 request, that a request for the denied model gets the evaluator's 403 and a `denied` record, that a decrypted host the policy does not list is refused by the decrypt-list guard, that a client cannot change the address the processor sees, that an empty table refuses the request, and that the shipped processor image will not start without the maps.

`SDK=1 test/integration/run.sh` (CI job "SDK streams") runs the stack with `-remove-first-tool` and a policy that decrypts both hosts, then streams three mock scenarios with the provider SDKs through Envoy as `it-pod`, trusting only the gateway CA. With no redirect in the stack, each client sends its connections to the providers' hosts on port 443 to Envoy's redirect listener itself, keeping the provider's URL, SNI and Host. The SDKs are Python `anthropic` 2.6.0 and `openai` 3.46.0, Node `@anthropic-ai/sdk` 1.6.0 and `openai` 7.53.0, each with the raw event iterator and the stream helper (`test/sdk`). The scenarios are Anthropic text, tool, text (`s4-a-text-tool-text`), an OpenAI chat response with two tool calls (`s4-o-baseline`), and a Responses function call followed by a message (`s4-r-baseline`). It also streams `s4-a-trailers` with streamcheck: the tool is removed, the last event's blank line is a lone CR, and the body ends in an HTTP trailer (the generated Envoy config enables trailers on the mock's cluster). The processor must forward the event the editor still holds before it answers the trailers. `test/sdk/check.py` requires that no SDK raises, that the removed call is gone and the remaining indexes run from 0, that Anthropic's second text block (index 2 upstream) arrives as index 1 with the stop reason still `tool_use`, that Responses sequence numbers stay contiguous, and that no helper's final object holds the removed item.

`test/smoke/run.sh` (CI job "Processor image smoke") runs the shipped image itself in kind: as its own user, against empty `conns` and `bindings` maps pinned in the node's bpffs (`test/smoke/pinmaps`), with a service account against a real API server and the storage CRDs. The account starts with no RBAC, so the health path must answer 503; once a ClusterRole with `list` and `watch` on both kinds is bound to it, the informers sync and it must answer 200 with `"evaluator":"unavailable"`. The same image with no maps must exit with "open the connection tables". The processor opens the maps as a non-root user with no capabilities. A kernel that refuses `bpf()` to unprivileged users (`kernel.unprivileged_bpf_disabled` on older kernels) would need `CAP_BPF` for it; the smoke job shows what the CI runner's kernel allows.

### Latency

`test/bench/latency.sh` starts the integration stack in its own compose project, with the test evaluator in enforce mode and the mock streaming 40 text deltas 20 ms apart. `latbench` sends the same streamed request 200 times straight to the mock's TLS listener and 200 times through Envoy and the processor, each on a new connection. The script prints, for time to first token and the gap between events, the p99 of the proxied path minus the direct path, and fails above +10 ms or +1 ms. It also prints the processor's own time per response chunk from its records.

The CI job "Latency bench" runs it three times on GitHub's Ubuntu runner, where Docker runs natively. It reports and does not gate yet, because shared runners are noisy too. Its first three runs added 1.74, 1.64 and 1.79 ms to TTFT at p99, and 0.24, 0.26 and 0.27 ms to the event gap. The processor spent 28 µs per chunk on average, and the slowest chunk of a call was at most 108 to 183 µs at p99.

A laptop is not the place to judge the 1 ms budget. Three runs on an Apple M1 Pro (8 cores, 16 GB, macOS 15.7, Docker Desktop with 8 CPUs) added 3.3, 13.0 and 7.3 ms to TTFT at p99, and 1.88, 1.98 and 0.84 ms to the event gap. The processor's own work is about 40 to 65 µs per chunk on average, but single chunks took up to 9 ms. With `GODEBUG=gctrace=1`, the processor's GC stop-the-world phases took 0.7 to 2.3 ms of wall clock in Docker Desktop's VM, against tens of microseconds on a native Linux host, and the direct path's own p99 event gap was 30 ms for events sent 20 ms apart. The VM's scheduling is larger than the budget being measured.

