---
type: reality
status: active
owner: amirmalka
scope: repo
---

# Processor

The processor is the gateway's Envoy external processor (`ext_proc`). Envoy sends it every decrypted request and response in `FULL_DUPLEX_STREAMED` mode, so the processor sees each body chunk and returns the bytes Envoy forwards. It works out which pod sent the request, parses the request and the streamed response, and writes one record per transaction.

The command is `cmd/processor`. The wiring is `internal/app`, the server `internal/extproc`.

## Who sent the request

Identity comes from two tables node-agent pins under `/sys/fs/bpf/kubescape-sandbox/http/` (`internal/conntable`), and from node-agent's workload lookup (`internal/lookup`). Nothing the client sends is used.

1. Envoy passes the downstream remote address as the `source.address` request attribute. That is the pod socket's own address and port. An IPv4 address in its IPv6-mapped form is the same key.
2. `conns`, keyed on that address and port, gives the cgroup, the pid, the binding and the original destination. It is read on every request and never cached by address, because the kernel reuses an address and port for another pod's connection once the first one closes.
3. `bindings`, keyed on the cgroup, gives the pod's fail posture (`allow` or `deny`) and its health-gate state.
4. `GET /v1/workload?cgroup=<id>` on `/run/kubescape-sandbox/lookup.sock` names the namespace, pod, container, controller and the policy objects that cover the pod.

A request is refused with a 403 from the processor, before anything reaches the provider, when:

| `reject_reason` | Cause |
|---|---|
| `no_source_address` | Envoy sent no usable `source.address` |
| `no_connection_entry` | the connection is not in `conns` |
| `not_bound` | the cgroup has no `bindings` entry, or node-agent answers that it is not bound |
| `connection_table_error` | reading a map failed |
| `no_connection_table` | the processor has no tables (a build or wiring error) |

A PROXY protocol identity that arrives in the `kubescape.sandbox.attribution` metadata is never used. The record notes it as `ppv2_ignored`.

When node-agent's socket does not answer, the last answer for that cgroup is served from a cache, and the record carries `lookup_failing_since`. With no cached answer the record carries `lookup_error` and only the kernel half of the identity. Neither case is refused.

The lookup runs while the request headers wait, so it is kept short. One request per cgroup is in flight at a time; while it is, other requests for that cgroup get the cached answer at once. After a failed request the cgroup is not asked about again for one second. A request the client abandoned does not count as a failure.

The pod's namespace, pod name, container, binding id, fail posture and original destination are also written to the `kubescape.sandbox.audit` metadata, so Envoy's access log shows them.

### What the Envoy config must do

The identity is only as good as `source.address`, so the listener must report the socket's own address. `deploy/envoy/envoy.yaml` does two things for that, and a config that drops either lets a pod be taken for another pod:

- It has no `proxy_protocol` listener filter. That filter replaces the remote address with the one in the PROXY header, which the pod writes.
- The HTTP connection manager sets `use_remote_address: true`. Without it Envoy takes the remote address from an `X-Forwarded-For` header.

`test/integration/run.sh` sends both a forged `X-Forwarded-For` header and a PROXY protocol line and fails if the processor sees the forged address.

The explicit-proxy listener (`explicit_proxy`, port 3128) cannot serve decrypted hosts with this processor. A connection that arrives through it has no socket address to look up and no `conns` entry, so every request on its decrypting chain is refused with `no_source_address`.

### Map layout

Integers are in host byte order. Addresses are 16 bytes, IPv4 in its IPv6-mapped form. The structs use natural C alignment:

| Map | Key | Value |
|---|---|---|
| `conns` | address (16), port `u16`: 18 bytes | cgroup `u64`, pid `u32`, binding `u32`, original destination address (16) and port `u16`, padded to 40 bytes |
| `bindings` | cgroup `u64`: 8 bytes | binding `u32`, posture `u8` (0 allow, 1 deny), gate `u8` (0 redirecting, 1 failing open, 2 recovering), padded to 8 bytes |

The processor opens both maps read-only at start and exits if either is missing or has another key or value size. It needs `CAP_BPF` and the bpffs mount.

## Streams

| Package | What it does |
|---|---|
| `pkg/jsonscan` | reads named top-level string fields, such as `model`, from a JSON request body in constant memory |
| `internal/sse` | splits a server-sent event stream into events, whatever the chunk boundaries |
| `internal/streamfmt` | recognises Anthropic Messages, OpenAI Chat Completions and OpenAI Responses events, and tracks the items, the stop reason and the end of the stream |
| `internal/renumber` | removes items from a stream and renumbers the ones after them; nothing in the processor calls it yet |
| `internal/eventstream` | AWS event-stream frames (Bedrock) |
| `internal/wsframe` | WebSocket frames after an upgrade |

The record's `stop_reason` comes from `streamfmt`: Anthropic's `stop_reason`, OpenAI's `finish_reason`, or the status of a Responses stream's closing event.

## Flags

| Flag | Default | |
|---|---|---|
| `-listen` | `unix:///run/kubescape-sandbox/extproc.sock` | gRPC address for Envoy |
| `-maps-dir` | `/sys/fs/bpf/kubescape-sandbox/http` | where `conns` and `bindings` are pinned |
| `-lookup-socket` | `/run/kubescape-sandbox/lookup.sock` | node-agent's workload lookup |
| `-lookup-refresh` | `5s` | ask node-agent again once a cached answer is this old |
| `-chunk-budget` | `0` (off) | the stall watchdog |
| `-otlp-endpoint`, `-records` | empty | where records go besides the log |
| `-debug-addr` | `127.0.0.1:9102` | debug server, no authentication |

## Testing

`go test -race ./...` covers the packages. The pinned-map test in `internal/conntable` needs root and runs as root in CI.

`test/integration/run.sh` runs Envoy with `test/processor-it`, which is the same server against an in-memory table that names one fixed pod, because the stack has no eBPF redirect. It checks a streamed call end to end, that the record names the pod, that a client cannot change the address the processor sees, that an empty table refuses the request, and that the shipped processor image will not start without the maps.
