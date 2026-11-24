---
type: reality
status: active
owner: amirmalka
scope: repo
---

# Node controller

The node controller is the gateway's control process on one node. It decides which hostnames Envoy decrypts there, and for which pods. The program is `cmd/node-controller`.

This page describes what is in the code today. The plan for the rest is `docs/superpowers/plans/2026-11-24-node-controller.md`. Until its later PRs land, `cmd/node-controller` still runs the seeded SDS server with the older `hostset.Set`; the host set and the node view described below are built and tested but not wired in yet.

## Host set

`internal/hostset.NodeSet` is the set of names that get a certificate and a filter chain on the node.

Policy objects give two lists. An exact host is in the set as soon as an object on the node asks for it. A host pattern never reaches Envoy as a pattern: a name under it joins only after node-agent has seen it in a workload's DNS answers (`Observe`). The SNI a client sends is never enough to join.

### The cap

One cap covers every name, exact and learned together (default 256). It bounds how many certificates the node mints whatever the policies say.

- An exact host takes a free slot. With none free, it takes the slot of the learned name seen longest ago that has no open connections.
- A sighted name does the same.
- When the set is full and nothing can be evicted, the name is left out. Its traffic passes through undecrypted, and it is counted in `Counts().OverCap`.
- Names already in the set keep their place. A new exact host that sorts earlier does not displace one that has a chain.

### Names with open connections

Removing a chain cuts the streams on it, so a name with open connections is never removed. When no object wants a name any more and it is busy, it stays in the set, retired: it keeps its chain and its certificate, it still holds a slot, and no pod's list contains it, so no new connection is decrypted for it. `Sweep` drops it once it is idle.

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
