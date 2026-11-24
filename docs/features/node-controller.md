---
type: reality
status: active
owner: amirmalka
scope: repo
---

# Node controller

The node controller is the gateway's control process on one node. It decides which hostnames Envoy decrypts there, and for which pods. The program is `cmd/node-controller`.

This page describes what is in the code today. The plan for the rest is `docs/superpowers/plans/2026-11-24-node-controller.md`. Until its later PRs land, `cmd/node-controller` still runs the seeded SDS server with the older `hostset.Set`; the host set described below is built and tested but not wired in yet.

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
