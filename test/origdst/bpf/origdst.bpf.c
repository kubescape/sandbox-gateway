// SPDX-License-Identifier: (GPL-2.0-only OR Apache-2.0)
//
// Answers getsockopt(SOL_IP, SO_ORIGINAL_DST) on the gateway listener's accepted sockets
// from the conns table.
//
// The redirect rewrites the destination at connect time, in a cgroup hook, so netfilter
// has no NAT entry and the kernel has no answer to SO_ORIGINAL_DST. Envoy's stock
// original_dst listener filter asks exactly that question; with this program attached it
// gets the destination the pod was connecting to, and an ORIGINAL_DST cluster forwards a
// passthrough connection there. Envoy needs no custom filter.
//
// This copy is the integration test's stand-in. The real one belongs with the redirect
// programs, which own the conns map.
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SOL_IP 0
#define SO_ORIGINAL_DST 80
#define AF_INET 2

// The listener's port, host byte order. The loader sets it.
const volatile __u16 listen_port = 18443;

// Layout of the pinned conns map, as internal/conntable reads it.
struct conn_key {
	__u8 addr[16]; // the pod socket's address, IPv4 as v4-mapped
	__u16 port;    // host byte order
};
struct conn_val {
	__u64 cgroup;
	__u32 pid;
	__u32 binding;
	__u8 addr[16]; // original destination
	__u16 port;    // host byte order
	__u8 pad[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct conn_key);
	__type(value, struct conn_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} conns SEC(".maps");

SEC("cgroup/getsockopt")
int origdst(struct bpf_sockopt *ctx)
{
	if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST)
		return 1;
	struct bpf_sock *sk = ctx->sk;
	if (!sk || sk->family != AF_INET || sk->src_port != listen_port)
		return 1;

	// The key is the client side of the connection: for an accepted socket, the peer.
	struct conn_key k = {};
	__u32 peer = sk->dst_ip4;
	k.addr[10] = 0xff;
	k.addr[11] = 0xff;
	__builtin_memcpy(&k.addr[12], &peer, 4);
	k.port = bpf_ntohs(sk->dst_port);

	struct conn_val *v = bpf_map_lookup_elem(&conns, &k);
	if (!v)
		return 1; // not a redirected connection: leave the kernel's error in place

	struct sockaddr_in *sa = ctx->optval;
	if ((void *)(sa + 1) > ctx->optval_end)
		return 1;
	sa->sin_family = AF_INET;
	sa->sin_port = bpf_htons(v->port);
	__builtin_memcpy(&sa->sin_addr, &v->addr[12], 4);
	// Two separate 4-byte stores. Left to itself the compiler merges them into one
	// 8-byte store, which the verifier refuses for this context.
	*(volatile __s32 *)&ctx->optlen = sizeof(*sa);
	*(volatile __s32 *)&ctx->retval = 0;
	return 1;
}

char _license[] SEC("license") = "Dual BSD/GPL";
