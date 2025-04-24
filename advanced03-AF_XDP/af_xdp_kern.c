/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

/* Map of AF_XDP sockets: maps each receive queue index to a socket FD.
 * Used by bpf_redirect_map to forward packets into the corresponding user-space socket.
 *
 * type       : BPF_MAP_TYPE_XSKMAP  – map type for AF_XDP socket redirection
 * key        : __u32               – receive queue index
 * value      : __u32               – user‐space socket file descriptor
 * max_entries: 64                  – maximum number of queues supported
 */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

/* Per-CPU array for packet statistics: counts packets seen on each queue.
 * We use this to pass every other packet (pkt_count++ & 1) before redirecting.
 *
 * type       : BPF_MAP_TYPE_PERCPU_ARRAY – map type for per-CPU storage
 * key        : __u32                    – receive queue index
 * value      : __u32                    – packet count
 * max_entries: 64                       – maximum number of queues supported
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	// __u32 *pkt_count;

	// pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	// if (pkt_count) {
		// /* We pass every other packet */
		// if ((*pkt_count)++ & 1)
		// 	return XDP_PASS;
	// }

	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
