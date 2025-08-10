/* SPDX-License-Identifier: GPL-2.0 */
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#ifndef __LIBXDP_XSK_DEF_XDP_PROG_H
#define __LIBXDP_XSK_DEF_XDP_PROG_H

#define XDP_METADATA_SECTION "xdp_metadata"
#define XSK_PROG_VERSION 1

#endif /* __LIBXDP_XSK_DEF_XDP_PROG_H */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>


#define DEFAULT_QUEUE_IDS 64

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xsk_def_prog);

/* Program refcount, in order to work properly,
 * must be declared before any other global variables
 * and initialized with '1'.
 */
volatile int refcnt = 1;

/* This is the program for post 5.3 kernels. */
SEC("xdp")
int xsk_def_prog(struct xdp_md *ctx)
{
	/* Make sure refcount is referenced by the program */
	if (!refcnt)
		return XDP_PASS;

	/* A set entry here means that the corresponding queue_id
	 * has an active AF_XDP socket bound to it.
	 */
	// bpf_printk("xsk_def_prog: Processing packet on queue %d", ctx->rx_queue_index);
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);
