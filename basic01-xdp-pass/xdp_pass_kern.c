/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	bpf_printk("xdp_prog_simple executed, ctx: %p\n", ctx);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
