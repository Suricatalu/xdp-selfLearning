/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

static __always_inline int __parse_ethhdr(struct hdr_cursor *nh,
	void *data_end,
	struct ethhdr **ethhdr)
{
struct ethhdr *eth = nh->pos;
int hdrsize = sizeof(*eth);

/* Byte-count bounds check; check if current pointer + size of header
* is after data_end.
*/
if (nh->pos + hdrsize > data_end)
return -1;

nh->pos += hdrsize;
*ethhdr = eth;

return eth->h_proto; /* network-byte-order */
}

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{

	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	
	int vlid = -1;

	/* Check if there is a vlan tag to pop */
	if (!proto_is_vlan(eth->h_proto))
		return -1;

	/* Still need to do bounds checking */
	vlh = (struct vlan_hdr *)(eth + 1);
	if (vlh + 1 > data_end)
		return -1;

	/* Save vlan ID for returning, h_proto for updating Ethernet header */
	vlid = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
	h_proto = vlh->h_vlan_encapsulated_proto;

	/* Make a copy of the outer Ethernet header before we cut it off */
	eth_cpy = *eth;

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (struct ethhdr *)(void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (eth + 1 > data_end)
		return -1;

	/* Copy back the old Ethernet header and update the proto type */
	*eth = eth_cpy;
	eth->h_proto = h_proto;

	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
					 struct ethhdr *eth, int vlid)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;

	/* Check if there is a vlan tag to pop */
	if (proto_is_vlan(eth->h_proto))
		return -1;

	/* Make a copy of the outer Ethernet header before we cut it off */
	eth_cpy = *eth;

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(*vlh)))
		return -1;
	
	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (struct ethhdr *)(void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (eth + 1 > data_end)
		return -1;
	
	/* Copy back the old Ethernet header and update the proto type */
	*eth = eth_cpy;

	/* Push a new VLAN tag */
	vlh = (struct vlan_hdr *)(eth + 1);

	/* Need to do bounds checking */
	if (vlh + 1 > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;
	eth->h_proto = bpf_htons(ETH_P_8021Q);
	
	return 0;
}

/* Implement assignment 1 in this section */
SEC("xdp")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	bpf_printk("xdp recieves a packets, and starts parsing\n");
	
	nh_type = __parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;
	
	bpf_printk("The eth nh_type is 0x%04x\n", bpf_ntohs(nh_type));
	
	if (nh_type == bpf_htons(ETH_P_IP)) {
		nh_type = parse_iphdr(&nh, data_end, &iph);

		bpf_printk("The ip nh_type is 0x%04x\n", bpf_ntohs(nh_type));
		
		if (nh_type < 0)
			return XDP_PASS;
		
		__u8 *saddr8 = (__u8 *)&iph->saddr;
		bpf_printk("IPv4 packet's source ip address: %d.%d.%d.%d\n", saddr8[0], saddr8[1], saddr8[2], saddr8[3]);

	} else if (nh_type == bpf_htons(ETH_P_IPV6)) {
		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		
		if (nh_type < 0)
			return XDP_PASS;
		
		__u8 *saddr8 = ip6h->addrs.saddr.in6_u.u6_addr8;
		bpf_printk("IPv6 packet's source ip address: %02x%02x:%02x%02x:%02x%02x:%02x:%02x:%02x\n", saddr8[0], saddr8[1], saddr8[2], saddr8[3], saddr8[4], saddr8[5], saddr8[6], saddr8[7], saddr8[8], saddr8[9], saddr8[10]);
	}

	if (iph != NULL)
	{
		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph;
			nh_type = parse_tcphdr(&nh, data_end, &tcph);
			if (nh_type < 0)
				return XDP_PASS;

			tcph->dest = bpf_htons(bpf_ntohs(tcph->dest) - 1);
			bpf_printk("TCP packet's destination port is now %d\n", bpf_ntohs(tcph->dest));
		}

		if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph;
			nh_type = parse_udphdr(&nh, data_end, &udph);
			if (nh_type < 0)
				return XDP_PASS;

			udph->dest = bpf_htons(bpf_ntohs(udph->dest) - 1);
			bpf_printk("UDP packet's destination port is now %d\n", bpf_ntohs(udph->dest));
		}
	} else if (ip6h != NULL) {
		if (ip6h->nexthdr == IPPROTO_TCP) {
			struct tcphdr *tcph;
			nh_type = parse_tcphdr(&nh, data_end, &tcph);
			if (nh_type < 0)
				return XDP_PASS;

			tcph->dest = bpf_htons(bpf_ntohs(tcph->dest) - 1);
			bpf_printk("TCP packet's destination port is now %d\n", bpf_ntohs(tcph->dest));
		}

		if (ip6h->nexthdr == IPPROTO_UDP) {
			struct udphdr *udph;
			nh_type = parse_udphdr(&nh, data_end, &udph);
			if (nh_type < 0)
				return XDP_PASS;

			udph->dest = bpf_htons(bpf_ntohs(udph->dest) - 1);
			bpf_printk("UDP packet's destination port is now %d\n", bpf_ntohs(udph->dest));
		}
	}
	return XDP_PASS;
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	bpf_printk("The data pointer is %u\n", ctx->data);
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);
	bpf_printk("The modified data pointer is %u\n", ctx->data);

	return XDP_PASS;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
