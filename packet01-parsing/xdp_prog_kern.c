/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

#define VLAN_HLEN 4

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
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

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	int hdrsize = sizeof(*ip6h);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ip6h;

	return ip6h->nexthdr; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize = sizeof(*iph);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;
	
	*iphdr = iph;

	/* Variable-length field: calculate and return header size */
	hdrsize = iph->ihl * 4;
	if (nh->pos + hdrsize > data_end)
		return -1;
	
	nh->pos += hdrsize;

	return iph->protocol; /* network-byte-order */
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;
	int hdrsize = sizeof(*icmp6h);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type; /* network-byte-order */
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;
	int hdrsize = sizeof(*icmph);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmphdr = icmph;
	
	return icmph->type; /* network-byte-order */
}

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_vlanhdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct vlan_hdr **vlhdr)
{
	struct vlan_hdr *vlh = nh->pos;
	int hdrsize = sizeof(*vlh);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*vlhdr = vlh;

	return vlh->h_vlan_encapsulated_proto; /* network-byte-order */
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct vlan_hdr *vhdr;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct icmphdr *icmph;
	struct icmp6hdr *icmp6h;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	int nh_ipnext;
	int nh_icmp6type;

	bpf_printk("xdp recieves a packets, and starts parsing\n");
	
	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == -1)
	{
		action = XDP_DROP;
		return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
	}

	bpf_printk("IPv6 packet's MAC address: %02x:%02x:%02x:%02x:%02x:%02x to another interface whose MAC is %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth->h_source[0], eth->h_source[1], eth->h_source[2],
		eth->h_source[3], eth->h_source[4], eth->h_source[5],
		eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

	bpf_printk("The next type of ethernet hdr is 0x%04x\n", bpf_ntohs(nh_type));

	for (int i = 0; i < VLAN_HLEN; i++)
	{
		if (proto_is_vlan(nh_type))
		{
			nh_type = parse_vlanhdr(&nh, data_end, &vhdr);
			if (nh_type == -1)
			{
				action = XDP_DROP;
				return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
			}
			bpf_printk("The next type of vlan hdr is %x\n", bpf_ntohs(nh_type));
		}
	}

	if (nh_type == bpf_htons(ETH_P_IPV6))
	{
		nh_ipnext = parse_ip6hdr(&nh, data_end, &ip6h);
		bpf_printk("nh_ipnext: %x\n", bpf_ntohs(nh_ipnext));
		if (nh_ipnext == -1)
		{
			action = XDP_DROP;
			return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
		}
	
		__u8 *saddr8 = ip6h->addrs.saddr.in6_u.u6_addr8;
	
		bpf_printk("IPv6 packet's source ip address: %02x%02x:%02x%02x:%02x%02x:%02x:%02x:%02x\n", saddr8[0], saddr8[1], saddr8[2], saddr8[3], saddr8[4], saddr8[5], saddr8[6], saddr8[7], saddr8[8], saddr8[9], saddr8[10]);
	}

	if (nh_type == bpf_htons(ETH_P_IP))
	{
		nh_ipnext = parse_iphdr(&nh, data_end, &iph);
		if (nh_ipnext == -1)
		{
			action = XDP_DROP;
			return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
		}

		__u8 *saddr8 = (__u8 *)&iph->saddr;
		bpf_printk("IPv4 packet's source ip address: %d.%d.%d.%d\n", saddr8[0], saddr8[1], saddr8[2], saddr8[3]);
	}
	
	if (nh_ipnext == IPPROTO_ICMPV6)
	{
		nh_icmp6type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_icmp6type == -1)
		{
			action = XDP_DROP;
			return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
		}

		__be16 icmp6seq = icmp6h->icmp6_sequence;
		bpf_printk("nh_icmp6seq: %u\n", bpf_ntohs(icmp6seq));

		if (bpf_ntohs(icmp6seq) % 2 == bpf_htons(0))
		{
			action = XDP_DROP;
			return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
		}
	}

	if (nh_ipnext == IPPROTO_ICMP)
	{
		int nh_icmptype = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_icmptype == -1)
		{
			action = XDP_DROP;
			return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
		}

		__be16 icmpseq = icmph->un.echo.sequence;
		bpf_printk("nh_icmpseq: %u\n", bpf_ntohs(icmpseq));

		if (bpf_ntohs(icmpseq) % 2 == 0)
		{
			action = XDP_DROP;
			return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
		}
	}

	/* Assignment additions go below here */
	action = XDP_PASS;
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
