#include <string.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include "af_xdp_lib.h"

static volatile bool global_exit = false;

static void int_exit(int sig)
{
    global_exit = true;
}


/* Process a single packet */
bool process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
    uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
     *
     * Some assumptions to make it easier:
     * - No VLAN handling
     * - Only if nexthdr is ICMP
     * - Just return all data with MAC/IP swapped, and type set to
     *   ICMPV6_ECHO_REPLY
     * - Recalculate the icmp checksum */

    if (true) {
        uint8_t tmp_mac[ETH_ALEN];
        struct in6_addr tmp_ip;
        struct ethhdr *eth = (struct ethhdr *) pkt;
        struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
        struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

        if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
            len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
            ipv6->nexthdr != IPPROTO_ICMPV6 ||
            icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
            return false;

        memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
        memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        memcpy(eth->h_source, tmp_mac, ETH_ALEN);

        memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
        memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
        memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

        icmp->icmp6_type = ICMPV6_ECHO_REPLY;

        af_xdp_csum_replace2(&icmp->icmp6_cksum,
                  htons(ICMPV6_ECHO_REQUEST << 8),
                  htons(ICMPV6_ECHO_REPLY << 8));

        return true;
    }

    return false;
}

int main() {
    printf("AF_XDP Sample Program\n");

    struct af_xdp_context *ctx = af_xdp_init();
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to initialize AF_XDP context\n");
        return -1;
    }
    
    // 設置信號處理
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    
    // 設置配置 - 使用活躍的介面
    const char *ifname = "lib";  // 使用我們看到的活躍介面
    ctx->cfg.ifindex = if_nametoindex(ifname);
    printf("Using interface: %s (index: %d)\n", ifname, ctx->cfg.ifindex);
    if (ctx->cfg.ifindex == 0) {
        fprintf(stderr, "ERROR: Interface '%s' not found\n", ifname);
        af_xdp_cleanup(ctx);
        return -1;
    }
    ctx->cfg.ifname = malloc(10);
    strncpy(ctx->cfg.ifname, ifname, sizeof(ctx->cfg.ifname) - 1);
    printf("Interface name set to: %s\n", ctx->cfg.ifname);
    ctx->cfg.ifname[sizeof(ctx->cfg.ifname) - 1] = '\0';  // 確保字串結尾
    printf("Interface index: %d\n", ctx->cfg.ifindex);
    
    // 初始化其他必要的配置
    ctx->cfg.xdp_flags = 0;
    ctx->cfg.xsk_bind_flags = 0;
    ctx->cfg.xsk_if_queue = 0;
    ctx->cfg.xsk_poll_mode = true;
    
    printf("Starting AF_XDP program on interface: %s (index: %d)\n", ctx->cfg.ifname, ctx->cfg.ifindex);
    
    // 添加調試輸出
    printf("Configuration: xdp_flags=%u, xsk_bind_flags=%u, xsk_if_queue=%u\n", 
           ctx->cfg.xdp_flags, ctx->cfg.xsk_bind_flags, ctx->cfg.xsk_if_queue);
    
    // 設置程序（可選）
    // printf("Setting up XDP program...\n");
    // if (af_xdp_setup_program(ctx, "af_xdp_kern.o", "xsk_def_prog") < 0) {
    //     fprintf(stderr, "WARNING: Failed to setup XDP program, continuing without custom program\n");
    // }
    
    // 設置套接字
    printf("Setting up AF_XDP socket...\n");
    if (af_xdp_setup_socket(ctx) < 0) {
        fprintf(stderr, "ERROR: Failed to setup AF_XDP socket\n");
        af_xdp_cleanup(ctx);
        return -1;
    }
    
    // 啟動統計線程
    // printf("Starting statistics thread...\n");
    // if (af_xdp_start_stats_thread(ctx) < 0) {
    //     fprintf(stderr, "ERROR: Failed to start stats thread\n");
    //     af_xdp_cleanup(ctx);
    //     return -1;
    // }
    
    printf("AF_XDP program started successfully. Press Ctrl+C to exit.\n");
    
    // 主處理循環
    // Main loop using poll() and new receive/process API
    {
        // Setup poll for XSK socket
        struct pollfd fds[1];
        int ret, nfds = 1;
        memset(fds, 0, sizeof(fds));
        fds[0].fd = xsk_socket__fd(ctx->xsk_socket->xsk);
        fds[0].events = POLLIN;
        
        uint64_t addrs[RX_BATCH_SIZE];
        uint32_t lens[RX_BATCH_SIZE];
        while (!global_exit && !ctx->global_exit) {
            if (ctx->cfg.xsk_poll_mode) {
                ret = poll(fds, nfds, -1);
                if (ret <= 0)
                    continue;
            }
            unsigned int n = af_xdp_receive(ctx->xsk_socket, addrs, lens, RX_BATCH_SIZE);
            for (unsigned int i = 0; i < n; i++) {
                if (process_packet(ctx->xsk_socket, addrs[i], lens[i])) {
                    if (!af_xdp_ready_send(ctx->xsk_socket, addrs[i], lens[i])) {
                        af_xdp_free_umem_frame(ctx->xsk_socket, addrs[i]);
                    }
                } else {
                    af_xdp_free_umem_frame(ctx->xsk_socket, addrs[i]);
                }
                ctx->xsk_socket->stats.rx_bytes += lens[i];
            }
            af_xdp_complete_tx(ctx->xsk_socket);
        }
    }
    
    printf("Shutting down...\n");
    
    // 清理
    af_xdp_cleanup(ctx);
    return 0;
}