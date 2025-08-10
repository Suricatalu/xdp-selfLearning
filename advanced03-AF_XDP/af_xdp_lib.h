/* SPDX-License-Identifier: GPL-2.0 */

#ifndef AF_XDP_LIB_H
#define AF_XDP_LIB_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include "../common/common_params.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

/* Data structures */
struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

/* Library context structure */
struct af_xdp_context {
	struct xdp_program *prog;
	int xsk_map_fd;
	bool custom_xsk;
	struct config cfg;
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	pthread_t stats_poll_thread;
	bool stats_thread_running;
	bool global_exit;
};

/* Function declarations */

/* Initialize AF_XDP context */
struct af_xdp_context *af_xdp_init(void);

/* Clean up AF_XDP context */
void af_xdp_cleanup(struct af_xdp_context *ctx);

/* Configure UMEM */
struct xsk_umem_info *af_xdp_configure_umem(void *buffer, uint64_t size);

/* Configure XSK socket */
struct xsk_socket_info *af_xdp_configure_socket(struct config *cfg,
												struct xsk_umem_info *umem,
												int xsk_map_fd,
												bool custom_xsk);

/* Frame allocation functions */
uint64_t af_xdp_alloc_umem_frame(struct xsk_socket_info *xsk);
void af_xdp_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame);
uint64_t af_xdp_umem_free_frames(struct xsk_socket_info *xsk);

/* Packet processing functions */
void af_xdp_complete_tx(struct xsk_socket_info *xsk);

/* New API: send one packet (reserve tx slot, submit descriptor, update stats) */
bool af_xdp_ready_send(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len);

/* New API: receive up to max_entries, fill user-provided addrs and lens arrays */
unsigned int af_xdp_receive(struct xsk_socket_info *xsk,
							uint64_t *addrs,
							uint32_t *lens,
							unsigned int max_entries);

/* Statistics functions */
void af_xdp_stats_print(struct stats_record *stats_rec,
					   struct stats_record *stats_prev);
void *af_xdp_stats_poll(void *arg);
uint64_t af_xdp_gettime(void);
double af_xdp_calc_period(struct stats_record *r, struct stats_record *p);

/* Setup functions */
int af_xdp_setup_program(struct af_xdp_context *ctx, const char *filename,
						const char *progname);
int af_xdp_setup_socket(struct af_xdp_context *ctx);
int af_xdp_start_stats_thread(struct af_xdp_context *ctx);

/* Utility functions */
void af_xdp_set_global_exit(struct af_xdp_context *ctx, bool exit_flag);
bool af_xdp_should_exit(struct af_xdp_context *ctx);

/* Inline utility functions */
static inline __u32 af_xdp_ring_prod_free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

/* Checksum utility functions */
static inline __sum16 af_xdp_csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;
	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 af_xdp_csum16_sub(__sum16 csum, __be16 addend)
{
	return af_xdp_csum16_add(csum, ~addend);
}

static inline void af_xdp_csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~af_xdp_csum16_add(af_xdp_csum16_sub(~(*sum), old), new);
}

#endif /* AF_XDP_LIB_H */
