/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include "af_xdp_lib.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

/* Initialize AF_XDP context */
struct af_xdp_context *af_xdp_init(void)
{
	struct af_xdp_context *ctx;
	printf("Initializing AF_XDP context...\n");
	ctx = calloc(1, sizeof(*ctx));
	printf("AF_XDP context initialized.\n");
	if (!ctx)
		return NULL;
	printf("AF_XDP context created.\n");
	ctx->cfg.ifindex = -1;
	ctx->custom_xsk = false;
	ctx->global_exit = false;
	ctx->xsk_map_fd = -1;
	printf("AF_XDP context successfully created.\n");
	return ctx;
}

/* Clean up AF_XDP context */
void af_xdp_cleanup(struct af_xdp_context *ctx)
{
	if (!ctx)
		return;

	ctx->global_exit = true;

	if (ctx->xsk_socket) {
		xsk_socket__delete(ctx->xsk_socket->xsk);
		free(ctx->xsk_socket);
	}

	if (ctx->umem) {
		xsk_umem__delete(ctx->umem->umem);
		free(ctx->umem);
	}

	if (ctx->prog) {
		xdp_program__detach(ctx->prog, ctx->cfg.ifindex, XDP_MODE_UNSPEC, 0);
		xdp_program__close(ctx->prog);
	}

	free(ctx);
}

/* Configure UMEM */
struct xsk_umem_info *af_xdp_configure_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
				   NULL);
	if (ret) {
		errno = -ret;
		free(umem);
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

/* Frame allocation functions */
uint64_t af_xdp_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

void af_xdp_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	// printf("DEBUG: Freeing frame. Current free count: %u\n", xsk->umem_frame_free);
	assert(xsk->umem_frame_free < NUM_FRAMES);
	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

uint64_t af_xdp_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

/* Configure XSK socket */
struct xsk_socket_info *af_xdp_configure_socket(struct config *cfg,
												struct xsk_umem_info *umem,
												int xsk_map_fd,
												bool custom_xsk)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	
	printf("DEBUG: Creating XSK socket with interface %s, queue %d\n",
	       cfg->ifname, cfg->xsk_if_queue);
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;
	printf("DEBUG: XSK socket created successfully.\n");

	if (custom_xsk) {
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
	} else {
		/* Getting the program ID must be after the xdp_socket__create() call */
		if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
			goto error_exit;
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	printf("DEBUG: Reserving fill queue space for %d frames\n",
	       XSK_RING_PROD__DEFAULT_NUM_DESCS);
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
					 XSK_RING_PROD__DEFAULT_NUM_DESCS,
					 &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			af_xdp_alloc_umem_frame(xsk_info);

	printf("DEBUG: Reserving fill queue space completed, submitting %d frames\n",
	       XSK_RING_PROD__DEFAULT_NUM_DESCS);
	xsk_ring_prod__submit(&xsk_info->umem->fq,
				  XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	free(xsk_info);
	return NULL;
}

/* Complete TX operations */
void af_xdp_complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			af_xdp_free_umem_frame(xsk,
						*xsk_ring_cons__comp_addr(&xsk->umem->cq,
									  idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

/* New API: send a packet (reserve TX descriptor, submit, update stats) */
bool af_xdp_ready_send(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
	uint32_t tx_idx = 0;
	int ret;

	/* Reserve one TX descriptor slot */
	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (ret != 1)
		return false;

	/* Setup TX descriptor */
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len  = len;
	xsk_ring_prod__submit(&xsk->tx, 1);

	/* Update outstanding and stats */
	xsk->outstanding_tx++;
	return true;
}

/* Receive batch: peek RX ring, refill fill-ring, and copy addr/len into user arrays */
unsigned int af_xdp_receive(struct xsk_socket_info *xsk,
							uint64_t *addrs,
							uint32_t *lens,
							unsigned int max_entries)
{
	uint32_t idx_rx = 0;
	// printf("DEBUG: Receiving packets, max entries: %u\n", max_entries);
	unsigned int rcvd = xsk_ring_cons__peek(&xsk->rx, max_entries, &idx_rx);
	if (!rcvd)
		return 0;
	// printf("DEBUG: Received %u packets\n", rcvd);
	/* refill fill-ring */
	uint32_t idx_fq = 0;
	unsigned int stock = xsk_prod_nb_free(&xsk->umem->fq,
										  af_xdp_umem_free_frames(xsk));
	if (stock) {
		int ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock, &idx_fq);
		while (ret != (int)stock)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock, &idx_fq);
		for (unsigned int i = 0; i < stock; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = af_xdp_alloc_umem_frame(xsk);
		xsk_ring_prod__submit(&xsk->umem->fq, stock);
	}
	
	for (unsigned int i = 0; i < rcvd; i++) {
		addrs[i] = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		lens[i]  = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);

	return rcvd;
}



/* Setup XDP program */
int af_xdp_setup_program(struct af_xdp_context *ctx, const char *filename,
						const char *progname)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct bpf_map *map;
	int err;
	char errmsg[1024];

	if (!filename || filename[0] == 0)
		return 0; /* No custom program */

	ctx->custom_xsk = true;
	xdp_opts.open_filename = filename;
	xdp_opts.prog_name = progname;
	xdp_opts.opts = &opts;

	if (progname && progname[0] != 0) {
		ctx->prog = xdp_program__create(&xdp_opts);
	} else {
		ctx->prog = xdp_program__open_file(filename, NULL, &opts);
	}

	err = libxdp_get_error(ctx->prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		return err;
	}

	err = xdp_program__attach(ctx->prog, ctx->cfg.ifindex, ctx->cfg.attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			ctx->cfg.ifname, errmsg, err);
		return err;
	}

	/* We also need to load the xsks_map */
	map = bpf_object__find_map_by_name(xdp_program__bpf_obj(ctx->prog), "xsks_map");
	ctx->xsk_map_fd = bpf_map__fd(map);
	if (ctx->xsk_map_fd < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(ctx->xsk_map_fd));
		return -1;
	}

	return 0;
}

/* Setup socket */
int af_xdp_setup_socket(struct af_xdp_context *ctx)
{
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};

	printf("DEBUG: Starting af_xdp_setup_socket\n");
	
	/* Allow unlimited locking of memory */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		return -1;
	}
	printf("DEBUG: Memory limit set successfully\n");

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	printf("DEBUG: Allocating %lu bytes for packet buffer\n", packet_buffer_size);
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		return -1;
	}
	printf("DEBUG: Packet buffer allocated successfully\n");

	/* Initialize shared packet_buffer for umem usage */
	printf("DEBUG: Configuring UMEM\n");
	ctx->umem = af_xdp_configure_umem(packet_buffer, packet_buffer_size);
	if (ctx->umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		free(packet_buffer);
		return -1;
	}
	printf("DEBUG: UMEM configured successfully\n");

	/* Open and configure the AF_XDP (xsk) socket */
	printf("DEBUG: Configuring XSK socket\n");
	ctx->xsk_socket = af_xdp_configure_socket(&ctx->cfg, ctx->umem,
											 ctx->xsk_map_fd, ctx->custom_xsk);
	if (ctx->xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		return -1;
	}
	printf("DEBUG: XSK socket configured successfully\n");

	return 0;
}

/* Utility functions */
void af_xdp_set_global_exit(struct af_xdp_context *ctx, bool exit_flag)
{
	ctx->global_exit = exit_flag;
}

bool af_xdp_should_exit(struct af_xdp_context *ctx)
{
	return ctx->global_exit;
}






