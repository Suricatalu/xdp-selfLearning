/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP redirect helper\n"
	" - Allows to populate/query tx_port and redirect_params maps\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include "../common/xdp_stats_kern_user.h"

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"redirect-dev",         required_argument,	NULL, 'r' },
	 "Redirect to device <ifname>", "<ifname>", true},

	{{"src-mac", required_argument, NULL, 'L' },
	 "Source MAC address of <dev>", "<mac>", true },

	{{"dest-mac", required_argument, NULL, 'R' },
	 "Destination MAC address of <redirect-dev>", "<mac>", true },

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	/* Assignment 3: parse a MAC address in this function and place the
	 * result in the mac array */
	int values[ETH_ALEN];
	if (sscanf(str, "%x:%x:%x:%x:%x:%x",
			   &values[0], &values[1], &values[2],
			   &values[3], &values[4], &values[5]) != ETH_ALEN) {
		fprintf(stderr, "ERR: Invalid MAC address format: %s\n", str);
		return -1;
	}

	for (int i = 0; i < ETH_ALEN; i++) {
		if (values[i] < 0 || values[i] > 0xFF) {
			fprintf(stderr, "ERR: Invalid MAC address value: %s\n", str);
			return -1;
		}
		mac[i] = (unsigned char)values[i];
	}

	return 0;
}

static int write_iface_params(int map_fd, unsigned char *src, unsigned char *dest)
{
	if (bpf_map_update_elem(map_fd, src, dest, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf("forward: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			src[0], src[1], src[2], src[3], src[4], src[5],
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
	      );

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int i;
	int len;
	int map_fd;
	bool redirect_map;
	char pin_dir[PATH_MAX];
	char tx_port_path[PATH_MAX];
	char redirect_params_path[PATH_MAX];
	unsigned char src[ETH_ALEN];
	unsigned char dest[ETH_ALEN];

	struct config cfg = {
		.ifindex   = -1,
		.redirect_ifindex   = -1,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	redirect_map = (cfg.ifindex > 0) && (cfg.redirect_ifindex > 0);

	if (cfg.redirect_ifindex > 0 && cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.src_mac, src) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.src_mac);
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.dest_mac, dest) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.dest_mac);
		return EXIT_FAIL_OPTION;
	}


	/* Assignment 3: open the tx_port map corresponding to the cfg.ifname interface */
	map_fd = -1;

	snprintf(tx_port_path, PATH_MAX, "%s/%s/tx_port", pin_basedir, cfg.ifname);
	map_fd = bpf_obj_get(tx_port_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Failed to open tx_port map: %s\n", strerror(errno));
		return EXIT_FAIL_BPF;
	}

	printf("Opened tx_port map: %s (map_fd: %d)\n", tx_port_path, map_fd);

	printf("map dir: %s\n", pin_dir);
	

	if (redirect_map) {
		/* setup a virtual port for the static redirect */
		i = 0;
		bpf_map_update_elem(map_fd, &i, &cfg.redirect_ifindex, 0);
		printf("redirect from ifnum=%d to ifnum=%d\n", cfg.ifindex, cfg.redirect_ifindex);

		/* Assignment 3: open the redirect_params map corresponding to the cfg.ifname interface */
		map_fd = -1;

		snprintf(redirect_params_path, PATH_MAX, "%s/%s/redirect_params", pin_basedir, cfg.ifname);
		map_fd = bpf_obj_get(redirect_params_path);
		if (map_fd < 0) {
			fprintf(stderr, "ERR: Failed to open redirect_params map: %s\n", strerror(errno));
			return EXIT_FAIL_BPF;
		}

		printf("Opened redirect_params map: %s (map_fd: %d)\n", redirect_params_path, map_fd);

		/* Setup the mapping containing MAC addresses */
		if (write_iface_params(map_fd, src, dest) < 0) {
			fprintf(stderr, "can't write iface params\n");
			return 1;
		}
	}

	return EXIT_OK;
}
