/*
CAVEAT;
- for now, this code only works with a single CPU computer. 
*/

static const char *__doc__ = "userspace part of krep \n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/xdp_stats_kern_user.h"

#include "bpf_util.h" /* bpf_num_possible_cpus */

struct record_sd {
	struct key_addr key;
	__u64 ts1;
	__u64 ts2;
	__u64 c;
	__u64 dc;
	__u64 mark;
};

struct record_d {
	__u64 daddr;
	__u64 ts1_star;
	__u64 ts2_star;
	__u64 c_star;
};

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};

static void stats_collect(int map_fd, __u64 record) {
	struct key_addr key, prev_key;
	__u64 res;

	while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
		res = bpf_map_lookup_elem(map_fd, &key, &record);
		if(res < 0) {
			printf("No value??\n");
		} else {
			printf("key: %u, val: %llu\n", key.saddr ,record);
		}
    		prev_key=key;
	}
}

static int stats_poll(const char *pin_dir, int map_fd, __u32 id, int interval) {
	struct bpf_map_info info = {};
	__u64 record = 0;
	setlocale(LC_NUMERIC, "en_US");

	while(1) {
		map_fd = open_bpf_map_file(pin_dir, "ts1", &info);
		if (map_fd < 0) {
			return EXIT_FAIL_BPF;
		} else if (id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			close(map_fd);
			return 0;
		}

		stats_collect(map_fd, record);
		close(map_fd);
		sleep(interval);
	}
}

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int main(int argc, char **argv) {
	const struct bpf_map_info map_expect = {
		.key_size	= sizeof(struct key_addr),
		.value_size	= sizeof(__u64),
		.max_entries	= 10000,
	};
	struct bpf_map_info info = { 0 };
	int interval = 2;
	char pin_dir[PATH_MAX];
	int ts1_map_fd;
	int len, err;

	struct config cfg = {
		.ifindex	= -1,
		.do_unload	= false,
	};

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	for ( ;; ) {
		ts1_map_fd = open_bpf_map_file(pin_dir, "ts1", &info);
		if (ts1_map_fd < 0) {
			return EXIT_FAIL_BPF;
		}
		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			close(ts1_map_fd);
			return err;
		}

		err = stats_poll(pin_dir, ts1_map_fd, info.id, interval);
		close(ts1_map_fd);
		if (err < 0)
			return err;
	}

	return EXIT_OK;
}
