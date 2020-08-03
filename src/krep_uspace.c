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
#include <arpa/inet.h>

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

static void stats_collect_and_print(int map_fd, __u64 record) {
	struct key_addr key, prev_key;
	char source_addr[16];
	char dest_addr[16];
	__u64 res;

	while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
		res = bpf_map_lookup_elem(map_fd, &key, &record);
		if(res < 0) {
			printf("No value??\n");
		} else {
			const char *res_s = inet_ntop(AF_INET, &key.saddr, 
					              source_addr, sizeof(source_addr));
			if (res_s==0) {
				printf("failed to convert address to string (errno=%d)",errno);
			}
			const char *res_d = inet_ntop(AF_INET, &key.daddr, 
					              dest_addr, sizeof(dest_addr));
			if (res_d==0) {
				printf("failed to convert address to string (errno=%d)",errno);
			}
			printf("s:%s, d:%s, val:%llu\n", source_addr, dest_addr, record);
		}
    		prev_key=key;
	}
}

static int stats_poll(const char *pin_dir, int interval) {
	const struct bpf_map_info map_expect = {
		.key_size	= sizeof(struct key_addr),
		.value_size	= sizeof(__u64),
		.max_entries	= 10000,
	};
	struct bpf_map_info info, info_ts1, info_ts2, info_c, info_dc, info_mark = { 0 };
	int ts1_map_fd, ts2_map_fd, c_map_fd, dc_map_fd, mark_map_fd;
	int err_ts1, err_ts2, err_c, err_dc, err_mark;
	__u64 record_ts1=0, record_ts2=0, record_c=0, record_dc=0, record_mark = 0;
	setlocale(LC_NUMERIC, "en_US");

	// TS1
	ts1_map_fd = open_bpf_map_file(pin_dir, "ts1", &info_ts1);
	if (ts1_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	err_ts1 = check_map_fd_info(&info_ts1, &map_expect);
	if (err_ts1) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(ts1_map_fd);
		return err_ts1;
	}

	// TS2
	ts2_map_fd = open_bpf_map_file(pin_dir, "ts2", &info_ts2);
	if (ts2_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	err_ts2 = check_map_fd_info(&info_ts2, &map_expect);
	if (err_ts2) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(ts2_map_fd);
		return err_ts2;
	}

	// Counter C
	c_map_fd = open_bpf_map_file(pin_dir, "counter_c", &info_c);
	if (c_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	err_c = check_map_fd_info(&info_c, &map_expect);
	if (err_c) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(c_map_fd);
		return err_c;
	}

	// Diffcount dc
	dc_map_fd = open_bpf_map_file(pin_dir, "diffcount_dc", &info_dc);
	if (dc_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	err_dc = check_map_fd_info(&info_dc, &map_expect);
	if (err_dc) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(dc_map_fd);
		return err_dc;
	}

	// mark
	mark_map_fd = open_bpf_map_file(pin_dir, "mark", &info_mark);
	if (mark_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	err_mark = check_map_fd_info(&info_mark, &map_expect);
	if (err_mark) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(mark_map_fd);
		return err_mark;
	}

	while(1) {
		ts1_map_fd = open_bpf_map_file(pin_dir, "ts1", &info);
		if (ts1_map_fd < 0) {
			return EXIT_FAIL_BPF;
		} else if (info_ts1.id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			close(ts1_map_fd);
			return 0;
		}
		printf("TS1 \n");
		stats_collect_and_print(ts1_map_fd, record_ts1);
		close(ts1_map_fd);
		printf("\n");

		ts2_map_fd = open_bpf_map_file(pin_dir, "ts2", &info);
		if (ts2_map_fd < 0) {
			return EXIT_FAIL_BPF;
		} else if (info_ts2.id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			close(ts2_map_fd);
			return 0;
		}
		printf("TS2 \n");
		stats_collect_and_print(ts2_map_fd, record_ts2);
		close(ts2_map_fd);
		printf("\n");

		c_map_fd = open_bpf_map_file(pin_dir, "counter_c", &info);
		if (c_map_fd < 0) {
			return EXIT_FAIL_BPF;
		} else if (info_c.id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			close(c_map_fd);
			return 0;
		}
		printf("Counter C \n");
		stats_collect_and_print(c_map_fd, record_c);
		close(c_map_fd);
		printf("\n");

		dc_map_fd = open_bpf_map_file(pin_dir, "diffcount_dc", &info);
		if (dc_map_fd < 0) {
			return EXIT_FAIL_BPF;
		} else if (info_dc.id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			close(dc_map_fd);
			return 0;
		}
		printf("Diffcount DC \n");
		stats_collect_and_print(dc_map_fd, record_dc);
		close(dc_map_fd);
		printf("\n");

		mark_map_fd = open_bpf_map_file(pin_dir, "mark", &info);
		if (mark_map_fd < 0) {
			return EXIT_FAIL_BPF;
		} else if (info_mark.id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			close(mark_map_fd);
			return 0;
		}
		printf("Mark \n");
		stats_collect_and_print(mark_map_fd, record_mark);
		close(mark_map_fd);
		printf("\n");

		sleep(interval);
	}
}

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int main(int argc, char **argv) {
	int interval = 2;
	char pin_dir[PATH_MAX];
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

	err = stats_poll(pin_dir, interval);
	if (err < 0)
		return err;

	return EXIT_OK;
}
