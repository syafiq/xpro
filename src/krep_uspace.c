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

struct record_sd {
	struct key_addr key;
	__u64 ts1;
	__u64 ts2;
	__u64 c;
	__u64 dc;
	__u64 mark;
}

struct record_d {
	__u64 daddr;
	__u64 ts1_star;
	__u64 ts2_star;
	__u64 c_star;
}

const char *pin_basedir = "/sys/fs/bpf";

int main(int argc, char **argv) {
	const struct bpf_map_info map_expect = {
		.key_size	= sizeof(struct key_addr),
		.value_size	= sizeof(__u64),
		.max_entries	= 10000,
	};
	int interval = 2;
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
		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			close(stats_map_fd);
			return err;
		}

		err = stats_poll(pin_dir, stats_map_fd, info.id, info.type, interval);
		close(stats_map_fd);
		if (err < 0)
			return err;
	}

	return EXIT_OK;
}
