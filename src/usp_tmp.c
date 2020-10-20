#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <math.h>

#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/xdp_stats_kern_user.h"

#include "bpf_util.h" /* bpf_num_possible_cpus */
#include <arpa/inet.h>
#include <stdint.h>
#include <inttypes.h>
#define BILLION  1000000000L

#define PROXY_PORT 5683
#define SERVER_PORT 5683
#define MAXLINE 1024 

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX  4096
#endif

static unsigned long epoch_nsecs(void) {
  long int ns;
    time_t sec;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    sec = spec.tv_sec;
    ns = spec.tv_nsec;

    return (uint64_t) sec * BILLION + (uint64_t) ns;
}

static unsigned long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

int main() {

	setlocale(LC_NUMERIC, "en_US");
	
	__u64 now_since_epoch;
    __u64 now_since_boot;
    __u64 tdiff;
    now_since_boot = get_nsecs();
	now_since_epoch = epoch_nsecs();
    tdiff = now_since_epoch - now_since_boot;
    //printf("now_since_epoch %llu \n", now_since_epoch);
    //printf("now_since_boot %llu \n", now_since_boot);
    //printf("tdiff %llu \n", tdiff);

	char pin_dir[PATH_MAX];
	int lendir = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, "ens10");
	if (lendir < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	const struct bpf_map_info map_expect = {
        .type        = BPF_MAP_TYPE_PERCPU_HASH,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u64),
		.max_entries = 5,
        .map_flags   = BPF_F_NO_PREALLOC,
	};

	struct bpf_map_info tdiff_info = {0};

	int tdiff_fd;
	int err_tdiff;

	tdiff_fd = open_bpf_map_file(pin_dir, "tdiff", &tdiff_info);
	if (tdiff_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	err_tdiff = check_map_fd_info(&tdiff_info, &map_expect);
	if (err_tdiff) {
		printf("ERR: map via FD not compatible\n");
		close(tdiff_fd);
		return err_tdiff;
	}

    __u32 tdiff_num = 1;
    __u32 *tdk = &tdiff_num;
    
	bpf_map_update_elem(tdiff_fd, tdk, &tdiff, BPF_ANY);
}
