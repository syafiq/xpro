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

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX  4096
#endif

int main() {

    int stats_fd;
    int err_stats;
    __u64 valdrop;
    int resdrop;

    char pin_dir[PATH_MAX];
    int lendir = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, "enp2s0");
    if (lendir < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    const struct bpf_map_info map_expect = {
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u64),
        .max_entries  = 5,
    };

    struct bpf_map_info stats_info = {0};

    stats_fd = open_bpf_map_file(pin_dir, "stats", &stats_info);
    if (stats_fd < 0) {
        return EXIT_FAIL_BPF;
    }
    err_stats = check_map_fd_info(&stats_info, &map_expect);
    if (err_stats) {
        printf("ERR: map via FD not compatible\n");
        close(stats_fd);
        return err_stats;
    }
    __u32 drop = 1;
    resdrop = bpf_map_lookup_elem(stats_fd, &drop, &valdrop);
    printf("resdrop %d \n", resdrop);
    if (resdrop == 0) {
        printf("drop %llu \n", valdrop);
    }
}
