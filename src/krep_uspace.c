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

static int stats_poll
