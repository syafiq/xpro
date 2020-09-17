/* SPDX-License-Identifier: GPL-2.0 */

/* Used by BPF-prog kernel side BPF-progs and userspace programs,
 * for sharing xdp_stats common struct and DEFINEs.
 */
#ifndef __XDP_STATS_KERN_USER_H
#define __XDP_STATS_KERN_USER_H

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct key_addr {
	__u32 saddr;
	__u32 daddr;
};

__u64 maparr[5];

struct mapval {
	__u64 ts1;
	__u64 ts2;
	__u64 c;
	__u64 dc;
	__u64 mark;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __XDP_STATS_KERN_USER_H */
