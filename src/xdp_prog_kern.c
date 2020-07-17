#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/xdp_stats_kern_user.h" /* common structure for both userspace and kernel code */
#include "../common/xdp_stats_kern.h"

struct hdr_cursor {
	void *pos;
};

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr,val))
#endif

static __always_inline
int parse_eth(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr, int *l3_offset){

	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* length sanity check */
	if(nh->pos +1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	*l3_offset = hdrsize;
	return 1;
}

static __always_inline
int parse_ipv4(struct xdp_md *ctx, int l3_offset){
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;
	if (iph + 1 > data_end) {
		return XDP_ABORTED;
	}

	return XDP_PASS;
}

SEC("xdp_prog")
int xdp_program(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int l3_offset = 0;
	__u32 action;

	/* iterator pointer and next header type */
	struct hdr_cursor nh;
	int nh_type;

	/* point next header at the starting point of data */
	nh.pos = data;

	/* L2 parse */
	nh_type = parse_eth(&nh, data_end, &eth, &l3_offset);
	if(!nh_type) {
		return XDP_PASS;
	}
	action = parse_ipv4(ctx, l3_offset);

	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
