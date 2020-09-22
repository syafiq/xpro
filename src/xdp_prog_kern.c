#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/udp.h>

#include "../common/xdp_stats_kern_user.h" /* common structure for both userspace and kernel code */
#include "../common/xdp_stats_kern.h"

struct hdr_cursor {
	void *pos;
};

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr,val))
#endif

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

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

	struct key_addr ka;
	struct mapval mv;
	__u64 get_ns, *t_now;
	__u64 TT1 = 2000000000; //ns -> 2 sec
	__u64 TT2 = 1000000000; //ns -> 1 sec
	//__u64 TT3 = 2000000000; //ns
	__u64 TF1 = 500;
	//__u64 TF2 = 500;

	if (iph + 1 > data_end) {
		return XDP_ABORTED;
	}

	ka.saddr = iph->saddr;
	ka.daddr = iph->daddr; // real dest IP addr
	//bpf_printk("DEBUG: src: %llu, dst: %llu\n", ka.saddr, ka.daddr);

	__u64 *mv_get = bpf_map_lookup_elem(&mapall, &ka);
	get_ns = bpf_ktime_get_ns();
	t_now = &get_ns;

	if(mv_get && t_now) {
		mv.ts1 = *((__u64 *)mv_get);
		mv.ts2 = *((__u64 *)mv_get +1);
		mv.c = *((__u64 *)mv_get +2); 
		mv.dc = *((__u64 *)mv_get +3); 
		mv.mark = *((__u64 *)mv_get +4); 

		if((*t_now-mv.ts2) > TT1) {
			mv.ts1 = (__u64) *t_now;
			mv.c = 0;
			mv.dc = 0;
			mv.mark = 1;
		}

	} else {
		mv.ts1 = (__u64) *t_now;
		mv.ts2 = (__u64) *t_now;
		mv.c = 0;
		mv.dc = 0;
		mv.mark = 0;
	}

	mv.c = mv.c + 1;
	mv.dc = mv.dc +1;
	mv.ts2 = (__u64) *t_now;

	bpf_printk("DEBUG: ts1:%llu, ts2:%llu\n", mv.ts1, mv.ts2);
	bpf_printk("DEBUG: c:%lu, dc:%lu, mark:%u\n", mv.c, mv.dc, mv.mark);
	//bpf_printk("size of %lu-byte\n", sizeof(maparr));
	
	//__u64 mv_arr[5] = {mv.ts1, mv.ts2, mv.c, mv.dc, mv.mark};
	//void *vp = mv_arr;

	//bpf_map_update_elem(&mapall, &ka, vp, BPF_ANY);
	if ((mv.ts2-mv.ts1) > TT2 ) { 
		if (((mv.c*1000000000)/(mv.ts2-mv.ts1)) > TF1) {
			bpf_printk("DROP HIGH! \n");
			return XDP_DROP;
			// Send an overload warning
		}
	}
	// remove tunnel header and forward packet
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
