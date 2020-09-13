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
	__u64 *ts1_get, *ts2_get, *c_get, *dc_get, *t_now;
	__u64 *ts1_star_get, *ts2_star_get, *c_star_get;
	__u64 ts1_val, ts2_val, c_val, dc_val, mark_val, get_ns;
	__u64 ts1_star_val, ts2_star_val, c_star_val;
	__u64 one = 1;
	__u64 zero = 0;
	__u64 incr_c = 0;
	__u64 incr_dc = 0;
	__u64 incr_c_star = 0;
	__u64 TT1 = 2000000000; //ns
	__u64 TT2 = 1000000000; //ns
	__u64 TT3 = 60000; //ns
	__u64 TF1 = 500;
	__u64 TF2 = 60000;
	__u32 dest_addr;

	if (iph + 1 > data_end) {
		return XDP_ABORTED;
	}

	ka.saddr = iph->saddr;
	ka.daddr = iph->daddr;
	//bpf_printk("DEBUG: src: %llu, dst: %llu\n", ka.saddr, ka.daddr);

	if (ka.saddr == 1194895552) {
		//bpf_printk("drop by IP! \n");
		return XDP_DROP;
	}
	ts1_get = bpf_map_lookup_elem(&ts1, &ka);
	ts2_get = bpf_map_lookup_elem(&ts2, &ka);
	c_get = bpf_map_lookup_elem(&counter_c, &ka);
	get_ns = bpf_ktime_get_ns();
	t_now = &get_ns;

	if(ts1_get && ts2_get && c_get && t_now) {
		//if (ts1_get && ts2_get && c_get) {
		//	bpf_printk("ts1_get:%llu, ts2_get:%llu\n, t_now:%llu\n", *ts1_get, *ts2_get, *t_now);
		//	bpf_printk("diff_tnow2 %llu \n", *t_now-*ts2_get);
		//}
		if((*t_now-*ts2_get) > TT1) {
			//bpf_printk("inside TT1 \n");
			ts1_val = bpf_map_update_elem(&ts1, &ka, t_now, BPF_EXIST);
        	        c_val = bpf_map_update_elem(&counter_c, &ka, &zero, BPF_EXIST);
        	        dc_val = bpf_map_update_elem(&diffcount_dc, &ka, &zero, BPF_EXIST);
        	        mark_val = bpf_map_update_elem(&mark, &ka, &one, BPF_EXIST);	
		}
	} else {
		ts1_val = bpf_map_update_elem(&ts1, &ka, t_now, BPF_ANY);
                ts2_val = bpf_map_update_elem(&ts2, &ka, t_now, BPF_ANY);
                c_val = bpf_map_update_elem(&counter_c, &ka, &zero, BPF_ANY);
                dc_val = bpf_map_update_elem(&diffcount_dc, &ka, &zero, BPF_ANY);
                mark_val = bpf_map_update_elem(&mark, &ka, &zero, BPF_ANY);
	}

	c_get = bpf_map_lookup_elem(&counter_c, &ka);
	if (c_get) {
		incr_c = (__u64) *c_get+one;
		c_val = bpf_map_update_elem(&counter_c, &ka, &incr_c, BPF_EXIST);
	}
        dc_get = bpf_map_lookup_elem(&diffcount_dc, &ka);
	if (dc_get) {
		incr_dc = (__u64) *dc_get+one;
		dc_val = bpf_map_update_elem(&diffcount_dc, &ka, &incr_dc, BPF_EXIST);
	}

        ts2_val = bpf_map_update_elem(&ts2, &ka, t_now, BPF_EXIST);

	ts1_get = bpf_map_lookup_elem(&ts1, &ka);
	ts2_get = bpf_map_lookup_elem(&ts2, &ka);

	//if (ts1_get && ts2_get && c_get) {
	//	bpf_printk("c_get:%llu, ts1_get:%llu, ts2_get:%llu\n", *c_get, *ts1_get, *ts2_get);
	//	bpf_printk("diff_ts %llu \n", *ts2_get-*ts1_get);
	//}

	if (ts1_get && ts2_get && c_get) {
		if ((*ts2_get-*ts1_get) > TT2 ) { 
			if (((*c_get*1000000000)/(*ts2_get-*ts1_get)) > TF1) {
				//bpf_printk("DROP! \n");
				return XDP_DROP;
				// Send an overload warning
			}
		}
	}

	dest_addr = iph->daddr;
	ts1_star_get = bpf_map_lookup_elem(&ts1_star, &dest_addr);
	if (ts1_star_get && ts1_get) {
		if (*ts1_get < *ts1_star_get) {
			ts1_star_val = bpf_map_update_elem(&ts1_star, &dest_addr, ts1_get, BPF_EXIST);
		}
	} else {
		if (ts1_get) {
			ts1_star_val = bpf_map_update_elem(&ts1_star, &dest_addr, ts1_get, BPF_NOEXIST);
		}
	}

	ts2_star_get = bpf_map_lookup_elem(&ts2_star, &dest_addr);
	if (ts2_star_get && ts2_get) {
		if (*ts2_get > *ts2_star_get) {
			ts2_star_val = bpf_map_update_elem(&ts2_star, &dest_addr, ts2_get, BPF_EXIST);
		}
	} else {
		if (ts2_get) {
			ts2_star_val = bpf_map_update_elem(&ts2_star, &dest_addr, ts2_get, BPF_NOEXIST);
		}
	}

	c_star_get = bpf_map_lookup_elem(&c_star, &dest_addr);
	if (c_star_get && c_get && dc_get) {
		incr_c_star = (__u64) *c_star_get + (__u64) *c_get + (__u64) *dc_get;
		c_star_val = bpf_map_update_elem(&c_star, &dest_addr, &incr_c_star, BPF_EXIST);
	} else {
		if (c_get && dc_get) {
			incr_c_star = (__u64) *c_get + (__u64) *dc_get;
			c_star_val = bpf_map_update_elem(&c_star,&dest_addr, &incr_c_star, BPF_NOEXIST);
		}
	}

	ts1_star_get = bpf_map_lookup_elem(&ts1_star, &dest_addr);
	ts2_star_get = bpf_map_lookup_elem(&ts2_star, &dest_addr);
	c_star_get = bpf_map_lookup_elem(&c_star, &dest_addr);

	if (ts1_star_get && ts2_star_get && c_star_get) {
		// bpf_printk("ts1_star: %llu, ts2_star: %llu, c_star: %llu", *ts1_star_get, *ts2_star_get, *c_star_get);
		if (*ts2_star_get - *ts1_star_get > TT3) {
			if ((*c_star_get/(*ts2_star_get-*ts1_star_get)) > TF2) {
				return XDP_DROP;
			}
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
