#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include <bpf/bpf_helpers.h>

#include "../common/xdp_stats_kern_user.h" /* common structure for both userspace and kernel code */
#include "../common/xdp_stats_kern.h"

SEC("xdp_prog")
int xdp_program(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	unsigned char *payload, *msg;
	unsigned char dest_inside[9]; // FIXME: both 9 and 5 here are magic
	unsigned char msg_inside[5];
	unsigned int payload_size;
	unsigned int msg_n, dest_n;
	struct key_addr ka;
	struct mapval mv;
	__u64 get_ns;
	__u64 *t_now;
	__u64 TT1 = 1000000000;

	// sanity check
	ip = data + sizeof(*eth);
	udp = (void *)ip + sizeof(*ip);
	if ((void *)udp + sizeof(*udp) > data_end) {
		return XDP_PASS;
	}

	// if UDP
	if (ip->protocol == IPPROTO_UDP) {

		payload_size = ntohs(udp->len) - sizeof(*udp);
		payload = (unsigned char *)udp + sizeof(*udp);
		if ((void *)payload + payload_size > data_end)
			return XDP_PASS;

		if (htons(udp->dest) == 5683) { // if CoAP
			dest_n = bpf_probe_read_kernel_str(dest_inside, sizeof(dest_inside), payload);
			msg = (unsigned char *)payload + 9; // FIXME: and also here
			msg_n = bpf_probe_read_kernel_str(msg_inside, sizeof(msg_inside), msg);
			if ((dest_n > 0) && (msg_n > 0)) {
				// bpf_printk("dest %s \n", dest_inside);
				// bpf_printk("msg %s \n", msg_inside);
				ka.saddr = ip->saddr;
				//ka.daddr = (__u32) *dest_inside;
				ka.daddr = ip->daddr;
				// bpf_printk("ka.saddr %llu \n", ka.saddr);
				// bpf_printk("ka.daddr %llu \n", ka.daddr);
				__u64 *mv_get = bpf_map_lookup_elem(&mapall, &ka);
				t_now = &get_ns;

				if (mv_get && t_now) {
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
				mv.dc = mv.dc + 1;
				mv.ts2 = (__u64) *t_now;
			}
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
