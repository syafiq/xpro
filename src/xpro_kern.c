#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <stdlib.h>

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
	struct key_addr ka, key;
	struct mapval mv;
	__u64 get_ns;
	__u64 *t_now;
	__u64 TT1 = 1000000000;
	__u64 TT2 = 1000000000;
	__u64 TT3 = 1000000000;
	__u64 TF1;
	__u64 TF2 = 800000;
	int a;
  __u64 dropvalinit = 0;
  __u64 passvalinit = 0;
  __u32 drop_gen1 = 1;
  __u32 pass_gen1 = 2;
  __u32 drop_gen2 = 3;
  __u32 pass_gen2 = 4;
  __u32 drop_gen3 = 5;
  __u32 pass_gen3 = 6;
  __u32 pass_gen4 = 7;
  __u64 *dstat_gen1, *dstat_gen2, *dstat_gen3;
  __u64 *pstat_gen1, *pstat_gen2, *pstat_gen3, *pstat_gen4;

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
				ka.saddr = ip->saddr;
				// FIXME: should be dest_inside, but strtoul conversion in bpf is kind of weird
        if(ip->saddr == 214542528) { //gen1 -> normal one
          TF1 = 20000000;
        } else { // gen2 or else -> infected
          TF1 = 100000;
        }
				ka.daddr = 2893719744; 
				__u64 *mv_get = bpf_map_lookup_elem(&mapall, &ka);
				get_ns = bpf_ktime_get_ns();
				t_now = &get_ns;

        __u32 tdiff_num = 1;
        __u32 *tdk = &tdiff_num;
        __u64 *td = bpf_map_lookup_elem(&tdiff, tdk);

        if (td) {
          if (mv_get && t_now) {
				    mv.ts1 = *((__u64 *)mv_get);
				    mv.ts2 = *((__u64 *)mv_get +1);
				    mv.c = *((__u64 *)mv_get +2);
				    mv.dc = *((__u64 *)mv_get +3);
				    mv.mark = *((__u64 *)mv_get +4);
				    	
				    if(((*t_now)+(*td)-mv.ts2) > TT1) {
				    	mv.ts1 = (*t_now) + (*td);
				    	mv.c = 0;
				    	mv.dc = 0;
				    	mv.mark = 1;
				    }

				    } else {
				    	mv.ts1 = (*t_now) + (*td);
				    	mv.ts2 = (*t_now) + (*td);
              mv.c = 0;
				    	mv.dc = 0;
				    	mv.mark = 0;
				    }
				    mv.c = mv.c + 1;
				    mv.dc = mv.dc + 1;
			      mv.ts2 = (*t_now) + (*td);

				    __u64 mv_arr[5] = {mv.ts1, mv.ts2, mv.c, mv.dc, mv.mark};
				    void *vp = mv_arr;

				    bpf_map_update_elem(&mapall, &ka, vp, BPF_ANY);

				    if ((mv.ts2-mv.ts1) > TT2 ) { 
				    	if (((mv.c*1000000000)/(mv.ts2-mv.ts1)) > TF1) {
                if(ip->saddr == 214542528) { //gen1 -> normal one
                  dstat_gen1 = bpf_map_lookup_elem(&stats, &drop_gen1);
                  if (dstat_gen1) {
                    __sync_fetch_and_add(dstat_gen1, 1);
                    bpf_map_update_elem(&stats, &drop_gen1, dstat_gen1, BPF_ANY);
                  } else {
                    bpf_map_update_elem(&stats, &drop_gen1, &dropvalinit, BPF_ANY);
                  }
                } else {
                  dstat_gen2 = bpf_map_lookup_elem(&stats, &drop_gen2);
                  if (dstat_gen2) {
                    __sync_fetch_and_add(dstat_gen2, 1);
                    bpf_map_update_elem(&stats, &drop_gen2, dstat_gen2, BPF_ANY);
                  } else {
                    bpf_map_update_elem(&stats, &drop_gen2, &dropvalinit, BPF_ANY);
                  }
                }
				    		return XDP_DROP;
				    	}
				    }

            if(ip->saddr == 214542528) { //gen1 -> normal one
              pstat_gen1 = bpf_map_lookup_elem(&stats, &pass_gen1);
              if (pstat_gen1) {
                __sync_fetch_and_add(pstat_gen1, 1);
                bpf_map_update_elem(&stats, &pass_gen1, pstat_gen1, BPF_ANY);
              } else {
                bpf_map_update_elem(&stats, &pass_gen1, &passvalinit, BPF_ANY);
              }
            } else {
              pstat_gen2 = bpf_map_lookup_elem(&stats, &pass_gen2);
              if (pstat_gen2) {
                __sync_fetch_and_add(pstat_gen2, 1);
                bpf_map_update_elem(&stats, &pass_gen2, pstat_gen2, BPF_ANY);
              } else {
                bpf_map_update_elem(&stats, &pass_gen2, &passvalinit, BPF_ANY);
              }
            }

            
            if((ip->saddr==214542528) || (ip->saddr==214608064) || \
            (ip->saddr==214673600) || (ip->saddr==214739136)){
              pstat_gen4 = bpf_map_lookup_elem(&stats, &pass_gen4);
              if (pstat_gen4) {
                __sync_fetch_and_add(pstat_gen4, 1);
                bpf_map_update_elem(&stats, &pass_gen4, pstat_gen4, BPF_ANY);
              } else {
                bpf_map_update_elem(&stats, &pass_gen4, &passvalinit, BPF_ANY);
              }
              return XDP_PASS;
            } else {
				      // LOW RATE attack
				      // =======================================================				
				      __u64 *look;
				      struct mapval mvl;
				      __u64 curr_ts1 = 0;
				      __u64 curr_ts2 = 0;
				      __u64 curr_cdc = 0;

				      // this loop might be optimized, it's a hack after all
				      for(a=201; a<205; a++) { // optim HERE! server: 192.168.201-204.11
				      	__u32 sa = (__u32) 16777216*11 + 65536*a + 256*168 + 192;
				      	__u32 da = (__u32) 16777216*172 + 65536*122 + 256*168 + 192;
				      	key.saddr = sa;
				      	key.daddr = da;
				      	look = bpf_map_lookup_elem(&mapall, &key);
				      	if (look) {
				      		mvl.ts1 = *((__u64 *)look);
				      		if ((mvl.ts1 < curr_ts1) || (curr_ts1 == 0)) {
				      			curr_ts1 = mvl.ts1;
				      		}
				      		mvl.ts2 = *((__u64 *)look+1);
				      		if (mvl.ts2 > curr_ts2) {
				      			curr_ts2 = mvl.ts2;
				      		}
				      		mvl.c = *((__u64 *)look+2);
				      		mvl.dc = *((__u64 *)look+3);
				      		curr_cdc = curr_cdc+mv.c+mv.dc;
				      	}
				      }
              //bpf_printk("curr_cdc_tf2 %llu \n", (curr_cdc*1000000000/(curr_ts2-curr_ts1)));

              //bpf_printk("TF2_calc %llu ", (curr_cdc*1000000000/(curr_ts2-curr_ts1)));
				      if ((curr_ts2-curr_ts1 > TT3) && ((curr_cdc*1000000000/(curr_ts2-curr_ts1)) >= TF2) ) {
                dstat_gen3 = bpf_map_lookup_elem(&stats, &drop_gen3);
                if (dstat_gen3) {
                  __sync_fetch_and_add(dstat_gen3, 1);
                  bpf_map_update_elem(&stats, &drop_gen3, dstat_gen3, BPF_ANY);
                } else {
                  bpf_map_update_elem(&stats, &drop_gen3, &dropvalinit, BPF_ANY);
                }
                return XDP_DROP;
				      } else {
                pstat_gen3 = bpf_map_lookup_elem(&stats, &pass_gen3);
                if (pstat_gen3) {
                  __sync_fetch_and_add(pstat_gen3, 1);
                  bpf_map_update_elem(&stats, &pass_gen3, pstat_gen3, BPF_ANY);
                } else {
                  bpf_map_update_elem(&stats, &pass_gen3, &passvalinit, BPF_ANY);
                }
              }
            }
          }
			  }
		  }
	  }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
