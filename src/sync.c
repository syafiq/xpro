#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

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
#include <hiredis/hiredis.h>

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX  4096
#endif

static unsigned long get_nsecs(void) {
  struct timespec ts;

      clock_gettime(CLOCK_MONOTONIC, &ts);
      return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static unsigned long epoch_nsecs(void) {
  long int ns;
    time_t sec;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    sec = spec.tv_sec;
    ns = spec.tv_nsec;

    return (uint64_t) sec * BILLION + (uint64_t) ns;
}

int main() 
{
        char pin_dir[PATH_MAX];
        int lendir = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, "ens3");
        if (lendir < 0) {
                fprintf(stderr, "ERR: creating pin dirname\n");
                return EXIT_FAIL_OPTION;
        }

	const struct bpf_map_info map_expect = {
                .key_size = sizeof(struct key_addr),
                .value_size = sizeof(maparr),
                .max_entries  = 10000,
        };
        struct bpf_map_info mapall_info = {0};

        int mapall_fd;
        int err_mapall;

	struct key_addr ka;
	char *p;
	int res;
	__u64 now_since_boot;
	__u64 now_since_epoch;
	__u64 ts1_get, ts2_get, c_get, dc_get, mark_get, ts1_sync, ts2_sync;
	__u64 ts1_l, ts2_l, c_l, dc_l, mark_l;
	__u64 retval[3];

	redisContext *c_m = redisConnect("192.168.122.99", 6379);

	if (c_m == NULL || c_m->err) 
	{
		if (c_m) 
		{
			printf("Error: %s\n", c_m->errstr);
		} else 
		{
			printf("Can't allocate redis context\n");
		}
	}

	int TT1, TT4, r;
	char *idaddr, *idaddr_proc;
	uint32_t i;
	redisReply *tr_m; // temporary reply pointer M and L
	redisReply *rset_m;
	redisReply *reply_m;
	redisReply *size_m;
	void *vp;
	struct key_addr prev_key, key;
	char bytes_s[INET_ADDRSTRLEN], bytes_d[INET_ADDRSTRLEN];
	char charbuf[INET_ADDRSTRLEN+INET_ADDRSTRLEN+1];
	__u64 ts1, ts2, c;

	while(1) 
	{
		// 1. first we should send W (load) to M_db
		// 2. receive W value of all other proxies from M_db
		size_m = redisCommand(c_m, "DBSIZE");
		reply_m = redisCommand(c_m, "SCAN 0 COUNT 1000"); // COUNT->ugly hack!
		TT1 = 60000;
		TT4 = 60000;
		r= 60000;
		res = -1;

		for (i=0; i < size_m->integer; i++) {
			/*
			 * for each (i, D_addr) in M_db
			 * */

			idaddr = reply_m->element[1]->element[i]->str;
			idaddr_proc = calloc(strlen(idaddr)+1, sizeof(char));
			strcpy(idaddr_proc, idaddr);
			p = strtok(idaddr_proc, ",");
			if (p) {
				inet_pton(AF_INET, p, &ka.saddr);
			}
			p = strtok(NULL, ",");
			if (p) {
				inet_pton(AF_INET, p, &ka.daddr);
			}
			free(idaddr_proc);
			
			mapall_fd = open_bpf_map_file(pin_dir, "mapall", &mapall_info);
			if (mapall_fd < 0) {
                	        return EXIT_FAIL_BPF;
                	}
                	err_mapall = check_map_fd_info(&mapall_info, &map_expect);
                	if (err_mapall) {
                	        printf("ERR: map via FD not compatible\n");
                	        close(mapall_fd);
                	        return err_mapall;
                	}
			res = bpf_map_lookup_elem(mapall_fd, &ka, &retval);
			close(mapall_fd);
			tr_m = redisCommand(c_m,"HGETALL %s", idaddr);

			if (res == 0) 
			{
				/*
				 * if i,D_addr in L_db
				 * */

				ts1_get = *((__u64 *)retval);
				ts2_get = *((__u64 *)retval+1);
				c_get = *((__u64 *)retval+2);
				dc_get = *((__u64 *)retval+3);
				mark_get = *((__u64 *)retval+4);

				now_since_boot = get_nsecs();
				now_since_epoch = epoch_nsecs();
				ts1_sync = now_since_epoch-(now_since_boot-ts1_get);
				ts2_sync = now_since_epoch-(now_since_boot-ts2_get);

				if ((mark_get == 1) && 
				(ts1_sync-((__u64)atoi(tr_m->element[1]->str)) > TT1))
				{ 
					/*
					 * if mark'=1 and ts1'-ts1>TT1
					 * 	mark' = 0
					 * 	dc' = 0
					 * 	ts1 = ts1'
					 * 	ts2 = ts2'
					 * 	c = c'
					 * */

					mark_l = 0;
					dc_l = 0;
					rset_m = redisCommand(c_m, "HSET %s ts1 %llu", idaddr, ts1_sync);
					rset_m = redisCommand(c_m, "HSET %s ts2 %llu", idaddr, ts2_sync);
					rset_m = redisCommand(c_m, "HSET %s c %llu", idaddr, c_get);
				} else 
				{
					/* else 
					 * 	mark' = 0
					 * 	if ts2' < ts2
					 * 		ts2' = ts2
					 * 	else if ts2'-ts1 > TT4
					 * 		ts1' = ts2'-(ts2'-ts1)/r
					 * 		c = floor(c/r)
					 * 		ts1 = ts1'
					 * 		ts2 = ts2'
					 * 	else
					 * 		ts2 = ts2'
					 * */

					mark_l = 0;
					if(ts2_sync < (__u64)atoi(tr_m->element[3]->str))
					{
						ts2_l = (__u64) atoi(tr_m->element[3]->str);
					} else if (ts2_sync-(__u64)atoi(tr_m->element[1]->str) > TT4) 
					{
						ts1_l = ts2_sync-((ts2_sync-(__u64) atoi(tr_m->element[1]->str))/r);
						rset_m = redisCommand(c_m, "HSET %s c %d", idaddr,
							 floor((__u64)atoi(tr_m->element[5]->str)/r));
						rset_m = redisCommand(c_m, "HSET %s ts1 %llu", idaddr, ts1_sync);
						rset_m = redisCommand(c_m, "HSET %s ts2 %llu", idaddr, ts2_sync);
					} else
					{
						rset_m = redisCommand(c_m, "HSET %s ts2 %s", idaddr, ts2_sync);
					}

					/*
					 * if ts1' > ts1
					 * 	ts1' = ts1
					 * else if ts2'-ts1' > TT4
					 * 	ts1 = ts1'
					 * c' = c + dc'
					 * c = c'
					 * dc' = 0
					 * */

					if(ts1_sync > (__u64)atoi(tr_m->element[1]->str))
					{
						ts1_l = (__u64)atoi(tr_m->element[1]->str);
						
					} else if (ts2_sync-ts1_sync > TT4)
					{
						rset_m = redisCommand(c_m, "HSET %s ts1 %llu", idaddr, ts1_sync);
					}
					c_l = (__u64) atoi(tr_m->element[5]->str) + dc_get;
					rset_m = redisCommand(c_m, "HSET %s c %s", idaddr, c_l);
					dc_l = 0;
				}
			} else 
			{
				/*
				 * ts1' = ts1
				 * ts2' = ts2
				 * c' = c
				 * dc' = 0
				 * mark' = 0
				 * */

				ts1_l = (__u64) atoi(tr_m->element[1]->str);
				ts2_l = (__u64) atoi(tr_m->element[3]->str);
				c_l = (__u64) atoi(tr_m->element[5]->str);
				dc_l = 0;
				mark_l = 0;
			}
			ts1_l = ts1_l-(now_since_epoch-now_since_boot);
			ts2_l = ts2_l-(now_since_epoch-now_since_boot);
			
			__u64 mv_arr[5] = {ts1_l, ts2_l, c_l, dc_l, mark_l};
			vp = mv_arr;
			bpf_map_update_elem(mapall_fd, &ka, vp, BPF_NOEXIST);
			freeReplyObject(tr_m);
		}

		/*
		 * for each (i, D_addr) in M_db
		 * 	if (i, D_addr) not in M_db
		 * 		ts1 = ts1'
		 * 		ts2 = ts2'
		 * 		c = c'
		 * */
                prev_key.daddr = -1;
                prev_key.saddr = -1;
                key.daddr = -1;
                key.saddr = -1;

		mapall_fd = open_bpf_map_file(pin_dir, "mapall", &mapall_info);
		if (mapall_fd < 0) {
                        return EXIT_FAIL_BPF;
                }
                err_mapall = check_map_fd_info(&mapall_info, &map_expect);
                if (err_mapall) {
                        printf("ERR: map via FD not compatible\n");
                        close(mapall_fd);
                        return err_mapall;
                }

                prev_key.daddr = -1;
                prev_key.saddr = -1;
                key.daddr = -1;
                key.saddr = -1;

		while(bpf_map_get_next_key(mapall_fd, &prev_key, &key) == 0) {
			inet_ntop(AF_INET, &(key.saddr), bytes_s, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(key.daddr), bytes_d, INET_ADDRSTRLEN);
			snprintf(charbuf, sizeof(charbuf), "%s,%s", bytes_s, bytes_d);

			rset_m = redisCommand(c_m,"EXISTS %s", charbuf);
			if (rset_m->integer == 0) {
				bpf_map_lookup_elem(mapall_fd, &key, &retval);
				ts1 = *((__u64 *)retval);
				ts2 = *((__u64 *)retval+1);
				c = *((__u64 *)retval+2);
				ts1 = now_since_epoch-(now_since_boot-ts1);
				ts2 = now_since_epoch-(now_since_boot-ts2);
				rset_m = redisCommand(c_m, "HSET %s ts1 %llu", charbuf, ts1);
				rset_m = redisCommand(c_m, "HSET %s ts2 %llu", charbuf, ts2);
				rset_m = redisCommand(c_m, "HSET %s c %llu", charbuf, c);
			}
			prev_key = key;
		}
		close(mapall_fd);
		freeReplyObject(rset_m);
		freeReplyObject(reply_m);

		sleep(3);
	}
}
