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
#define BILLION 1000000000L
#include <hiredis/hiredis.h>

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX  4096
#endif

int main() 
{
    char pin_dir[PATH_MAX];
    int lendir = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, "ens10");
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
	__u64 retval[3];

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
	__u64 ts1_upl, ts2_upl, c_upl;
	__u64 ts1_m, ts2_m, c_m;
	__u64 ts1_l, ts2_l, c_l, dc_l, mark_l;

	while(1) 
	{
		redisContext *db_m = redisConnect("192.168.122.171", 6379);

		if (db_m == NULL || db_m->err) 
		{
			if (db_m) 
			{
				printf("Error: %s\n", db_m->errstr);
			} else 
			{
				printf("Can't allocate redis context\n");
			}
		}

		// 1. first we should send W (load) to M_db
		// 2. receive W value of all other proxies from M_db
		size_m = redisCommand(db_m, "DBSIZE");
		reply_m = redisCommand(db_m, "SCAN 0 COUNT 1000"); // COUNT->ugly hack!
		TT1 = 1000000000;
		TT4 = 1000000000;
		r= 1;

		for (i=0; i < size_m->integer; i++) {
			/*
			 * for each (i, D_addr) in M_db
			 * */

			res = -1;
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
			
			mapall_fd = open_bpf_map_file(pin_dir, "mapall", &mapall_info);
			if (mapall_fd < 0) {
                return EXIT_FAIL_BPF;
            }
            err_mapall = check_map_fd_info(&mapall_info, &map_expect);
            if (err_mapall) {
            	printf("ERR: map via FD not compatible 0\n");
                close(mapall_fd);
                return err_mapall;
            }
			//printf("ka.saddr %u ka.daddr %u ", ka.saddr, ka.daddr);
			res = bpf_map_lookup_elem(mapall_fd, &ka, &retval);
			close(mapall_fd);
			tr_m = redisCommand(db_m,"HGETALL %s", idaddr);
			free(idaddr_proc);

			ts1_m = strtoull((tr_m->element[1]->str),NULL,10);
			ts2_m = strtoull((tr_m->element[3]->str),NULL,10);
			c_m = strtoull((tr_m->element[5]->str),NULL,10);
            printf("ts1 %llu ts2 %llu c %llu \n", ts1_m, ts2_m, c_m);
			if (res == 0) {
				/*
				 * if i,D_addr in L_db
				 * */

				ts1_l = *((__u64 *)retval);
				ts2_l = *((__u64 *)retval+1);
				c_l = *((__u64 *)retval+2);
				dc_l = *((__u64 *)retval+3);
				mark_l = *((__u64 *)retval+4);
				printf("idaddr %s ts1 %llu ts2 %llu c_l %llu\n", idaddr, ts1_l, ts2_l, c_l);
				printf("TF2 atas %f \n", floor((c_l+dc_l)*1000000000/ (ts2_l-ts1_l)));
				if (mark_l == 1) {
					mark_l = 0;
					//printf("A \n");
					if (ts1_l-ts1_m > TT1) {
						//printf("B \n");
						dc_l = 0;
						rset_m = redisCommand(db_m, "HSET %s ts1 %llu", idaddr, ts1_l);
						rset_m = redisCommand(db_m, "HSET %s ts2 %llu", idaddr, ts2_l);
						rset_m = redisCommand(db_m, "HSET %s c %llu", idaddr, c_l);
					} else {
						//printf("C \n");
						goto marknotnil;
					}
				} else {
					//printf("D \n");
					marknotnil:
					if(ts2_l < ts2_m) {
						//printf("E \n");
						ts2_l = ts2_m;
					} else {
						//printf("F \n");
						if (ts2_l-ts1_m > TT4) {
							//printf("G \n");
							ts1_l = ts2_l-((ts2_l-ts1_m)/r);
							c_m = floor(c_m/r);
							rset_m = redisCommand(db_m, "HSET %s ts1 %llu", idaddr, ts1_l);
						}
						rset_m = redisCommand(db_m, "HSET %s ts2 %llu", idaddr, ts2_l);
					}

					if(ts1_l > ts1_m) {
						//printf("H \n");
						ts1_l = ts1_m;
					} else {
						//printf("I \n");
						if (ts1_l-ts2_l > TT4) {
							//printf("J \n");
							rset_m = redisCommand(db_m, "HSET %s ts1 %llu", idaddr, ts1_l);
						} else {
							//printf("K \n");
							ts1_l = ts1_m;
						}
					}
					//printf("L \n");
					c_l = c_m + dc_l;
				}
				//printf("M \n");
				rset_m = redisCommand(db_m, "HSET %s c %llu", idaddr, c_l);
				dc_l = 0;
				freeReplyObject(rset_m);
			} else {
				//printf("N \n");
				/*
				 * ts1' = ts1
				 * ts2' = ts2
				 * c' = c
				 * dc' = 0
				 * mark' = 0
				 * */

				ts1_l = ts1_m;
				ts2_l = ts2_m;
				c_l = c_m;
				dc_l = 0;
				mark_l = 0;
			}
			printf("TF2 bawah %f \n", floor(c_l*1000000000/ (ts2_l-ts1_l)));
			__u64 mv_arr[5] = {ts1_l, ts2_l, c_l, dc_l, mark_l};
			vp = mv_arr;

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

			//printf("ka.saddr %u ka.daddr %u c %llu dc %llu mark %llu \n", ka.saddr, ka.daddr, c_l, dc_l, mark_l);
			mapall_fd = open_bpf_map_file(pin_dir, "mapall", &mapall_info);
			if (mapall_fd < 0) {
				return EXIT_FAIL_BPF;
			}
			err_mapall = check_map_fd_info(&mapall_info, &map_expect);
            if (err_mapall) {
            	printf("ERR: map via FD not compatible 1\n");
                close(mapall_fd);
                return err_mapall;
            }
			bpf_map_update_elem(mapall_fd, &ka, vp, BPF_ANY);
			free(idaddr_proc);
			close(mapall_fd);
			freeReplyObject(tr_m);
		}

		/*
		 * for each (i, D_addr) in M_db
		 * 	if (i, D_addr) not in M_db
		 * 		ts1 = ts1'
		 * 		ts2 = ts2'
		 * 		c = c'
		 * */

		mapall_fd = open_bpf_map_file(pin_dir, "mapall", &mapall_info);
		if (mapall_fd < 0) {
        	return EXIT_FAIL_BPF;
        }

        err_mapall = check_map_fd_info(&mapall_info, &map_expect);
        if (err_mapall) {
                printf("ERR: map via FD not compatible 2\n");
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
			rset_m = redisCommand(db_m,"EXISTS %s", charbuf);
			if (key.saddr != 0) {
				if (key.daddr != 0) {
					if (rset_m->integer == 0) {
						bpf_map_lookup_elem(mapall_fd, &key, &retval);
						ts1_upl = *((__u64 *)retval);
						ts2_upl = *((__u64 *)retval+1);
						c_upl = *((__u64 *)retval+2);
						rset_m = redisCommand(db_m, "HSET %s ts1 %llu", charbuf, ts1_upl);
						rset_m = redisCommand(db_m, "HSET %s ts2 %llu", charbuf, ts2_upl);
						rset_m = redisCommand(db_m, "HSET %s c %llu", charbuf, c_upl);
					}
				}
			}
			prev_key = key;
			freeReplyObject(rset_m);
		}
		close(mapall_fd);
		freeReplyObject(reply_m);

		redisFree(db_m);
		sleep(4);
	}
}
