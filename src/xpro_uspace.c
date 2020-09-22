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
#include <stdint.h>
#include <inttypes.h>
#define BILLION  1000000000L

#define PROXY_PORT 5683
#define SERVER_PORT 5683
#define MAXLINE 1024 

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX  4096
#endif

static unsigned long epoch_nsecs(void) {
  long int ns;
    time_t sec;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    sec = spec.tv_sec;
    ns = spec.tv_nsec;

    return (uint64_t) sec * BILLION + (uint64_t) ns;
}

int main() {

	setlocale(LC_NUMERIC, "en_US");
	
	/*
	 * Proxy socket part
	 * */
	int sockfd, sock_serv; 
	char buffer[MAXLINE]; 
	struct sockaddr_in proxaddr, cliaddr, servaddr; 
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		exit(EXIT_FAILURE); 
	} 
	if ( (sock_serv = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		exit(EXIT_FAILURE); 
	} 
	memset(&proxaddr, 0, sizeof(proxaddr)); 
	memset(&cliaddr, 0, sizeof(cliaddr)); 
	memset(&servaddr, 0, sizeof(servaddr)); 
	
	proxaddr.sin_family = AF_INET;
	proxaddr.sin_addr.s_addr = INADDR_ANY; 
	proxaddr.sin_port = htons(PROXY_PORT); 

	if ( bind(sockfd, (const struct sockaddr *)&proxaddr, sizeof(proxaddr)) < 0 ) { 
	    	perror("bind failed"); 
	    	exit(EXIT_FAILURE); 
	}

	/*
	 * bpf part
	 * */
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

	__u64 now_since_epoch, blocked_since_epoch;
	__u64 retval[3];
	__u64 curr_ts1 = 0, ts1;
	__u64 curr_ts2 = 0, ts2;
	__u64 curr_cdc = 0, c, dc;
	__u64 TT3 = 1000000000;
	__u64 TF2 = 100;
	int n;
	socklen_t len;
	struct key_addr prev_key, key, ka;
	char *dest_inside, *msg_inside;
	unsigned char bytes[4];
	char charbuf[32];
	struct mapval mv;
	__u64 mv_get[5];
	int res;
        __u64 TT1 = 2000000000; //ns -> 2 sec
        //__u64 TT2 = 1000000000; //ns -> 1 sec
        //__u64 TT3 = 2000000000; //ns
        //__u64 TF1 = 500;
        //__u64 TF2 = 500;
	void *vp;
	__u64 mv_arr[5];

	while(1) {
		res = -1;
		now_since_epoch = epoch_nsecs();
		printf("time_now %llu \n", now_since_epoch);
		len = sizeof(cliaddr);
		n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, 
				(struct sockaddr *) &cliaddr, &len);
		buffer[n] = '\0';
		//printf("ka.saddr %d \n", cliaddr.sin_addr.s_addr);
		ka.saddr = cliaddr.sin_addr.s_addr;

		char *p = strtok(buffer, ",");
		if(p) {
			dest_inside = p;
			inet_pton(AF_INET, dest_inside, &ka.daddr);
			//printf("ka.daddr %u \n", ka.daddr);
		}
		p = strtok(NULL, ",");
		if (p)
			msg_inside = p;

		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = inet_addr(dest_inside);
		servaddr.sin_port = htons(SERVER_PORT);
		
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
		res = bpf_map_lookup_elem(mapall_fd, &ka, &mv_get);

		if (res == 0) {
			mv.ts1 = *((__u64 *)mv_get);
                	mv.ts2 = *((__u64 *)mv_get +1);
                	mv.c = *((__u64 *)mv_get +2);
                	mv.dc = *((__u64 *)mv_get +3);
                	mv.mark = *((__u64 *)mv_get +4);

			if(now_since_epoch-mv.ts2 > TT1) {
			        mv.ts1 = now_since_epoch;
                                mv.c = 0;
                                mv.dc = 0;
                                mv.mark = 1;	
			}
		} else {
                        mv.ts1 = now_since_epoch;
                        mv.ts2 = now_since_epoch;
                        mv.c = 0;
                        mv.dc = 0;
                        mv.mark = 0;
		}

                mv.c = mv.c + 1;
                mv.dc = mv.dc +1;
                mv.ts2 = now_since_epoch;

		mv_arr[0] = mv.ts1;
		mv_arr[1] = mv.ts2;
		mv_arr[2] = mv.c;
		mv_arr[3] = mv.dc;
		mv_arr[4] = mv.mark;
		
		vp = mv_arr;
		bpf_map_update_elem(mapall_fd, &ka, vp, BPF_ANY);

		prev_key.daddr = -1;
		prev_key.saddr = -1;
		key.daddr = -1;
		key.saddr = -1;
		curr_ts1 = 0;
		curr_ts2 = 0;
		curr_cdc = 0;

		while(bpf_map_get_next_key(mapall_fd, &prev_key, &key) == 0) {
    			bytes[3] = key.daddr & 0xFF;
    			bytes[2] = (key.daddr >> 8) & 0xFF;
    			bytes[1] = (key.daddr >> 16) & 0xFF;
    			bytes[0] = (key.daddr >> 24) & 0xFF;
			snprintf(charbuf, sizeof(charbuf), "%d.%d.%d.%d", 
					bytes[3], bytes[2], bytes[1], bytes[0]);
			if (strcmp(charbuf, dest_inside) == 0) {
				bpf_map_lookup_elem(mapall_fd, &key, &retval);

				ts1 = *((__u64 *)retval);
				if ((ts1 < curr_ts1) || (curr_ts1 == 0)) {
					curr_ts1 = ts1;	
				}
				ts2 = *((__u64 *)retval+1); 
				if (ts2 > curr_ts2) {
					curr_ts2 = ts2;
				}
				c = *((__u64 *)retval+2); 
				dc = *((__u64 *)retval+3);
				curr_cdc = curr_cdc+c+dc;
			}
			prev_key = key;
		}
		close(mapall_fd);
		len = sizeof(servaddr);

		//printf("ts2-ts1 %llu \n", curr_ts2-curr_ts1);
		//printf("curr_cdc %llu \n", curr_cdc);
		if (curr_ts2-curr_ts1 > TT3) {
			printf("TF2 %f \n", floor(curr_cdc*1000000000/ (curr_ts2-curr_ts1)));
			if (floor(curr_cdc*1000000000/ (curr_ts2-curr_ts1)) >= TF2) {
				blocked_since_epoch = epoch_nsecs();
				printf("blocked_since_epoch %llu \n", blocked_since_epoch);
				;
			}
		} else {
			sendto(sock_serv, (const char *)msg_inside, strlen(msg_inside), 
			MSG_CONFIRM, (const struct sockaddr *) &servaddr, len);
		}
	}
}
