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

#define PROXY_PORT 5683
#define SERVER_PORT 5683
#define MAXLINE 1024 

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX  4096
#endif

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

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("192.168.122.71");
	servaddr.sin_port = htons(SERVER_PORT);
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
	mapall_fd = open_bpf_map_file(pin_dir, "mapall", &mapall_info);
	if (mapall_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	err_mapall = check_map_fd_info(&mapall_info, &map_expect);
	if (err_mapall) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(mapall_fd);
		return err_mapall;
	}

	while(1) {
		int n;
		socklen_t len;
		len = sizeof(cliaddr);
		n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, 
				(struct sockaddr *) &cliaddr, &len);
		buffer[n] = '\0';

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

		struct key_addr key, next_key;
		key.daddr = -1;
		key.saddr = -1;
		__u64 curr_ts1 = 0, ts1;
		__u64 curr_ts2 = 0, ts2;
		__u64 curr_cdc = 0, c, dc;
		while(bpf_map_get_next_key(mapall_fd, &key, &next_key) == 0) {
			__u64 *retval[3];
			bpf_map_lookup_elem(mapall_fd, &key, retval);
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

			printf("%llu %llu %llu %llu \n", ts1, ts2, c, dc);
			key = next_key;
		}

		close(mapall_fd);

		len = sizeof(servaddr);
		sendto(sock_serv, (const char *)buffer, strlen(buffer), 
			MSG_CONFIRM, (const struct sockaddr *) &servaddr, len);
	}
}
