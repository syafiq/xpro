//static const char *__doc__ = "sync between L_db and M_db \n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <hiredis/hiredis.h>

int main() {
	//redisContext *c = redisConnect("192.168.57.12", 6379);
	redisContext *c_m = redisConnect("192.168.57.12", 6379);
	redisReply *reply_m;

	redisContext *c_l = redisConnect("127.0.0.1", 6379);
	redisReply *reply_l;

	if (c_m == NULL || c_m->err) {
		if (c_m) {
			printf("Error: %s\n", c_m->errstr);
		} else {
			printf("Can't allocate redis context\n");
		}
	}

	while(1) {
		// 1. first we should send W (load) to M_db
		// 2. receive W value of all other proxies from M_db
		reply_m = redisCommand(c_m, "SCAN 0");
		reply_l = redisCommand(c_l, "SCAN 0");
		char idaddr;

		uint32_t i, no_elmt = reply->element[1]->elements;
		for (i=0; i<no_elmt; i++){
			idaddr = reply->element[1]->element[i]->str;
			//printf("SET: %s \n", reply->element[1]->element[i]->str);

		}

		sleep(10);

		//freeReplyObject(reply_m);
	}
}
