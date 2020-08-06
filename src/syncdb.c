//static const char *__doc__ = "sync between L_db and M_db \n";

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <hiredis/hiredis.h>

int is_idaddr_in_ldb(char *id, redisReply *r) {
	int i, no_elmt_l = r->element[1]->elements;
	for (i=0; i<no_elmt_l; i++) {
		if(strcmp(id,r->element[1]->element[i]->str) == 0){
			return i;
		}
	}
	return -1;
}

int main() {
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

	if (c_l == NULL || c_l->err) {
		if (c_l) {
			printf("Error: %s\n", c_l->errstr);
		} else {
			printf("Can't allocate redis context\n");
		}
	}

	while(1) {
		// 1. first we should send W (load) to M_db
		// 2. receive W value of all other proxies from M_db
		reply_m = redisCommand(c_m, "SCAN 0");
		reply_l = redisCommand(c_l, "SCAN 0");
		redisReply *tr_m, *tr_l; // temporary reply pointer M and L
		redisReply *rset_m, *rset_l;
		int TT1 = 60000, TT4 = 60000;
		char *idaddr;
		int loc_ldb;

		uint32_t i, no_elmt_m = reply_m->element[1]->elements;
		for (i=0; i<no_elmt_m; i++){
			idaddr = reply_m->element[1]->element[i]->str;
			loc_ldb = is_idaddr_in_ldb(idaddr, reply_l);
			if (loc_ldb >= 0) {
				tr_l = redisCommand(c_l,"HGETALL %s", idaddr);
				tr_m = redisCommand(c_m,"HGETALL %s", idaddr);
				if (strcmp(tr_l->element[8]->str,"1") == 0) { // if mark == 1
					rset_l = redisCommand(c_l, "HSET %s mark 0", // L_db: mark=0
							idaddr);
					if(atoi(tr_l->element[1]->str)-atoi(tr_m->element[1]->str) > TT1) { //ts1'-ts1>TT1
						rset_l = redisCommand(c_l, "HSET %s dc 0"); //L_db: dc=0
						rset_m = redisCommand(c_m, "HSET %s ts1 %s", idaddr, //M_db, ts1=ts1'
								tr_l->element[1]->str);
						rset_m = redisCommand(c_m, "HSET %s ts2 %s", idaddr, //M_db, ts2=ts2'
								tr_l->element[3]->str);
						rset_m = redisCommand(c_m, "HSET %s c %s", idaddr, //M_db, c=c'
								tr_l->element[5]->str);
					}
					printf("%s \n",tr_l->element[0]->str);
				} else {
					if(atoi(tr_l->element[3]->str)<atoi(tr_m->element[3]->str)){ // if ts2'<ts2
						rset_l = redisCommand(c_l, "HSET %s ts2 %s", idaddr, // ts2'=ts2
								tr_m->element[3]->str);
					} else if (atoi(tr_m->element[3]->str)-atoi(tr_l->element[1]->str) > TT4) {//elseif ts2'-ts1 > TT4
						
					}
				}
				//printf("%s\n",reply_l->element[8]->str);
			} else {
				printf("it's not there \n");
			}
		}

		//reply_m = redisCommand();

		sleep(10);

		//freeReplyObject(reply_m);
	}
}
