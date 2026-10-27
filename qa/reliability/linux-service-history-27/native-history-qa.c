/* Test-only CLI for the root-native persistence component. It does not run
 * workloads, prove physical closure, expose a service socket, or claim KVE. */
#define _GNU_SOURCE
#include "verification-linux-uid-history.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int knowledge_linux_uid_history_test_io(const char *phase) {
    const char *crash=getenv("KV_HISTORY_TEST_CRASH");
    if(crash&&!strcmp(crash,phase))_exit(88);
    const char *fail=getenv("KV_HISTORY_TEST_FAIL");
    return fail&&!strcmp(fail,phase);
}
static int decode(const char *value,unsigned char out[32]) {
    if(!value||strlen(value)!=64)return -1;
    for(unsigned i=0;i<32;i++){
        unsigned byte;char suffix;
        if(sscanf(value+i*2,"%2x%c",&byte,&suffix)<1)return -1;
        out[i]=(unsigned char)byte;
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc<4)return 64;
    kv_linux_uid_configuration config={.anchor_dir=argv[2],.journal_dir=argv[3],
        .uid_first=1000100000U,.uid_last=1000100005U,
        .installation_id={1,2,3,4},.host_id={9,8,7,6}};
    if(!strcmp(argv[1],"wrong-config"))config.installation_id[0]^=1;
    const char *reason=NULL;
    if(!strcmp(argv[1],"initialize")){
        int rc=kv_linux_uid_initialize(&config,&reason);
        printf("{\"ok\":%s,\"reason\":\"%s\"}\n",rc?"false":"true",reason);return rc?1:0;
    }
    kv_linux_uid_history *history=kv_linux_uid_open(&config,&reason);
    if(!history){printf("{\"ok\":false,\"reason\":\"%s\"}\n",reason);return 1;}
    int rc=0;
    if(!strcmp(argv[1],"hold")){
        puts("{\"holding\":true}");fflush(stdout);
        if(getchar()==EOF)rc=-1;
    }else if(!strcmp(argv[1],"reserve")){
        unsigned char nonce[32],boot[16]={7,8,9};kv_linux_uid_reservation reservation;
        if(argc!=5||decode(argv[4],nonce))return 64;
        rc=kv_linux_uid_reserve(history,nonce,boot,&reservation);
    }else if(!strcmp(argv[1],"close")||!strcmp(argv[1],"wrong-close")||!strcmp(argv[1],"zero-proof")){
        kv_linux_uid_snapshot state;unsigned char proof[32]={5,4,3,2,1};
        if(kv_linux_uid_read(history,&state))rc=-1;
        else{
            if(!strcmp(argv[1],"wrong-close"))state.reservation.authority_uid++;
            if(!strcmp(argv[1],"zero-proof"))memset(proof,0,32);
            rc=kv_linux_uid_record_closed(history,&state.reservation,proof);
        }
    }else if(strcmp(argv[1],"inspect")&&strcmp(argv[1],"wrong-config"))return 64;
    kv_linux_uid_snapshot state={0};
    const char *operation_reason=kv_linux_uid_reason(history);
    if(rc==0)rc=kv_linux_uid_read(history,&state);
    printf("{\"ok\":%s,\"reason\":\"%s\",\"records\":%llu,\"allocations\":%llu,"
           "\"pending\":%s,\"authority_uid\":%u,\"worker_uid\":%u}\n",
           rc?"false":"true",rc?operation_reason:kv_linux_uid_reason(history),
           (unsigned long long)state.record_sequence,(unsigned long long)state.allocations,
           state.pending_cleanup?"true":"false",state.reservation.authority_uid,state.reservation.worker_uid);
    kv_linux_uid_close(history);return rc?1:0;
}
