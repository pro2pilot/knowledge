/* QA-only, read-only Darwin lifetime observer. Never sends a signal/reclaims.
 * Combined proc ABI matches the pinned broker. SZOMB is Apple's public process
 * status: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc.h
 * A zombie proves stopped execution, NOT collection/resource release. */
#if !defined(__APPLE__)
#error "requires real Darwin"
#endif
#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>

struct KUnique { uint8_t uuid[16]; uint64_t uniqueid,parent_uniqueid;
    int32_t pidversion; uint32_t reserved; uint64_t reserved2,reserved3; };
struct KIdentity { struct proc_bsdinfo bsd; struct KUnique unique; };
_Static_assert(sizeof(struct KUnique)==56,"Darwin unique ABI");
_Static_assert(SZOMB==5,"Darwin zombie status ABI");
static bool number(const char *p,uint64_t *out) {
    if(!p||!*p||strlen(p)>20||(*p=='0'&&p[1]))return false;
    for(const char *c=p;*c;c++)if(*c<'0'||*c>'9')return false;
    errno=0;char *end=NULL;unsigned long long n=strtoull(p,&end,10);
    if(errno||!end||*end)return false;*out=(uint64_t)n;return true;
}
static void quoted(const char *p) {
    putchar('"');
    for(const unsigned char *s=(const unsigned char *)p;*s;s++){
        if(*s=='"'||*s=='\\'){putchar('\\');putchar(*s);}
        else if(*s<32)printf("\\u%04x",*s);else putchar(*s);
    }
    putchar('"');
}
int main(int argc,char **argv) {
    uint64_t pid=0,unique=0,sec=0,usec=0;
    if((argc!=2&&argc!=5)||!number(argv[1],&pid)||pid<1||pid>INT_MAX||
        (argc==5&&(!number(argv[2],&unique)||!unique||!number(argv[3],&sec)||!sec||
          !number(argv[4],&usec)||usec>999999)))return 64;
    struct KIdentity v;memset(&v,0,sizeof(v));errno=0;
    int got=proc_pidinfo((pid_t)pid,18,0,&v,sizeof(v));int saved=errno;
    if(got!=(int)sizeof(v)||v.bsd.pbi_pid!=pid||!v.unique.uniqueid||v.unique.pidversion<=0){
        bool absent=got==0&&saved==ESRCH;
        printf("{\"schema\":\"knowledge-darwin-qa-birth.v1\",\"pid\":%" PRIu64 ",\"state\":\"%s\"}\n",pid,absent?"absent":"unavailable");
        return absent?0:1;
    }
    if(argc==5&&(v.unique.uniqueid!=unique||v.bsd.pbi_start_tvsec!=sec||v.bsd.pbi_start_tvusec!=usec)){
        printf("{\"schema\":\"knowledge-darwin-qa-birth.v1\",\"pid\":%" PRIu64 ",\"state\":\"replaced\"}\n",pid);return 0;
    }
    char image[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(proc_pidpath((pid_t)pid,image,sizeof(image))<=0&&v.bsd.pbi_status!=SZOMB){
        printf("{\"schema\":\"knowledge-darwin-qa-birth.v1\",\"pid\":%" PRIu64 ",\"state\":\"unavailable\"}\n",pid);return 1;
    }
    printf("{\"schema\":\"knowledge-darwin-qa-birth.v1\",\"pid\":%u,\"unique_id\":\"%" PRIu64 "\","
        "\"start_sec\":\"%" PRIu64 "\",\"start_usec\":\"%" PRIu64 "\",\"pidversion\":%d,\"ruid\":%u,"
        "\"state\":\"%s\",\"image\":",v.bsd.pbi_pid,v.unique.uniqueid,v.bsd.pbi_start_tvsec,
        v.bsd.pbi_start_tvusec,v.unique.pidversion,v.bsd.pbi_ruid,v.bsd.pbi_status==SZOMB?"same_zombie":"same_running");
    quoted(image);puts("}");return 0;
}

