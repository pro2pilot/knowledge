/* QA-only, read-only parent/birth binding for the disposable public pipeline.
 * No signals or recovery. A parent PID alone is not an ownership proof. */
#if !defined(__APPLE__)
#error "requires real Darwin"
#endif
#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
struct Unique { uint8_t uuid[16]; uint64_t unique,parent; int32_t version; uint32_t reserved; uint64_t reserved2,reserved3; };
struct Identity { struct proc_bsdinfo bsd; struct Unique unique; };
_Static_assert(sizeof(struct Unique)==56,"Darwin combined process ABI");
_Static_assert(SZOMB==5,"Darwin zombie process ABI");
static int number(const char *s,uint64_t *out) {
  if(!s||!*s||strlen(s)>20||(*s=='0'&&s[1]))return 0;
  for(const char *p=s;*p;p++)if(*p<'0'||*p>'9')return 0;
  char *end=NULL;errno=0;unsigned long long n=strtoull(s,&end,10);
  if(errno||!end||*end)return 0;*out=n;return 1;
}
static void quote(const char *s) {
  putchar('"');for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
    if(*p=='"'||*p=='\\'){putchar('\\');putchar(*p);}
    else if(*p<32)printf("\\u%04x",*p);else putchar(*p);
  }putchar('"');
}
int main(int argc,char **argv) {
  uint64_t pid=0;if(argc!=2||!number(argv[1],&pid)||pid<2||pid>INT_MAX)return 64;
  struct Identity before={0},after={0};char image[PROC_PIDPATHINFO_MAXSIZE]={0};
  if(proc_pidinfo((pid_t)pid,18,0,&before,sizeof(before))!=(int)sizeof(before)||before.bsd.pbi_pid!=pid||
      before.unique.unique==0||before.unique.parent==0||before.unique.version<=0||before.bsd.pbi_status==SZOMB)return 1;
  if(proc_pidpath((pid_t)pid,image,sizeof(image))<=0)return 1;
  if(proc_pidinfo((pid_t)pid,18,0,&after,sizeof(after))!=(int)sizeof(after)||after.bsd.pbi_pid!=pid||
      before.unique.unique!=after.unique.unique||before.unique.version!=after.unique.version||
      before.unique.parent!=after.unique.parent||before.bsd.pbi_ppid!=after.bsd.pbi_ppid||
      before.bsd.pbi_start_tvsec!=after.bsd.pbi_start_tvsec||before.bsd.pbi_start_tvusec!=after.bsd.pbi_start_tvusec||
      before.bsd.pbi_ruid!=after.bsd.pbi_ruid||after.bsd.pbi_status==SZOMB)return 1;
  printf("{\"schema\":\"knowledge-darwin-qa-process-parent.v1\",\"pid\":%u,\"parent_pid\":%u,"
    "\"unique_id\":\"%" PRIu64 "\",\"parent_unique_id\":\"%" PRIu64 "\",\"start_sec\":\"%" PRIu64 "\","
    "\"start_usec\":\"%" PRIu64 "\",\"pidversion\":%d,\"ruid\":%u,\"image\":",
    after.bsd.pbi_pid,after.bsd.pbi_ppid,after.unique.unique,after.unique.parent,
    after.bsd.pbi_start_tvsec,after.bsd.pbi_start_tvusec,after.unique.version,after.bsd.pbi_ruid);
  quote(image);puts("}");return 0;
}
