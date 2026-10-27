/* QA-only, read-only parent/birth binding for the disposable public pipeline.
 * No signals or recovery. A parent PID alone is not an ownership proof. */
#if !defined(__APPLE__)
#error "requires real Darwin"
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
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
static int fifo_reader(int argc,char **argv) {
  uint64_t pid,unique,sec,usec,uid;
  if(argc!=8||!number(argv[2],&pid)||pid<2||pid>INT_MAX||!number(argv[3],&unique)||!unique
    ||!number(argv[4],&sec)||!sec||!number(argv[5],&usec)||usec>=1000000
    ||!number(argv[6],&uid)||uid>UINT_MAX)return 64;
  struct Identity before={0},after={0};struct stat target={0},live={0};
  int target_ok=lstat(argv[7],&target)==0&&S_ISFIFO(target.st_mode)&&target.st_nlink==1&&target.st_uid==uid;
  int birth_before=proc_pidinfo((pid_t)pid,18,0,&before,sizeof(before))==(int)sizeof(before)
    &&before.bsd.pbi_pid==pid&&before.unique.unique==unique&&before.bsd.pbi_start_tvsec==sec
    &&before.bsd.pbi_start_tvusec==usec&&before.bsd.pbi_ruid==uid&&before.bsd.pbi_status!=SZOMB;
  enum { FD_CAP=16384 };struct proc_fdinfo *fds=calloc(FD_CAP,sizeof(*fds));
  if(!fds)return 70;
  int bytes=0,scan_errno=0,listed=0,vnodes=0,fifos=0,matched=0;
  if(target_ok&&birth_before){errno=0;bytes=proc_pidinfo((pid_t)pid,PROC_PIDLISTFDS,0,fds,FD_CAP*(int)sizeof(*fds));scan_errno=errno;}
  int complete=bytes>0&&bytes<FD_CAP*(int)sizeof(*fds)&&bytes%(int)sizeof(*fds)==0;
  if(complete){listed=bytes/(int)sizeof(*fds);
    for(int i=0;i<listed;i++){
      if(fds[i].proc_fdtype!=PROX_FDTYPE_VNODE)continue;
      struct vnode_fdinfo info={0};
      if(proc_pidfdinfo((pid_t)pid,fds[i].proc_fd,PROC_PIDFDVNODEINFO,&info,sizeof(info))!=(int)sizeof(info))continue;
      vnodes++;
      if(!S_ISFIFO(info.pvi.vi_stat.vst_mode))continue;fifos++;
      /* proc_fileinfo reports kernel FREAD/FWRITE bits (1/2), not O_RDONLY. */
      if(info.pvi.vi_stat.vst_dev==(uint32_t)target.st_dev&&info.pvi.vi_stat.vst_ino==(uint64_t)target.st_ino
        &&info.pvi.vi_stat.vst_uid==uid&&(info.pfi.fi_openflags&3u)==1u)matched++;
    }
  }
  free(fds);
  int birth_after=proc_pidinfo((pid_t)pid,18,0,&after,sizeof(after))==(int)sizeof(after)
    &&after.bsd.pbi_pid==pid&&after.unique.unique==unique&&after.bsd.pbi_start_tvsec==sec
    &&after.bsd.pbi_start_tvusec==usec&&after.bsd.pbi_ruid==uid&&after.bsd.pbi_status!=SZOMB;
  int stable=target_ok&&lstat(argv[7],&live)==0&&S_ISFIFO(live.st_mode)&&live.st_nlink==1
    &&live.st_dev==target.st_dev&&live.st_ino==target.st_ino&&live.st_uid==target.st_uid;
  int observed=target_ok&&birth_before&&birth_after&&stable&&complete&&scan_errno==0&&matched==1;
  printf("{\"schema\":\"knowledge-macos-qa-fifo-reader.v1\",\"observed\":%s,\"target_fifo\":%s,"
    "\"birth_before\":%s,\"birth_after\":%s,\"target_stable\":%s,\"fd_scan_complete\":%s,"
    "\"fd_count\":%d,\"vnode_count\":%d,\"fifo_count\":%d,\"exact_read_fd_count\":%d,\"errno\":%d}\n",
    observed?"true":"false",target_ok?"true":"false",birth_before?"true":"false",birth_after?"true":"false",
    stable?"true":"false",complete?"true":"false",listed,vnodes,fifos,matched,scan_errno);
  return observed?0:1;
}
int main(int argc,char **argv) {
  if(argc>1&&!strcmp(argv[1],"--fifo"))return fifo_reader(argc,argv);
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
