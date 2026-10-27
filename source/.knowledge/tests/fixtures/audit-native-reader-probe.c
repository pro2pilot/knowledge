/* Linux/POSIX test harness for verbatim extracted Darwin C producer code.
 * Root ownership/ancestor metadata, ACL and SHA are stubs, not Darwin qualification.
 * read/open hooks mutate real files at deterministic observation boundaries. */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#ifndef __APPLE__
#define st_mtimespec st_mtim
#define st_ctimespec st_ctim
#endif
#define MIN(a,b) ((a)<(b)?(a):(b))
typedef unsigned long CC_LONG;
typedef struct { size_t bytes; } CC_SHA256_CTX;
static size_t hashed_bytes, read_bytes, read_calls, result_bytes;
static int CC_SHA256_Init(CC_SHA256_CTX *ctx) {ctx->bytes=0;return 1;}
static int CC_SHA256_Update(CC_SHA256_CTX *ctx,const void *p,CC_LONG n) {(void)p;ctx->bytes+=n;hashed_bytes+=n;return 1;}
static int CC_SHA256_Final(unsigned char *out,CC_SHA256_CTX *ctx) {(void)ctx;memset(out,0,32);return 1;}
static bool safe_acl(const char *path) {(void)path;return true;}
static const char *mode,*target;
static bool hook_fired;
/* The workspace parent may be group/world-writable. Ancestor permissions and root ownership
 * are modeled; target dev/inode, mode/type, timestamps and all reads are real.
 * No global directory is chmod'd to satisfy the native trust policy. */
static int test_lstat(const char *path,struct stat *st) {
    int rc=lstat(path,st);size_t n=strlen(path);
    if(!rc&&strncmp(path,target,n)==0&&target[n]=='/'){
        st->st_mode&=~0022;st->st_uid=0;
    }
    if(!rc)st->st_uid=0; /* model administrator-owned image without requiring sudo */
    return rc;
}
static int test_fstat(int fd,struct stat *st) {
    int rc=fstat(fd,st);if(!rc)st->st_uid=0;return rc;
}
static int test_open(const char *path,int flags,...) {
    if(!strcmp(path,target)&&!strcmp(mode,"fifo-swap")&&!hook_fired){
        hook_fired=true;if(unlink(path)||mkfifo(path,0600)){perror("fifo fixture");exit(90);}
    }
    return open(path,flags);
}
static void mutate(void) {
    if(hook_fired)return;hook_fired=true;
    if(!strcmp(mode,"growth")){
        int fd=open(target,O_WRONLY|O_APPEND);char block[65536];memset(block,'g',sizeof(block));
        if(fd<0||write(fd,block,sizeof(block))!=sizeof(block)||close(fd)){perror("growth fixture");exit(90);}
    }else if(!strcmp(mode,"same-length")){
        int fd=open(target,O_WRONLY);char block[4096];memset(block,'m',sizeof(block));
        struct timespec times[2]={{1234567890,0},{1234567890,123456789}};
        if(fd<0||pwrite(fd,block,sizeof(block),0)!=sizeof(block)||futimens(fd,times)||close(fd)){perror("rewrite fixture");exit(90);}
    }else if(!strcmp(mode,"name-swap")){
        char alternate[8192];snprintf(alternate,sizeof(alternate),"%s.other",target);
        int fd=open(alternate,O_WRONLY|O_CREAT|O_EXCL,0600);char block[4096];memset(block,'a',sizeof(block));
        if(fd<0||write(fd,block,sizeof(block))!=sizeof(block)||close(fd)||rename(alternate,target)){perror("rename fixture");exit(90);}
    }
}
static ssize_t test_read(int fd,void *buffer,size_t size) {
    read_calls++;
    if(!hook_fired&&!strcmp(mode,"eintr")){hook_fired=true;errno=EINTR;return -1;}
    if(!hook_fired&&!strcmp(mode,"early-eof")){hook_fired=true;return 0;}
    mutate();ssize_t n=read(fd,buffer,size);if(n>0)read_bytes+=(size_t)n;return n;
}
static ssize_t test_pread(int fd,void *buffer,size_t size,off_t offset) {
    read_calls++;
    if(!hook_fired&&!strcmp(mode,"eintr")){hook_fired=true;errno=EINTR;return -1;}
    if(!hook_fired&&!strcmp(mode,"early-eof")){hook_fired=true;return 0;}
    mutate();ssize_t n=pread(fd,buffer,size,offset);if(n>0)read_bytes+=(size_t)n;return n;
}
#define fstat test_fstat
#define lstat test_lstat
#define open test_open
#define read test_read
#define pread test_pread
/* EXTRACTED_PRODUCTION_FUNCTIONS */
#undef fstat
#undef lstat
#undef open
#undef read
#undef pread
int main(int argc,char **argv) {
    if(argc!=3)return 64;mode=argv[1];target=argv[2];char digest[65]={0};
    bool ok=protected_image(target,digest);
    printf("{\"accepted\":%s,\"hashed_bytes\":%zu,\"read_bytes\":%zu,\"read_calls\":%zu,\"result_bytes\":%zu,\"hook_fired\":%s}\n",
      ok?"true":"false",hashed_bytes,read_bytes,read_calls,result_bytes,hook_fired?"true":"false");
    return 0;
}
