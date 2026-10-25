#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int inject_send_eintr, inject_recv_eintr, inject_write_eintr;
static size_t cap_send, cap_recv;
static ssize_t fixtureSend(int fd,const void *data,size_t length,int flags) {
    if(inject_send_eintr){inject_send_eintr--;errno=EINTR;return -1;}
    if(cap_send&&length>cap_send)length=cap_send;
    return send(fd,data,length,flags);
}
static ssize_t fixtureRecv(int fd,void *data,size_t length,int flags) {
    if(inject_recv_eintr){inject_recv_eintr--;errno=EINTR;return -1;}
    if(cap_recv&&length>cap_recv)length=cap_recv;
    return recv(fd,data,length,flags);
}
static ssize_t fixtureWrite(int fd,const void *data,size_t length) {
    if(inject_write_eintr){inject_write_eintr--;errno=EINTR;return -1;}
    return write(fd,data,length);
}
#define send fixtureSend
#define recv fixtureRecv
#define write fixtureWrite
#include "verification-darwin-transport.h"
#undef send
#undef recv
#undef write

static uint64_t clockMS(void) { struct timespec value;assert(clock_gettime(CLOCK_MONOTONIC,&value)==0);
    return (uint64_t)value.tv_sec*1000+(uint64_t)value.tv_nsec/1000000; }
static void pauseMS(unsigned ms) { struct timespec value={(time_t)(ms/1000),(long)(ms%1000)*1000000};
    while(nanosleep(&value,&value)&&errno==EINTR){} }
static void pair(int fd[2]) { assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0); }
static void writeAll(int fd,const void *data,size_t length) { const char *cursor=data;
    while(length){ssize_t n=write(fd,cursor,length);if(n<0&&errno==EINTR)continue;assert(n>0);cursor+=n;length-=(size_t)n;} }
static unsigned passed;
static void emit(const char *name) { passed++;printf("%s\n",name);fflush(stdout); }

static void parseNegative(const char *name,const unsigned char *wire,size_t length,bool response,int expected) {
    int fd[2];pair(fd);writeAll(fd[1],wire,length);close(fd[1]);struct KVTReader reader={0};
    int result=kvtRead(fd[0],&reader,response,KVT_TURN_BYTES,clockMS());
    assert(result==expected);kvtReaderClear(&reader);close(fd[0]);emit(name);
}

static void slowReader(unsigned delay) {
    int fd[2];pair(fd);int small=4096;assert(setsockopt(fd[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small))==0);
    size_t length=512u*1024u;unsigned char *bytes=malloc(length);assert(bytes);memset(bytes,'a',length);
    pid_t child=fork();assert(child>=0);
    if(child==0){close(fd[0]);pauseMS(delay);size_t total=0;unsigned char buffer[4096];
        for(;;){ssize_t n=read(fd[1],buffer,sizeof(buffer));if(n<0&&errno==EINTR)continue;if(n<=0)break;
            for(ssize_t i=0;i<n;i++){assert(buffer[i]=='a');}
            total+=(size_t)n;}
        close(fd[1]);free(bytes);_exit(total==length?0:2);}
    close(fd[1]);struct KVTBuffer queue={0};assert(kvtAppend(&queue,bytes,length,KVT_QUEUE_LIMIT));free(bytes);
    uint64_t started=clockMS(),last=started;unsigned turns=0;bool blocked=false;
    while(queue.length){assert(clockMS()-started<10000);int rc=kvtFlush(fd[0],&queue,KVT_TURN_BYTES,true,clockMS(),&last);
        assert(rc>=0);if(rc==KVT_WAIT)blocked=true;turns++;struct pollfd wait={fd[0],POLLOUT,0};assert(poll(&wait,1,20)>=0);}
    close(fd[0]);int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    assert(blocked&&turns>1&&clockMS()-started>=delay);kvtBufferClear(&queue);
    char name[96];snprintf(name,sizeof(name),"physical: paused consumer %u ms preserves all bytes",delay);emit(name);
}

int main(void) {
    signal(SIGPIPE,SIG_IGN);
    struct KVTBuffer queue={0};struct KVTReader reader={0};int fd[2];uint64_t last=0;
    assert(KVT_DEFAULT_TRANSPORT_MS==30000&&KVT_DEFAULT_LIFECYCLE_MS==120000);emit("policy: generous separate transport/lifecycle defaults");
    assert(kvtDeadline(UINT64_MAX-2,10)==UINT64_MAX&&kvtDeadline(100,30)==130);
    assert(!kvtExpired(90,100,30)&&!kvtExpired(129,100,30)&&kvtExpired(130,100,30));emit("unit: overflow-safe absolute deadlines");
    pair(fd);int closed=fd[1];close(fd[1]);
    struct pollfd unused[2]={kvtPollSlot(closed,0),kvtPollSlot(fd[0],0)};
    assert(unused[0].fd==-1&&unused[1].fd==-1&&poll(unused,2,20)==0);close(fd[0]);
    emit("physical: unused closed/HUP poll slots are disabled, preventing helper busy-spin");
    assert(kvtAppend(&queue,"abc",3,10));unsigned char before[3];memcpy(before,queue.bytes,3);
    assert(!kvtAppend(&queue,"xxxxxxxx",8,10)&&queue.length==3&&!memcmp(before,queue.bytes,3));
    assert(!kvtReserve(&queue,SIZE_MAX,10));kvtBufferClear(&queue);emit("unit: queue overflow retains exact prior bytes");
    const unsigned char zero[]={0,0,0,0},huge[]={255,255,255,255},partial[]={0,0};
    const unsigned char truncated[]={0,0,0,3,'a'},kind[]={'X',0,0,0,1,'a'};
    parseNegative("physical: zero request length rejected",zero,sizeof(zero),false,KVT_INVALID);
    parseNegative("physical: oversized wire length rejected",huge,sizeof(huge),false,KVT_INVALID);
    parseNegative("physical: EOF within length header rejected",partial,sizeof(partial),false,KVT_EOF);
    parseNegative("physical: EOF within body rejected",truncated,sizeof(truncated),false,KVT_EOF);
    parseNegative("physical: unknown response kind rejected",kind,sizeof(kind),true,KVT_INVALID);
    pair(fd);assert(kvtQueueFrame(&queue,'J',"{}",2,true));assert(kvtFlush(fd[0],&queue,128,true,10,&last)==KVT_READY);
    assert(kvtRead(fd[1],&reader,true,128,10)==KVT_READY);assert(reader.header[0]=='J'&&reader.body_length==2&&!memcmp(reader.body,"{}",2));
    kvtReaderClear(&reader);kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("physical: complete typed frame preserves payload");
    pair(fd);assert(kvtQueueFrame(&queue,'O',"abc",3,true));assert(kvtQueueFrame(&queue,'E',"def",3,true));
    assert(kvtFlush(fd[0],&queue,128,true,10,&last)==KVT_READY);
    assert(kvtRead(fd[1],&reader,true,128,10)==KVT_READY&&reader.header[0]=='O');kvtReaderClear(&reader);
    assert(kvtRead(fd[1],&reader,true,128,10)==KVT_READY&&reader.header[0]=='E');
    kvtReaderClear(&reader);kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("physical: adjacent frames remain separated after reset");
    pair(fd);assert(kvtQueueFrame(&queue,'O',NULL,0,true));assert(kvtQueueFrame(&queue,'J',"{}",2,true));
    assert(kvtFlush(fd[0],&queue,128,true,10,&last)==KVT_READY);
    assert(kvtRead(fd[1],&reader,true,128,10)==KVT_READY&&reader.header[0]=='O'&&reader.body_length==0);kvtReaderClear(&reader);
    assert(kvtRead(fd[1],&reader,true,128,10)==KVT_READY&&reader.header[0]=='J'&&reader.body_length==2);
    kvtReaderClear(&reader);kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("physical: empty output frame is distinct from terminal JSON");
    pair(fd);assert(kvtAppend(&queue,"0123456789",10,32));assert(kvtFlush(fd[0],&queue,4,true,10,&last)==KVT_WAIT);
    assert(kvtAppend(&queue,"abcdefghij",10,32));assert(kvtFlush(fd[0],&queue,128,true,10,&last)==KVT_READY);
    char combined[20];assert(read(fd[1],combined,sizeof(combined))==20&&!memcmp(combined,"0123456789abcdefghij",20));
    kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("physical: queue compaction preserves stream order");
    pair(fd);unsigned char block[1024];memset(block,1,sizeof(block));assert(kvtAppend(&queue,block,sizeof(block),2048));
    cap_send=1;assert(kvtFlush(fd[0],&queue,1024,true,10,&last)==KVT_WAIT&&queue.length==1024-KVT_TURN_CALLS);cap_send=0;
    kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("fault-injection: short writes cannot monopolize one scheduler turn");
    pair(fd);assert(kvtQueueFrame(&queue,'O',block,sizeof(block),true));assert(kvtFlush(fd[0],&queue,2048,true,10,&last)==KVT_READY);
    cap_recv=1;assert(kvtRead(fd[1],&reader,true,2048,10)==KVT_WAIT&&reader.header_used+reader.body_used==KVT_TURN_CALLS);cap_recv=0;
    kvtReaderClear(&reader);kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("fault-injection: short reads cannot monopolize one scheduler turn");
    pair(fd);inject_send_eintr=3;assert(kvtQueueFrame(&queue,'J',"{}",2,true));
    assert(kvtFlush(fd[0],&queue,128,true,20,&last)==KVT_READY&&inject_send_eintr==0);
    inject_recv_eintr=3;assert(kvtRead(fd[1],&reader,true,128,20)==KVT_READY&&inject_recv_eintr==0);
    kvtReaderClear(&reader);kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("fault-injection: interrupted socket operations resume safely");
    pair(fd);inject_send_eintr=100;assert(kvtAppend(&queue,"x",1,10));
    assert(kvtFlush(fd[0],&queue,128,true,20,&last)==KVT_WAIT&&inject_send_eintr==100-KVT_TURN_CALLS&&queue.length==1);inject_send_eintr=0;
    kvtBufferClear(&queue);close(fd[0]);close(fd[1]);emit("fault-injection: repeated EINTR remains bounded per turn");
    pair(fd);close(fd[1]);assert(kvtAppend(&queue,"x",1,10));assert(kvtFlush(fd[0],&queue,128,true,20,&last)==KVT_ERROR);
    kvtBufferClear(&queue);close(fd[0]);emit("physical: disconnected consumer yields error without SIGPIPE death");
    pair(fd);uint64_t started=clockMS();for(unsigned tick=0;tick<10;tick++){
        assert(kvtRead(fd[0],&reader,true,128,clockMS())==KVT_WAIT&&reader.header_used==0);pauseMS(20);}
    assert(clockMS()-started>=180);kvtReaderClear(&reader);close(fd[0]);close(fd[1]);emit("physical: silent socket remains pending without fabricated frame or EOF");
    pair(fd);pid_t child=fork();assert(child>=0);if(child==0){close(fd[0]);uint32_t length=htonl(2);writeAll(fd[1],&length,4);
        pauseMS(200);writeAll(fd[1],"{}",2);close(fd[1]);_exit(0);}
    close(fd[1]);started=clockMS();unsigned ticks=0;int rc;
    while((rc=kvtRead(fd[0],&reader,false,128,clockMS()))==KVT_WAIT){ticks++;assert(clockMS()-started<10000);pauseMS(5);}
    assert(rc==KVT_READY&&ticks>1&&reader.body_length==2&&!memcmp(reader.body,"{}",2));
    int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    kvtReaderClear(&reader);close(fd[0]);emit("physical: 200 ms fragmented request remains valid and yields scheduler turns");
    slowReader(50);slowReader(200);slowReader(1000);
    int pipefd[2];assert(pipe(pipefd)==0&&kvtNonblocking(pipefd[1]));
    unsigned char *large=malloc(1024*1024);assert(large);memset(large,0,1024*1024);
    assert(kvtAppend(&queue,large,1024*1024,KVT_QUEUE_LIMIT));free(large);inject_write_eintr=3;
    assert(kvtFlush(pipefd[1],&queue,KVT_TURN_BYTES,false,40,&last)==KVT_WAIT&&queue.length&&inject_write_eintr==0);
    size_t retained=queue.length;last=41;assert(kvtFlush(pipefd[1],&queue,KVT_TURN_BYTES,false,42,&last)==KVT_WAIT&&queue.length==retained&&last==41);
    assert(!kvtExpired(1041,last,KVT_DEFAULT_TRANSPORT_MS)&&kvtExpired(30041,last,KVT_DEFAULT_TRANSPORT_MS));
    kvtBufferClear(&queue);close(pipefd[0]);close(pipefd[1]);emit("physical+clock-unit: paused pipe preserves data and finite independent idle budget");
    pair(fd);int control[2];pair(control);int small=4096;assert(setsockopt(fd[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small))==0);
    large=malloc(1024*1024);assert(large);memset(large,0,1024*1024);assert(kvtAppend(&queue,large,1024*1024,KVT_QUEUE_LIMIT));free(large);
    for(unsigned turn=0;turn<10;turn++)assert(kvtFlush(fd[0],&queue,KVT_TURN_BYTES,true,50,&last)>=0);
    assert(queue.length);struct KVTBuffer other={0};assert(kvtQueueFrame(&other,'J',"{}",2,true));
    assert(kvtFlush(control[0],&other,128,true,50,&last)==KVT_READY&&kvtRead(control[1],&reader,true,128,50)==KVT_READY);
    kvtReaderClear(&reader);kvtBufferClear(&queue);kvtBufferClear(&other);close(fd[0]);close(fd[1]);close(control[0]);close(control[1]);
    emit("physical: blocked output does not prevent independent control frame progress");
    assert(passed==25);
    printf("PASS: %u transport checks; real Linux/Darwin POSIX sockets plus explicitly labeled injected/unit cases; not Darwin containment qualification\n",passed);
    return 0;
}
