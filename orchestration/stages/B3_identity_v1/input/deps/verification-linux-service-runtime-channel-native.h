#ifndef KNOWLEDGE_LINUX_SERVICE_RUNTIME_CHANNEL_NATIVE_H
#define KNOWLEDGE_LINUX_SERVICE_RUNTIME_CHANNEL_NATIVE_H
/* Fixed linked native implementation only. This layout is NOT a public
 * descriptor/receipt/validator factory. The original raw-child entry alone
 * initializes it after atomic birth and private RELEASE; the transport anchor
 * borrows it until its last real endpoint has closed, in that same process. */
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "verification-linux-service-result-wire.h"
#define KV_RUNTIME_PACKET_BYTES 24576
#define KV_RUNTIME_PAYLOAD_BYTES (KV_RUNTIME_PACKET_BYTES-64)
#define KV_RUNTIME_BUNDLE_REPLY_MAX KV_LINUX_RESULT_REPLY_MAX_BYTES
#define KV_RUNTIME_READ_NS UINT64_C(1000000000)
#define KV_RUNTIME_RETAIN_NS UINT64_C(5000000000)
enum kv_runtime_kind {
    KV_RT_RELEASE=1,KV_RT_LIMITS=2,KV_RT_LIMITS_ACK=3,KV_RT_REPLY=4,
    KV_RT_REPLY_ACK=5,KV_RT_STOP=6,KV_RT_CLAIMED=7,KV_RT_CLAIMED_ACK=8,
    KV_RT_CONFIRMED=9,KV_RT_CONFIRMED_ACK=10
};
enum kv_runtime_epoch {KV_RT_ADMISSION=1,KV_RT_ACTIVE=2,KV_RT_READ=3};
struct kv_runtime_packet {unsigned char bytes[KV_RUNTIME_PACKET_BYTES];};
struct kv_linux_service_control_anchor;
struct kv_linux_runtime_channel {
    pid_t owner,parent;
    int parent_pidfd,control,revoked;
    enum kv_runtime_epoch epoch;
    uint64_t setup,work,cleanup,read_end,next_reply,awaiting_reply;
    struct kv_linux_service_control_anchor *anchor; /* Reciprocal, borrowed. */
};
static inline uint64_t kv_rt_get(const unsigned char *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static inline void kv_rt_put(unsigned char *p,uint64_t v,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(v>>(8*i));}
static inline int kv_rt_zero(const unsigned char *p,size_t n){unsigned v=0;while(n--)v|=*p++;return !v;}
static inline uint64_t kv_rt_now(void){struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000||
        (uint64_t)t.tv_sec>INT64_MAX/UINT64_C(1000000000))return 0;
    return(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static inline int kv_rt_before(uint64_t end){uint64_t n=kv_rt_now();return n&&n<end;}
static inline int kv_rt_read_deadline(uint64_t end,uint64_t upper){
    uint64_t n=kv_rt_now();return n&&end>n&&end<=upper&&end-n<=KV_RUNTIME_READ_NS;
}
static inline int kv_rt_live(int fd){struct pollfd p={fd,POLLIN,0};return fd>=0&&poll(&p,1,0)==0&&!p.revents;}
static inline uint64_t kv_rt_min(uint64_t a,uint64_t b){return a<b?a:b;}
static inline uint64_t kv_rt_bound(const struct kv_linux_runtime_channel *c){
    return c->epoch==KV_RT_READ?c->read_end:c->epoch==KV_RT_ACTIVE?c->cleanup:kv_rt_min(c->setup,kv_rt_min(c->work,c->cleanup));
}
static inline int kv_rt_owned(const struct kv_linux_runtime_channel *c){
    return c&&c->owner==getpid()&&c->parent>0&&getppid()==c->parent&&!c->revoked&&
        c->epoch>=KV_RT_ADMISSION&&c->epoch<=KV_RT_READ&&kv_rt_live(c->parent_pidfd)&&kv_rt_before(kv_rt_bound(c));
}
static inline int kv_rt_send(int fd,unsigned kind,uint64_t work,uint64_t cleanup,uint64_t ordinal,
    uint64_t deadline,const unsigned char *payload,unsigned size){
    if(size>KV_RUNTIME_PAYLOAD_BYTES||(!payload&&size)){errno=EINVAL;return -1;}
    struct kv_runtime_packet p;memset(&p,0,sizeof p);memcpy(p.bytes,"KVLRT1",6);
    kv_rt_put(p.bytes+8,kind,4);kv_rt_put(p.bytes+16,work,8);kv_rt_put(p.bytes+24,cleanup,8);
    kv_rt_put(p.bytes+32,ordinal,8);kv_rt_put(p.bytes+40,deadline,8);kv_rt_put(p.bytes+48,size,4);
    if(size)memcpy(p.bytes+64,payload,size);
    return send(fd,p.bytes,sizeof p.bytes,MSG_DONTWAIT|MSG_NOSIGNAL)==(ssize_t)sizeof p.bytes?0:-1;
}
/* 1 exact fixed packet,0 EAGAIN/EINTR,2 actual EOF,-1 poison. A credential-
 * bearing zero seqpacket is never treated as EOF. All delivered rights close. */
static inline int kv_rt_receive(int fd,pid_t sender,struct kv_runtime_packet *p){
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(8*sizeof(int))];} controls;
    memset(&controls,0,sizeof controls);struct iovec io={p->bytes,sizeof p->bytes};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=controls.bytes,.msg_controllen=sizeof controls.bytes};
    ssize_t n=recvmsg(fd,&m,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    if(n<0)return -1;
    int bad=n!=(ssize_t)sizeof p->bytes||(m.msg_flags&(MSG_TRUNC|MSG_CTRUNC)),credentials=0,rights=0;
    struct ucred cred={0};
    for(struct cmsghdr *h=CMSG_FIRSTHDR(&m);h;h=CMSG_NXTHDR(&m,h)){
        if(h->cmsg_len<CMSG_LEN(0)){bad=1;continue;}size_t size=h->cmsg_len-CMSG_LEN(0);
        if(h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SCM_RIGHTS){
            rights=1;if(size%sizeof(int))bad=1;
            for(size_t i=0;i<size/sizeof(int);i++){int received;memcpy(&received,(unsigned char*)CMSG_DATA(h)+i*sizeof(int),sizeof received);close(received);}
        }else if(h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SCM_CREDENTIALS&&size==sizeof cred){credentials++;memcpy(&cred,CMSG_DATA(h),sizeof cred);}
        else bad=1;
    }
    if(!n){struct pollfd closed={fd,POLLRDHUP,0};
        if(!m.msg_controllen&&!rights&&!(m.msg_flags&(MSG_TRUNC|MSG_CTRUNC))&&poll(&closed,1,0)>0&&
            (closed.revents&(POLLHUP|POLLRDHUP)))return 2;
        errno=EPROTO;return -1;
    }
    unsigned size=(unsigned)kv_rt_get(p->bytes+48,4);
    if(bad||rights||credentials!=1||cred.pid!=sender||cred.uid||cred.gid||memcmp(p->bytes,"KVLRT1\0\0",8)||
        !kv_rt_zero(p->bytes+12,4)||!kv_rt_zero(p->bytes+52,12)||size>KV_RUNTIME_PAYLOAD_BYTES||
        !kv_rt_zero(p->bytes+64+size,KV_RUNTIME_PAYLOAD_BYTES-size)||
        kv_rt_get(p->bytes+8,4)<KV_RT_RELEASE||kv_rt_get(p->bytes+8,4)>KV_RT_CONFIRMED_ACK){errno=EPROTO;return -1;}
    return 1;
}
static inline int kv_rt_shape(const struct kv_runtime_packet *p,unsigned kind,uint64_t work,uint64_t cleanup,uint64_t ordinal){
    return kv_rt_get(p->bytes+8,4)==kind&&kv_rt_get(p->bytes+16,8)==work&&kv_rt_get(p->bytes+24,8)==cleanup&&
        kv_rt_get(p->bytes+32,8)==ordinal&&!kv_rt_get(p->bytes+40,8)&&!kv_rt_get(p->bytes+48,4);
}
/* Never invokes guard/F/current. ACK processing is a separate finite step. */
static inline int kv_rt_progress(struct kv_linux_runtime_channel *c){
    if(!kv_rt_owned(c)){if(c&&c->owner==getpid())c->revoked=1;errno=ECANCELED;return -1;}
    for(unsigned i=0;i<2;i++){
        struct kv_runtime_packet p;int n=kv_rt_receive(c->control,c->parent,&p);
        if(!n)return 0;
        if(n!=1||!c->awaiting_reply||!kv_rt_shape(&p,KV_RT_REPLY_ACK,c->work,c->cleanup,c->awaiting_reply))goto bad;
        c->awaiting_reply=0;
    }
    return 0;
bad:c->revoked=1;errno=ECANCELED;return -1;
}
static inline int kv_rt_reply(struct kv_linux_runtime_channel *c,const unsigned char *bytes,unsigned size,uint64_t ordinal,uint64_t deadline){
    if(kv_rt_progress(c)||c->awaiting_reply||ordinal!=c->next_reply||ordinal==UINT64_MAX||
        (size!=128&&size!=704&&(size<128+576+KV_LINUX_RESULT_HEADER_BYTES+KV_LINUX_RESULT_COMMAND_BYTES||size>KV_RUNTIME_BUNDLE_REPLY_MAX))||
        !deadline||deadline>kv_rt_bound(c)||!kv_rt_before(deadline))goto bad;
    if(kv_rt_send(c->control,KV_RT_REPLY,c->work,c->cleanup,ordinal,deadline,bytes,size))goto bad;
    c->awaiting_reply=ordinal;c->next_reply++;return 0;
bad:c->revoked=1;errno=ECANCELED;return -1;
}
#endif
