#define _GNU_SOURCE
#include "verification-linux-service-runtime-front.h"
#include "verification-linux-service-runtime-input.h"
#include "verification-linux-service-child-runtime-input.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Fixed bounded runtime private wire: header64+payload24512, exact24576.
 * No rights, serialized owner or arbitrary relay/callback constructor. */
#define session_packet kv_runtime_packet
#define RELEASE KV_RT_RELEASE
#define LIMITS KV_RT_LIMITS
#define LIMITS_ACK KV_RT_LIMITS_ACK
#define REPLY KV_RT_REPLY
#define REPLY_ACK KV_RT_REPLY_ACK
#define STOP KV_RT_STOP
struct session_config {
    char anchor[PATH_MAX],journal[PATH_MAX];
    kv_linux_uid_configuration history;
    struct kv_linux_daemon_policy policy;
    struct kv_linux_service_child_runtime_pins pins;
};
struct native_session {
    pid_t pid;
    int pidfd,control,public_send,reaped,eof,failed,cancelled,delivery,limits,queued;
    int reservation_set,intent_held;
    enum kv_runtime_epoch epoch;
    unsigned reply_size;
    uint64_t read_end,reply_deadline;
    uint64_t setup,work,cleanup,next_reply;
    unsigned char connection_nonce[16],clock_boot[16],reservation[64];
    unsigned char reply[KV_RUNTIME_PAYLOAD_BYTES];
};
struct kv_linux_runtime_front {
    pid_t owner;
    int listener,failed,stopping;
    struct session_config config;
    struct native_session *slots[KV_LINUX_DAEMON_CONNECTIONS];
    uint64_t births,replies,failures;
};
static uint64_t get(const unsigned char *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static int zero(const unsigned char *p,size_t n){unsigned v=0;while(n--)v|=*p++;return !v;}
static uint64_t now_ns(void){struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000||
        (uint64_t)t.tv_sec>INT64_MAX/UINT64_C(1000000000))return 0;
    return(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static uint64_t minimum(uint64_t a,uint64_t b){return a<b?a:b;}
static uint64_t bound(const struct native_session *s){
    return s->epoch==KV_RT_READ?s->read_end:s->epoch==KV_RT_ACTIVE?s->cleanup:minimum(s->setup,minimum(s->work,s->cleanup));
}
static int before(uint64_t end){uint64_t n=now_ns();return n&&n<end;}
static int live(int fd){struct pollfd p={fd,POLLIN,0};return fd>=0&&poll(&p,1,0)==0&&!p.revents;}
static int high(int fd){if(fd<0)return -1;int result=fcntl(fd,F_DUPFD_CLOEXEC,16);int saved=errno;close(fd);errno=saved;return result;}
static int root_profile(void){uid_t a,b,c;gid_t d,e,f;struct sigaction action;
    return !getresuid(&a,&b,&c)&&!getresgid(&d,&e,&f)&&!a&&!b&&!c&&!d&&!e&&!f&&
        !sigaction(SIGCHLD,NULL,&action)&&action.sa_handler==SIG_DFL&&!(action.sa_flags&SA_NOCLDWAIT);
}
static int one_thread(void){
    DIR *directory=opendir("/proc/self/task");if(!directory)return 0;
    unsigned count=0;struct dirent *entry;errno=0;
    while((entry=readdir(directory)))if(entry->d_name[0]!='.')count++;
    int ok=!errno&&count==1;closedir(directory);return ok;
}
static int owned(const kv_linux_runtime_front *f){if(!f){errno=EINVAL;return 0;}if(f->owner!=getpid()){errno=ECHILD;return 0;}return 1;}
static int packet_send(int fd,unsigned kind,uint64_t work,uint64_t cleanup,uint64_t ordinal,const unsigned char *payload){
    return kv_rt_send(fd,kind,work,cleanup,ordinal,0,payload,payload?32:0);
}
static int packet_receive(int fd,pid_t sender,struct session_packet *p){return kv_rt_receive(fd,sender,p);}
static int control_shape(const struct session_packet *p,unsigned kind,uint64_t work,uint64_t cleanup,uint64_t ordinal){
    return kv_rt_shape(p,kind,work,cleanup,ordinal);
}
static int child_ack(pid_t parent,unsigned kind,uint64_t work,uint64_t cleanup,uint64_t ordinal,uint64_t limit){
    while(getppid()==parent&&live(4)&&before(limit)){
        struct session_packet p;int n=packet_receive(5,parent,&p);
        if(n)return n==1&&control_shape(&p,kind,work,cleanup,ordinal)&&live(4)&&before(limit)?0:-1;
        struct pollfd watches[2]={{4,POLLIN,0},{5,POLLIN|POLLRDHUP,0}};
        if(poll(watches,2,10)<0&&errno!=EINTR)return -1;
    }return -1;
}
static int await_reply(struct kv_linux_runtime_channel *ch){
    while(ch->awaiting_reply){
        if(kv_rt_progress(ch))return -1;
        if(ch->awaiting_reply){struct pollfd p={ch->control,POLLIN|POLLRDHUP,0};if(poll(&p,1,10)<0&&errno!=EINTR)return -1;}
    }return kv_rt_progress(ch);
}
/* Called ONLY immediately after the actual typed claim/read check below.
 * Parent independently admits the transition before its still-live old bound.
 * ACK wait never calls a guard/F/current and cannot recursively send replies. */
static int child_transition(struct kv_linux_runtime_channel *ch,unsigned kind,unsigned ack,enum kv_runtime_epoch next){
    uint64_t old=kv_rt_bound(ch);
    if(await_reply(ch)||!before(old)||packet_send(ch->control,kind,ch->work,ch->cleanup,0,NULL)||
        child_ack(ch->parent,ack,ch->work,ch->cleanup,0,old))return -1;
    ch->epoch=next;return kv_rt_progress(ch);
}
static int session_child(struct session_config *config,pid_t parent,uint64_t setup,uint64_t work,uint64_t cleanup){
    struct kv_linux_service_connection connection={.socket_fd=-1,.peer_pidfd=-1,.clock={.namespace_fd=-1}};
    kv_linux_service_actor *actor=NULL;kv_linux_service_child_runtime *runtime=NULL;int result=121;
    struct kv_linux_service_event event={.source_fd=-1};
    struct kv_linux_runtime_channel ch={.owner=getpid(),.parent=parent,.parent_pidfd=4,.control=5,
        .epoch=KV_RT_ADMISSION,.setup=setup,.work=work,.cleanup=cleanup,.read_end=cleanup+KV_RUNTIME_RETAIN_NS,.next_reply=1};
    struct kv_linux_service_reply last={0};
    config->history.anchor_dir=config->anchor;config->history.journal_dir=config->journal;
    if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||!root_profile()||!live(4)||clearenv()||
        child_ack(parent,RELEASE,work,cleanup,0,kv_rt_bound(&ch))||
        kv_linux_service_connect(&connection,3,config->policy.authorized_uid,config->policy.authorized_gid,config->policy.max_source_bytes)||
        kv_linux_service_runtime_route_bind(&connection,&ch))goto done;
    close(3);
    for(;;){
        int got=0;
        while(!got){
            if(kv_rt_progress(&ch))goto done;
            got=kv_linux_service_receive_v3(&connection,&event);if(got<0)goto done;
            if(!got){struct pollfd watches[3]={{4,POLLIN,0},{5,POLLIN|POLLRDHUP,0},{connection.socket_fd,POLLIN|POLLRDHUP,0}};
                if(poll(watches,3,10)<0&&errno!=EINTR)goto done;}
        }
        if(!actor){
            if(event.op!=KV_LINUX_HELLO||!event.clock_domain_validated)goto done;
            ch.work=work=minimum(work,event.requested_work_deadline_ns);ch.cleanup=cleanup=minimum(cleanup,event.requested_cleanup_deadline_ns);
            ch.read_end=cleanup+KV_RUNTIME_RETAIN_NS;
            unsigned char labels[32];memcpy(labels,connection.nonce,16);memcpy(labels+16,connection.clock.boot_id,16);
            if(!work||cleanup<work||kv_rt_progress(&ch)||packet_send(5,LIMITS,work,cleanup,0,labels)||
                child_ack(parent,LIMITS_ACK,work,cleanup,0,kv_rt_bound(&ch))||
                OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG,NULL)!=1||kv_rt_progress(&ch))goto done;
            actor=kv_linux_service_actor_open(&config->history,connection.clock.boot_id,NULL);if(!actor)goto done;
        }
        unsigned char bytes[128];
        if(kv_rt_progress(&ch)||kv_linux_service_actor_process_v3_bounded(actor,&connection,&event,work,cleanup,setup,&last)||
            kv_rt_progress(&ch)||kv_linux_service_reply_encode_v3(bytes,&last)||
            kv_linux_service_runtime_reply(&connection,bytes,128,last.ordinal,kv_rt_bound(&ch))||await_reply(&ch))goto done;
        if(last.kind==KV_REPLY_INTENT_HELD)break;
        if(last.kind!=KV_REPLY_HELLO&&last.kind!=KV_REPLY_RESERVED)goto done;
    }
    runtime=kv_linux_service_child_runtime_start(&config->pins,actor,&connection,&last.reservation);
    if(!runtime||kv_linux_service_child_runtime_claim_matches(runtime,actor,&connection)!=1||
        child_transition(&ch,KV_RT_CLAIMED,KV_RT_CLAIMED_ACK,KV_RT_ACTIVE))goto done;
    for(;;){
        if(kv_rt_progress(&ch)||kv_linux_service_child_runtime_poll(runtime,0))goto done;
        struct kv_linux_service_child_status state;
        if(kv_linux_service_child_runtime_status(runtime,&state)||state.failed||state.cancelled)goto done;
        if(state.mode==KV_CHILD_CONFIRMED_READ&&ch.epoch!=KV_RT_READ){
            unsigned char witnessed[576];
            if(kv_linux_service_child_runtime_read_confirmed(runtime,witnessed)||
                child_transition(&ch,KV_RT_CONFIRMED,KV_RT_CONFIRMED_ACK,KV_RT_READ))goto done;
        }
        if(!ch.awaiting_reply){
            struct kv_linux_service_event read={.source_fd=-1};int got=kv_linux_service_runtime_take_read(&connection,&read);
            if(got<0)goto done;
            if(got){
                unsigned char payload[KV_RUNTIME_PAYLOAD_BYTES];unsigned size=128;
                struct kv_linux_service_reply reply={.protocol_version=3,.ordinal=read.ordinal,.reservation=last.reservation,
                    .work_deadline_ns=work,.cleanup_deadline_ns=cleanup,.kind=KV_REPLY_RECOVERY_REQUIRED,
                    .phase=KV_PHASE_PENDING,.reason=KV_REASON_HISTORY};
                memcpy(reply.connection_nonce,connection.nonce,16);
                if(ch.epoch==KV_RT_READ){
                    if(read.op==KV_LINUX_READ_RESULT_BUNDLE){
                        size_t used=0;
                        if(kv_linux_service_child_runtime_read_bundle(runtime,payload+128,sizeof payload-128,&used)||
                            used>KV_LINUX_FINALIZATION_BUNDLE_MAX_BYTES)goto done;
                        reply.kind=KV_REPLY_SIGNED_RESULT_BUNDLE;size=128+(unsigned)used;
                    }else{
                        if(kv_linux_service_child_runtime_read_confirmed(runtime,payload+128))goto done;
                        reply.kind=KV_REPLY_SIGNED_HISTORY;size=704;
                    }
                    reply.phase=KV_PHASE_CLOSED;reply.reason=KV_REASON_OK;
                }
                if(kv_linux_service_reply_encode_v3(payload,&reply)||kv_rt_progress(&ch)||
                    kv_linux_service_runtime_reply(&connection,payload,size,read.ordinal,read.source_bytes))goto done;
            }
        }
        struct pollfd watches[3]={{4,POLLIN,0},{5,POLLIN|POLLRDHUP,0},{connection.socket_fd,POLLIN|POLLRDHUP,0}};
        if(poll(watches,3,1)<0&&errno!=EINTR)goto done;
    }
done:
    ch.revoked=1; /* Disable every route before any cancellation/close effect. */
    if(event.source_fd>=0)close(event.source_fd);
    if(runtime){
        (void)kv_linux_service_child_runtime_cancel(runtime);
        while(kv_linux_service_child_runtime_close(&runtime)){
            /* Retain the same owners. Parent owns the actual outer C/read end;
             * actual process death cannot turn this into UID closure proof. */
            struct pollfd p={4,POLLIN,0};(void)poll(&p,1,1);
        }
    }
    if(actor){(void)kv_linux_service_actor_abandon_connection(actor,&connection);kv_linux_service_actor_close(actor);}
    kv_linux_service_disconnect(&connection);close(3);close(4);close(5);return result;
}
static void disable(struct native_session *s){s->delivery=0;s->queued=0;s->cancelled=1;}
static void cancel(struct native_session *s){
    disable(s);
    if(s->control>=0)(void)packet_send(s->control,STOP,s->work,s->cleanup,0,NULL);
    if(!s->reaped&&s->pidfd>=0&&syscall(SYS_pidfd_send_signal,s->pidfd,SIGKILL,NULL,0)&&errno!=ESRCH)s->failed=1;
}
static struct native_session *start_session(kv_linux_runtime_front *front,int accepted,uint64_t start){
    struct native_session *s=calloc(1,sizeof *s);if(!s)return NULL;
    s->pidfd=s->control=s->public_send=-1;s->next_reply=1;s->delivery=1;s->epoch=KV_RT_ADMISSION;
    s->setup=start+front->config.policy.setup_ns;s->work=start+front->config.policy.work_ns;
    s->cleanup=s->work+front->config.policy.cleanup_ns;s->read_end=s->cleanup+KV_RUNTIME_RETAIN_NS;
    int pair[2]={-1,-1},raw=-1,parent=-1;
    s->public_send=fcntl(accepted,F_DUPFD_CLOEXEC,16);raw=fcntl(accepted,F_DUPFD_CLOEXEC,16);
    parent=high((int)syscall(SYS_pidfd_open,getpid(),0));
    if(s->public_send<0||raw<0||parent<0||socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair))goto failed;
    int pass=1;
    for(unsigned i=0;i<2;i++){pair[i]=high(pair[i]);if(pair[i]<0||setsockopt(pair[i],SOL_SOCKET,SO_PASSCRED,&pass,sizeof pass))goto failed;}
    if(!root_profile()||!one_thread()||!before(bound(s)))goto failed;
#if defined(__x86_64__) && defined(SYS_clone) && defined(SYS_pidfd_send_signal) && defined(SYS_close_range)
    int born=-1;pid_t child=(pid_t)syscall(SYS_clone,CLONE_PIDFD|SIGCHLD,NULL,&born,NULL,0);
    if(child<0)goto failed;
    if(!child){
        struct session_config copied=front->config;pid_t creator=front->owner;
        uint64_t setup=s->setup,work=s->work,cleanup=s->cleanup;
        /* Main closes its original listener before the first front poll.
             * Retire this inherited duplicate BEFORE overwriting any FD that
             * might hold Main's singleton lock; do not rely on close_range's
             * internal descriptor order. No CLONE_FILES sharing exists.
             * Close before every fallible parent-liveness check as well. */
        if(close(front->listener))_exit(120);
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=creator||!live(parent)||
            dup3(raw,3,O_CLOEXEC)!=3||dup3(parent,4,O_CLOEXEC)!=4||dup3(pair[1],5,O_CLOEXEC)!=5||
            syscall(SYS_close_range,6,~0U,0))_exit(120);
        for(int fd=0;fd<3;fd++)close(fd);
        int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC|O_NOFOLLOW);struct stat st;
        if(nullfd!=0||fstat(0,&st)||!S_ISCHR(st.st_mode)||st.st_rdev!=makedev(1,3)||dup2(0,1)!=1||dup2(0,2)!=2)_exit(120);
        _exit(session_child(&copied,creator,setup,work,cleanup));
    }
    /* Publish the actual birth handle BEFORE any fallible relocation/release.
     * Never lose it on EMFILE and never substitute pidfd_open(child PID). */
    s->pid=child;s->pidfd=born;s->control=pair[0];pair[0]=-1;front->births++;
    close(pair[1]);pair[1]=-1;
    if(born<0||!live(born)||!before(bound(s))||packet_send(s->control,RELEASE,s->work,s->cleanup,0,NULL))goto failed;
    close(raw);close(parent);return s;
#else
    errno=ENOTSUP;
#endif
failed:
    for(unsigned i=0;i<2;i++)if(pair[i]>=0)close(pair[i]);
    if(raw>=0)close(raw);
    if(parent>=0)close(parent);
    if(s->pid>0){s->failed=1;cancel(s);return s;}
    if(s->public_send>=0)close(s->public_send);
    free(s);return NULL;
}
static int reply_shape(struct native_session *s,const unsigned char *p){
    struct kv_linux_service_reply r={0};unsigned char encoded[128];
    r.protocol_version=(uint32_t)get(p+8,4);r.kind=(uint32_t)get(p+12,4);r.ordinal=get(p+16,8);
    memcpy(r.connection_nonce,p+24,16);r.reservation.allocation_sequence=get(p+40,8);
    r.reservation.authority_uid=(uint32_t)get(p+48,4);r.reservation.worker_uid=(uint32_t)get(p+52,4);
    memcpy(r.reservation.attempt_nonce,p+56,32);memcpy(r.reservation.boot_id,p+88,16);
    r.reason=(uint32_t)get(p+104,4);r.phase=(uint32_t)get(p+108,4);
    r.work_deadline_ns=get(p+112,8);r.cleanup_deadline_ns=get(p+120,8);
    if(r.ordinal!=s->next_reply||memcmp(r.connection_nonce,s->connection_nonce,16)||
        kv_linux_service_reply_encode_v3(encoded,&r)||memcmp(encoded,p,128)||
        (r.work_deadline_ns&&(r.work_deadline_ns!=s->work||r.cleanup_deadline_ns!=s->cleanup))||
        (s->next_reply==1&&r.kind!=KV_REPLY_HELLO))return 0;
    if(s->epoch==KV_RT_ADMISSION&&s->next_reply>1&&r.kind!=KV_REPLY_ERROR&&r.kind!=KV_REPLY_RECOVERY_REQUIRED&&
        r.kind!=(s->next_reply==2?KV_REPLY_RESERVED:KV_REPLY_INTENT_HELD))return 0;
    if(s->epoch!=KV_RT_ADMISSION&&r.kind!=KV_REPLY_RECOVERY_REQUIRED&&r.kind!=KV_REPLY_STOP_REQUESTED&&
        r.kind!=KV_REPLY_OBSERVATION&&r.kind!=KV_REPLY_ERROR&&!(s->epoch==KV_RT_READ&&
            (r.kind==KV_REPLY_SIGNED_HISTORY||r.kind==KV_REPLY_SIGNED_RESULT_BUNDLE)))return 0;
    if(s->epoch==KV_RT_ADMISSION&&s->next_reply==3&&r.kind==KV_REPLY_INTENT_HELD)s->intent_held=1;
    if(r.reservation.allocation_sequence){
        if(s->reservation_set&&memcmp(s->reservation,p+40,64))return 0;
        if(r.kind!=KV_REPLY_RECOVERY_REQUIRED&&memcmp(r.reservation.boot_id,s->clock_boot,16))return 0;
        if(!s->reservation_set){memcpy(s->reservation,p+40,64);s->reservation_set=1;}
    }
    return 1;
}
static int bundle_shape(const unsigned char *p,unsigned size){
    if(size<128+576+KV_LINUX_RESULT_HEADER_BYTES+KV_LINUX_RESULT_COMMAND_BYTES||size>KV_RUNTIME_BUNDLE_REPLY_MAX)return 0;
    const unsigned char *message=p+128,*transcript=p+128+576;
    uint64_t count=get(message+20,4);
    return count&&count<=KV_LINUX_RESULT_MAX_COMMANDS&&size==128+576+KV_LINUX_RESULT_HEADER_BYTES+count*KV_LINUX_RESULT_COMMAND_BYTES&&
        !memcmp(message,"KVLSIG1\0",8)&&get(message+8,4)==1&&get(message+12,4)==512&&get(message+16,4)==1&&
        !memcmp(transcript,"KVWRESULT3",10)&&get(transcript+10,2)==1&&zero(transcript+12,4)&&!zero(transcript+16,32)&&get(transcript+48,8)==count;
}
static void drive(kv_linux_runtime_front *front,struct native_session *s){
    if(!root_profile()||!before(bound(s))){s->failed=1;disable(s);}
    siginfo_t info;memset(&info,0,sizeof info);
    if(!s->reaped&&s->pidfd>=0){
        if(waitid(P_PIDFD,(id_t)s->pidfd,&info,WEXITED|WNOHANG)){s->failed=1;disable(s);}
        else if(info.si_pid){
            if(info.si_pid==s->pid&&!info.si_uid&&(info.si_code==CLD_EXITED||info.si_code==CLD_KILLED||info.si_code==CLD_DUMPED))s->reaped=1;
            s->failed=1;disable(s);
        }
    }
    if(!s->reaped&&!live(s->pidfd)){s->failed=1;disable(s);}
    for(unsigned i=0;i<4&&!s->eof;i++){
        struct session_packet p;int n=packet_receive(s->control,s->pid,&p);
        if(!n)break;
        if(n==2){s->eof=1;disable(s);break;}
        if(n<0){s->failed=1;disable(s);break;}
        if(!s->delivery||s->reaped||!before(bound(s))||!live(s->pidfd)){disable(s);continue;}
        unsigned kind=(unsigned)get(p.bytes+8,4);uint64_t work=get(p.bytes+16,8),cleanup=get(p.bytes+24,8);
        if(kind==LIMITS&&s->epoch==KV_RT_ADMISSION&&!s->limits&&!s->queued&&!get(p.bytes+32,8)&&!get(p.bytes+40,8)&&get(p.bytes+48,4)==32&&!zero(p.bytes+64,16)&&!zero(p.bytes+80,16)&&
            work&&work<=s->work&&cleanup>=work&&cleanup<=s->cleanup){
            s->limits=1;s->work=work;s->cleanup=cleanup;s->read_end=cleanup+KV_RUNTIME_RETAIN_NS;
            memcpy(s->connection_nonce,p.bytes+64,16);memcpy(s->clock_boot,p.bytes+80,16);
            if(!before(bound(s))||!live(s->pidfd)||packet_send(s->control,LIMITS_ACK,work,cleanup,0,NULL)){s->failed=1;disable(s);}
        }else if(kind==KV_RT_CLAIMED&&s->epoch==KV_RT_ADMISSION&&s->limits&&s->reservation_set&&s->intent_held&&s->next_reply>=4&&!s->queued&&
            control_shape(&p,KV_RT_CLAIMED,s->work,s->cleanup,0)&&before(bound(s))){
            if(packet_send(s->control,KV_RT_CLAIMED_ACK,s->work,s->cleanup,0,NULL)||!before(bound(s))){s->failed=1;disable(s);}
            else s->epoch=KV_RT_ACTIVE;
        }else if(kind==KV_RT_CONFIRMED&&s->epoch==KV_RT_ACTIVE&&s->limits&&s->reservation_set&&!s->queued&&
            control_shape(&p,KV_RT_CONFIRMED,s->work,s->cleanup,0)&&before(s->cleanup)){
            if(packet_send(s->control,KV_RT_CONFIRMED_ACK,s->work,s->cleanup,0,NULL)||!before(s->cleanup)){s->failed=1;disable(s);}
            else s->epoch=KV_RT_READ;
        }else if(kind==REPLY&&s->limits&&!s->queued&&work==s->work&&cleanup==s->cleanup&&
            get(p.bytes+32,8)==s->next_reply&&reply_shape(s,p.bytes+64)&&
            ((get(p.bytes+48,4)==128&&get(p.bytes+76,4)!=KV_REPLY_SIGNED_HISTORY&&get(p.bytes+76,4)!=KV_REPLY_SIGNED_RESULT_BUNDLE)||
             (get(p.bytes+48,4)==704&&s->epoch==KV_RT_READ&&get(p.bytes+76,4)==KV_REPLY_SIGNED_HISTORY)||
             (s->epoch==KV_RT_READ&&get(p.bytes+76,4)==KV_REPLY_SIGNED_RESULT_BUNDLE&&bundle_shape(p.bytes+64,(unsigned)get(p.bytes+48,4))))&&
            get(p.bytes+40,8)&&get(p.bytes+40,8)<=bound(s)&&before(get(p.bytes+40,8))&&
            ((get(p.bytes+76,4)!=KV_REPLY_SIGNED_HISTORY&&get(p.bytes+76,4)!=KV_REPLY_SIGNED_RESULT_BUNDLE)||
                kv_rt_read_deadline(get(p.bytes+40,8),bound(s)))){
            s->reply_size=(unsigned)get(p.bytes+48,4);s->reply_deadline=get(p.bytes+40,8);
            memcpy(s->reply,p.bytes+64,s->reply_size);s->queued=1;
        }else{s->failed=1;disable(s);}
    }
    if(s->delivery&&s->queued){
        /* The retained public FD is SEND-ONLY. Never receive or SHUT_RD here:
         * the original child transport anchor owns the exclusive reader. */
        struct pollfd out={s->public_send,POLLOUT|POLLRDHUP,0};int ready=poll(&out,1,0);
        if(ready<0||(out.revents&(POLLERR|POLLHUP|POLLRDHUP|POLLNVAL))||!before(bound(s))||!before(s->reply_deadline)||!live(s->pidfd)){s->failed=1;disable(s);}
        else if(out.revents&POLLOUT){
            ssize_t sent=send(s->public_send,s->reply,s->reply_size,MSG_DONTWAIT|MSG_NOSIGNAL);
            if(sent==(ssize_t)s->reply_size){
                s->queued=0;front->replies++;
                if(!before(bound(s))||!before(s->reply_deadline)||!live(s->pidfd)||packet_send(s->control,REPLY_ACK,s->work,s->cleanup,s->next_reply,NULL)){s->failed=1;disable(s);}
                else s->next_reply++;
            }else if(sent>=0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)){s->failed=1;disable(s);}
        }
    }
    if(!s->delivery)cancel(s);
}
static void release_session(kv_linux_runtime_front *f,unsigned i){
    struct native_session *s=f->slots[i];if(!s||!s->reaped||!s->eof)return;
    close(s->pidfd);close(s->control);close(s->public_send);if(s->failed)f->failures++;free(s);f->slots[i]=NULL;
}
kv_linux_runtime_front *kv_linux_runtime_front_open(int listener,const kv_linux_uid_configuration *history,const struct kv_linux_daemon_policy *policy,const struct kv_linux_service_child_runtime_pins *pins){
    if(!history||!policy||!pins||!history->anchor_dir||!history->journal_dir||!root_profile()||!one_thread()){errno=EINVAL;return NULL;}
    size_t a=strnlen(history->anchor_dir,PATH_MAX),j=strnlen(history->journal_dir,PATH_MAX);
    if(!a||a>=PATH_MAX||!j||j>=PATH_MAX||history->anchor_dir[0]!='/'||history->journal_dir[0]!='/'||
        !policy->authorized_uid||!policy->authorized_gid||!policy->max_source_bytes||policy->max_source_bytes>KV_LINUX_SERVICE_MAX_SOURCE_BYTES||
        !policy->setup_ns||!policy->work_ns||!policy->cleanup_ns||policy->setup_ns>policy->work_ns||
        policy->work_ns>UINT64_C(3600000000000)||policy->cleanup_ns>UINT64_C(60000000000)){errno=EINVAL;return NULL;}
    int domain=0,type=0,accepting=0,pass=0,flags=fcntl(listener,F_GETFL);socklen_t n=sizeof(int);
    struct sockaddr_un address;memset(&address,0,sizeof address);socklen_t address_bytes=sizeof address;
    if(flags<0||!(flags&O_NONBLOCK)||getsockopt(listener,SOL_SOCKET,SO_DOMAIN,&domain,&n)||domain!=AF_UNIX||
        getsockopt(listener,SOL_SOCKET,SO_TYPE,&type,&n)||type!=SOCK_SEQPACKET||
        getsockopt(listener,SOL_SOCKET,SO_ACCEPTCONN,&accepting,&n)||!accepting||
        getsockopt(listener,SOL_SOCKET,SO_PASSCRED,&pass,&n)||pass!=1||
        getsockname(listener,(struct sockaddr*)&address,&address_bytes)||address.sun_family!=AF_UNIX||
        address_bytes!=offsetof(struct sockaddr_un,sun_path)+sizeof(KV_LINUX_SERVICE_RUNTIME_SOCKET)||
        memcmp(address.sun_path,KV_LINUX_SERVICE_RUNTIME_SOCKET,sizeof(KV_LINUX_SERVICE_RUNTIME_SOCKET))){errno=EINVAL;return NULL;}
    kv_linux_runtime_front *f=calloc(1,sizeof *f);if(!f)return NULL;
    f->owner=getpid();f->listener=-1;f->config.history=*history;f->config.policy=*policy;f->config.pins=*pins;
    memcpy(f->config.anchor,history->anchor_dir,a+1);memcpy(f->config.journal,history->journal_dir,j+1);
    f->config.history.anchor_dir=f->config.anchor;f->config.history.journal_dir=f->config.journal;
    f->listener=fcntl(listener,F_DUPFD_CLOEXEC,16);if(f->listener<0){free(f);return NULL;}return f;
}
int kv_linux_runtime_front_stop(kv_linux_runtime_front *f){
    if(!owned(f))return -1;
    f->stopping=1;for(unsigned i=0;i<KV_LINUX_DAEMON_CONNECTIONS;i++)if(f->slots[i]){disable(f->slots[i]);cancel(f->slots[i]);}
    return 0;
}
int kv_linux_runtime_front_poll(kv_linux_runtime_front *f,unsigned wait_ms){
    if(!owned(f)||wait_ms>1000){errno=EINVAL;return -1;}
    if(!root_profile()||!one_thread()){f->failed=1;(void)kv_linux_runtime_front_stop(f);}
    struct pollfd watches[1+3*KV_LINUX_DAEMON_CONNECTIONS];memset(watches,0,sizeof watches);
    watches[0].fd=f->stopping?-1:f->listener;watches[0].events=POLLIN;
    uint64_t start=now_ns(),deadline=UINT64_MAX;if(!start){f->failed=1;(void)kv_linux_runtime_front_stop(f);wait_ms=0;}
    for(unsigned i=0;i<KV_LINUX_DAEMON_CONNECTIONS;i++){
        struct native_session *s=f->slots[i];if(s){drive(f,s);release_session(f,i);s=f->slots[i];}
        watches[1+3*i].fd=s&&!s->reaped?s->pidfd:-1;watches[1+3*i].events=POLLIN;
        watches[2+3*i].fd=s&&!s->eof?s->control:-1;watches[2+3*i].events=POLLIN|POLLRDHUP;
        watches[3+3*i].fd=s&&s->delivery?s->public_send:-1;watches[3+3*i].events=POLLRDHUP|(s&&s->queued?POLLOUT:0);
        if(s&&s->delivery)deadline=minimum(deadline,bound(s));
    }
    start=now_ns();if(!start)wait_ms=0;
    else if(deadline!=UINT64_MAX){uint64_t left=deadline>start?(deadline-start+999999)/1000000:0;if(left<wait_ms)wait_ms=(unsigned)left;}
    if(poll(watches,1+3*KV_LINUX_DAEMON_CONNECTIONS,(int)wait_ms)<0&&errno!=EINTR){f->failed=1;(void)kv_linux_runtime_front_stop(f);}
    /* Old births/cursors are drained before any freed slot can be reused. */
    for(unsigned i=0;i<KV_LINUX_DAEMON_CONNECTIONS;i++)if(f->slots[i]){drive(f,f->slots[i]);release_session(f,i);}
    for(unsigned accepted=0;!f->stopping&&accepted<4&&(watches[0].revents&POLLIN);accepted++){
        int raw=accept4(f->listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(raw<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){f->failed=1;(void)kv_linux_runtime_front_stop(f);}break;}
        unsigned slot;for(slot=0;slot<KV_LINUX_DAEMON_CONNECTIONS;slot++)if(!f->slots[slot])break;
        uint64_t n=now_ns();
        if(slot<KV_LINUX_DAEMON_CONNECTIONS&&n&&n<=(uint64_t)INT64_MAX-f->config.policy.work_ns-f->config.policy.cleanup_ns-KV_RUNTIME_RETAIN_NS)
            f->slots[slot]=start_session(f,raw,n);
        close(raw);
    }
    return f->failed?-1:0;
}
int kv_linux_runtime_front_observe(const kv_linux_runtime_front *f,struct kv_linux_runtime_front_observation *out){
    if(!owned(f)||!out){errno=EINVAL;return -1;}
    struct kv_linux_runtime_front_observation o={.births=f->births,.replies_relayed=f->replies,.failed_sessions=f->failures,.stopping=f->stopping,.failed=f->failed};
    for(unsigned i=0;i<KV_LINUX_DAEMON_CONNECTIONS;i++)if(f->slots[i]){o.retained++;o.delivery_enabled+=(unsigned)f->slots[i]->delivery;o.adopted_caller_bounds+=(unsigned)f->slots[i]->limits;}
    *out=o;return 0;
}
int kv_linux_runtime_front_close(kv_linux_runtime_front **owned_front){
    if(!owned_front){errno=EINVAL;return -1;}kv_linux_runtime_front *f=*owned_front;if(!f)return 0;
    if(!owned(f))return -1;
    (void)kv_linux_runtime_front_stop(f);if(f->listener>=0){close(f->listener);f->listener=-1;}
    (void)kv_linux_runtime_front_poll(f,0);
    for(unsigned i=0;i<KV_LINUX_DAEMON_CONNECTIONS;i++)if(f->slots[i]){errno=EBUSY;return -1;}
    free(f);*owned_front=NULL;return 0;
}
