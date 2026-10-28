#define KLS_ROOT "/var/lib/knowledge-linux-native-v1"
#define KLS_CALLER_UID 1001
#define KLS_UID_FIRST 1590000000
#define KLS_UID_LAST 1590009999
#define KLS_INSTALLATION_ID "00112233445566778899aabbccddeeff"
#define KLS_HOST_ID "ffeeddccbbaa99887766554433221100"
#define KLS_NATIVE_SOURCE_SHA "0000000000000000000000000000000000000000000000000000000000000000"
#define KLS_NODE_SHA KLS_NATIVE_SOURCE_SHA
#define KLS_RUNTIME_MANIFEST_SHA KLS_NATIVE_SOURCE_SHA
#define KLS_TRUSTED_SOURCE_MANIFEST_SHA KLS_NATIVE_SOURCE_SHA
#define main production_native_main
#include "../../../../source/.knowledge/tools/lib/verification-linux-service.c"
#undef main
#include <assert.h>

static unsigned checks;
#define CHECK(value) do { checks++;if(!(value)){fprintf(stderr,"failed check %u at line %d: %s (errno %d)\n",checks,__LINE__,#value,errno);return 1;} } while(0)

static int send_rights(int socket,const int *fds,size_t count) {
  unsigned char body=42;struct iovec io={&body,1};char control[CMSG_SPACE(32*sizeof(int))];memset(control,0,sizeof(control));
  struct msghdr message={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=CMSG_SPACE(count*sizeof(int))};
  struct cmsghdr *c=CMSG_FIRSTHDR(&message);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(count*sizeof(int));memcpy(CMSG_DATA(c),fds,count*sizeof(int));
  return sendmsg(socket,&message,MSG_NOSIGNAL)==1?0:-1;
}
int main(void) {
  struct kls_request request={.magic=KLS_MAGIC,.version=KLS_VERSION,.op=KLS_HELLO,.ordinal=1,.work_deadline_ns=UINT64_C(5000000000),.cleanup_ms=1000};request.nonce[0]=1;
  CHECK(request_shape(&request)==0);
  request.reserved=1;CHECK(request_shape(&request)<0);request.reserved=0;
  request.payload_len=1;CHECK(request_shape(&request)<0);request.payload_len=0;
  request.pid=12;CHECK(request_shape(&request)<0);request.pid=0;
  request.ordinal=0;CHECK(request_shape(&request)<0);request.ordinal=1;
  request.op=KLS_REGISTER_WRITER;CHECK(request_shape(&request)<0);request.pid=2;CHECK(request_shape(&request)==0);
  request.op=KLS_OPEN;request.payload_len=1;CHECK(request_shape(&request)<0);request.pid=0;CHECK(request_shape(&request)==0);
  request.payload_len=KLS_MAX_INPUT+1;CHECK(request_shape(&request)<0);request.payload_len=1;
  request.cleanup_ms=KLS_MAX_CLEANUP_MS+1;CHECK(request_shape(&request)<0);request.cleanup_ms=1000;
  request.work_deadline_ns=UINT64_MAX;CHECK(request_shape(&request)<0);request.work_deadline_ns=UINT64_C(5000000000);
  struct kls_request changed=request;CHECK(same_attempt(&request,&changed));changed.nonce[3]=1;CHECK(!same_attempt(&request,&changed));
  CHECK(relative_name("fixtures/test.js",0));CHECK(!relative_name("/tmp/test.js",0));CHECK(!relative_name("fixtures/../test.js",0));CHECK(!relative_name("fixtures//test.js",0));CHECK(!relative_name("fixtures\\test.js",0));CHECK(relative_name(".",1));CHECK(!relative_name(".",0));

  int source=(int)syscall(SYS_memfd_create,"native-boundary-source",MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_NOEXEC_SEAL);
  CHECK(source>=0);CHECK(write_all(source,"source",6)==0);CHECK(!sealed_input(source,6));
  CHECK(fcntl(source,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_WRITE)==0);CHECK(sealed_input(source,6));CHECK(!sealed_input(source,5));
  int seals=fcntl(source,F_GET_SEALS);CHECK(seals>=0);CHECK((seals&(F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL))==(F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL));
  char digest_a[65],digest_b[65];CHECK(digest_fd(source,64,digest_a)==0);CHECK(lseek(source,2,SEEK_SET)==2);CHECK(digest_fd(source,64,digest_b)==0);CHECK(!strcmp(digest_a,digest_b));CHECK(write(source,"x",1)<0&&errno==EPERM);

  int pair[2];CHECK(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)==0);int one=1;CHECK(setsockopt(pair[1],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))==0);
  CHECK(packet_send(pair[0],"A",1,source)==0);char byte=0;int passed=-1;struct ucred cred;
  CHECK(packet_recv(pair[1],&byte,1,&passed,&cred,1)==1);CHECK(byte=='A'&&passed>=0&&cred.pid==getpid());CHECK(sealed_input(passed,6));close(passed);
  int rights[32];for(unsigned i=0;i<32;i++)rights[i]=source;
  CHECK(send_rights(pair[0],rights,2)==0);CHECK(packet_recv(pair[1],&byte,1,&passed,&cred,1)<0&&errno==EPROTO&&passed==-1);
  CHECK(send_rights(pair[0],rights,32)==0);CHECK(packet_recv(pair[1],&byte,1,&passed,&cred,1)<0&&errno==EPROTO&&passed==-1);
  CHECK(packet_send(pair[0],"oversized",9,-1)==0);CHECK(packet_recv(pair[1],&byte,1,&passed,&cred,1)<0&&errno==EPROTO);

  struct ucred original;socklen_t length=sizeof(original);CHECK(getsockopt(pair[1],SOL_SOCKET,SO_PEERCRED,&original,&length)==0);
  pid_t child=fork();CHECK(child>=0);if(!child){int status=packet_send(pair[0],"C",1,-1);_exit(status?1:0);}
  int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
  CHECK(packet_recv(pair[1],&byte,1,&passed,&cred,1)==1);CHECK(cred.pid==child&&cred.pid!=original.pid&&passed<0);
  close(pair[0]);close(pair[1]);close(source);
  CHECK(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)==0);
  CHECK(packet_send(pair[1],"F",1,-1)==0);CHECK(packet_send(pair[0],"S",1,-1)==0);close(pair[1]);
  ssize_t final=packet_recv(pair[0],&byte,1,&passed,NULL,0);
  if(final<0&&errno==ECONNRESET)final=packet_recv(pair[0],&byte,1,&passed,NULL,0);
  CHECK(final==1&&byte=='F'&&passed<0);
  ssize_t ending=packet_recv(pair[0],&byte,1,&passed,NULL,0);CHECK(ending==0||(ending<0&&errno==ECONNRESET));close(pair[0]);
  printf("{\"status\":\"PASS\",\"checks\":%u,\"scm_credentials_inherited_sender_distinguished\":true,\"extra_fds_rejected\":true,\"ancillary_truncation_rejected\":true,\"sealed_shared_offset_ignored\":true,\"final_before_late_stop_eof_observed\":true}\n",checks);
  return 0;
}
