/* Ordinary-user physical regression for the production-of-QA socket parser.
 * Includes the exact service implementation, but never invokes its daemon. */
#define main unused_service_main
#include "service.c"
#undef main
#define REQUIRE(test) do { if(!(test)) { fprintf(stderr,"event regression line %d\n",__LINE__);return 1; } } while(0)
int main(void) {
  REQUIRE(getuid()!=0&&geteuid()!=0);
  int pair[2],one=1;
  REQUIRE(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair)==0);
  REQUIRE(setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))==0);
  struct event sent={.kind=2,.role=1,.ok=1},got;struct ucred credentials;
  REQUIRE(event_recv(pair[0],&got,&credentials)==0);
  REQUIRE(event_send(pair[1],&sent)==0);
  REQUIRE(event_recv(pair[0],&got,&credentials)==1&&got.role==1&&credentials.uid==getuid()&&credentials.pid==getpid());
  sent.role=2;REQUIRE(event_send(pair[1],&sent)==0);
  REQUIRE(event_recv(pair[0],&got,&credentials)==1&&got.role==2);
  /* An actual empty message is malformed, not a peer close. */
  REQUIRE(send(pair[1],"",0,MSG_NOSIGNAL)==0);
  REQUIRE(event_recv(pair[0],&got,&credentials)==-1);
  unsigned char oversized[sizeof(sent)+1]={0};
  REQUIRE(send(pair[1],oversized,sizeof(oversized),MSG_NOSIGNAL)==sizeof(oversized));
  REQUIRE(event_recv(pair[0],&got,&credentials)==-1);
  close(pair[1]);struct pollfd p={pair[0],POLLIN,0};
  REQUIRE(poll(&p,1,1000)>0&&(p.revents&POLLHUP));
  REQUIRE(event_recv(pair[0],&got,&credentials)==2);
  close(pair[0]);
  /* HUP cannot promote a zero-size packet into a valid EOF. */
  REQUIRE(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair)==0);
  REQUIRE(setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))==0);
  sent.role=1;REQUIRE(event_send(pair[1],&sent)==0);
  sent.role=2;REQUIRE(event_send(pair[1],&sent)==0);
  REQUIRE(send(pair[1],"",0,MSG_NOSIGNAL)==0);close(pair[1]);
  p.fd=pair[0];p.revents=0;
  REQUIRE(poll(&p,1,1000)>0&&(p.revents&POLLHUP));
  REQUIRE(event_recv(pair[0],&got,&credentials)==1&&got.role==1);
  REQUIRE(event_recv(pair[0],&got,&credentials)==1&&got.role==2);
  REQUIRE(event_recv(pair[0],&got,&credentials)==-1);
  REQUIRE(event_recv(pair[0],&got,&credentials)==2);close(pair[0]);
  puts("{\"status\":\"PASS_SOCKET_PARSER\",\"checks\":6,\"privileged\":false}");
  return 0;
}
