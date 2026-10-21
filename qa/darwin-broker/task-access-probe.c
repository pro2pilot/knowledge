/* Audit-only readonly Mach permission probe. Targets are this program's own
 * root parent and original-UID sentinel. Never reads/modifies target tasks. */
#define _DARWIN_C_SOURCE
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <sandbox.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

static void facts(const char *stage,pid_t root,pid_t original) {
  mach_port_t access=MACH_PORT_NULL,root_task=MACH_PORT_NULL,original_task=MACH_PORT_NULL;
  kern_return_t access_rc=task_get_special_port(mach_task_self(),TASK_ACCESS_PORT,&access);
  kern_return_t root_rc=task_for_pid(mach_task_self(),root,&root_task);
  kern_return_t original_rc=task_for_pid(mach_task_self(),original,&original_task);
  printf("{\"stage\":\"%s\",\"ruid\":%u,\"euid\":%u,\"access_rc\":%d,\"access_nonnull\":%s,\"root_task_rc\":%d,\"root_task_nonnull\":%s,\"original_task_rc\":%d,\"original_task_nonnull\":%s}\n",
         stage,getuid(),geteuid(),access_rc,MACH_PORT_VALID(access)?"true":"false",
         root_rc,MACH_PORT_VALID(root_task)?"true":"false",original_rc,MACH_PORT_VALID(original_task)?"true":"false");
  if(MACH_PORT_VALID(access))mach_port_deallocate(mach_task_self(),access);
  if(MACH_PORT_VALID(root_task))mach_port_deallocate(mach_task_self(),root_task);
  if(MACH_PORT_VALID(original_task))mach_port_deallocate(mach_task_self(),original_task);
}
int main(int argc,char **argv) {
  setvbuf(stdout,NULL,_IONBF,0);alarm(30);
  if(argc==4&&!strcmp(argv[1],"--leaf")){
    facts("private_post_exec",(pid_t)strtol(argv[2],NULL,10),(pid_t)strtol(argv[3],NULL,10));return 0;
  }
  if(argc!=4||getuid()!=0)return 64;
  uid_t original=(uid_t)strtoul(argv[1],NULL,10),private_uid=(uid_t)strtoul(argv[2],NULL,10);
  if(original<500||original>=1000000000||private_uid<1000000000||private_uid>=1900000000)return 64;
  int pipefd[2],ready[2];if(pipe(pipefd)||pipe(ready))return 71;
  pid_t root=getpid(),sentinel=fork();if(sentinel<0)return 71;
  if(!sentinel){close(pipefd[1]);close(ready[0]);gid_t g=original;
    if(setgroups(1,&g)||setgid(g)||setuid(original))_exit(120);
    char ack='R';if(write(ready[1],&ack,1)!=1)_exit(120);close(ready[1]);
    char c;while(read(pipefd[0],&c,1)<0&&errno==EINTR){};_exit(0);
  }
  close(pipefd[0]);close(ready[1]);char ack=0;
  if(read(ready[0],&ack,1)!=1||ack!='R'){close(ready[0]);close(pipefd[1]);waitpid(sentinel,NULL,0);return 71;}close(ready[0]);
  pid_t child=fork();
  if(child<0){close(pipefd[1]);waitpid(sentinel,NULL,0);return 71;}
  if(!child){close(pipefd[1]);alarm(8);gid_t g=private_uid;
    if(setgroups(1,&g)||setgid(g)||setuid(private_uid))_exit(120);
    /* Release acquired references before the sandbox. Only the inherited slot
     * remains; subsequent observations actually attempt reacquisition. */
    mach_port_t access=MACH_PORT_NULL;
    if(task_get_special_port(mach_task_self(),TASK_ACCESS_PORT,&access)==KERN_SUCCESS&&MACH_PORT_VALID(access))
      mach_port_deallocate(mach_task_self(),access);
    char *error=NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if(sandbox_init(argv[3],0,&error)){if(error)sandbox_free_error(error);_exit(121);}
#pragma clang diagnostic pop
    facts("private_post_sandbox",root,sentinel);
    char root_text[32],original_text[32];snprintf(root_text,sizeof(root_text),"%d",root);snprintf(original_text,sizeof(original_text),"%d",sentinel);
    execl(argv[0],argv[0],"--leaf",root_text,original_text,(char*)NULL);_exit(122);
  }
  int child_status=0,sentinel_status=0;
  while(waitpid(child,&child_status,0)<0&&errno==EINTR){}
  close(pipefd[1]);while(waitpid(sentinel,&sentinel_status,0)<0&&errno==EINTR){}
  printf("{\"stage\":\"parent_reaped\",\"child_wait_status\":%d,\"sentinel_wait_status\":%d,\"backend_certified\":false}\n",child_status,sentinel_status);
  return WIFEXITED(child_status)&&WEXITSTATUS(child_status)==0&&WIFEXITED(sentinel_status)&&WEXITSTATUS(sentinel_status)==0?0:1;
}
