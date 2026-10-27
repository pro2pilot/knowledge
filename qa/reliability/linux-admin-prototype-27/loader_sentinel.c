/* QA-only UNTRUSTED loader input, never installed or mapped by authority.
 * The exit sentinel detects execution even if authority denies marker writes. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <link.h>
#include <stdlib.h>
#include <unistd.h>
unsigned int la_version(unsigned int version) { (void)version; return LAV_CURRENT; }
__attribute__((constructor)) static void loaded(void) {
  const char *file=getenv("KNOWLEDGE_QA_LOADER_SENTINEL");
  if(file) {
    int fd=open(file,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd>=0) { const char message[]="UNTRUSTED_CONSTRUCTOR_EXECUTED\n";
      ssize_t ignored=write(fd,message,sizeof(message)-1);(void)ignored;close(fd); }
  }
  _exit(93);
}
