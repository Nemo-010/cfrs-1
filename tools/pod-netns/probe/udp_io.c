#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
static void say(const char*f,...){va_list a;__builtin_va_start(a,f);vprintf(f,a);__builtin_va_end(a);putchar('\n');fflush(stdout);}
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  say("=== UDP: does a datagram leave this host? ===");
  struct sockaddr_in d; memset(&d,0,sizeof d);
  d.sin_family=AF_INET; d.sin_port=htons(53); d.sin_addr.s_addr=0x01010101;
  int fd=socket(AF_INET,SOCK_DGRAM,0);
  say("socket(AF_INET,SOCK_DGRAM) -> %d (%s)",fd,fd<0?strerror(errno):"ok");
  if(fd<0) return 1;
  errno=0; int r=connect(fd,(struct sockaddr*)&d,sizeof d);
  say("connect 1.1.1.1:53 -> %d (%s)",r,r==0?"ok":strerror(errno));
  const char*q="ab";
  errno=0; ssize_t n=send(fd,q,2,0);
  say("send -> %zd (%s)",n,n<0?strerror(errno):"ok");
  errno=0; n=sendto(fd,q,2,0,(struct sockaddr*)&d,sizeof d);
  say("sendto -> %zd (%s)",n,n<0?strerror(errno):"ok");
  close(fd);
  say("\n=== io_uring: available, or denied by the cage? ===");
#ifdef __NR_io_uring_setup
  struct { unsigned entries; unsigned pad[2]; } p={.entries=8};
  errno=0; long rc=syscall(__NR_io_uring_setup,&p);
  say("io_uring_setup(8) -> %ld %s",rc,rc<0?strerror(errno):"OK (AVAILABLE)");
  if(rc>=0) say("*** io_uring AVAILABLE: a filter omitting it can be bypassed ***");
#else
  say("__NR_io_uring_setup undefined");
#endif
  return 0;
}
