// A second network boundary beneath CDP interception. Chromium and every child
// inherit this filter; only Unix-domain sockets are available. The Go broker
// remains outside it. Never install a no-sandbox fallback here.
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__aarch64__)
#define ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define ARCH AUDIT_ARCH_X86_64
#else
#error Unsupported architecture
#endif
#define DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
int main(int argc, char **argv) {
 if(argc<2) return 120;
 int probe=argc==2 && !strcmp(argv[1],"--probe");
 pid_t parent=getppid();
 struct rlimit core={0,0}, cpu={18,18}, files={256,256};
 int setup_errno=0;const char *setup_stage="ok";
 // Synthetic probe mode diagnoses each prerequisite independently. Ordinary
 // browser launches still fail closed on the first missing protection.
#define SETUP(call,stage) do { if((call)) { if(!probe)return 120; if(!setup_errno){setup_errno=errno;setup_stage=stage;} } } while(0)
 SETUP(setrlimit(RLIMIT_CORE,&core),"core_limit");
 SETUP(setrlimit(RLIMIT_CPU,&cpu),"cpu_limit");
 SETUP(setrlimit(RLIMIT_NOFILE,&files),"file_limit");
 SETUP(prctl(PR_SET_PDEATHSIG,SIGKILL),"parent_death_signal");
 if(getppid()!=parent)return 120;
 int parent_errno=0;
 if(probe && prctl(PR_SET_DUMPABLE,0))parent_errno=errno;
 struct sock_filter filter[]={
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
  BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,ARCH,1,0),
  BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
  // Also rejects x32 syscall numbers on x86-64.
  BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000,0,1),
  BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
  DENY(SYS_ptrace), DENY(SYS_process_vm_readv), DENY(SYS_process_vm_writev),
  DENY(SYS_pidfd_getfd), DENY(SYS_bpf), DENY(SYS_io_uring_setup),
  DENY(SYS_io_uring_enter), DENY(SYS_io_uring_register),
  BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socket,1,0),
  BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socketpair,0,3),
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args)),
  BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_UNIX,1,0),
  BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
  BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
 };
 struct sock_fprog p={sizeof filter/sizeof filter[0],filter};
 int nonew_errno=0,seccomp_errno=0;
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))nonew_errno=errno;
 if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p))seccomp_errno=errno;
 if(!probe && (nonew_errno||seccomp_errno))return 120;
 if(probe) {
  int fd=socket(AF_INET,SOCK_STREAM,0), denied4=fd<0&&errno==EPERM;if(fd>=0)close(fd);
  fd=socket(AF_INET6,SOCK_STREAM,0);int denied6=fd<0&&errno==EPERM;if(fd>=0)close(fd);
  int user=unshare(CLONE_NEWUSER)==0, ns_errno=errno;
  int namespaces=user && unshare(CLONE_NEWNET|CLONE_NEWPID|CLONE_NEWNS)==0;
  if(user && !namespaces)ns_errno=errno;
  printf("{\"seccompInstalled\":%s,\"ipv4Denied\":%s,\"ipv6Denied\":%s,\"userNamespace\":%s,\"browserNamespaces\":%s,\"namespaceErrno\":%d,\"setupStage\":\"%s\",\"setupErrno\":%d,\"parentProtectionErrno\":%d,\"noNewPrivilegesErrno\":%d,\"seccompErrno\":%d}\n",seccomp_errno?"false":"true",denied4?"true":"false",denied6?"true":"false",user?"true":"false",namespaces?"true":"false",namespaces?0:ns_errno,setup_stage,setup_errno,parent_errno,nonew_errno,seccomp_errno);
  return 0;
 }
 execv(argv[1],argv+1);
 return 120;
}
