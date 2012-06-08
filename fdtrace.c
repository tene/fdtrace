#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/uio.h>

void usage(const char *name) {
    fprintf(stderr, "Usage: %s PID FD\n", name);
}

/* Need to do this since process_vm_readv() is not yet available in libc.
 */
#if !defined(__NR_process_vm_readv)
# if defined(I386)
#  define __NR_process_vm_readv  347
# elif defined(X86_64)
#  define __NR_process_vm_readv  310
# elif defined(POWERPC)
#  define __NR_process_vm_readv  351
# endif
#endif

#if defined(__NR_process_vm_readv)
static ssize_t process_vm_readv(pid_t pid,
                const struct iovec *lvec,
                unsigned long liovcnt,
                const struct iovec *rvec,
                unsigned long riovcnt,
                unsigned long flags)
{
       return syscall(__NR_process_vm_readv, (long)pid, lvec, liovcnt, rvec, riovcnt, flags);
}
#else
# define process_vm_readv(...) (errno = ENOSYS, -1)
#endif
/* end of hack */

void dump_data(pid_t pid, unsigned long int addr, unsigned long int len) {
    char buf[len];
    struct iovec local[1], remote[1];
    //int rv;

    local[0].iov_base = buf;
    remote[0].iov_base = (void *)addr;
    local[0].iov_len = remote[0].iov_len = len;

    //rv =
    process_vm_readv(
            pid,
            local, 1,
            remote, 1,
            0);
    printf("%.*s", (int)len, buf);
}

int main(int argc, char **argv) {
    if (3 != argc) {
        usage(argv[0]);
        return 1;
    }
    const char *pidstr = argv[1];
    const char *fdstr  = argv[2];
    const pid_t pid = atoi(pidstr);
    const int fd  = atoi(fdstr);
    //printf("pid = %d\nfd = %d\n", pid, fd);
    long rv = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (0 != rv) {
        fprintf(stderr, "Could not attach to pid %d\n", pid);
        return 2;
    }

    //long params[3];
    int insyscall = 0;
    struct user_regs_struct regs;
    int status;

    while(1) {
        waitpid(pid, &status, 0);
        if(WIFEXITED(status))
            break;
        ptrace(PTRACE_GETREGS, pid,
                NULL, &regs);
        if(regs.orig_rax == __NR_write) {
            if(insyscall == 0) {
                /* Syscall entry */
                insyscall = 1;
                if (fd != regs.rdi)
                    continue;
                //printf("Write %lu bytes\n", regs.rdx);
                dump_data(pid, regs.rsi, regs.rdx);
            }
            else { /* Syscall exit */
                /* printf("Write returned "
                        "with %ld\n", regs.rax);*/
                insyscall = 0;
            }
        }
        ptrace(PTRACE_SYSCALL, pid,
                NULL, NULL);
    }
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
