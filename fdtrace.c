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
#include <stdbool.h>

typedef enum { READ, WRITE } iotype_t;

typedef void (*iotrace_handler)(pid_t pid, int fd, iotype_t type, size_t len, const char *buf, void *user_data);
struct iotrace_handler_record {
    iotrace_handler handler;
    void *user_data;
};

static size_t handler_count = 0;
static size_t handler_buf_size = 0;
struct iotrace_handler_record *handlers = NULL;

void register_iotrace_handler(iotrace_handler h, void *u) {
    if (handler_count + 1 >= handler_buf_size) {
        handler_buf_size = 5 + handler_buf_size * 2;
        handlers = realloc(handlers, sizeof(struct iotrace_handler_record) * handler_buf_size);
    }
    handlers[handler_count].handler = h;
    handlers[handler_count].user_data = u;
    handler_count++;
}

static void handle_data(pid_t pid, int fd, iotype_t type, size_t len, unsigned long int addr) {
    char buf[len];
    struct iovec local[1], remote[1];

    local[0].iov_base = buf;
    remote[0].iov_base = (void *)addr;
    local[0].iov_len = remote[0].iov_len = len;

    process_vm_readv(
            pid,
            local, 1,
            remote, 1,
            0);

    for (size_t i = 0; i < handler_count; i++) {
        handlers[i].handler(pid, fd, type, len, buf, handlers[i].user_data);
    }
}

static int handle_syscall(pid_t pid) {
    static int insyscall = 0;
    static int fd;
    static unsigned long int addr;
    static size_t len;

    struct user_regs_struct regs;

    long rv = ptrace(PTRACE_GETREGS, pid,
            NULL, &regs);
    if (0 != rv) {
        perror("Could not fetch registers: ");
        return -1;
    }

    if(insyscall == 0) { /* Syscall entry */
        insyscall = 1;
        if (regs.orig_rax == __NR_write) {
            fd = regs.rdi;
            addr = regs.rsi;
            len = regs.rdx;
            handle_data(pid, fd, WRITE, len, addr);
        } else if (regs.orig_rax == __NR_read) {
            fd = regs.rdi;
            addr = regs.rsi;
        }
    } else { /* Syscall exit */
        insyscall = 0;
        if (regs.orig_rax == __NR_read) {
            len = regs.rax;
            if (len > 0)
                handle_data(pid, fd, READ, len, addr);
        }
    }
    return 0;
}


int run_trace(const pid_t pid) {
    long rv = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (0 != rv) {
        perror("Could not attach to process: ");
        return 2;
    }

    int status;
    int signal = 0;

    waitpid(pid, &status, 0);
    if(WIFEXITED(status))
        return 0;

    rv = ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD);
    if (0 != rv) {
        perror("Could not set options: ");
        return 2;
    }

    while(1) {
        ptrace(PTRACE_SYSCALL, pid,
                NULL, signal);
        signal = 0;

        waitpid(pid, &status, 0);
        if(WIFEXITED(status))
            break;

        bool is_syscall = false;
        switch (WSTOPSIG(status)) {
            case SIGTRAP | 0x80:
                is_syscall = true;
                break;
            default:
                signal = WSTOPSIG(status);
        }

        if (is_syscall) {
            handle_syscall(pid);
        }
    }
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s PID\n", name);
}

void my_handler(pid_t pid, int fd, iotype_t type, size_t len, const char *buf, void *user_data) {
    printf("%s %zu bytes on fd %d\n", (type == READ) ? "read" : "wrote", len, fd);
}

int main(int argc, char **argv) {
    if (2 != argc) {
        usage(argv[0]);
        return 1;
    }
    const char *pidstr = argv[1];
    const pid_t pid = atoi(pidstr);

    register_iotrace_handler(my_handler, NULL);

    run_trace(pid);
    return 0;
}
