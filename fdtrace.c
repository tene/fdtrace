#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "iotrace.h"

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

    iotrace(pid);
    return 0;
}
