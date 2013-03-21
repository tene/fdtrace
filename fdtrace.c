#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include "iotrace.h"

//TODO dynamic resize array
#define LOGBUFSIZE 512
static FILE *readlog[LOGBUFSIZE];
static FILE *writelog[LOGBUFSIZE];

void __init_logbuf(void) __attribute__((constructor));
void __init_logbuf(void) {
    for (size_t i = 0; i < LOGBUFSIZE; i++) {
        readlog[i] = NULL;
        writelog[i] = NULL;
    }
}

FILE *get_handle(pid_t pid, int fd, iotype_t type) {
    assert(fd < LOGBUFSIZE);
    if (type == READ || type == WRITE) {
        FILE **n = (type == READ) ? readlog : writelog;

        if (n[fd] == NULL) {
            size_t buflen = 512;
            char filename[buflen];
            snprintf(filename, buflen, "iolog.%d.%s.%d", fd, (type == READ) ? "read" : "write", (int)pid);
            n[fd] = fopen(filename, "w");
        }

        return n[fd];
    }
    return NULL;
}

void my_handler(pid_t pid, int fd, iotype_t type, size_t len, const char *buf, void *user_data) {
    FILE *log = get_handle(pid, fd, type);
    if (type == READ || type == WRITE) {
        printf("%s %zu bytes on fd %d\n", (type == READ) ? "read" : "wrote", len, fd);
        fwrite(buf, len, sizeof(char), log);
        fflush(log);
    }
}

int main(int argc, char **argv) {
    pid_t pid = 0;
    if (argc == 3 && strncmp(argv[1], "-p", 2) == 0) {
        char *endptr;
        pid = strtol(argv[2], &endptr, 10);
    } else {
        pid = fork();
        if (pid == 0) {
            execvp(argv[1], &argv[1]);
        }
    }

    register_iotrace_handler(my_handler, NULL);

    iotrace(pid);

    for (size_t i = 0; i < LOGBUFSIZE; i++) {
        if (readlog[i] != NULL) {
            fclose(readlog[i]);
            readlog[i] = NULL;
        }
        if (writelog[i] != NULL) {
            fclose(writelog[i]);
            writelog[i] = NULL;
        }
    }
    return 0;
}
