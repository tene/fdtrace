#include <sys/types.h>

typedef enum { READ, WRITE } iotype_t;

typedef void (*iotrace_handler)(pid_t pid, int fd, iotype_t type, size_t len, const char *buf, void *user_data);

struct iotrace_handler_record {
    iotrace_handler handler;
    void *user_data;
};

void register_iotrace_handler(iotrace_handler h, void *u);
int iotrace(const pid_t pid);
