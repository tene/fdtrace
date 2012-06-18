CFLAGS := -Wall -Werror -g -ggdb -fvisibility=hidden -std=c99
PROGS := fdtrace

all: $(PROGS)

fdtrace: fdtrace.c Makefile
	gcc $(CFLAGS) -o fdtrace fdtrace.c
