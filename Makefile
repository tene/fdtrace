CFLAGS := -Wall -Werror -g -ggdb -fvisibility=hidden -std=c99
LIBS := libiotrace.so iotrace.o
PROGS := fdtrace

all: $(PROGS) $(LIBS)

iotrace.o: iotrace.c iotrace.h Makefile
	gcc -c $(CFLAGS) -o iotrace.o iotrace.c

libiotrace.so: iotrace.c iotrace.h Makefile
	gcc -shared -fPIC $(CFLAGS) -o libiotrace.so iotrace.c

fdtrace: fdtrace.c Makefile iotrace.o
	gcc $(CFLAGS) -o fdtrace fdtrace.c iotrace.o
