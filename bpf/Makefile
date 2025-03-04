CLANG ?= clang
CFLAGS := -O2 -g -Wall -Wextra

LIBBPF_HEADERS := $(shell brew --prefix libbpf)/include
KERNEL_HEADERS := $(shell brew --prefix)/include

CC := gcc
CFLAGS := -O2 -g -Wall -Wextra -I./include

.PHONY: all clean test

all: test_conntrack

# Compile BPF program
conntrack.bpf.o: conntrack.bpf.c
	$(CLANG) -target bpf \
		-D__BPF_TRACING__ \
		-I$(LIBBPF_HEADERS) \
		-I$(KERNEL_HEADERS) \
		-I./include \
		$(CFLAGS) -c $< -o $@

# Compile test program
test_conntrack: tests/test_conntrack.c
	$(CC) $(CFLAGS) $< -o $@

test: all
	./test_conntrack

clean:
	rm -f *.o test_conntrack 