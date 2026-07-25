APP = openlat

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean verify-bpf

all: $(APP)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(APP).bpf.o: $(APP).bpf.c $(APP).h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(APP).o: $(APP).c $(APP).skel.h $(APP).h
	$(CLANG) $(CFLAGS) -c $< -o $@

$(APP): $(APP).o
	$(CLANG) $(CFLAGS) $< -lbpf -lelf -lz -o $@

clean:
	rm -f $(APP) $(APP).o $(APP).bpf.o $(APP).skel.h vmlinux.h

verify-bpf: vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -c $(APP).bpf.c -o /tmp/temp.o
	$(BPFTOOL) prog load /tmp/temp.o /sys/fs/bpf/$(APP)
	rm -f /sys/fs/bpf/$(APP) /tmp/temp.o
