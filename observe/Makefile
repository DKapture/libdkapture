
BPF_SRC = $(shell ls *.bpf.c)
TARGETs = $(BPF_SRC:%.bpf.c=%)
PROJ_ROOT ?= ..
BPF_TARGET_ARCH := $(shell uname -m)
ifeq ($(BPF_TARGET_ARCH), loongarch64)
	BPF_TARGET_ARCH := loongarch
endif

LDFLAGS = -Wl,--no-as-needed -lbpf -lpthread -luuid
CLANG_FLAGS = -g -MMD -Wall -O2 -I$(PROJ_ROOT)/include \
			-I/usr/include/$(shell uname -m)-linux-gnu/ \
			-I/lib/modules/$(shell uname -r)/build/include
CFLAGS := -MMD -g -Wall -I$(PROJ_ROOT)/include
ifneq ($(SHARED_LIB), )
	CFLAGS += -fPIC 
	CFLAGS += -DBUILTIN
endif
ifneq ($(GTEST), )
	CFLAGS += -DBUILTIN
endif
CXXFLAGS = $(CFLAGS)
CC = gcc
CXX = g++

.PHONY: all clean
# 注明不要删除的中间文件
.PRECIOUS: %.skel.h
# .SECONDARY:
.SUFFIXES:

all: $(TARGETs)

arp-observe: arp-observe.o
bio-stat: bio-stat.o
file-occupation: file-occupation.o
hrtimer: hrtimer.o
lscgroup: lscgroup.o
lsock: lsock.o
net-traffic: net-traffic.o 
peek-fd: peek-fd.o 
proc-info: proc-info.o
ps: ps.o
run-queue: run-queue.o
spinlock_ob: spinlock_ob.o
switch_count: switch_count.o
syscall-stat: syscall-stat.o
trace-exec: trace-exec.o
trace-file: trace-file.o
trace-signal: trace-signal.o
urblat: urblat.o
usb_ob: usb_ob.o
wakeup_count: wakeup_count.o
kmemleak: kmemleak.o
mountsnoop: mountsnoop.o
irqsnoop: irqsnoop.o
ext4snoop: ext4snoop.o
pagefault: pagefault.o
xhci-snoop: xhci-snoop.o
btrfs-snoop: btrfs-snoop.o
rcu-insight: rcu-insight.o
tcp-insight: tcp-insight.o
net-snoop: net-snoop.o
sched-snoop: sched-snoop.o
workqueue-snoop: workqueue-snoop.o
graphics-snoop: graphics-snoop.o
thermal-snoop: thermal-snoop.o
power-snoop: power-snoop.o

$(TARGETs): log.o
	$(CXX) $(LDFLAGS) $^ -o $@

%.o: %.cpp %.skel.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c %.skel.h
	$(CC) $(CFLAGS) -c $< -o $@

%.o: $(PROJ_ROOT)/so/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

%.bpf.o: %.bpf.c $(PROJ_ROOT)/include/vmlinux.h $(PROJ_ROOT)/include/kconfig.h
	clang -D__$(BPF_TARGET_ARCH)__ $(CLANG_FLAGS) -target bpf -c $< -o $@

$(PROJ_ROOT)/include/vmlinux.h:
	make -C $(PROJ_ROOT)/include/ vmlinux.h

$(PROJ_ROOT)/include/kconfig.h:
	make -C $(PROJ_ROOT)/include/ kconfig.h

clean:
	rm -f $(PROJ_ROOT)/include/vmlinux.h *.skel.h *.o *.d $(TARGETs)

-include $(wildcard *.d)
	
