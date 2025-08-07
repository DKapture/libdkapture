
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
CFLAGS = -MMD -g -Wall -I$(PROJ_ROOT)/include
CXXFLAGS = $(CFLAGS)
CC = gcc
CXX = g++

.PHONY: all clean
.PRECIOUS: %.skel.h
# .SECONDARY:
.SUFFIXES:

all: $(TARGETs)

net-filter: net-filter.o
rm-forbid: rm-forbid.o
signal-filter: signal-filter.o
tc-port: tc-port.o 

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

%.bpf.o: %.bpf.c $(PROJ_ROOT)/include/vmlinux.h
	clang -D__$(BPF_TARGET_ARCH)__ $(CLANG_FLAGS) -target bpf -c $< -o $@

$(PROJ_ROOT)/include/vmlinux.h:
	make -C $(PROJ_ROOT)/include/

clean:
	rm -f $(PROJ_ROOT)/include/vmlinux.h *.skel.h *.o *.d $(TARGETs)

-include $(wildcard *.d)
	
