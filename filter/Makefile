PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)
BPF_SRC = $(shell ls *.bpf.c)
TARGETs = $(BPF_SRC:%.bpf.c=$(BUILD_DIR)/%)
BPF_TARGET_ARCH := $(shell uname -m)
ifeq ($(BPF_TARGET_ARCH), loongarch64)
	BPF_TARGET_ARCH := loongarch
endif

LDFLAGS = -Wl,--no-as-needed -lbpf -lpthread -luuid
CLANG_FLAGS = -g -MMD -Wall -O2 -I$(PROJ_ROOT)/include \
			-I/usr/include/$(shell uname -m)-linux-gnu/ \
			-I/lib/modules/$(shell uname -r)/build/include \
			-I$(PROJ_ROOT)/build/include
CFLAGS = -MMD -g -Wall -I$(PROJ_ROOT)/include \
			-I$(PROJ_ROOT)/build/include \
			-I$(BUILD_DIR)
CXXFLAGS = $(CFLAGS)
CC = gcc
CXX = g++

.PHONY: all clean distclean
.SECONDARY:
.SUFFIXES:

all: $(TARGETs)

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/%: $(BUILD_DIR)/%.o $(BUILD_DIR)/log.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: %.cpp $(BUILD_DIR)/%.skel.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.c $(BUILD_DIR)/%.skel.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o | $(BUILD_DIR)
	bpftool gen skeleton $< > $@

$(BUILD_DIR)/%.bpf.o: %.bpf.c $(PROJ_ROOT)/build/include/vmlinux.h $(PROJ_ROOT)/build/include/kconfig.h | $(BUILD_DIR)
	clang -D__$(BPF_TARGET_ARCH)__ $(CLANG_FLAGS) -target bpf -c $< -o $@

$(PROJ_ROOT)/build/include/vmlinux.h $(PROJ_ROOT)/build/include/kconfig.h:
	make -C $(PROJ_ROOT)/include/

$(BUILD_DIR)/log.o: $(PROJ_ROOT)/so/log.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(BUILD_DIR)/*.skel.h $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(TARGETs)

distclean:
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)
	
