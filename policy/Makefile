# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1-only

PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)
C_SRC = $(shell ls *.c 2>/dev/null)
CXX_SRC = $(shell ls *.cpp 2>/dev/null)
TARGETs = $(C_SRC:%.c=$(BUILD_DIR)/%) $(CXX_SRC:%.cpp=$(BUILD_DIR)/%)

LDFLAGS = -Wl,--no-as-needed -lbpf -lpthread
CFLAGS := -Wall -I$(PROJ_ROOT)/include \
			-I$(PROJ_ROOT)/build/include \
			-I$(PROJ_ROOT)/bpf/export \
			-I$(BUILD_DIR)
ifeq ($(Release),1)
	CFLAGS := -DNDEBUG -O2 $(CFLAGS)
else
	CFLAGS := -MMD -g -Og $(CFLAGS)
endif
BPF_DIR := $(PROJ_ROOT)/bpf/build/$(MODULE)
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

$(BUILD_DIR)/%.o: $(PROJ_ROOT)/so/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BPF_DIR)/%.bpf.o | $(BUILD_DIR)
	bpftool gen skeleton $< > $@
	python3 $(PROJ_ROOT)/script/patch_skel.py --obj-dir $(BPF_DIR) $@

clean:
	rm -f $(BUILD_DIR)/*.skel.h $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(TARGETs)

distclean:
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)
	
