PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR := $(PROJ_ROOT)/build/$(MODULE)
BPF_DIR := $(PROJ_ROOT)/bpf/build/$(MODULE)
C_SRC = $(shell ls *.c 2>/dev/null)
CXX_SRC = $(shell ls *.cpp 2>/dev/null)
TARGETs = $(C_SRC:%.c=$(BUILD_DIR)/%) $(CXX_SRC:%.cpp=$(BUILD_DIR)/%)

LDFLAGS = -Wl,--no-as-needed -lbpf -lpthread
CFLAGS := -MMD -g -Wall -I$(PROJ_ROOT)/include -I$(BUILD_DIR)

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
.SECONDARY:
.SUFFIXES:

# Ensure object directory exists

all: $(TARGETs)

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/%: $(BUILD_DIR)/%.o $(BUILD_DIR)/log.o
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: %.cpp $(BUILD_DIR)/%.skel.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.c $(BUILD_DIR)/%.skel.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(PROJ_ROOT)/so/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BPF_DIR)/%.bpf.o | $(BUILD_DIR)
	bpftool gen skeleton $< > $@
	python3 $(PROJ_ROOT)/script/patch_skel.py --obj-dir $(BUILD_DIR) $@

clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(TARGETs)

distclean:
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)
	
