# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)
TEST_SRC_C = $(wildcard *.c)
TEST_SRC_CPP = $(wildcard *.cpp)
TEST_OBJ = $(TEST_SRC_C:%.c=%.o) $(TEST_SRC_CPP:%.cpp=%.o)
TARGET = $(TEST_OBJ:%.o=$(BUILD_DIR)/%)
CXXFLAGS = -g -I$(PROJ_ROOT)/observe \
		   -I$(PROJ_ROOT)/include \
		   -I$(BUILD_DIR)

.PHONY: all clean

all: $(TARGET)

$(BUILD_DIR)/%: $(BUILD_DIR)/%.o | $(BUILD_DIR)
	g++ $(CXXFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	g++ $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR):
	@mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
