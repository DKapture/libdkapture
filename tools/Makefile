# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)

.PHONY: all clean extern-prep

all: $(BUILD_DIR)/extern-prep

$(BUILD_DIR)/extern-prep: extern-prep.cpp btf-preprocessor.cpp btf-preprocessor.h | $(BUILD_DIR)
	$(CXX) -I$(CURDIR) -o $@ extern-prep.cpp btf-preprocessor.cpp -lelf -lz -lbpf -lpthread

extern-prep: $(BUILD_DIR)/extern-prep

$(BUILD_DIR):
	@mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
