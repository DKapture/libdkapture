# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

BUILD_DIR = build
TARGETs = bpf observe filter so tools demo
BPF_TARGET_ARCH := $(shell uname -m)
ifeq ($(BPF_TARGET_ARCH), loongarch64)
	BPF_TARGET_ARCH := loongarch
endif
ifneq ($(BPF_TARGET_ARCH), loongarch)
	TARGETs += policy
endif
SUBTARGETs = $(foreach i,$(TARGETs),$(i)/%)
MAKE = make PROJ_ROOT=$(shell pwd)

.PHONY: all clean distclean pseudo $(TARGETs)
.SUFFIXES:

USE_SUBMODULE ?= 1

all: $(TARGETs)

demo test: so
bpf: $(if $(filter 1,$(USE_SUBMODULE)),bpf.gitsubmodule)
observe filter policy so: bpf

$(TARGETs):
	$(MAKE) -C $@

$(SUBTARGETs): pseudo
	$(MAKE)  $* -C $(shell dirname $@)

test: pseudo
	# 如果网络有问题，请参考.gitmodules文件，手动拉取子仓库放到对应目录 
	git submodule update --init --depth 1 googletest
	$(MAKE) -C $@

pseudo:

%.gitsubmodule:
	git submodule update --init $*

clean:
	@for i in $(TARGETs); do $(MAKE) -C $$i clean; done

distclean:
	@for i in $(TARGETs); do $(MAKE) -C $$i distclean; done
	rm -rf $(BUILD_DIR)

help:
	# 编译完整项目:
	# 	make 或者 make all
	#
	# 清理完整项目：
	#	make clean
	#
	# 编译指定子模块：
	#	make dir
	#	例如 make test 或 make observe
	# 
	# 编译模块的指定目标:
	# 	make dir/target 
	#	例如 make observe/bio-stat
	#		make observe/clean
	#
	# 清理指定子模块：
	# 	make dir/clean
	#	或 
	#	make clean -C dir
	#	例如 make observe/clean
	# 
	# 编译测试用例并运行
	#	make test
	#	或者
	#	make -C test
