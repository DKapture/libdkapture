# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

BUILD_DIR = build
TARGETs = include tools observe filter policy
SUBTARGETs = $(foreach i,$(TARGETs),$(i)/%)
MAKE = make PROJ_ROOT=$(shell pwd)

.PHONY: all clean distclean pseudo $(TARGETs)
.SUFFIXES:

all: $(TARGETs)

observe filter policy: include tools

$(TARGETs):
	$(MAKE) -C $@

$(SUBTARGETs): pseudo
	$(MAKE)  $* -C $(shell dirname $@)

pseudo:

clean:
	@for i in $(TARGETs); do $(MAKE) -C $$i clean; done

distclean:
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
	#	例如 make observe
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
