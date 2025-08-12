BUILD_DIR = build
TARGETs = include observe filter policy so tools kmodules demo
SUBTARGETs = $(foreach i,$(TARGETs),$(i)/%)
MAKE = make PROJ_ROOT=$(shell pwd)

.PHONY: all clean distclean pseudo $(TARGETs)
.SUFFIXES:

all: $(TARGETs)

demo: so
test: so
so: observe filter policy
observe filter policy: include

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
