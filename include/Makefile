PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)

.PHONY: all clean distclean
.SECONDARY:
.SUFFIXES:

all: $(BUILD_DIR)/vmlinux.h $(BUILD_DIR)/kconfig.h

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/vmlinux.h: /sys/kernel/btf/vmlinux | $(BUILD_DIR)
	bpftool btf dump file $< format c > $@

$(BUILD_DIR)/kconfig.h: /proc/config.gz | $(BUILD_DIR)
	python3 $(PROJ_ROOT)/script/gen_kconfig.py $@

clean:

distclean: clean
	rm -f $(BUILD_DIR)/vmlinux.h $(BUILD_DIR)/kconfig.h

.PHONY: all clean distclean