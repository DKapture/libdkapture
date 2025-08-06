all: vmlinux.h kconfig.h

vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file $< format c > $@

kconfig.h: /proc/config.gz
	python3 ../script/gen_kconfig.py

clean include:
	rm -f vmlinux.h kconfig.h