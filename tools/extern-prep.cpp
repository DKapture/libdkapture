// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

/**
 * @brief 将 BPF .o 文件中 extern map 声明预处理为定义
 *
 * bpftool gen skeleton / libbpf 不支持 extern SEC(".maps")，
 * 此工具先预处理再喂给 bpftool。
 *
 * extern map 名通过自定义 ELF section .extern_map_names 嵌入 .bpf.o，
 * 运行时由 bpf_linker_resolve_extern() 解析。
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "btf-preprocessor.h"

// 确保 PinRegistry 文件和锁文件存在
static void init_pin_registry_files()
{
	const char *files[] = {
		"/var/tmp/.dkapture-pin-registry",
		"/var/tmp/.dkapture-pin-registry.lock",
		nullptr
	};
	for (int i = 0; files[i]; i++) {
		int fd = open(files[i], O_CREAT | O_RDWR, 0644);
		if (fd >= 0) {
			fchmod(fd, 0644);
			close(fd);
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <input.bpf.o> <output.bpf.o>\n",
			argv[0]);
		return 1;
	}

	init_pin_registry_files();

	std::vector<ExternVarInfo> ext_vars;
	BtfPreprocessor preproc;
	int n = preproc.preprocess(argv[1], argv[2], &ext_vars);
	if (n < 0) {
		fprintf(stderr, "Error: %s\n", preproc.last_error());
		return 1;
	}

	if (n == 0) {
		fprintf(stdout, "No extern maps in '%s', copied to '%s'\n",
			argv[1], argv[2]);
	} else {
		fprintf(stdout, "Preprocessed %d extern map(s) in '%s' -> '%s'\n",
			n, argv[1], argv[2]);
	}
	return 0;
}
