// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <set>

#include <unistd.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf-linker.h"
#include "pin-registry.h"

int bpf_linker_resolve_extern(struct bpf_object *obj)
{
	struct bpf_map *map;
	int resolved = 0;

	bpf_map__for_each(map, obj) {
		const char *name = bpf_map__name(map);
		if (!name) continue;
		std::string map_name(name);  // 拷贝，避免 libbpf 内部指针失效

		std::string pin_path = PinRegistry::lookup(map_name.c_str());
		if (pin_path.empty()) continue;  // 不在注册表中 → owned map

		int fd = bpf_obj_get(pin_path.c_str());
		if (fd < 0) {
			if (errno == ENOENT) {
				/* 陈旧条目：map 已不存在，清除并重新创建 */
				PinRegistry::remove_entry(map_name.c_str());
				continue;
			}
			fprintf(stderr, "[BpfLinker] bpf_obj_get(%s) failed: "
				"%s\n", pin_path.c_str(), strerror(errno));
			return -errno;
		}
		int err = bpf_map__reuse_fd(map, fd);
		close(fd);
		if (err) {
			fprintf(stderr, "[BpfLinker] bpf_map__reuse_fd(%s) "
				"failed: %d\n", map_name.c_str(), err);
			return err;
		}
		fprintf(stdout, "[BpfLinker] resolved extern map '%s' -> %s\n",
			map_name.c_str(), pin_path.c_str());
		resolved++;
	}
	if (resolved > 0)
		fprintf(stdout, "[BpfLinker] %d map(s) resolved\n", resolved);
	return 0;
}

int bpf_linker_pin_shared(struct bpf_map *map)
{
	if (!map) return -EINVAL;

	const char *name = bpf_map__name(map);
	if (!name || !name[0]) return -EINVAL;

	if (mkdir("/sys/fs/bpf/dkapture", 0755) != 0 && errno != EEXIST)
		return -errno;

	std::string pin_path =
		std::string("/sys/fs/bpf/dkapture/") + name;

	return PinRegistry::register_map(name, map, pin_path.c_str());
}