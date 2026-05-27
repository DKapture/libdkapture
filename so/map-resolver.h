// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef __MAP_RESOLVER_H__
#define __MAP_RESOLVER_H__

#include <string>
#include <bpf/libbpf.h>

/**
 * @brief 将本地 map fd 绑定到已 pin map
 *
 * 通过 bpf_obj_get() 打开已 pin map，再调用 bpf_map__reuse_fd()
 * 告知 libbpf 使用已有的内核 map 实例。
 * 必须在 bpf_object__load() 之前调用。
 */
class MapResolver {
public:
    /**
     * @brief 将单个 BPF map 绑定到已有的已 pin map
     * @param map      已打开 BPF 对象中的 bpf_map
     * @param pin_path 已 pin map 的完整路径
     * @return 成功返回 0，失败返回负 errno
     */
    int resolve(struct bpf_map *map, const char *pin_path);

    const char *last_error() const { return m_last_error.c_str(); }

private:
    std::string m_last_error;
};

#endif
