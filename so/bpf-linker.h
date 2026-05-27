// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef __BPF_LINKER_H__
#define __BPF_LINKER_H__

#include <string>
#include <vector>

#include <bpf/libbpf.h>

#include "map-resolver.h"

/**
 * @brief BPF Map 链接时共享优化器
 *
 * 接管外部已打开的 bpf_object，通过 PinRegistry 查找共享 map，
 * 使用 bpf_map__reuse_fd 绑定共享实例，然后加载到内核。
 *
 * extern map 名由 extern-prep 在构建时写入 /tmp/.dkapture-extern-maps-<prog>，
 * adopt_and_load() 直接读取，确保只共享真正的 extern map。
 */
class BpfLinker {
public:
    BpfLinker();
    ~BpfLinker();

    int set_object(struct bpf_object *obj);

    int adopt_and_load(struct bpf_object *obj, const char *prog_name);

    int resolve_all_maps();

    int load();

private:
    struct bpf_object *m_obj = nullptr;

    std::string m_last_error;
    std::vector<std::string> m_extern_names;

    MapResolver m_resolver;
};

#endif

// __FILE__ 在调用方展开，得到调用方的文件路径
#define DK_LINK_LOAD(linker, obj) (linker).adopt_and_load((obj), __FILE__)
