// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef __BPF_LINKER_H__
#define __BPF_LINKER_H__

#include <bpf/libbpf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 在 bpf_object__load 之前，解析 extern map
 *
 * 遍历所有 map，检查 PinRegistry：如果 map 名已在注册表中，
 * 则调用 bpf_map__reuse_fd 绑定共享实例。
 *
 * @param obj  已 open 但未 load 的 bpf_object
 * @return 成功返回 0，失败返回负 errno
 */
int bpf_linker_resolve_extern(struct bpf_object *obj);

/**
 * @brief 封装 bpf_map__pin + PinRegistry::register_map，一行完成共享
 *
 * @param map      要共享的 BPF map
 * @param pin_path 完整的 bpffs pin 路径
 * @return 成功返回 0，失败返回负 errno
 */
int bpf_linker_pin_shared(struct bpf_map *map);

#ifdef __cplusplus
}
#endif

#endif
