// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef __PIN_REGISTRY_H__
#define __PIN_REGISTRY_H__

#include <string>
#include <vector>
#include <utility>

#include <bpf/libbpf.h>

/**
 * @brief 共享 pin map 注册表
 *
 * pin map 的工具调用 register_map() 注册 pin 路径，
 * BpfLinker 调用 lookup() 精确查找，无需全盘扫描。
 *
 * 注册表存储于 /var/run/dkapture/pin-registry（tmpfs，与 bpffs 同寿命）。
 * flock 文件锁做并发保护。
 */
class PinRegistry {
public:
    static constexpr const char *REGISTRY_FILE = "/var/tmp/.dkapture-pin-registry";
    static constexpr const char *LOCK_FILE     = "/var/tmp/.dkapture-pin-registry.lock";

    /// 封装 bpf_map__pin + 注册表写入，一行完成
    static int register_map(const char *name,
                             struct bpf_map *map,
                             const char *pin_path);

    /// 查询 pin 路径，未找到返回空串
    static std::string lookup(const char *name);

    /// 从注册表中删除一条 map 记录（不 unpin 内核 map）
    static int remove_entry(const char *name);

    /// 列出所有已注册项
    static std::vector<std::pair<std::string, std::string>> list();

private:
    static int lock_fd();
    static void unlock_fd(int fd);
    static std::vector<std::pair<std::string, std::string>> read_all();
    static int write_all(const std::vector<std::pair<std::string, std::string>> &entries);
};

#endif
