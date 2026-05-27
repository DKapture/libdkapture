// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>

#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <fstream>
#include <sstream>

#include "pin-registry.h"

// ─────────────────────────────────────────────────────────
int PinRegistry::lock_fd()
{
    int fd = open(LOCK_FILE, O_RDWR);
    if (fd < 0) return -errno;
    if (flock(fd, LOCK_EX) != 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}
// ─────────────────────────────────────────────────────────
void PinRegistry::unlock_fd(int fd)
{
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}
// ─────────────────────────────────────────────────────────
int PinRegistry::register_map(const char *name,
                               struct bpf_map *map,
                               const char *pin_path)
{
    if (!name || !map || !pin_path)
        return -EINVAL;

    // 校验注册表文件由 extern-prep 预创建
    if (access(REGISTRY_FILE, F_OK) != 0 || access(LOCK_FILE, F_OK) != 0) {
        fprintf(stderr, "[PinRegistry] registry file missing, run extern-prep first\n");
        return -ENOENT;
    }

    // pin map 到 bpffs（已存在则跳过，避免 libbpf 打印 EEXIST）
    int err;
    if (access(pin_path, F_OK) != 0) {
        err = bpf_map__pin(map, pin_path);
        if (err) return err;
    }


    int fd = lock_fd();
    if (fd < 0) return fd;

    auto entries = read_all();

    // 更新或追加
    bool found = false;
    for (auto &e : entries) {
        if (e.first == name) {
            e.second = pin_path;
            found = true;
            break;
        }
    }
    if (!found)
        entries.push_back({name, pin_path});

    err = write_all(entries);
    unlock_fd(fd);
    return err;
}
// ─────────────────────────────────────────────────────────
std::string PinRegistry::lookup(const char *name)
{
    if (!name) return "";

    int fd = lock_fd();
    if (fd < 0) return "";

    auto entries = read_all();
    unlock_fd(fd);

    for (const auto &e : entries) {
        if (e.first == name)
            return e.second;
    }
    return "";
}
// ─────────────────────────────────────────────────────────
int PinRegistry::remove_entry(const char *name)
{
    if (!name) return -EINVAL;

    int fd = lock_fd();
    if (fd < 0) return fd;

    auto entries = read_all();
    auto it = entries.begin();
    while (it != entries.end()) {
        if (it->first == name)
            it = entries.erase(it);
        else
            ++it;
    }

    int err = write_all(entries);
    unlock_fd(fd);
    return err;
}
// ─────────────────────────────────────────────────────────
std::vector<std::pair<std::string, std::string>> PinRegistry::list()
{
    int fd = lock_fd();
    if (fd < 0) return {};

    auto entries = read_all();
    unlock_fd(fd);
    return entries;
}
// ─────────────────────────────────────────────────────────
std::vector<std::pair<std::string, std::string>> PinRegistry::read_all()
{
    std::vector<std::pair<std::string, std::string>> entries;
    std::ifstream in(REGISTRY_FILE);
    if (!in) return entries;

    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string name, path;
        if (ss >> name >> path)
            entries.push_back({name, path});
    }
    return entries;
}
// ─────────────────────────────────────────────────────────
int PinRegistry::write_all(
    const std::vector<std::pair<std::string, std::string>> &entries)
{
    int fd = open(REGISTRY_FILE, O_WRONLY | O_TRUNC);
    if (fd < 0) return -errno;

    for (const auto &e : entries) {
        std::string line = e.first + " " + e.second + "\n";
        ssize_t n = write(fd, line.c_str(), line.size());
        if (n < 0) { int e = errno; close(fd); return -e; }
    }

    close(fd);
    return 0;
}
