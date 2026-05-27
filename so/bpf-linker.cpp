// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <climits>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>

#include <fstream>
#include <sstream>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "bpf-linker.h"
#include "pin-registry.h"

BpfLinker::BpfLinker()
{
}

BpfLinker::~BpfLinker()
{
}

int BpfLinker::set_object(struct bpf_object *obj)
{
    if (!obj) {
        m_last_error = "null bpf_object";
        return -EINVAL;
    }
    m_obj = obj;
    return 0;
}

static std::string extract_prog_name(const char *file)
{
    if (!file) return "";
    const char *base = strrchr(file, '/');
    const char *name = base ? base + 1 : file;
    std::string s(name);
    auto pos = s.rfind('.');
    if (pos != std::string::npos) s.erase(pos);
    return s;
}

int BpfLinker::adopt_and_load(struct bpf_object *obj, const char *prog_name)
{
    int err = set_object(obj);
    if (err) return err;

    const char *registry_files[] = {
        "/var/tmp/.dkapture-extern-maps",
        "/var/tmp/.dkapture-extern-maps.lock",
        "/var/tmp/.dkapture-pin-registry",
        "/var/tmp/.dkapture-pin-registry.lock",
        nullptr
    };
    for (int i = 0; registry_files[i]; i++) {
        if (access(registry_files[i], F_OK) != 0) {
            fprintf(stderr, "[BpfLinker] %s missing, run extern-prep first\n",
                    registry_files[i]);
            return -ENOENT;
        }
    }

    std::string prog = extract_prog_name(prog_name);

    if (!prog.empty()) {
        const char *registry = "/var/tmp/.dkapture-extern-maps";
        const char *lock_file = "/var/tmp/.dkapture-extern-maps.lock";

        int fd = open(lock_file, O_RDWR);
        if (fd >= 0 && flock(fd, LOCK_SH) == 0) {
            std::ifstream in(registry);
            if (in) {
                std::string line;
                while (std::getline(in, line)) {
                    std::istringstream ss(line);
                    std::string file_name, extern_name;
                    if (ss >> file_name >> extern_name) {
                        if (file_name == prog) {
                            m_extern_names.push_back(extern_name);
                            fprintf(stdout, "[BpfLinker] extern map: %s (from %s)\n",
                                    extern_name.c_str(), file_name.c_str());
                        }
                    }
                }
            }
            flock(fd, LOCK_UN);
            close(fd);
        } else if (fd >= 0) {
            m_last_error = std::string("flock failed: ") + strerror(errno);
            close(fd);
            return -errno;
        } else {
            m_last_error = std::string("open lock failed: ") + strerror(errno);
            return -errno;
        }
    }

    err = resolve_all_maps();
    if (err) return err;

    return load();
}

int BpfLinker::resolve_all_maps()
{
    if (!m_obj) {
        m_last_error = "no bpf_object loaded";
        return -EINVAL;
    }

    fprintf(stdout, "[BpfLinker] Resolving maps via PinRegistry...\n");

    if (m_extern_names.empty()) {
        fprintf(stdout, "[BpfLinker] 0 map(s) linked via registry\n");
        return 0;
    }

    struct bpf_map *map;
    int matched = 0;

    bpf_map__for_each(map, m_obj) {
        const char *name = bpf_map__name(map);
        if (!name || name[0] == '\0') continue;

        bool is_extern = false;
        for (auto &n : m_extern_names)
            if (n == name) { is_extern = true; break; }
        if (!is_extern) continue;

        std::string pin_path = PinRegistry::lookup(name);
        if (pin_path.empty()) continue;

        fprintf(stdout, "  [link] %s -> %s\n", name, pin_path.c_str());

        int err = m_resolver.resolve(map, pin_path.c_str());
        if (err) {
            m_last_error = m_resolver.last_error();
            return err;
        }
        matched++;
    }

    fprintf(stdout, "[BpfLinker] %d map(s) linked via registry\n", matched);
    return 0;
}

static void fix_maps_datasec(struct bpf_object *obj)
{
    // 注意：bpf_object__btf 返回 const，btf__type_by_id 返回 const，
    // libbpf 未提供修改 datasec offset/size 的公开 API。
    //
    // 为什么需要修复：BtfPreprocessor 预处理时，追加到 .maps section 的
    // extern 变量按 struct_size（不足 16 对齐到 16）计算偏移，但 libbpf
    // 打开 skeleton 后期望所有 var_secinfo.offset 严格递增且无间隙。
    // 此处在 bpf_object__load 之前修正 offset，避免加载时校验失败。
    struct btf *btf = (struct btf *)bpf_object__btf(obj);
    if (!btf) return;

    int sec_id = btf__find_by_name_kind(btf, ".maps", BTF_KIND_DATASEC);
    if (sec_id < 0) return;

    struct btf_type *sec = (struct btf_type *)btf__type_by_id(btf, sec_id);
    struct btf_var_secinfo *inf = btf_var_secinfos(sec);
    int vlen = btf_vlen(sec);

    __u32 next_off = 0;
    for (int i = 0; i < vlen; i++) {
        if (inf[i].offset != next_off) {
            const struct btf_type *var_t = btf__type_by_id(btf, inf[i].type);
            const char *name = var_t ? btf__name_by_offset(btf, var_t->name_off) : "?";
            fprintf(stderr, "[fix] %s: offset %u -> %u\n", name, inf[i].offset, next_off);
            inf[i].offset = next_off;
        }
        __u32 sz = inf[i].size;
        if (sz < 16) sz = 16;
        next_off += sz;
    }
    sec->size = next_off;
}

int BpfLinker::load()
{
    if (!m_obj) {
        m_last_error = "no bpf_object loaded";
        return -EINVAL;
    }

    fix_maps_datasec(m_obj);

    int err = bpf_object__load(m_obj);
    if (err) {
        char err_buf[256] = {};
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        m_last_error = std::string("bpf_object__load failed: ") + err_buf;
    }
    return err;
}
