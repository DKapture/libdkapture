// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

/**
 * @brief 将 BPF .o 文件中 extern map 声明预处理为定义
 *
 * bpftool gen skeleton / libbpf 不支持 extern SEC(".maps")，
 * 此工具先预处理再喂给 bpftool。
 *
 * 同时将检测到的 extern map 写入 /var/tmp/.dkapture-extern-maps，
 * 格式：程序名 extern_map名（每行一条）。
 * 供运行时 BpfLinker 读取，精确识别哪些 map 需要共享。
 */

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <fstream>

#include "btf-preprocessor.h"

static std::string extract_stem(const char *path)
{
    const char *last = strrchr(path, '/');
    const char *base = last ? last + 1 : path;
    const char *dot1 = strstr(base, ".bpf.o");
    std::string stem;
    if (dot1)
        stem.assign(base, dot1 - base);
    else
        stem = base;
    return stem;
}

// 确保注册表和锁文件存在
static void init_registry_files()
{
    const char *files[] = {
        "/var/tmp/.dkapture-extern-maps",
        "/var/tmp/.dkapture-extern-maps.lock",
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
        fprintf(stderr, "Usage: %s <input.bpf.o> <output.bpf.o>\n", argv[0]);
        return 1;
    }

    init_registry_files();

    std::vector<ExternVarInfo> ext_vars;
    BtfPreprocessor preproc;
    int n = preproc.preprocess(argv[1], argv[2], &ext_vars);
    if (n < 0) {
        fprintf(stderr, "Error: %s\n", preproc.last_error());
        return 1;
    }

    if (n == 0) {
        fprintf(stdout, "No extern maps in '%s', copied to '%s'\n", argv[1], argv[2]);
    } else {
        fprintf(stdout, "Preprocessed %d extern map(s) in '%s' -> '%s'\n",
                n, argv[1], argv[2]);

        // 写入 /var/tmp/.dkapture-extern-maps（精确去重：bpfname + mapname 同时重名才跳过）
        const char *registry = "/var/tmp/.dkapture-extern-maps";
        const char *lock_file = "/var/tmp/.dkapture-extern-maps.lock";
        std::string stem = extract_stem(argv[1]);

        int fd = open(lock_file, O_CREAT | O_RDWR, 0666);
        if (fd < 0 || flock(fd, LOCK_EX) != 0) {
            int e = errno;
            if (fd >= 0) close(fd);
            fprintf(stderr, "  [registry] lock failed: %s\n", strerror(e));
            return 1;
        }

        // 读取已有条目
        std::vector<std::string> lines;
        std::ifstream in(registry);
        if (in) {
            std::string line;
            while (std::getline(in, line))
                lines.push_back(line);
        }

        // 逐条检查，只有 bpfname 和 mapname 同时重名才跳过
        int added = 0;
        for (auto &v : ext_vars) {
            std::string entry = stem + " " + v.name;
            bool exists = false;
            for (auto &l : lines) {
                if (l == entry) { exists = true; break; }
            }
            if (!exists) {
                lines.push_back(entry);
                added++;
            }
        }

        // 写回
        std::ofstream out(registry);
        if (out) {
            for (auto &l : lines)
                out << l << "\n";
            fprintf(stdout, "  [registry] %s: added %d, total %zu entries\n",
                    stem.c_str(), added, lines.size());
        }

        flock(fd, LOCK_UN);
        close(fd);
    }
    return 0;
}
