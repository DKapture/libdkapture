// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: LGPL-2.1

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pwd.h>

struct ns_key_t {
    uint32_t type;
    uint64_t inum;
};

struct ns_owner_t {
    uint32_t pid;
    uint32_t uid;
};

// return a human display name for the namespace type
static const char* ns_display_name(uint32_t t)
{
    switch (t) {
    case 1: return "user";
    case 2: return "ipc";
    case 3: return "mnt";
    case 4: return "pid";
    case 5: return "net";
    case 6: return "uts";
    case 7: return "time";
    case 8: return "cgroup";
    case 9: return "pid_for_children";
    default: return "unknown";
    }
}

// return the filename used under /proc/[pid]/ns/ for this namespace
// some internal kernel variants (eg pid_for_children) map to the same
// proc name as pid
static const char* ns_proc_name(uint32_t t)
{
    switch (t) {
    case 1: return "user";
    case 2: return "ipc";
    case 3: return "mnt";
    case 4: return "pid";
    case 5: return "net";
    case 6: return "uts";
    case 7: return "time";
    case 8: return "cgroup";
    case 9: return "pid"; // pid_for_children appears as "pid" in /proc
    default: return "unknown";
    }
}

// try to find a pid that owns the namespace in /proc
static int find_owner_pid_for_ns(uint64_t inum, const char *nstype, time_t *ctime_out)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *de;
    char path[256];
    struct stat st;
    int found = -1;
    while ((de = readdir(d)) != NULL) {
        // some filesystems return DT_UNKNOWN; don't rely on d_type
        // skip non-numeric
        char *endptr;
        long pid = strtol(de->d_name, &endptr, 10);
        if (*endptr != '\0')
            continue;
        snprintf(path, sizeof(path), "/proc/%s/ns/%s", de->d_name, nstype);
        if (stat(path, &st) == 0) {
            if ((uint64_t)st.st_ino == inum) {
                found = (int)pid;
                if (ctime_out) *ctime_out = st.st_ctime;
                break;
            }
        }
    }
    closedir(d);
    return found;
}

static int bump_memlock_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (bump_memlock_rlimit())
        return 1;

    libbpf_set_print(NULL);

    const char *candidates[] = {
        "bpf/observe/lsns.bpf.o",
        "bpf/build/observe/lsns.bpf.o",
        "/usr/lib/dkapture/lsns.bpf.o",
        NULL
    };

    struct bpf_object *obj = nullptr;
    int err = 0;
    for (const char **p = candidates; *p; ++p) {
        obj = bpf_object__open_file(*p, NULL);
        if (obj) {
            if ((err = bpf_object__load(obj)) == 0) {
                std::cerr << "loaded BPF object: " << *p << "\n";
                break;
            }
            bpf_object__close(obj);
            obj = nullptr;
        }
    }
    if (!obj) {
        std::cerr << "failed to open/load BPF object. build the .bpf.o first.\n";
        std::cerr << "Try: make -C bpf/observe && make -C observe" << std::endl;
        return 1;
    }

    // find program by name (function name in bpf source)
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "iter_tasks");
    if (!prog) {
        std::cerr << "failed to find iter_tasks program in object\n";
        bpf_object__close(obj);
        return 1;
    }

    /* new libbpf API requires an attach opts pointer; pass NULL when none needed */
    struct bpf_link *link = bpf_program__attach_iter(prog, NULL);
    if (!link) {
        std::cerr << "failed to attach iterator program\n";
        bpf_object__close(obj);
        return 1;
    }

    int iter_fd = bpf_iter_create(bpf_link__fd(link));
    if (iter_fd < 0) {
        std::cerr << "bpf_iter_create failed: " << strerror(errno) << "\n";
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    // consume iterator until it finishes
    char buf[4096];
    while (read(iter_fd, buf, sizeof(buf)) > 0) {
        // drain
    }
    close(iter_fd);

    // fetch map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "ns_map");
    if (!map) {
        std::cerr << "failed to find ns_map in object\n";
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    // iterate keys
    ns_key_t prev = {};
    ns_key_t next = {};
    bool first = true;

    // Collect all entries, then sort by inum and print with NS first
    struct Entry {
        uint32_t type;
        uint64_t inum;
        uint32_t pid;
        uint32_t uid;
    };
    std::vector<Entry> entries;

    while (true) {
        int ret;
        if (first) {
            ret = bpf_map_get_next_key(map_fd, NULL, &next);
            first = false;
        } else {
            ret = bpf_map_get_next_key(map_fd, &prev, &next);
        }
        if (ret != 0)
            break;

        ns_owner_t owner = {0,0};
        if (bpf_map_lookup_elem(map_fd, &next, &owner) == 0) {
            entries.push_back(Entry{next.type, next.inum, owner.pid, owner.uid});
        } else {
            entries.push_back(Entry{next.type, next.inum, 0, 0});
        }

        prev = next;
    }

    // sort by inum ascending
    std::sort(entries.begin(), entries.end(), [](const Entry &a, const Entry &b){ return a.inum < b.inum; });

    // print header: NS<system-reminder> first, then TYPE, USER, PID, PATH
    std::cout << std::left << std::setw(20) << "NS" << std::setw(16) << "TYPE" << std::setw(12) << "USER" << std::setw(8) << "PID" << "PATH" << "\n";

    for (auto &e : entries) {
        const char *display = ns_display_name(e.type);
        const char *procname = ns_proc_name(e.type);
        char pathbuf[256] = "-";
        if (e.pid)
            snprintf(pathbuf, sizeof(pathbuf), "/proc/%u/ns/%s", e.pid, procname);

        std::string user_field;
        // presence of owner is indicated by pid != 0
        if (e.pid) {
            struct passwd pwd, *pwdp = NULL;
            long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
            if (bufsize < 0) bufsize = 16384;
            std::unique_ptr<char[]> buf(new char[bufsize]);
            char uname[64] = {0};
            bool have_name = false;
            if (getpwuid_r(e.uid, &pwd, buf.get(), bufsize, &pwdp) == 0 && pwdp) {
                strncpy(uname, pwd.pw_name, sizeof(uname)-1);
                uname[sizeof(uname)-1] = '\0';
                have_name = true;
            }
            // Always prefer username when resolvable; otherwise show numeric uid (including 0)
            user_field = have_name ? std::string(uname) : std::to_string(e.uid);
        } else {
            user_field = "-";
        }

        std::cout << std::left << std::setw(20) << e.inum << std::setw(16) << display << std::setw(12) << user_field << std::setw(8) << (e.pid ? std::to_string(e.pid) : std::string("-")) << pathbuf << "\n";
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
