#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>

#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "map-resolver.h"

int MapResolver::resolve(struct bpf_map *map, const char *pin_path)
{
    if (!map || !pin_path) {
        m_last_error = "invalid arguments";
        return -EINVAL;
    }

    int fd = bpf_obj_get(pin_path);
    if (fd < 0) {
        m_last_error = std::string("failed to open pinned map '") +
                       pin_path + "': " + strerror(errno);
        return -errno;
    }

    //告诉 libbpf 使用已有的内核 map 实例，而不是创建新实例，将fd复用给extern map，实现 map 共享
    int err = bpf_map__reuse_fd(map, fd);
    if (err) {
        char err_buf[256] = {};
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        m_last_error = std::string("bpf_map__reuse_fd failed for '") +
                       bpf_map__name(map) + "': " + err_buf;
        close(fd);
        return err;
    }

    // bpf_map__reuse_fd 内部 dup(fd) 并持有副本，此处关闭原始 fd
    close(fd);
    return 0;
}
