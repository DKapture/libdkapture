#define MOCK_ENABLE 1
#if MOCK_ENABLE
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <string>
#include <vector>
#include <unordered_map>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf.h>
#include "Ucom.h"
#include "dkapture.h"

#define RB_MAP_SIZE (1024 * 1024)
#define BPF_PIN_PATH "/sys/fs/bpf/dkapture"

struct bpf_link
{
    int fd;
    std::string pin_path;
};

struct bpf_program
{
    int fd;
    std::string name;
    std::string pin_path;
};

struct bpf_map
{
    int fd;
    std::string name;
    std::string pin_path;
};

struct bpf_object
{
    std::vector<bpf_program> progs;
    std::vector<bpf_map> maps;
    std::vector<bpf_link> links;
};

static bpf_object g_obj;

std::string fd_path(int fd)
{
    char path[PATH_MAX];
    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(buf, path, sizeof(path) - 1);
    if (len != -1)
    {
        path[len] = '\0'; // Null-terminate the string
        return std::string(path);
    }
    else
    {
        perror("readlink");
        return "";
    }
}

int bpf_map_get_next_id(uint32_t start_id, uint32_t *next_id)
{
    if (start_id > 10)
        return -(errno = ENOENT);
    *next_id = start_id + 1;
    return 0;
}

int bpf_map_get_fd_by_id(uint32_t id)
{
    return id;
}

int bpf_map_get_info_by_fd(
    int map_fd,
    struct bpf_map_info *info,
    __u32 *info_len)
{

    info->type = BPF_MAP_TYPE_RINGBUF;
    info->max_entries = RB_MAP_SIZE;
    sprintf(info->name, "dk_shared_mem");
    return 0;
}

int touch(const char *path)
{
    int fd = open(path, O_RDWR | O_TRUNC | O_CREAT, 0700);
    if (fd < 0)
    {
        return -errno;
    }
    close(fd);
    return 0;
}

int bpf_link__pin(struct bpf_link *link, const char *path)
{
    return 0;
}

int bpf_link__unpin(struct bpf_link *link)
{
    return 0;
}

struct bpf_program *
bpf_object__next_program(const struct bpf_object *obj, struct bpf_program *prev)
{
    if (prev == nullptr)
    {
        return (bpf_program *)&obj->progs[0];
    }
    for (int i = 0; i < obj->progs.size(); i++)
    {
        if (&obj->progs[i] == prev)
        {
            if (i == obj->progs.size() - 1)
            {
                return nullptr;
            }
            return (bpf_program *)&obj->progs[i + 1];
        }
    }
    return nullptr;
}

int bpf_program__fd(const struct bpf_program *prog)
{
    return prog->fd;
}

const char *bpf_program__name(const struct bpf_program *prog)
{
    return prog->name.c_str();
}

int bpf_program__pin(struct bpf_program *prog, const char *path)
{
    return 0;
}

int bpf_program__unpin(struct bpf_program *prog, const char *path)
{
    return 0;
}

bool bpf_program__autoload(const struct bpf_program *prog)
{
    return true;
}

int bpf_object__pin_maps(struct bpf_object *obj, const char *path)
{
    return 0;
}

struct bpf_program *
bpf_object__prev_program(const struct bpf_object *obj, struct bpf_program *prog)
{
    return nullptr;
}

libbpf_print_fn_t libbpf_set_print(libbpf_print_fn_t fn)
{
    return fn;
}

void bpf_object__destroy_skeleton(struct bpf_object_skeleton *s)
{
    if (!s)
        return;

    int fd;
    char buf[PATH_MAX];

    for (int i = 0; i < s->prog_cnt; i++)
    {
        close(g_obj.progs[i].fd);
        close(g_obj.links[i].fd);
    }
    g_obj.progs.clear();
    g_obj.links.clear();
    for (int i = 0; i < s->map_cnt; i++)
    {
        close(g_obj.maps[i].fd);
    }
    g_obj.maps.clear();
    free(s->maps);
    free(s->progs);
    free(s);
}

int bpf_object__find_map_fd_by_name(
    const struct bpf_object *obj,
    const char *name)
{
    for (int i = 0; i < obj->maps.size(); i++)
    {
        if (obj->maps[i].name == name)
        {
            return obj->maps[i].fd;
        }
    }
    return -(errno = ENOENT);
}

int bpf_object__open_skeleton(struct bpf_object_skeleton *s,
                              const struct bpf_object_open_opts *opts)
{
    if (access(BPF_PIN_PATH, F_OK) != 0)
    {
        if (0 != mkdir(BPF_PIN_PATH, 0700))
        {
            pr_error("mkdir: %s", strerror(errno));
            return -(errno = ENOENT);
        }
    }

    *s->obj = &g_obj;

    int fd;
    bpf_program prog;
    bpf_map map;
    bpf_link link;
    const char *name;
    char buf[PATH_MAX];

    g_obj.progs.reserve(s->prog_cnt);
    for (int i = 0; i < s->prog_cnt; i++)
    {
        name = s->progs[i].name;
        snprintf(buf, PATH_MAX, "%s/prog-%s", BPF_PIN_PATH, name);
        fd = open(buf, O_RDWR | O_TRUNC | O_CREAT, 0600);
        if (fd < 0)
            return -errno;
        prog.fd = fd;
        prog.pin_path = buf;
        prog.name = name;
        g_obj.progs.emplace_back(prog);
        *s->progs[i].prog = &g_obj.progs[i];
    }
    g_obj.maps.reserve(s->map_cnt);
    for (int i = 0; i < s->map_cnt; i++)
    {
        name = s->maps[i].name;
        snprintf(buf, PATH_MAX, "%s/map-%s", BPF_PIN_PATH, name);
        fd = open(buf, O_RDWR | O_TRUNC | O_CREAT, 0600);
        if (fd < 0)
            return -errno;
        map.fd = fd;
        map.pin_path = buf;
        map.name = name;
        g_obj.maps.emplace_back(map);
        *s->maps[i].map = &g_obj.maps[i];
        if (strcmp(name, "dk_shared_mem") == 0)
        {
            static char buf[4096] = {};
            for (int i = 0; i < RB_MAP_SIZE / sizeof(buf); i++)
                write(fd, buf, sizeof(buf));
        }
    }
    g_obj.links.reserve(s->prog_cnt);
    for (int i = 0; i < s->prog_cnt; i++)
    {
        name = s->progs[i].name;
        snprintf(buf, PATH_MAX, "%s/link-%s", BPF_PIN_PATH, name);
        fd = open(buf, O_RDWR | O_TRUNC | O_CREAT, 0600);
        if (fd < 0)
            return -errno;
        link.fd = fd;
        link.pin_path = buf;
        g_obj.links.emplace_back(link);
        *s->progs[i].link = &g_obj.links[i];
    }
    return 0;
}

int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms)
{
    usleep(100000);
    return 0;
}

void ring_buffer__free(struct ring_buffer *rb)
{
    free(rb);
}

int bpf_map_update_elem(
    int fd, const void *key,
    const void *value,
    __u64 flags)
{
    return 0;
}

struct ring_buffer *
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx,
		 const struct ring_buffer_opts *opts)
{
    return (struct ring_buffer *)malloc(1024);
}

int bpf_map__set_value_size(struct bpf_map *map, __u32 size)
{
    return 0;
}

int bpf_map__set_max_entries(struct bpf_map *map, __u32 max_entries)
{
    return 0;
}

int bpf_map__fd(const struct bpf_map *map)
{
    return 0;
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    return 0;
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    return 0;
}

int bpf_object__load_skeleton(struct bpf_object_skeleton *s)
{
    return 0;
}

int bpf_object__attach_skeleton(struct bpf_object_skeleton *s)
{
    return 0;
}

void bpf_object__detach_skeleton(struct bpf_object_skeleton *s)
{
}

int bpf_link__fd(const struct bpf_link *link)
{
    return link->fd;
}

int bpf_iter_create(int link_fd)
{
    return dup(link_fd);
}

int epoll_ctl(int __epfd, int __op, int __fd,
              struct epoll_event *__event)
{
    return 0;
}

ssize_t
read(int __fd, void *__buf, size_t __nbytes)
{
    for (int i = 0; i < g_obj.maps.size(); i++)
    {
        if (g_obj.maps[i].fd == __fd)
        {
            return 0;
        }
    }
    return syscall(__NR_read, __fd, __buf, __nbytes);
}
#endif
