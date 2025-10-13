// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "log.h"
#include <asm-generic/errno.h>

#include <cassert>
#include <cstddef>
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
#include <sys/time.h>

#include <string>
#include <vector>
#include <map>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf.h>
#include <sys/mman.h>
#include "dkapture.h"
#include "ring-buffer.h"
#include "mock-data-generator.h"

#define RB_MAP_SIZE (1024 * 1024)
#define BPF_PIN_PATH "/sys/fs/bpf/dkapture"
#define ALIGN_UP(x, a) ((x) + (a) - (x) % (a))

std::string test_name;
// (map_name, (key_size, value_size, max_entries, type))
std::map<std::string, std::tuple<int, int, int, bpf_map_type>> *map_info = NULL;

struct bpf_link
{
	int fd;
	bpf_program *prog;
	std::string pin_path;
};

struct bpf_program
{
	int fd;
	std::string name;
	std::string pin_path;
	bpf_map *map;
	void (*function)(bpf_program *p);
};

struct bpf_map
{
	int fd;
	size_t key_size;
	size_t value_size;
	size_t max_entries;
	size_t sz;
	void *mem;
	bpf_map_type type;
	std::string name;
	std::string pin_path;
};

struct bpf_object
{
	std::vector<bpf_program> progs;
	std::vector<bpf_map> maps;
	std::vector<bpf_link> links;
};

struct ring_buffer
{
	int map_fd;
	ring_buffer_sample_fn sample_cb;
	void *ctx;
	const struct ring_buffer_opts *opts;
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

int bpf_rb_map_push_data(bpf_map *map, void *data, size_t sz)
{
	char *p = nullptr;
	size_t rb_sz = 0;
	size_t idx = 0;
	int page_size = getpagesize();
	p = (char *)map->mem;
	rb_sz = map->sz;
	unsigned long *csm_idx = (unsigned long *)p;
	unsigned long *pdc_idx = (unsigned long *)(p + page_size);
	if (*csm_idx + rb_sz <= *pdc_idx + sz)
	{
		return -E2BIG;
	}
	p += page_size * 2;
	idx = *pdc_idx;
	idx &= (rb_sz - 1);
	p += idx;
	long &len = *(long *)p;
	len = sz;
	p += BPF_RINGBUF_HDR_SZ;
	memcpy(p, data, sz);
	*pdc_idx += sz + BPF_RINGBUF_HDR_SZ;
	*pdc_idx = (*pdc_idx + 7) & ~7;
	return 0;
}

int ring_buffer__push(int fd, void *data, size_t sz)
{
	if (fd == 0 || !data || sz == 0)
	{
		return -EINVAL;
	}
	for (auto &i : g_obj.maps)
	{
		if (i.fd == fd && i.type == BPF_MAP_TYPE_RINGBUF)
		{
			int ret = bpf_rb_map_push_data(&i, data, sz);
			return ret;
		}
	}
	return -ENOENT;
}

void dump_task(bpf_program *p)
{
	bpf_map *map = p->map;
	auto mock_data = generate_mock_process_data(10);
	for (auto it : mock_data)
	{
		bpf_rb_map_push_data(map, it, sizeof(*it) + it->dsz);
	}
	cleanup_mock_process_data(mock_data);
}

int bpf_map_get_next_id(uint32_t start_id, uint32_t *next_id)
{
	if (start_id > g_obj.maps.size())
	{
		return -(errno = ENOENT);
	}
	*next_id = start_id + 1;
	return 0;
}

int bpf_map_get_fd_by_id(uint32_t id)
{
	if (id > g_obj.maps.size())
	{
		return -(errno = ENOENT);
	}
	return g_obj.maps[id - 1].fd;
}

int bpf_map_get_info_by_fd(
	int map_fd,
	struct bpf_map_info *info,
	__u32 *info_len
)
{
	for (int i = 0; i < g_obj.maps.size(); i++)
	{
		if (g_obj.maps[i].fd == map_fd)
		{
			info->type = g_obj.maps[i].type;
			info->max_entries = g_obj.maps[i].sz;
			sprintf(info->name, "%s", g_obj.maps[i].name.c_str());
			return 0;
		}
	}
	return -(errno = EBADFD);
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
	{
		return;
	}

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
		munmap(g_obj.maps[i].mem, g_obj.maps[i].sz);
		close(g_obj.maps[i].fd);
	}
	g_obj.maps.clear();
	free(s->maps);
	free(s->progs);
	free(s);
}

int bpf_object__find_map_fd_by_name(
	const struct bpf_object *obj,
	const char *name
)
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

int bpf_object__open_skeleton(
	struct bpf_object_skeleton *s,
	const struct bpf_object_open_opts *opts
)
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

	for (int i = 0; i < s->map_cnt; i++)
	{
		name = s->maps[i].name;
		snprintf(buf, PATH_MAX, "%s/map-%s", BPF_PIN_PATH, name);
		fd = open(buf, O_RDWR | O_TRUNC | O_CREAT, 0600);
		if (fd < 0)
		{
			return -errno;
		}
		map.fd = fd;
		map.pin_path = buf;
		map.name = name;
		if (map_info && map_info->count(map.name))
		{
			const auto &[k, v, e, t] = (*map_info)[map.name];
			map.key_size = k;
			map.value_size = v;
			map.max_entries = e;
			map.sz = (k + v) * e;
			map.type = t;
		}
		else
		{
			map.sz = RB_MAP_SIZE;
			map.type = BPF_MAP_TYPE_UNSPEC;
		}
		int page_size = getpagesize();
		if (strcmp(name, "dk_shared_mem") == 0 ||
			map.type == BPF_MAP_TYPE_RINGBUF)
		{
			int ret = 0;
			ret = ftruncate(fd, page_size * 2 + RB_MAP_SIZE);
			assert(ret == 0);
			map.type = BPF_MAP_TYPE_RINGBUF;
			map.mem = mmap(
				NULL,
				page_size * 2 + RB_MAP_SIZE,
				PROT_READ | PROT_WRITE,
				MAP_SHARED,
				fd,
				0
			);
			assert(map.mem != MAP_FAILED);
			memset(map.mem, 0, page_size * 2 + RB_MAP_SIZE);
		}
		else
		{
			map.mem = nullptr;
		}
		g_obj.maps.push_back(std::move(map));
		*s->maps[i].map = &g_obj.maps[i];
	}

	for (int i = 0; i < s->prog_cnt; i++)
	{
		name = s->progs[i].name;
		snprintf(buf, PATH_MAX, "%s/prog-%s", BPF_PIN_PATH, name);
		fd = open(buf, O_RDWR | O_TRUNC | O_CREAT, 0600);
		if (fd < 0)
		{
			return -errno;
		}
		prog.fd = fd;
		prog.pin_path = buf;
		prog.name = name;
		prog.map = nullptr;
		prog.function = nullptr;
		if (strcmp(name, "dump_task") == 0)
		{
			prog.function = dump_task;
			for (auto &it : g_obj.maps)
			{
				if (it.name == "dk_shared_mem")
				{
					prog.map = &it;
					break;
				}
			}
		}
		g_obj.progs.push_back(std::move(prog));
		*s->progs[i].prog = &g_obj.progs[i];

		snprintf(buf, PATH_MAX, "%s/link-%s", BPF_PIN_PATH, name);
		fd = open(buf, O_RDWR | O_TRUNC | O_CREAT, 0600);
		if (fd < 0)
		{
			return -errno;
		}
		link.fd = fd;
		link.pin_path = buf;
		link.prog = &g_obj.progs[i];
		g_obj.links.push_back(std::move(link));
		*s->progs[i].link = &g_obj.links[i];
	}
	return 0;
}

#include <time.h>
#include <unistd.h>

int ring_buffer__poll(struct ring_buffer *rb, int timeout)
{
	if (!rb || !rb->sample_cb)
	{
		return -EINVAL;
	}

	struct bpf_map *map = nullptr;
	for (auto &i : g_obj.maps)
	{
		if (i.fd == rb->map_fd)
		{
			map = &i;
			break;
		}
	}
	if (!map || !map->mem)
	{
		return -ENOENT;
	}

	int page_size = getpagesize();
	char *base = (char *)map->mem;
	unsigned long *consumer = (unsigned long *)base;
	unsigned long *producer = (unsigned long *)(base + page_size);
	char *data_area = base + page_size * 2;
	size_t data_sz = map->sz;

	int records_consumed = 0;
	struct timespec start_ts, current_ts;
	bool use_timeout = (timeout >= 0);

	if (use_timeout)
	{
		clock_gettime(CLOCK_MONOTONIC, &start_ts);
	}

	while (true)
	{
		// 检查超时
		if (use_timeout)
		{
			clock_gettime(CLOCK_MONOTONIC, &current_ts);
			long elapsed_ms = (current_ts.tv_sec - start_ts.tv_sec) * 1000 +
							  (current_ts.tv_nsec - start_ts.tv_nsec) / 1000000;
			if (elapsed_ms >= timeout)
			{
				break;
			}
		}

		unsigned long cons = __atomic_load_n(consumer, __ATOMIC_RELAXED);
		unsigned long prod = __atomic_load_n(producer, __ATOMIC_ACQUIRE);

		bool processed = false;

		while (cons != prod)
		{
			processed = true;

			size_t offset = cons & (data_sz - 1);
			char *p = data_area + offset;
			long len = *(volatile long *)p;

			if (len <= 0)
			{
				cons += 8;
				cons = (cons + 7) & ~7;
				continue;
			}

			if (cons + 8 + len > prod)
			{
				break; // 不完整记录
			}

			p += 8;
			int ret = rb->sample_cb(rb->ctx, p, len);

			cons += 8 + len;
			cons = (cons + 7) & ~7;
			records_consumed++;
		}

		// 更新 consumer
		if (cons != __atomic_load_n(consumer, __ATOMIC_RELAXED))
		{
			__atomic_store_n(consumer, cons, __ATOMIC_RELEASE);
		}

		// 决定是否继续
		if (processed)
		{
			// 处理了数据，继续下一次循环（非阻塞行为）
			continue;
		}

		if (timeout == 0)
		{
			// 非阻塞模式，立即返回
			break;
		}

		// 短暂休眠
		std::this_thread::sleep_for(std::chrono::microseconds(1));
	}

	return records_consumed;
}

void ring_buffer__free(struct ring_buffer *rb)
{
	free(rb);
}

static off_t bpf_map_lookup_key(int fd, const void *key, struct bpf_map *map)
{
	off_t ret = lseek(fd, 0, SEEK_SET);
	u8 *buf[map->key_size];
	while (ret < map->sz)
	{
		ssize_t t = read(fd, buf, map->key_size);
		if (t != map->key_size)
		{
			break;
		}
		if (memcmp(key, buf, map->key_size) == 0)
		{
			break;
		}
		ret = lseek(fd, map->value_size, SEEK_CUR);
	}
	return ret;
}

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
	if (!map_info)
	{
		return 0;
	}
	struct bpf_map *map = nullptr;
	for (auto &i : g_obj.maps)
	{
		if (i.fd == fd)
		{
			map = &i;
			break;
		}
	}
	if (!map)
	{
		return 0;
	}

	off_t fsize = lseek(fd, 0, SEEK_END);
	off_t pos = bpf_map_lookup_key(fd, key, map);
	if (flags & BPF_EXIST)
	{
		if (fsize == pos)
		{
			return -ENOENT;
		}
	}
	else if (flags & BPF_NOEXIST)
	{
		if (fsize != pos)
		{
			return -EEXIST;
		}
		if (fsize + map->key_size + map->value_size > map->sz)
		{
			return -E2BIG;
		}
	}
	else
	{
		if (fsize == pos && fsize + map->key_size + map->value_size > map->sz)
		{
			return -E2BIG;
		}
	}
	long ret;
	ret = lseek(fd, pos, SEEK_SET);
	ret = write(fd, key, map->key_size);
	ret = write(fd, value, map->value_size);
	return 0;
}

struct ring_buffer *ring_buffer__new(
	int map_fd,
	ring_buffer_sample_fn sample_cb,
	void *ctx,
	const struct ring_buffer_opts *opts
)
{
	struct ring_buffer *rb =
		(struct ring_buffer *)malloc(sizeof(struct ring_buffer));

	rb->map_fd = map_fd;
	rb->sample_cb = sample_cb;
	rb->ctx = ctx;
	rb->opts = opts;
	return rb;
}

int bpf_map__set_value_size(struct bpf_map *map, __u32 size)
{
	map->sz = size;
	return 0;
}

int bpf_map__set_max_entries(struct bpf_map *map, __u32 max_entries)
{
	map->max_entries = max_entries;
	return 0;
}

int bpf_map__fd(const struct bpf_map *map)
{
	return map->fd;
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	if (!map_info)
	{
		return 0;
	}
	struct bpf_map *map = nullptr;
	for (auto &i : g_obj.maps)
	{
		if (i.fd == fd)
		{
			map = &i;
			break;
		}
	}
	if (!map)
	{
		return 0;
	}

	off_t fsize = lseek(fd, 0, SEEK_END);
	off_t pos = bpf_map_lookup_key(fd, key, map);
	if (fsize == pos)
	{
		return -ENOENT;
	}
	lseek(fd, pos + map->key_size, SEEK_SET);
	read(fd, value, map->value_size);
	return 0;
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	if (!next_key)
	{
		return -EINVAL;
	}
	if (!map_info)
	{
		return 0;
	}
	struct bpf_map *map = nullptr;
	for (auto &i : g_obj.maps)
	{
		if (i.fd == fd)
		{
			map = &i;
			break;
		}
	}
	if (!map)
	{
		return 0;
	}

	off_t fsize = lseek(fd, 0, SEEK_END);
	off_t pos;
	if (!key)
	{
		pos = 0;
	}
	else
	{
		pos =
			bpf_map_lookup_key(fd, key, map) + map->key_size + map->value_size;
	}

	if (fsize <= pos)
	{
		return -ENOENT;
	}
	lseek(fd, pos, SEEK_SET);
	read(fd, next_key, map->key_size);
	return 0;
}

long bpf_for_each_map_elem(
	struct bpf_map *map,
	void *callback_fn,
	void *callback_ctx,
	__u64 flags
)
{
	if (!map || !callback_fn)
	{
		pr_error("Invalid parameters in %s", __func__);
		return -EINVAL;
	}
	long (*callback)(struct bpf_map *, const void *, void *, void *) =
		(long (*)(struct bpf_map *, const void *, void *, void *))callback_fn;
	void *key = malloc(map->key_size);
	if (!key)
	{
		return -ENOMEM;
	}
	void *next_key = malloc(map->key_size);
	if (!next_key)
	{
		free(key);
		return -ENOMEM;
	}
	void *value = malloc(map->value_size);
	if (!value)
	{
		free(key);
		free(next_key);
		return -ENOMEM;
	}
	long ret = bpf_map_get_next_key(map->fd, NULL, next_key);
	while (ret == 0)
	{
		std::swap(key, next_key);
		ret = bpf_map_lookup_elem(map->fd, key, value);
		if (ret)
		{
			goto out_free_mem;
		}

		ret = callback(map, key, value, callback_ctx);
		if (ret)
		{
			goto out_free_mem;
		}

		ret = bpf_map_get_next_key(map->fd, key, next_key);
	}
out_free_mem:
	free(key);
	free(next_key);
	free(value);
	return ret;
}

long bpf_for_each_map_elem(
	int fd,
	void *callback_fn,
	void *callback_ctx,
	__u64 flags
)
{
	for (auto &i : g_obj.maps)
	{
		if (i.fd == fd)
		{
			return bpf_for_each_map_elem(&i, callback_fn, callback_ctx, flags);
		}
	}
	return -ENOENT;
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
	for (int i = 0; i < g_obj.links.size(); i++)
	{
		if (g_obj.links[i].fd == link_fd)
		{
			return dup(link_fd);
		}
	}
	return -1;
}

struct EpollCtl
{
	int fd;
	int notify;
	struct epoll_event event;
};
std::map<int, EpollCtl> ep_list;
int epoll_ctl(int __epfd, int __op, int __fd, struct epoll_event *__event)
{
	EpollCtl ctl = {};
	ctl.fd = __fd;
	ctl.event = *__event;
	ep_list[__epfd] = ctl;
	return 0;
}

int epoll_wait(
	int __epfd,
	struct epoll_event *__events,
	int __maxevents,
	int __timeout
)
{
	auto it = ep_list.find(__epfd);
	if (it == ep_list.end())
	{
		return -1;
	}
	EpollCtl &ctl = it->second;
	if (ctl.notify)
	{
		*__events = ctl.event;
		ctl.notify = 0;
		return 1;
	}
	return 0;
}

/**
 * 拦截c库read，以便实现bpf数据的read模拟。
 */
ssize_t read(int __fd, void *__buf, size_t __nbytes)
{
	for (int i = 0; i < g_obj.links.size(); i++)
	{
		std::string path = fd_path(__fd);
		if (path != g_obj.links[i].pin_path)
		{
			continue;
		}

		bpf_program *prog = g_obj.links[i].prog;
		if (prog->function)
		{
			prog->function(prog);
		}
		for (auto &it : ep_list)
		{
			if (prog->map && it.second.fd == prog->map->fd)
			{
				it.second.notify = 1;
			}
		}
		return 0;
	}
	return syscall(__NR_read, __fd, __buf, __nbytes);
}

static void *vaddr;
/**
 * @brief 拦截c库的mmap函数，我们需要利用mock它来模拟内核
 *        ringbuffer的功能。
 */
void *mmap(
	void *__addr,
	size_t __len,
	int __prot,
	int __flags,
	int __fd,
	__off_t __offset
)
{
	int page_size = getpagesize();
	int data_area_sz = (__len - page_size) / 2;
	if (__addr == NULL && __len > page_size && __offset == page_size &&
		__prot == PROT_READ && __flags == MAP_SHARED &&
		data_area_sz >= page_size && ((data_area_sz & (data_area_sz - 1)) == 0))
	{
		// 第一次映射只是为了获取一个足够大的、未使用的地址空间
		vaddr = (void *)
			syscall(__NR_mmap, __addr, __len, __prot, __flags, __fd, __offset);
		if (vaddr == MAP_FAILED)
		{
			return MAP_FAILED;
		}
		munmap(vaddr, __len);

		// 开始真正功能映射，模拟bpf ringbuffer的映射模式
		char *p = (char *)vaddr;
		vaddr = (void *)
			syscall(__NR_mmap, p, page_size, __prot, __flags, __fd, __offset);
		if (vaddr == MAP_FAILED)
		{
			return MAP_FAILED;
		}
		p += page_size;
		__offset += page_size;

		// 验证两个地址空间映射到了同一个文件区域。
		lseek(__fd, __offset, SEEK_SET);
		write(__fd, "abcdefgh", sizeof("abcdefgh"));

		p = (char *)syscall(
			__NR_mmap,
			p,
			data_area_sz,
			__prot,
			__flags,
			__fd,
			__offset
		);
		if (p == MAP_FAILED)
		{
			return MAP_FAILED;
		}

		// 验证第一个空间映射的区域。
		if (strncmp(p, "abcdefgh", sizeof("abcdefgh")))
		{
			return MAP_FAILED;
		}
		p += data_area_sz;

		p = (char *)syscall(
			__NR_mmap,
			p,
			data_area_sz,
			__prot,
			__flags,
			__fd,
			__offset
		);
		if (p == MAP_FAILED)
		{
			return MAP_FAILED;
		}

		// 验证第二个空间映射的区域。
		if (strncmp(p, "abcdefgh", sizeof("abcdefgh")))
		{
			return MAP_FAILED;
		}

		return vaddr;
	}
	return (void *)
		syscall(__NR_mmap, __addr, __len, __prot, __flags, __fd, __offset);
}

/**
 * @brief 拦截c库的munmap，与上面mmap的拦截配对
 */
int munmap(void *__addr, size_t __len)
{
	char *p = (char *)__addr;
	if (__addr == vaddr)
	{
		int page_size = getpagesize();
		syscall(__NR_munmap, p, page_size);
		p += page_size;
		__len -= page_size;
		__len /= 2;
		syscall(__NR_munmap, p, __len);
		p += __len;
	}
	return syscall(__NR_munmap, p, __len);
}

#endif
