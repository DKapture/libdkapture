#include "Ulog.h"
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
	int sz;
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

void bpf_rb_push_data(bpf_map *map, void *data, size_t sz)
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
		pr_error("!!! rb left space is not enough !!!");
		return;
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
}

void dump_task(bpf_program *p)
{
	bpf_map *map = p->map;
	auto mock_data = generate_mock_process_data(10);
	for (auto it : mock_data)
	{
		bpf_rb_push_data(map, it, sizeof(*it) + it->dsz);
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
		map.sz = RB_MAP_SIZE;
		int page_size = getpagesize();
		if (strcmp(name, "dk_shared_mem") == 0)
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

int bpf_ringbuffer_push(
	RingBuffer *m_bpf_rb,
	int bpf_idx,
	DKapture::DataHdr *dh
)
{
	int ret = 0;
	size_t page_size = getpagesize();
	// bpf ringbuffer中前两个页是控制数据结构。
	bpf_idx += page_size * 2 + BPF_RINGBUF_HDR_SZ;
	ret = lseek(m_bpf_rb->map_fd, bpf_idx, SEEK_SET);
	if (ret < 0)
	{
		return -1;
	}
	return write(m_bpf_rb->map_fd, dh, sizeof(DKapture::DataHdr) + dh->dsz);
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

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
	return 0;
}

struct ring_buffer *ring_buffer__new(
	int map_fd,
	ring_buffer_sample_fn sample_cb,
	void *ctx,
	const struct ring_buffer_opts *opts
)
{
	return (struct ring_buffer *)malloc(1024);
}

int bpf_map__set_value_size(struct bpf_map *map, __u32 size)
{
	return map->sz = size;
}

int bpf_map__set_max_entries(struct bpf_map *map, __u32 max_entries)
{
	return 0;
}

int bpf_map__fd(const struct bpf_map *map)
{
	return map->fd;
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
