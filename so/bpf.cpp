#include <cerrno>
#include <dirent.h>
#include <system_error>

#include "bpf.h"
#include "Ulog.h"
#include "types.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#include <vector>

#define PIN_PATH "/sys/fs/bpf/dkapture"

#define link_idx(links, link) \
	(((long)&links.dump_task - (long)&links) / sizeof(bpf_link *))

int BPF::retreat_bpf_map(const char *name)
{
	int err;
	u32 id = 0;
	int fd = -1;
	struct bpf_map_info info = {};
	u32 len = sizeof(info);
	std::string map_pin_path(PIN_PATH "/map-");
	map_pin_path += name;
	if (access(map_pin_path.c_str(), F_OK) != 0)
	{
		return -ENOENT;
	}
	while (true)
	{
		err = bpf_map_get_next_id(id, &id);
		if (err)
		{
			if (errno == ENOENT)
				break;
			pr_error("bpf_map_get_next_id: %s%s", strerror(errno),
				 errno == EINVAL ? " -- kernel too old?" : "");
			break;
		}

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0)
		{
			if (errno == ENOENT)
				continue;
			pr_error("bpf_map_get_fd_by_id (%u): %s", id,
				 strerror(errno));
			break;
		}
		err = bpf_map_get_info_by_fd(fd, &info, &len);
		if (err)
		{
			pr_error("bpf_map_get_info_by_fd: %s", strerror(errno));
			::close(fd);
			break;
		}

		if (strcmp(info.name, name) == 0)
		{
			m_map_id = id;
			return fd;
		}
		::close(fd);
	}
	return -errno;
}

std::string BPF::retreat_bpf_iter(const char *name)
{
	char buf[PATH_MAX];
	snprintf(buf, sizeof(buf), PIN_PATH "/link-%s", name);
	if (access(buf, F_OK) != 0)
		return "";
	return buf;
}

int BPF::bpf_pin_links(const char *pin_dir)
{
	int err = 0;
	char buf[PATH_MAX];
	std::vector<bpf_link *> links;
	for (int i = 0; i < m_obj->skeleton->prog_cnt; i++)
	{
		bpf_link *link = *m_obj->skeleton->progs[i].link;
		if (!link)
			continue;
		const char *name = m_obj->skeleton->progs[i].name;
		snprintf(buf, PATH_MAX, "%s/link-%s", pin_dir, name);
		err = bpf_link__pin(link, buf);
		if (err)
		{
			pr_error("link pin %s: %s", buf, strerror(errno));
			goto err_out;
		}
		links.push_back(link);
	}
	return 0;
err_out:
	for (auto link : links)
		bpf_link__unpin(link);
	return err;
}

/**
 * 重写libbpf.so库中bpf_object__pin_programs的实现，原实现无法完成本文件需求。
 */
int BPF::bpf_pin_programs(const char *path)
{
	struct bpf_program *prog;
	char buf[PATH_MAX];
	int err;
	struct bpf_object *obj = m_obj->obj;

	bpf_object__for_each_program(prog, obj)
	{
		int fd = bpf_program__fd(prog);
		if (!bpf_program__autoload(prog) && fd < 0)
			continue;
		const char *prog_name = bpf_program__name(prog);
		snprintf(buf, PATH_MAX, "%s/%s", path, prog_name);
		err = bpf_program__pin(prog, buf);
		if (err)
			goto err_out;
	}

	return 0;

err_out:
	while ((prog = bpf_object__prev_program(obj, prog)))
	{
		const char *prog_name = bpf_program__name(prog);
		snprintf(buf, PATH_MAX, "%s/%s", path, prog_name);
		bpf_program__unpin(prog, buf);
	}

	return err;
}

BPF::BPF()
{
	int err = 0;
	try
	{
		m_shm = new SharedMemory();
		m_bpf_lock = new SpinLock(&m_shm->bpf_lock);
		bpf_ref_cnt = &m_shm->bpf_ref_cnt;
	}
	catch (...)
	{
		this->~BPF();
		throw;
	}
	/**
     * TODO:
     * 临界区可能会被信号中断导致进程异常推出，需要处理这种情况下的锁未释放的问题
     */
	m_bpf_lock->lock();
	// Implementation for opening the capture
	m_map_fd = retreat_bpf_map("dk_shared_mem");
	if (m_map_fd >= 0)
	{ // look like there is already a bpf program loaded
		pr_debug("use existing bpf mirror");
		m_proc_iter_link_path = retreat_bpf_iter("dump_task");
		if (m_proc_iter_link_path.empty())
		{
			err = -errno;
			goto err_out;
		}
	}
	else
	{
		pr_debug("creating new bpf mirror");
		m_obj = proc_info_bpf::open_and_load();
		if (!m_obj)
			goto err_out;
		err = proc_info_bpf::attach(m_obj);
		if (0 != err)
			goto err_out;
		err = bpf_object__pin_maps(m_obj->obj, PIN_PATH);
		if (err)
			goto err_out;
		err = bpf_pin_programs(PIN_PATH);
		if (err)
			goto err_out;
		if (0 != bpf_pin_links(PIN_PATH))
			goto err_out;
		m_map_fd = bpf_get_map_fd(m_obj->obj, "dk_shared_mem",
					  goto err_out);
	}
	(*bpf_ref_cnt)++;
	m_bpf_lock->unlock();
	return;

err_out:
	m_bpf_lock->unlock();
	pr_error("BPF::BPF(): %s", strerror(-err));
	throw std::system_error(-err, std::generic_category(), "shmget failed");
}

BPF::~BPF()
{
	if (m_obj)
	{
		proc_info_bpf::detach(m_obj);
		proc_info_bpf::destroy(m_obj);
		m_obj = nullptr;
	}
	else
	{ // bpf obj got through pin path
		if (m_map_fd)
		{
			::close(m_map_fd);
			m_map_fd = -1;
		}
	}
	if (m_bpf_lock)
	{
		m_bpf_lock->lock();
		if (--(*bpf_ref_cnt) <= 0)
		{
			*bpf_ref_cnt = 0;
			DIR *dir = opendir(PIN_PATH);
			if (dir)
			{
				struct dirent64 *entry;
				while ((entry = readdir64(dir)) != nullptr)
				{
					if (strcmp(entry->d_name, ".") == 0 ||
					    strcmp(entry->d_name, "..") == 0)
						continue;
					std::string path(PIN_PATH);
					path += "/";
					path += entry->d_name;
					unlink(path.c_str());
				}
				closedir(dir);
			}
			rmdir(PIN_PATH);
		}
		/**
         * 这个判断代码用于验证 bpf pin 路径被删除后，bpf 内核对象仍然会
         * 在短时间存活，即便它的引用计数已归零，应该是 unlink 的过程中，采
         * 用的异步释放，这段代码未删除的原因，仅用于惊醒开发者这一现象。
         */
		if (0 && bpf_map_get_fd_by_id(m_map_id) >= 0)
		{
			pr_warn("bpf map %d still exists after "
				"unlink pin path",
				m_map_id);
		}
		m_bpf_lock->unlock();
	}
	SAFE_DELETE(m_bpf_lock);
	SAFE_DELETE(m_shm);
}

int BPF::dump_task_file(void)
{
	int fd;
	ssize_t rd_sz;
	char buf[8]; // 实际上并没有使用
	if (m_obj)
		fd = bpf_create_iter(m_obj->links.dump_task_file, return -1);
	else
		fd = ::open(m_dump_task_file.c_str(), O_RDONLY);
	if (fd < 0)
	{
		pr_error("bpf_iter_create (%s): %s", m_dump_task_file.c_str(),
			 strerror(errno));
		return -1;
	}

	while ((rd_sz = ::read(fd, buf, sizeof(buf))) > 0)
	{
		// nothing needs to be done, just trigger the bpf iterator to run
		DEBUG(0, "rd_sz: (%ld)", rd_sz);
	}

	if (rd_sz < 0)
	{
		pr_error("read iter(%d): %s(%d)", fd, strerror(errno), errno);
	}
	::close(fd);
	return 0;
}
