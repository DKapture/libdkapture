
#include <thread>
#include <unistd.h>
#include <system_error>

#include "Ucom.h"
#include "dkapture.h"
#include "data-map.h"
#include "Ulog.h"

class dkapture : public DKapture
{
    private:
	DataMap *m_datamap = nullptr;
	u64 m_lifetime = 10;
	pid_t parse_path(const char *path, DataType &pid);

    public:
	virtual int open(FILE *fp = stdout, LogLevel lvl = INFO) override;
	virtual u64 lifetime(u64 ms) override;
	virtual ssize_t read(DataType dt, pid_t pid, DataHdr *buf, size_t bsz);
	virtual ssize_t read(std::vector<DataType> &dts, pid_t pid,
			     DataHdr *buf, size_t bsz);
	virtual ssize_t read(std::vector<const char *> &paths, DataHdr *buf,
			     size_t bsz);
	virtual ssize_t read(DataType dt, std::vector<pid_t> &pids,
			     DataHdr *buf, size_t bsz);
	virtual ssize_t read(const char *path, DataHdr *buf,
			     size_t bsz) override;
	virtual ssize_t read(DataType dt, DKCallback cb, void *ctx) override;
	virtual ssize_t read(std::vector<DataType> &dts, DKCallback cb,
			     void *ctx) override;
	virtual ssize_t read(std::vector<const char *> &paths, DKCallback cb,
			     void *ctx) override;
	virtual int kmemleak_scan_start(pid_t pid, DKCallback cb,
					void *ctx) override;
	virtual int kmemleak_scan_stop(void) override;
	virtual int file_watch(const char *path, DKCallback cb,
			       void *ctx) override;
	virtual int fs_watch(const char *path, DKCallback cb,
			     void *ctx) override;
	virtual int irq_watch(DKCallback cb, void *ctx) override;
	virtual int close(void) override;
	virtual ~dkapture() override;
};

int dkapture::open(FILE *fp, LogLevel lvl)
{
	int err = 0;
	Log::set_file(fp);
	Log::set_level(lvl);
	if (getuid() != 0)
	{
		pr_error("dkapture needs root permission");
		return -EPERM;
	}
	/**
     * TODO: 检测dkapture完整性，不完整时需要清理
     */
	if (m_datamap)
	{
		pr_error("dkapture already opened");
		return -EEXIST;
	}
	try
	{
		m_datamap = new DataMap();
	}
	catch (std::system_error &e)
	{
		pr_error("dkapture::open: %s", e.what());
		err = -e.code().value();
		goto err_out;
	}
	catch (...)
	{
		err = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	close();
	return err;
}

int dkapture::close(void)
{
	// Implementation for closing the capture
	SAFE_DELETE(m_datamap);
	return 0;
}

u64 dkapture::lifetime(u64 ms)
{
	// Implementation for tolerating a certain time
	if (ms == UINT64_MAX)
		return m_lifetime;
	if (ms > 3600 * 1000)
	{
		pr_warn("dkapture::lifetime: ms is too large, truncated to 1h");
		ms = 3600 * 1000;
	}
	u64 old = m_lifetime;
	m_lifetime = ms;
	return old;
}

ssize_t dkapture::read(DataType dt, pid_t pid, DataHdr *buf, size_t bsz)
{
	assert(sizeof(ulong) == sizeof(std::size_t));
	ulong key = MK_KEY(pid, dt);
	// m_datamap->list_all_entrys();
	int ret = m_datamap->find(key, m_lifetime, buf, bsz);
	DEBUG(0, "pid %d hash: %lx", pid, key);
	if (ret > 0)
	{
		DEBUG(0, "fetch old data");
	}
	DEBUG(0, "ret: %d", ret);
	return ret;
}

ssize_t dkapture::read(std::vector<DataType> &dts, pid_t pid, DataHdr *buf,
		       size_t bsz)
{
	for (auto dt : dts)
	{
		ssize_t ret = read(dt, pid, buf, bsz);
		if (ret < 0)
			continue;
		buf = (DataHdr *)((char *)buf + ret);
		bsz -= ret;
	}
	return bsz;
};

ssize_t dkapture::read(std::vector<const char *> &paths, DataHdr *buf,
		       size_t bsz)
{
	for (auto path : paths)
	{
		ssize_t ret = read(path, buf, bsz);
		if (ret < 0)
			continue;
		buf = (DataHdr *)((char *)buf + ret);
		bsz -= ret;
	}
	return bsz;
};
ssize_t dkapture::read(DataType dt, std::vector<pid_t> &pids, DataHdr *buf,
		       size_t bsz)
{
	ssize_t dsz = bsz;
	for (auto pid : pids)
	{
		ssize_t ret = read(dt, pid, buf, bsz);
		if (ret <= 0)
			continue;
		assert((size_t)ret <= bsz);
		buf = (DataHdr *)((char *)buf + ret);
		bsz -= ret;
	}
	return dsz - bsz;
};

pid_t dkapture::parse_path(const char *path, DataType &dt)
{
	if (strncmp(path, "/proc/", 6) != 0)
	{
		pr_error("'path' must start with /proc/");
		return -EINVAL;
	}
	path += 6;

	long i = 0;
	while (path[i] && path[i] != '/')
		i++;
	/**
     * 判断两个 / 中间的是不是 pid
     */
	char *end;
	pid_t pid = strtol(path, &end, 10);
	DEBUG(0, "pid: %d path: %s", pid, path);
	if (end == &path[i] && path[i] == '/')
	{
		path += i + 1;
		if (strcmp(path, "io") == 0)
			dt = PROC_PID_IO;
		else if (strcmp(path, "stat") == 0)
			dt = PROC_PID_STAT;
		else if (strcmp(path, "statm") == 0)
			dt = PROC_PID_STATM;
		else if (strcmp(path, "traffic") == 0)
			dt = PROC_PID_traffic;
		else if (strcmp(path, "status") == 0)
			dt = PROC_PID_STATUS;
		else if (strcmp(path, "schedstat") == 0)
			dt = PROC_PID_SCHEDSTAT;
		else if (strcmp(path, "fd") == 0)
			dt = PROC_PID_FD;
		else if (strcmp(path, "ns") == 0)
			dt = PROC_PID_NS;
		else
			return -ENOSYS;
	}
	else
	{
		return -ENOSYS;
	}
	return pid;
}

ssize_t dkapture::read(const char *path, DataHdr *buf, size_t bsz)
{
	if (!path || !buf || bsz == 0)
		return -EINVAL;
	DataType dt;
	pid_t pid = parse_path(path, dt);
	if (pid < 0)
	{
		pr_warn("try read %s: not implemented yet or invalid", path);
		return pid;
	}

	return read(dt, pid, buf, bsz);
}

int lsock_query(DKapture::DKCallback callback, void *ctx);

ssize_t dkapture::read(DataType dt, DKCallback cb, void *ctx)
{
	if (dt == PROC_PID_sock)
		return lsock_query(cb, ctx);
	m_datamap->set_iterator(cb, ctx);
	ssize_t ret = read(dt, 0, nullptr, 0);
	m_datamap->set_iterator(nullptr, nullptr);
	return ret;
}

ssize_t dkapture::read(std::vector<DataType> &dts, DKCallback cb, void *ctx)
{
	ssize_t total = 0;
	for (auto dt : dts)
	{
		ssize_t rsz = read(dt, cb, ctx);
		if (rsz <= 0)
			continue;
		total += rsz;
	}
	return total;
}

ssize_t dkapture::read(std::vector<const char *> &paths, DKCallback cb,
		       void *ctx)
{
	ssize_t total = 0;
	for (auto path : paths)
	{
		DataType dt;
		pid_t pid = parse_path(path, dt);
		if (pid < 0)
		{
			pr_warn("try read %s: not implemented yet or invalid",
				path);
			continue;
		}
		ssize_t rsz = read(dt, cb, ctx);
		if (rsz <= 0)
			continue;
		total += rsz;
	}
	return total;
}

int trace_file_deinit(void);
int trace_file_init(int argc, char **argv,
		    int (*cb)(void *, const void *, size_t), void *ctx);
int dkapture::file_watch(const char *path, DKCallback cb, void *ctx)
{
	if (cb == nullptr)
		return trace_file_deinit();

	if (path == nullptr || path[0] == 0)
	{
		char *arg0 = (char *)"dkapture";
		char *args[] = { arg0, 0 };
		return trace_file_init(1, args, cb, ctx);
	}
	else
	{
		char *arg0 = (char *)"dkapture";
		char *arg1 = (char *)"-p";
		char *arg2 = (char *)path;
		char *args[] = { arg0, arg1, arg2, 0 };
		return trace_file_init(3, args, cb, ctx);
	}
}

int kmemleak_stop(void);
int kmemleak_start(int argc, char **argv, DKapture::DKCallback cb, void *ctx);
int dkapture::kmemleak_scan_start(pid_t pid, DKCallback cb, void *ctx)
{
	char *arg0 = (char *)"dkapture";
	char *arg1 = (char *)"-p";
	char pid_s[16];
	sprintf(pid_s, "%d", pid);
	char *args[] = { arg0, arg1, pid_s, 0 };
	return kmemleak_start(3, args, cb, ctx);
}

int dkapture::kmemleak_scan_stop(void)
{
	return kmemleak_stop();
}

int mountsnoop_deinit(void);
int mountsnoop_init(int argc, char **argv, DKapture::DKCallback callback,
		    void *ctx);
int dkapture::fs_watch(const char *path, DKCallback cb, void *ctx)
{
	if (!cb)
		return mountsnoop_deinit();
	if (path == nullptr || path[0] == 0)
	{
		char *arg0 = (char *)"dkapture";
		char *args[] = { arg0, 0 };
		return mountsnoop_init(1, args, cb, ctx);
	}
	else
	{
		char *arg0 = (char *)"dkapture";
		char *arg1 = (char *)"-p";
		char *arg2 = (char *)path;
		char *args[] = { arg0, arg1, arg2, 0 };
		return trace_file_init(3, args, cb, ctx);
	}
}

int irqsnoop_deinit(void);
int irqsnoop_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);
int dkapture::irq_watch(DKCallback cb, void *ctx)
{
	if (!cb)
		return irqsnoop_deinit();

	char *arg0 = (char *)"dkapture";
	char *args[] = { arg0, 0 };
	return irqsnoop_init(1, args, cb, ctx);
}

dkapture::~dkapture()
{
	// Destructor implementation
	close();
}

DKapture *DKapture::new_instance()
{
	return new dkapture();
}