// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <cerrno>
#include <cstddef>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include <stdexcept>
#include <system_error>
#include <string>

#include "shm.h"
#include "spinlock.h"
#include "com.h"

#define VERSION 0x1234567890abcdefUL

// 所有有权限调用该so库的进程能共享的内存
static const key_t shm_key = 0x12345678;	// 共享内存的键值
static const size_t shm_size = 1024 * 1024; // 1MB
static int shm_id = -1;
static volatile SharedMemory *shm_ctl = nullptr;
// 进程级别自选锁
static long lock_obj = 0;
static SpinLock proc_lock(&lock_obj);
// 进程级别引用计数
static long proc_ref_cnt = 0;

void *SharedMemory::operator new(size_t sz)
{
	SpinLockGuard proc_lock_util_exit(&proc_lock);
	if (proc_ref_cnt > 0)
	{
		proc_ref_cnt++;
		return (void *)shm_ctl;
	}
	bool created = false;
	struct shmid_ds shm_info = {};
	std::string errmsg;
	int errcode;
	volatile long *version;
retry:
	if (created)
	{
		// 逻辑错误，shm创建成功时，是不可能走到重试逻辑的。
		errcode = ECANCELED;
		errmsg = "IPC_CREAT more than once";
		goto err_out;
	}

	shm_id = shmget(shm_key, 0, 0);
	if (shm_id == -1)
	{
		if (errno != ENOENT)
		{
			errcode = errno;
			errmsg = "shmget failed";
			goto err_out;
		}
		/**
		 * 当某些极端场景，两个进程同时走到这时，也不影响，两个进程在shmget
		 * 会发生竞争（内核完成），竞争失败的哪个会走retry流程，从而获取到
		 * 竞争成功的哪个进程创建成功的共享内存id
		 */
		shm_id = shmget(shm_key, shm_size, IPC_CREAT | IPC_EXCL | 0600);
		if (errno == EEXIST)
		{
			goto retry;
		}
		if (shm_id == -1)
		{
			throw std::system_error(
				errno,
				std::generic_category(),
				"shmget failed"
			);
		}
		created = true;
	}
	/**
	 * 代码走到这，共享内存一定创建/获取成功。
	 */
	if (shmctl(shm_id, IPC_STAT, &shm_info) < 0)
	{
		errcode = errno;
		errmsg = "shmctl failed";
		goto err_out;
	}
	if (shm_info.shm_segsz != shm_size || shm_info.shm_perm.uid != 0)
	{
		/**
		 * 共享内存大小不匹配，或者权限不匹配，说明这个共享内存不是我申请的
		 * 该shmid被占用了，退出。
		 * TODO：后续有更有方法再优化。
		 */
		errcode = EEXIST;
		errmsg = "shm_id already exists but not owned by dkapture";
		goto err_out;
	}
	shm_ctl = (typeof(shm_ctl))shmat(shm_id, nullptr, 0);
	if (shm_ctl == (void *)-1)
	{
		errcode = errno;
		errmsg = "shmat failed";
		goto err_out;
	}

	if (!check_consistency(shm_ctl))
	{
		created = true;
		memset((void *)shm_ctl, 0, shm_size);
	}

	version = &shm_ctl->version;
	if (created)
	{
		// 鉴于之前的竞争分析，只有一个进程（线程）会进入此分支
		// 初始化共享内存
		// 标注共享内存初始化完成
		*version = VERSION;
	}
	else
	{
		int timeout = 100;
		/**
		 * 这里以 VERSION 作为同步条件也不是很严谨，但考虑的 version 的
		 * 位宽是64位，重复的概率为 1/2^64，几乎不可能发生。
		 */
		while (*version != VERSION && timeout-- > 0)
		{ // 等共享内存初始化完成
			usleep(100);
		}
		/**
		 * 作为上面缺陷的最后一道防线，以及避免初始化进程同步期间异常退出导致死锁
		 */
		if (timeout <= 0)
		{
			errcode = ETIME;
			errmsg = "fail to validate shared memory";
			goto err_out;
		}
	}
	proc_ref_cnt = 1;
	return (void *)shm_ctl;
err_out:
	SharedMemory::cleanup();
	throw std::system_error(errcode, std::generic_category(), errmsg);
}

void SharedMemory::cleanup()
{
	proc_ref_cnt--;
	if (proc_ref_cnt > 0)
	{
		return;
	}
	proc_ref_cnt = 0;

	if (!shm_ctl)
	{
		return;
	}

	shmdt((void *)shm_ctl);
	shm_ctl = nullptr;

	struct shmid_ds shm_info = {};
	if (shmctl(shm_id, IPC_STAT, &shm_info) < 0)
	{
		return;
	}

	if (shm_info.shm_nattch == 0)
	{
		/**
		 * 不用考虑获取shm_info到IPC_RMID之间，shm_nattch发生改变，
		 * 出现这种情况的弊端只是旧的进程与新的进程共享的不是一块内存，
		 * 会些许降低多线程下的性能，不影响功能。
		 * 不处理的原因是，处理这种竞争场景十分复杂，并且还处理不好。
		 */
		shmctl(shm_id, IPC_RMID, nullptr);
		shm_id = -1;
	}
}

void SharedMemory::operator delete(void *ptr)
{
	SpinLockGuard proc_lock_util_exit(&proc_lock);
	SharedMemory::cleanup();
}

bool SharedMemory::check_consistency(volatile SharedMemory *shm_ctl)
{
	return SpinLock::check_consistency(&shm_ctl->data_map_lock) &&
		   SpinLock::check_consistency(&shm_ctl->ring_buffer_lock) &&
		   SpinLock::check_consistency(&shm_ctl->bpf_lock);
}

MirrorMemory::MirrorMemory(size_t bsz, int key) :
	addr(nullptr), bsz(0), shmid(-1)
{
	void *addr_mmap = nullptr;
	void *addr = nullptr;
	void *addr_mirror = nullptr;
	int shmid = -1;
	int page_size = getpagesize();

	if (bsz % page_size || bsz & (bsz - 1))
	{
		pr_error("buf size must be power of 2 and a multiple of page size");
		goto err;
	}

	/**
	 * 这里只是拿到一块没有使用的足够大的地址空间
	 * 需要的地址空间大小位 bsz * 2, mmap在第一参数指定null时，
	 * 会返回页对齐的地址，这个地址空间后面会被shmat重新映射，
	 * 所以不要munmap释放，由shmdt释放
	 */
	addr_mmap = mmap(
		nullptr,
		bsz * 2,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1,
		0
	);
	if (addr_mmap == MAP_FAILED)
	{
		pr_error("addr space exhausted: %s", strerror(errno));
		goto err;
	}

	shmid = shmget(key, bsz, IPC_CREAT | 0600);
	if (shmid < 0)
	{
		pr_error("shmget: %s", strerror(errno));
		goto err;
	}
	DEBUG(0, "mmap addr: %p, bsz: %ld", addr_mmap, bsz);
	addr = shmat(shmid, addr_mmap, SHM_REMAP);
	if (addr == (void *)-1)
	{
		pr_error("shmat: %s", strerror(errno));
		goto err;
	}
	DEBUG(0, "mirror shm 1st addr: %p", addr);
	addr_mirror = (void *)((char *)addr_mmap + bsz);
	addr_mirror = shmat(shmid, addr_mirror, SHM_REMAP);
	if (addr_mirror == (void *)-1)
	{
		pr_error("shmat: %s", strerror(errno));
		goto err;
	}
	DEBUG(0, "mirror shm 2nd addr: %p", addr_mirror);

	if (0)
	{
		// 调试代码
		*(long *)addr = 0xa0a0a0a0a0;
		*(long *)addr_mirror = 0x0a0a0a0a0a;

		if (*(long *)addr != 0x0a0a0a0a0a)
		{
			pr_error("share memory map failure");
			goto err;
		}
	}
	this->addr = addr;
	this->bsz = bsz;
	this->shmid = shmid;
	return;
err:
	if (addr != (char *)-1)
	{
		shmdt(addr);
	}
	if (addr_mirror != (char *)-1)
	{
		shmdt(addr_mirror);
	}
	if (addr_mmap != MAP_FAILED)
	{
		munmap(addr_mmap, bsz * 2);
	}
	throw std::system_error(
		errno,
		std::generic_category(),
		"mirror memory creatation failture"
		", check stdout for details"
	);
}

MirrorMemory::~MirrorMemory()
{
	size_t bsz = this->bsz;
	void *addr = this->addr;
	int shmid = this->shmid;
	void *addr_mmap = addr;
	if (addr)
	{
		/**
		 * shmdt和munmap释放只需要选择一种即可
		 * shmdt(addr);
		 * shmdt(addr_mirror);
		 */
		munmap(addr_mmap, bsz * 2);
		// 判断shmid是否还有人使用，否则删除它
		struct shmid_ds shminfo;
		if (shmctl(shmid, IPC_STAT, &shminfo) == 0)
		{
			// 此处会有竞争问题，但不影响功能
			if (shminfo.shm_nattch == 0)
			{
				shmctl(shmid, IPC_RMID, nullptr);
			}
		}
	}
}

void *MirrorMemory::getaddr() const
{
	return addr;
}

void *MirrorMemory::getmirror() const
{
	void *addr_mirror = (char *)((char *)addr + bsz);
	return addr_mirror;
}