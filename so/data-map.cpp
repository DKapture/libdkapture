// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <time.h>

#include <system_error>
#include <numeric>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "data-map.h"

/**
 * DataMap最大元素个数，如果map里全是进程数据，则单次最大记录
 * BPF_RB_MAX_ENTRY 个进程数据
 */
#define BPF_RB_MAX_ENTRY 300000

ulong round_up(ulong value, ulong alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

DataMap::DataMap()
{
	int page_size = getpagesize();
	assert((sizeof(AddrEntry) & (sizeof(AddrEntry) - 1)) == 0);
	assert((page_size % sizeof(AddrEntry)) == 0);
	assert((page_size & (page_size - 1)) == 0);
	ulong ent_sz, pow2;
	/**
	 * 将大小对其齐到页大小的整数倍和2的指数次方
	 */
	ent_sz = round_up(BPF_RB_MAX_ENTRY * sizeof(AddrEntry), page_size);
	pow2 = page_size;
	while (pow2 < ent_sz)
	{
		pow2 <<= 1;
	}
	ent_sz = pow2;
	DEBUG(0, "DataMap size: %lu", ent_sz);
	try
	{
		m_shm = new SharedMemory();
		m_bpf = new BPFManager();
		m_rb = new RingBuffer(ent_sz);
		m_lock = new SpinLock(&m_shm->data_map_lock);
		m_entrys = (typeof(m_entrys))m_rb->buf();
		m_idx = &m_shm->data_map_idx;
		m_bpf_rb = new RingBuffer(m_bpf->m_map_fd, handle_event, this);
	}
	catch (...)
	{
		this->~DataMap();
		throw;
	}

	m_ent_cnt = ent_sz / sizeof(AddrEntry);
	/**
	 * 开发期间，确保 m_ent_cnt 是 2 的指数次方
	 * 方便后续取模运算的性能优化
	 */
	DEBUG(0, "m_ent_cnt: %lu", m_ent_cnt);
	/**
	 * 如果不成立，需要调整
	 */
	assert((m_ent_cnt & (m_ent_cnt - 1)) == 0);
}

DataMap::~DataMap(void)
{
	SAFE_DELETE(m_bpf_rb);
	SAFE_DELETE(m_bpf);
	SAFE_DELETE(m_lock);
	SAFE_DELETE(m_rb);
	SAFE_DELETE(m_shm);
}

#define TIME_ns(ts) ((ts.tv_sec & 0xffffffff) * 1000000000UL + ts.tv_nsec)

void DataMap::push(ulong bpf_idx, ulong hash, ulong dsz)
{
	/**
	 * 确保是在锁保护下调用的
	 */
	assert(m_lock->try_lock() == false);
	/**
	 * TODO：
	 * 这里暂时没有考虑 *m_idx 溢出的情况
	 * 后续需要考虑
	 */
	ulong idx = (*m_idx)++;
	DEBUG(0, "DataMap push idx: %lu hash: %lx", idx, hash);
	/**
	 * 取模运算，前提是 m_ent_cnt 是 2 的指数次方
	 */
	idx &= (m_ent_cnt - 1);
	AddrEntry &ent = m_entrys[idx];
	struct timespec ts = {};
	/**
	 * 忽略 clock_gettime 调用失败，失败时，时间记录为0；
	 * 会有性能影响，但不会有功能影响
	 */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ent.data_idx = bpf_idx;
	ent.hash = hash;
	ent.dsz = dsz;
	/**
	 * 记录纳秒数，丢弃秒参数的高32位，只需低32位
	 * TODO: 检查是否有溢出问题
	 */
	ent.time = TIME_ns(ts);
}

int DataMap::sub_iterator(ulong idx, void *buf, size_t bsz) const
{
	idx &= (m_ent_cnt - 1);
	idx += m_ent_cnt;
	const AddrEntry &entry = m_entrys[idx];
	ulong cnt = entry.dsz;
	DKapture::DataType dt = KEY_DT(entry.hash);
	long st = idx - cnt;
	DEBUG(0, "sub_iterator st: %lu cnt: %lu bsz: %lu", st, cnt, bsz);
	int ret = 0;
	for (ulong i = st; i < idx; i++)
	{
		if (KEY_DT(m_entrys[i].hash) != dt)
		{
			continue;
		}
		DKapture::DataHdr *dh;
		dh = (typeof(dh))m_bpf_rb->buf(m_entrys[i].data_idx);
		DEBUG(
			0,
			"sub_iterator i: %lu idx: %lu hash: %lx",
			i,
			m_entrys[i].data_idx,
			m_entrys[i].hash
		);
		if (buf)
		{
			if (bsz < dh->dsz)
			{
				pr_error(
					"dkapture::read: buffer size is too small, %lu needed, %lu "
					"provided",
					dh->dsz,
					bsz
				);
				return -ENOBUFS;
			}
			memcpy((char *)buf + ret, dh, dh->dsz);
		}
		else if (m_user_cb)
		{
			/**
			 * 这里需要注意，m_user_cb 是用户传入的函数指针
			 * 需要保证线程安全
			 */
			DEBUG(0, "sub_iterator callback");
			int ret = m_user_cb(m_user_ctx, dh, dh->dsz);
			if (0 != ret)
			{
				return ret;
			}
		}
		ret += dh->dsz;
		bsz -= dh->dsz;
	}
	return ret;
}

int DataMap::handle_event(void *ctx, void *data, size_t data_sz)
{
	/**
	 * 确保是在锁保护下调用的
	 */
	DataMap &dm = *(DataMap *)ctx;
	assert(dm.m_lock->try_lock() == false);
	const struct DKapture::DataHdr *msg = (typeof(msg))data;
	if (0 && msg->pid > 7)
	{ // 调试代码
		return 0;
	}
	assert(sizeof(std::size_t) == sizeof(ulong));
	ulong key = ((ulong)msg->pid << 32) + msg->type;
	ulong idx = dm.m_bpf_rb->get_consumer_index();
	DEBUG(0, "[msg] type: %d pid: %d hash: %lx", msg->type, msg->pid, key);
	DEBUG(0, "ring buffer comsumer idx: %lu", idx);
	DEBUG(0, "idx: %lu msg %lx dsz %ld", idx, msg, msg->dsz);
	dm.push(idx, key, data_sz);
	/**
	 * TODO：还没有处理过量进程，导致单次遍历，自身的新数据把旧数据覆盖的场景
	 * if (dm.m_user_cb)
	 * {
	 *     int ret = dm.m_user_cb(dm.m_user_ctx, msg, data_sz);
	 *     if (ret < 0)
	 *     {
	 *         pr_error("callback failed: %d", ret);
	 *         return ret;
	 *     }
	 * }
	 */
	return 0;
}

int DataMap::update(DKapture::DataType dt)
{
	int err;
	ssize_t rd_sz;
	char buf[8]; // 实际上并没有使用
	int fd;
	ulong sidx = *m_idx;
	/**
	 * 确保是在锁保护下调用的
	 */
	assert(m_lock->try_lock() == false);
	if (m_bpf->m_obj)
	{
		fd = bpf_create_iter(m_bpf->m_obj->links.dump_task, return -1);
	}
	else
	{
		fd = ::open(m_bpf->m_proc_iter_link_path.c_str(), O_RDONLY);
	}
	if (fd < 0)
	{
		pr_error(
			"bpf_iter_create (%s): %s",
			m_bpf->m_proc_iter_link_path.c_str(),
			strerror(errno)
		);
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
	m_bpf->dump_task_file();

	while ((err = m_bpf_rb->poll(0)) > 0)
	{
	}

	if (err < 0)
	{
		pr_error("Error polling ring buffer: %d", err);
	}
	ulong dsz = *m_idx - sidx;
	ulong bpf_idx = m_bpf_rb->get_consumer_index();
	/**
	 * TODO: 根据 dt 缩小更新粒度
	 */
	this->push(bpf_idx, DKapture::PROC_PID_IO, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_STAT, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_traffic, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_STATM, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_SCHEDSTAT, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_FD, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_STATUS, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_NS, dsz++);
	this->push(bpf_idx, DKapture::PROC_PID_LOGINUID, dsz++);
	DEBUG(0, "update called");
	return 0;
}

int DataMap::async_update(DKapture::DataType dt)
{
	/**
	 * TODO:
	 */
	return 0;
}

int DataMap::unsafe_find(ulong hash, ulong lifetime, void *buf, size_t bsz)
{
	/**
	 * 确保是在锁保护下调用的
	 */
	assert(m_lock->try_lock() == false);
	long sidx = get_round_idx();
	long eidx = sidx + m_ent_cnt - 1;
	lifetime *= 1000000UL;
	struct timespec ts = {};
	DKapture::DataHdr *dh;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ulong now = TIME_ns(ts);
	ulong bpf_bsz = m_bpf_rb->get_bsz();
	ulong prod_idx = m_bpf_rb->get_producer_index();
	DEBUG(0, "map raw idx: %lu round idx: %lu", *m_idx, sidx);
	for (long i = eidx; i >= sidx; i--)
	{
		if (m_entrys[i].hash)
		{
			DEBUG(
				0,
				"i: %lu rb-idx: %lu hash: %lx vs %lx",
				i,
				m_entrys[i].data_idx,
				m_entrys[i].hash,
				hash
			);
		}
		/**
		 * m_entrys 中的下标和 bpf ring buffer中的下标都是正相关对应的
		 * bpf ringbuffer中有效范围是 [prod_idx-bpf_bsz, prod_idx)，
		 * 这个窗口可以被认为是一直在朝较大的方向滑动的，
		 * m_entrys 中的窗口范围是 [sidx, eidx]，并且，递增指向bpf ringbuffer
		 * ，如果有一个 m_entrys[i].data_idx 小于 prod_idx - bpf_bsz，
		 * 则说明这个 m_entrys[i] 中的数据和小于i索引的数据都已经过期。
		 * 如示意图：
		 *
		 *        m_entrys                bpf ring buffer
		 *     |           |          |                     |
		 *     |           |          |                     |
		 *   | |***********|--------->|                     |
		 *   | |***********|          |                     |
		 *   | |***********|          |*********************| | 滑
		 *   | |***********|          |*********************| | 动
		 *   | |***********|          |*********************| | 方
		 *   V |***********|--------->|*********************| v 向
		 *     |           |          |                     |
		 *     |           |          |                     |
		 */
		ulong rb_idx = m_entrys[i].data_idx;
		if (unlikely(rb_idx + bpf_bsz < prod_idx))
		{
			DEBUG(
				0,
				"expired data idx: %lu, prod_idx: %lu, bpf_bsz: %lu",
				rb_idx,
				prod_idx,
				bpf_bsz
			);
			break;
		}

		if (likely(m_entrys[i].hash != hash))
		{
			continue;
		}

		DEBUG(
			0,
			"time(%lu) cmp: %lu vs %lu",
			lifetime,
			m_entrys[i].time + lifetime,
			now
		);
		if (m_entrys[i].time + lifetime < now)
		{
			DEBUG(0, "data out of date");
			return -ETIME;
		}

		if (KEY_PID(hash) == 0)
		{
			// 所有进程数据
			DEBUG(0, "iterator all type %d", hash);
			return sub_iterator(i, buf, bsz);
		}

		dh = (typeof(dh))m_bpf_rb->buf(m_entrys[i].data_idx);
		if (bsz < dh->dsz)
		{
			pr_error(
				"dkapture::read: buffer size is too small, %lu needed, %lu "
				"privided",
				dh->dsz,
				bsz
			);
			return -ENOBUFS;
		}
		memcpy(buf, dh, dh->dsz);
		return dh->dsz;
	}
	return -ENOENT;
}

ulong DataMap::unsafe_find(ulong bpf_idx) const
{
	long idx = get_round_idx();
	long l = idx;
	long r = idx + m_ent_cnt - 1;
	long i;
	ulong rb_idx;
	/**
	 * TODO：
	 * 这里暂时没有考虑 data_idx 溢出的情况
	 * 后续需要考虑
	 */
	while (l <= r)
	{
		i = (l + r) / 2;
		rb_idx = m_entrys[i].data_idx;
		if (rb_idx == bpf_idx)
		{
			return i;
		}
		else if (rb_idx < bpf_idx)
		{
			l = i + 1;
		}
		else
		{
			r = i - 1;
		}
	}
	return ULONG_MAX;
}

long DataMap::get_round_idx() const
{
	/**
	 * 确保 idx 在 m_ent_cnt ~ 2 * m_ent_cnt范围内
	 * 因为 m_entrys 是双倍地址空间映射的，所以，idx范围
	 * 不会访问越界。
	 */
	long idx = *m_idx;
	idx &= (m_ent_cnt - 1);
	return idx;
}

int DataMap::find(ulong hash, ulong lifetime, void *buf, size_t bsz)
{
	/**
	 * TODO: buf传入非法地址，导致异常访问段错误时，
	 * 共享自旋锁没有解锁。
	 */
	int ret;
	SpinLockGuard lock_util_exit(m_lock);
	ret = unsafe_find(hash, lifetime, buf, bsz);
	if (ret > 0)
	{
		return ret;
	}
	/**
	 * update data and try again
	 */
	ret = update(KEY_DT(hash));
	if (ret != 0)
	{
		return ret;
	}
	ret = unsafe_find(hash, lifetime, buf, bsz);
	return ret;
}

void DataMap::list_all_entrys(void)
{
	SpinLockGuard lock_util_exit(m_lock);
	long sidx = get_round_idx();
	long eidx = sidx + m_ent_cnt;
	for (long i = sidx; i < eidx; i++)
	{
		if (m_entrys[i].hash == 0)
		{
			continue;
		}
		AddrEntry &ent = m_entrys[i];
		pr_info(
			"idx: %lu, data_idx: %lu, hash: %lx, time: %lu",
			i,
			ent.data_idx,
			ent.hash,
			ent.time
		);
	}
}