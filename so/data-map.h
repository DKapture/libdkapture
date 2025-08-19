#pragma once
#include "limits.h"

#include "ring-buffer.h"
#include "shm.h"
#include "spinlock.h"
#include "Ucom.h"
#include "dkapture.h"
#include "bpf.h"

#define MK_KEY(pid, dt) (((ulong)pid << 32) + dt)
#define KEY_PID(key) (key >> 32)
#define KEY_DT(key) ((DKapture::DataType)(key & 0XFFFFFFFF))

struct AddrEntry
{ // 需要能被page_size整除
	ulong data_idx;
	ulong hash;
	ulong time;
	ulong dsz;
};

class DataMap
{
#ifdef __GTEST__
    public:
#else
    private:
#endif
	AddrEntry *m_entrys = nullptr;
	RingBuffer *m_rb = nullptr;
	BPF *m_bpf = nullptr;
	RingBuffer *m_bpf_rb = nullptr;
	SharedMemory *m_shm = nullptr;
	SpinLock *m_lock = nullptr;
	long m_ent_cnt = 0;
	volatile long *m_idx = nullptr;
	DKapture::DKCallback m_user_cb = nullptr;
	void *m_user_ctx = nullptr;

	int unsafe_find(ulong hash, ulong lifetime, void *buf, size_t bsz);
	ulong unsafe_find(ulong bpf_idx) const;
	int sub_iterator(ulong si, void *buf, size_t bsz) const;
	long get_round_idx() const;
	int update(DKapture::DataType dt);
	int async_update(DKapture::DataType dt);
	void push(ulong bpf_idx, ulong hash, ulong dsz);
	static int handle_event(void *ctx, void *data, size_t data_sz);

    public:
	DataMap();
	~DataMap();
	int find(ulong hash, ulong lifetime, void *buf, size_t bsz);
	void list_all_entrys(void);
	void set_iterator(DKapture::DKCallback cb, void *ctx)
	{
		m_user_cb = cb;
		m_user_ctx = ctx;
	}
};