// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include "types.h"
#include <bpf/libbpf.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "shm.h"
#include "spinlock.h"

// 跨进程共享ring buffer
class RingBuffer
{
#ifdef __GTEST__
  public:
#else
  private:
#endif
	long type = 0;
	/**
	 * totle buffer size, it must be a power of 2 and a multiple of the page
	 * size
	 */
	size_t bsz = 0;
	int page_size;
	volatile ulong *comsumer_index;
	volatile ulong *producer_index;
	volatile void *data = nullptr;
	volatile void *data_mirror = nullptr;
	union
	{
		struct
		{
			int epoll_fd;
			int map_fd;
			void *ctx;
			ulong rci; // locked consumer index
			ring_buffer_sample_fn cb;
		};
		struct
		{
			SharedMemory *shm_ctl = nullptr;
			SpinLock *spinlock = nullptr;
			MirrorMemory *mirror_shm = nullptr;
		};
	};

  public:
	RingBuffer(int map_fd, ring_buffer_sample_fn cb, void *ctx);
	~RingBuffer();
	int poll(int timeout);
	ulong get_consumer_index(void) const;
	ulong get_producer_index(void) const;
	size_t get_bsz() const;

#define RING_BUF_TYPE_BPF 0
#define RING_BUF_TYPE_NORMAL 1
	RingBuffer(size_t bsz);
	size_t write(void *data, size_t dsz);
	size_t read(void *data, size_t dsz);
	void *buf(ulong idx = 0);
};