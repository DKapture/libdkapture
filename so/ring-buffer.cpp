#include <errno.h>
#include <sys/epoll.h>
#include <sys/mman.h>

#include <string>
#include <exception>
#include <sys/types.h>
#include <system_error>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "Ucom.h"
#include "Ulog.h"
#include "ring-buffer.h"

#define RING_BUF_TYPE_BPF 0
#define RING_BUF_TYPE_NORMAL 1

RingBuffer::RingBuffer(int map_fd, ring_buffer_sample_fn cb, void *ctx) :
	page_size(0), comsumer_index(NULL), producer_index(NULL), epoll_fd(-1),
	map_fd(-1), ctx(ctx), rci(0), cb(cb)
{
	struct bpf_map_info info;
	struct epoll_event ee;
	std::string err_msg;
	std::system_error exc;
	uint32_t len = sizeof(info);
	page_size = getpagesize();
	this->type = RING_BUF_TYPE_BPF;
	this->map_fd = map_fd;
	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0)
	{
		exc = std::system_error(
			errno,
			std::generic_category(),
			"failed to create epoll instance"
		);
		pr_error("create ring-buffer: %s", exc.what());
		goto err_out;
	}
	if (0 != bpf_map_get_info_by_fd(map_fd, &info, &len))
	{
		exc = std::system_error(
			errno,
			std::generic_category(),
			"bpf_map_get_info_by_fd"
		);
		pr_error("create ring-buffer: %s", exc.what());
		goto err_out;
	}
	if (info.type != BPF_MAP_TYPE_RINGBUF)
	{
		exc = std::system_error(
			EINVAL,
			std::generic_category(),
			"not a ring buffer map"
		);
		pr_error("create ring-buffer: %s", exc.what());
		goto err_out;
	}
	bsz = info.max_entries;
	DEBUG(0, "ring buffer size: %d", bsz);

	comsumer_index = (ulong *)
		mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (comsumer_index == MAP_FAILED)
	{
		exc = std::system_error(
			errno,
			std::generic_category(),
			"failed to mmap consumer page"
		);
		pr_error("create ring-buffer(%d): %s", map_fd, exc.what());
		goto err_out;
	}

	producer_index = (ulong *)mmap(
		NULL,
		page_size + 2 * bsz,
		PROT_READ,
		MAP_SHARED,
		map_fd,
		page_size
	);
	if (producer_index == MAP_FAILED)
	{
		exc = std::system_error(
			errno,
			std::generic_category(),
			"failed to mmap producer page"
		);
		pr_error("create ring-buffer: %s", exc.what());
		goto err_out;
	}
	data = (char *)producer_index + page_size;
	ee.events = EPOLLIN;
	ee.data.fd = map_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, map_fd, &ee) < 0)
	{
		exc = std::system_error(
			errno,
			std::generic_category(),
			"failed to add map fd to epoll"
		);
		pr_error("create ring-buffer: %s", exc.what());
		goto err_out;
	}
	return;
err_out:
	this->~RingBuffer();
	throw exc;
}

RingBuffer::RingBuffer(size_t bsz) : mirror_shm(nullptr)
{
	try
	{
		shm_ctl = new SharedMemory();
		spinlock = new SpinLock(&shm_ctl->ring_buffer_lock);
		comsumer_index = &shm_ctl->rdi;
		producer_index = &shm_ctl->wri;
	}
	catch (...)
	{
		this->~RingBuffer();
		throw;
	}
	type = RING_BUF_TYPE_NORMAL;
	key_t key = 0x12345678 + bsz;
	try
	{
		mirror_shm = new MirrorMemory(bsz, key);
	}
	catch (...)
	{
		this->~RingBuffer();
		throw;
	}
	this->data = mirror_shm->getaddr();
	this->bsz = bsz;
	return;
}

RingBuffer::~RingBuffer()
{
	if (type == RING_BUF_TYPE_NORMAL)
	{
		if (spinlock)
		{
			delete spinlock;
			spinlock = nullptr;
		}

		if (mirror_shm)
		{
			delete mirror_shm;
			mirror_shm = nullptr;
		}

		if (shm_ctl)
		{
			delete shm_ctl;
			shm_ctl = nullptr;
		}
	}
	else
	{
		if ((ulong)comsumer_index > 0)
		{
			munmap((void *)comsumer_index, page_size);
			comsumer_index = NULL;
		}
		if ((ulong)producer_index > 0)
		{
			munmap((void *)producer_index, page_size + 2 * bsz);
			producer_index = NULL;
		}
		if (epoll_fd > 0)
		{
			close(epoll_fd);
			epoll_fd = -1;
		}
	}
}

size_t RingBuffer::write(void *data, size_t dsz)
{
	spinlock->lock();
	size_t wri = *producer_index;
	size_t rdi = *comsumer_index;
	// in case overflow happens when usz + dsz
	size_t usz = wri - rdi;
	if (usz + dsz > bsz)
	{
		dsz = bsz - usz;
	}
	size_t off = wri % bsz;
	memcpy((char *)this->data + off, data, dsz);
	wri += dsz;
	*producer_index = wri;
	spinlock->unlock();
	return dsz;
}

size_t RingBuffer::read(void *data, size_t dsz)
{
	spinlock->lock();
	size_t wri = *producer_index;
	size_t rdi = *comsumer_index;
	size_t usz = wri - rdi;
	if (usz < dsz)
	{
		dsz = usz;
	}
	size_t off = rdi & (bsz - 1);
	memcpy(data, (char *)this->data + off, dsz);
	rdi += dsz;
	*comsumer_index = rdi;
	spinlock->unlock();
	return dsz;
}

void *RingBuffer::buf(ulong idx)
{
	if (type == RING_BUF_TYPE_BPF)
	{
		idx += BPF_RINGBUF_HDR_SZ;
	}

	idx &= (bsz - 1);
	return (char *)data + idx;
}

static inline int roundup_len(int len)
{
	/* clear out top 2 bits (discard and busy, if set) */
	len <<= 2;
	len >>= 2;
	/* add length prefix */
	len += BPF_RINGBUF_HDR_SZ;
	/* round up to 8 byte alignment */
	return (len + 7) / 8 * 8;
}

int RingBuffer::poll(int timeout)
{
	if (type != RING_BUF_TYPE_BPF)
	{
		return -EINVAL;
	}

	int err;
	struct epoll_event events;
	int cnt = epoll_wait(epoll_fd, &events, 1, timeout);
	if (cnt < 0)
	{
		return (-errno);
	}

	if (cnt == 0)
	{
		return 0;
	}

	if (events.data.fd != map_fd)
	{
		pr_error(
			"ringbuf: epoll_wait returned unexpected fd %d",
			events.data.fd
		);
		return -1;
	}

	void *sample;
	cnt = 0;
	rci = *comsumer_index;

	DEBUG(0, "producer: %ld comsumer: %ld", *producer_index, *comsumer_index);
	assert(*producer_index >= *comsumer_index);

	while (rci < *producer_index)
	{
		volatile int *plen = (int *)((char *)data + (rci & (bsz - 1)));
		int len = *plen;
		if (len & BPF_RINGBUF_BUSY_BIT)
		{
			break;
		}
		rci += roundup_len(len);

		if ((len & BPF_RINGBUF_DISCARD_BIT) == 0)
		{
			sample = (char *)plen + BPF_RINGBUF_HDR_SZ;
			err = cb(ctx, sample, len);
			if (err < 0)
			{
				return err;
			}
			cnt++;
		}
		/* update consumer pos */
		*comsumer_index = rci;
	}
	return cnt;
}

ulong RingBuffer::get_consumer_index(void) const
{
	return *comsumer_index;
}
ulong RingBuffer::get_producer_index(void) const
{
	return *producer_index;
}
size_t RingBuffer::get_bsz() const
{
	return bsz;
}