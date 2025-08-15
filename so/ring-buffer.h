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
     * totle buffer size, it must be a power of 2 and a multiple of the page size
     */
    size_t bsz = 0;
    int page_size;
    union
    {
        struct
        {
            int epoll_fd;
            int map_fd;
            void *ctx;
            ulong rci; // locked consumer index
            volatile ulong *comsumer_index;
            volatile ulong *producer_index;
            ring_buffer_sample_fn cb;
        };
        struct
        {
            size_t rdi = 0;
            size_t wri = 0;
            int shmid = -1;
        };
    };
    volatile void *data_mirror = nullptr;
    volatile void *data = nullptr;
    SharedMemory *shm_ctl = nullptr;
    SpinLock *spinlock = nullptr;
    volatile long *rb_ref_cnt = 0;

public:
    RingBuffer(int map_fd, ring_buffer_sample_fn cb, void *ctx);
    ~RingBuffer();
    int poll(int timeout);
    ulong get_consumer_index(void) { return *comsumer_index; }
    ulong get_producer_index(void) { return *producer_index; }
    size_t get_bsz() const { return bsz; }

#define RING_BUF_TYPE_BPF 0
#define RING_BUF_TYPE_NORMAL 1
    RingBuffer(size_t bsz);
    size_t write(void *data, size_t dsz);
    size_t read(void *data, size_t dsz);
    void *buf(ulong idx = 0);
};