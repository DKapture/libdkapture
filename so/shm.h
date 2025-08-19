#pragma once
#include "stddef.h"

class SharedMemory
{
	/**
     * 以下这些变量全在共享内存当中，整个类也是POD类型，所以请不要定义非POD类型的数据变量
     */
    private:
	/**
     * 共享内存系统级别独享一份，所以在通过代码宏进行预分配
     */
	// SharedMemory对象自身使用
	volatile long version;

    public:
	// 共有变量
	struct // BPF使用
	{
		volatile long bpf_lock;
		volatile long bpf_ref_cnt;
	};
	struct
	{
		volatile long ring_buffer_lock;
		volatile long ring_buffer_ref_cnt;
	};
	struct // DataMap类使用
	{
		volatile long data_map_lock;
		volatile long data_map_idx;
		volatile long data_map_ref_cnt;
	};

    private:
	// 禁用拷贝构造函数
	SharedMemory(const SharedMemory &) = delete;
	volatile void *operator=(const SharedMemory &) = delete;
	void *operator new[](size_t sz) = delete;
	void operator delete[](void *ptr) = delete;
	static bool check_consistency(volatile SharedMemory *shm_ctl);
	static void cleanup();

    public:
	void *operator new(size_t sz);
	void operator delete(void *ptr);
	SharedMemory(){};
	~SharedMemory(){};
};