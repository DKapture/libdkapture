// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#pragma once
#include "limits.h"

#include "shm.h"
#include "spinlock.h"
#include "com.h"
#include "proc-info.skel.h"

class BPFManager
{
#ifdef __GTEST__
  public:
#else
  private:
#endif
	SharedMemory *m_shm = nullptr;
	SpinLock *m_bpf_lock = nullptr;
	volatile long *bpf_ref_cnt = 0;
	int m_map_id = 0; // 调试使用，无逻辑影响
	int bpf_task_iter_fd = -1;
	std::string m_dump_task_file;

	int bpf_find_map(const char *name);
	std::string bpf_find_iter(const char *name);
	int bpf_pin_links(const char *pin_dir);
	int bpf_pin_programs(const char *path);
	int bpf_pin_maps(const char *path);
	static int handle_event(void *ctx, void *data, size_t data_sz);

  public:
	int m_map_fd = -1;
	proc_info_bpf *m_obj = nullptr;
	std::string m_proc_iter_link_path;
	int dump_task_file(void);

	BPFManager();
	~BPFManager();
};