// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#pragma once

#include "dkapture.h"
#include <assert.h>
#include <vector>
#include <cstring>
#include <cstdlib>

/**
 * @brief 生成模拟进程数据，用于测试和演示
 * @param num_processes 要生成的进程数量
 * @return
 * 返回包含所有进程数据的vector，每个元素是一个map，key为数据类型，value为对应的结构体数据
 */
inline std::vector<DKapture::DataHdr *>
generate_mock_process_data(int num_processes = 3)
{
	std::vector<DKapture::DataHdr *> result;

	for (int i = 0; i < num_processes; ++i)
	{
		DKapture::DataHdr *dh;

		// 生成 ProcPidTraffic 数据
		dh = (DKapture::DataHdr *)
			calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidTraffic));
		assert(dh);
		dh->type = DKapture::PROC_PID_traffic;
		dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidTraffic);
		dh->pid = 1000 + i;
		dh->tgid = 1000 + i;
		strcpy(dh->comm, "test");
		ProcPidTraffic *traffic = (ProcPidTraffic *)dh->data;
		traffic->rbytes = 1024 * 1024 * (i + 1); // 1MB, 2MB, 3MB...
		traffic->wbytes = 512 * 1024 * (i + 1);	 // 512KB, 1MB, 1.5MB...
		result.push_back(dh);

		// 生成 ProcPidStatus 数据
		dh = (DKapture::DataHdr *)
			calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidStatus));
		assert(dh);
		dh->type = DKapture::PROC_PID_STATUS;
		dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidStatus);
		dh->pid = 1000 + i;
		dh->tgid = 1000 + i;
		strcpy(dh->comm, "test");
		ProcPidStatus *status = (ProcPidStatus *)dh->data;
		status->umask = 022;
		status->state = 0x01; // S (sleeping)
		status->tracer_pid = 0;
		status->uid[0] = 1000 + i; // uid
		status->uid[1] = 1000 + i; // euid
		status->uid[2] = 1000 + i; // suid
		status->uid[3] = 1000 + i; // fsuid
		status->gid[0] = 1000 + i; // gid
		status->gid[1] = 1000 + i; // egid
		status->gid[2] = 1000 + i; // sgid
		status->gid[3] = 1000 + i; // fsgid
		result.push_back(dh);

		// 生成 ProcPidFd 数据 (模拟3个文件描述符)
		for (int fd_idx = 0; fd_idx < 3; ++fd_idx)
		{
			dh = (DKapture::DataHdr *)
				calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidFd));
			assert(dh);
			dh->type = DKapture::PROC_PID_FD;
			dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidFd);
			dh->pid = 1000 + i;
			dh->tgid = 1000 + i;
			strcpy(dh->comm, "test");
			ProcPidFd *fd = (ProcPidFd *)dh->data;
			fd->inode = 1000000 + i * 1000 + fd_idx;
			fd->fd = fd_idx;
			fd->dev = 0x801;   // 主设备号8，次设备号1
			fd->i_mode = 0644; // rw-r--r--
			result.push_back(dh);
		}

		// 生成 ProcPidSchedstat 数据
		dh = (DKapture::DataHdr *)
			calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidSchedstat));
		assert(dh);
		dh->type = DKapture::PROC_PID_SCHEDSTAT;
		dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidSchedstat);
		dh->pid = 1000 + i;
		dh->tgid = 1000 + i;
		strcpy(dh->comm, "test");
		ProcPidSchedstat *schedstat = (ProcPidSchedstat *)dh->data;
		schedstat->cpu_time = 1000000 + i * 100000;	 // CPU时间
		schedstat->rq_wait_time = 50000 + i * 10000; // 运行队列等待时间
		schedstat->timeslices = 100 + i * 50;		 // 时间片数量
		result.push_back(dh);

		// 生成 ProcPidIo 数据
		dh = (DKapture::DataHdr *)
			calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidIo));
		assert(dh);
		dh->type = DKapture::PROC_PID_IO;
		dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidIo);
		dh->pid = 1000 + i;
		dh->tgid = 1000 + i;
		strcpy(dh->comm, "test");
		ProcPidIo *io = (ProcPidIo *)dh->data;
		io->rchar = 2048 * 1024 + i * 1024 * 1024; // 读取字符数
		io->wchar = 1024 * 1024 + i * 512 * 1024;  // 写入字符数
		io->syscr = 1000 + i * 100;				   // 系统调用读取次数
		io->syscw = 500 + i * 50;				   // 系统调用写入次数
		io->read_bytes = 1024 * 1024 + i * 512 * 1024; // 读取字节数
		io->write_bytes = 512 * 1024 + i * 256 * 1024; // 写入字节数
		io->cancelled_write_bytes = 0; // 取消的写入字节数
		result.push_back(dh);

		// 生成 ProcPidStatm 数据
		dh = (DKapture::DataHdr *)
			calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidStatm));
		assert(dh);
		dh->type = DKapture::PROC_PID_STATM;
		dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidStatm);
		dh->pid = 1000 + i;
		dh->tgid = 1000 + i;
		strcpy(dh->comm, "test");
		ProcPidStatm *statm = (ProcPidStatm *)dh->data;
		statm->size = 100000 + i * 10000;	// 虚拟内存大小
		statm->resident = 50000 + i * 5000; // 常驻内存大小
		statm->shared = 10000 + i * 1000;	// 共享内存大小
		statm->text = 20000 + i * 2000;		// 代码段大小
		statm->data = 30000 + i * 3000;		// 数据段大小
		result.push_back(dh);

		// 生成 ProcPidStat 数据
		dh = (DKapture::DataHdr *)
			calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidStat));
		assert(dh);
		dh->type = DKapture::PROC_PID_STAT;
		dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidStat);
		dh->pid = 1000 + i;
		dh->tgid = 1000 + i;
		strcpy(dh->comm, "test");
		ProcPidStat *stat = (ProcPidStat *)dh->data;
		stat->state = 0x01;							 // S (sleeping)
		stat->ppid = 1;								 // 父进程ID
		stat->pgid = 1000 + i;						 // 进程组ID
		stat->sid = 1000 + i;						 // 会话ID
		stat->tty_nr = 0;							 // 控制终端
		stat->tty_pgrp = -1;						 // 终端进程组
		stat->flags = 0x400000;						 // 进程标志
		stat->cmin_flt = 100 + i * 10;				 // 子进程缺页中断
		stat->cmaj_flt = 10 + i;					 // 子进程主缺页中断
		stat->min_flt = 500 + i * 50;				 // 缺页中断
		stat->maj_flt = 50 + i * 5;					 // 主缺页中断
		stat->utime = 1000000 + i * 100000;			 // 用户态时间
		stat->stime = 500000 + i * 50000;			 // 内核态时间
		stat->cutime = 200000 + i * 20000;			 // 子进程用户态时间
		stat->cstime = 100000 + i * 10000;			 // 子进程内核态时间
		stat->priority = 20;						 // 优先级
		stat->nice = 0;								 // nice值
		stat->num_threads = 1 + i;					 // 线程数
		stat->start_time = 1000000000 + i * 1000000; // 启动时间
		stat->vsize = 100000000 + i * 10000000;		 // 虚拟内存大小
		stat->rss = 50000 + i * 5000;				 // 常驻内存大小
		stat->rsslim = 18446744073709551615ULL;		 // 内存限制
		stat->start_code = 0x400000;				 // 代码段起始地址
		stat->end_code = 0x400000 + 20000 + i * 2000; // 代码段结束地址
		stat->start_stack = 0x7fffffffe000;			  // 栈起始地址
		stat->kstkesp = 0x7fffffffe000;				  // 内核栈指针
		stat->kstkeip = 0x7f1234567890;				  // 内核栈指令指针
		stat->signal = 0;							  // 待处理信号
		stat->blocked = 0;							  // 阻塞信号
		stat->sigignore = 0;						  // 忽略信号
		stat->sigcatch = 0;							  // 捕获信号
		stat->wchan = 0;							  // 等待通道
		stat->exit_signal = 17;						  // 退出信号
		stat->processor = i % 4;					  // CPU编号
		stat->rt_priority = 0;						  // 实时优先级
		stat->policy = 0;							  // 调度策略
		stat->delayacct_blkio_ticks = 1000 + i * 100; // 块IO延迟
		stat->guest_time = 0;						  // 客户时间
		stat->cguest_time = 0;						  // 子进程客户时间
		stat->start_data = 0x600000;				  // 数据段起始地址
		stat->end_data = 0x600000 + 30000 + i * 3000; // 数据段结束地址
		stat->start_brk = 0x800000;					  // 堆起始地址
		stat->arg_start = 0x7fffffffe000;			  // 参数起始地址
		stat->arg_end = 0x7fffffffe100;				  // 参数结束地址
		stat->env_start = 0x7fffffffe200; // 环境变量起始地址
		stat->env_end = 0x7fffffffe300;	  // 环境变量结束地址
		stat->exit_code = 0;			  // 退出码
		result.push_back(dh);

		// 生成 ProcPidSock 数据 (模拟2个套接字)
		for (int sock_idx = 0; sock_idx < 2; ++sock_idx)
		{
			dh = (DKapture::DataHdr *)
				calloc(1, sizeof(DKapture::DataHdr) + sizeof(ProcPidSock));
			assert(dh);
			dh->type = DKapture::PROC_PID_sock;
			dh->dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidSock);
			dh->pid = 1000 + i;
			dh->tgid = 1000 + i;
			strcpy(dh->comm, "test");
			ProcPidSock *sock = (ProcPidSock *)dh->data;
			sock->fd = 10 + sock_idx; // 套接字文件描述符
			sock->ino = 2000000 + i * 1000 + sock_idx; // inode编号
			sock->family = 2;						   // AF_INET
			sock->type = 1;							   // SOCK_STREAM
			sock->state = 1;						   // TCP_ESTABLISHED
			sock->lip = 0x0100007f; // 127.0.0.1 (网络字节序)
			sock->rip = 0x0100007f; // 127.0.0.1 (网络字节序)
			sock->lport = 8080 + i * 100 + sock_idx; // 本地端口
			sock->rport = 80 + sock_idx;			 // 远程端口
			result.push_back(dh);
		}
	}

	return result;
}

/**
 * @brief 清理模拟进程数据，释放内存
 * @param data 要清理的数据
 */
inline void cleanup_mock_process_data(std::vector<DKapture::DataHdr *> &data)
{
	for (auto *dh : data)
	{
		free(dh);
	}
	data.clear();
}
