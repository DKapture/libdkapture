// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include <linux/bpf.h>
#include "data-map.h"

class DataMapTest : public ::testing::Test
{
  protected:
	DataMap *data_map;

	void SetUp() override
	{
		data_map = new DataMap();
	}

	void TearDown() override
	{
		delete data_map;
	}
};

static int bpf_ringbuffer_push(
	RingBuffer *m_bpf_rb,
	int bpf_idx,
	DKapture::DataHdr *dh
)
{
	int ret = 0;
	size_t page_size = getpagesize();
	// bpf ringbuffer中前两个页是控制数据结构。
	bpf_idx += page_size * 2 + BPF_RINGBUF_HDR_SZ;
	ret = lseek(m_bpf_rb->map_fd, bpf_idx, SEEK_SET);
	if (ret < 0)
	{
		return -1;
	}
	return write(m_bpf_rb->map_fd, dh, sizeof(DKapture::DataHdr) + dh->dsz);
}

TEST_F(DataMapTest, PushAndFind)
{
	ulong bpf_idx = 8;
	pid_t pid = 0x8888;
	ulong hash = MK_KEY(pid, DKapture::PROC_PID_STAT);
	ulong dsz = 128;

	// bpf系统接口被我们mock了，所以这里需要手动设置数据，模拟bpf系统接口的行为
	DKapture::DataHdr *dh = (typeof(dh))malloc(sizeof(DKapture::DataHdr) + dsz);
	assert(dh);
	dh->type = DKapture::PROC_PID_STAT;
	dh->pid = pid;
	dh->dsz = dsz;
	strcpy(dh->comm, "test");
	bpf_ringbuffer_push(data_map->m_bpf_rb, bpf_idx, dh);
	free(dh);

	data_map->m_lock->lock();
	// Push an entry into the DataMap
	data_map->push(bpf_idx, hash, dsz);
	data_map->m_lock->unlock();

	// Find the entry
	char buffer[256] = {};
	int ret = data_map->find(hash, 1000, buffer, sizeof(buffer));

	// Verify the result
	ASSERT_GT(ret, 0);
	ASSERT_EQ(((DKapture::DataHdr *)buffer)->type, DKapture::PROC_PID_STAT);
	ASSERT_EQ(((DKapture::DataHdr *)buffer)->pid, pid);
	ASSERT_STREQ(((DKapture::DataHdr *)buffer)->comm, "test");
}

TEST_F(DataMapTest, data_expired)
{
	ulong bpf_idx = 8;
	pid_t pid = 0x8888;
	ulong hash = MK_KEY(pid, DKapture::PROC_PID_STAT);
	ulong dsz = 128;

	data_map->m_lock->lock();
	// Push an entry into the DataMap
	data_map->push(bpf_idx, hash, dsz);
	data_map->m_lock->unlock();

	usleep(10000);
	// Try to find the invalidated entry
	char buffer[256] = {};
	int ret = data_map->find(hash, 10, buffer, sizeof(buffer));

	// Verify the entry is invalidated
	EXPECT_EQ(ret, -ETIME);
}

TEST_F(DataMapTest, ListAllEntries)
{
	DKapture::DataHdr *dh =
		(typeof(dh))malloc(sizeof(DKapture::DataHdr) + 1024);
	assert(dh);

	ulong bpf_idx1 = 8;
	pid_t pid1 = 0x8888;
	ulong hash1 = MK_KEY(pid1, DKapture::PROC_PID_STAT);
	ulong dsz1 = 512;

	ulong bpf_idx2 =
		bpf_idx1 + BPF_RINGBUF_HDR_SZ + sizeof(DKapture::DataHdr) + dsz1;
	pid_t pid2 = 0x9999;
	ulong hash2 = MK_KEY(pid2, DKapture::PROC_PID_IO);
	ulong dsz2 = 256;

	dh->type = DKapture::PROC_PID_STAT;
	dh->pid = pid1;
	dh->dsz = dsz1;
	bpf_ringbuffer_push(data_map->m_bpf_rb, bpf_idx1, dh);
	dh->type = DKapture::PROC_PID_IO;
	dh->pid = pid2;
	dh->dsz = dsz2;
	bpf_ringbuffer_push(data_map->m_bpf_rb, bpf_idx2, dh);
	free(dh);

	data_map->m_lock->lock();
	// Push two entries into the DataMap
	data_map->push(bpf_idx1, hash1, dsz1);
	data_map->push(bpf_idx2, hash2, dsz2);
	data_map->m_lock->unlock();

	// Redirect stdout to capture the output of list_all_entrys
	testing::internal::CaptureStdout();
	data_map->list_all_entrys();
	std::string output = testing::internal::GetCapturedStdout();

	// Verify the output contains both entries
	EXPECT_NE(output.find("hash: 888800000003"), std::string::npos);
	EXPECT_NE(output.find("data_idx: 8"), std::string::npos);
	EXPECT_NE(output.find("data_idx: 600"), std::string::npos);
}

TEST_F(DataMapTest, UpdateAndFind)
{
	pid_t pid = 1000;
	ulong hash = MK_KEY(pid, DKapture::PROC_PID_STAT);

	data_map->m_lock->lock();
	// Call update to simulate data population
	int ret = data_map->update(DKapture::PROC_PID_STAT);
	data_map->m_lock->unlock();
	EXPECT_EQ(ret, 0);

	// Try to find the updated entry
	char buffer[512] = {};
	ret = data_map->find(hash, 1000, buffer, sizeof(buffer));

	// Verify the result
	ASSERT_GT(ret, 0);
	ASSERT_EQ(((DKapture::DataHdr *)buffer)->type, DKapture::PROC_PID_STAT);
	ASSERT_EQ(((DKapture::DataHdr *)buffer)->pid, pid);
}

TEST_F(DataMapTest, AsyncUpdate)
{
	// Call async_update and verify it returns 0 (not implemented yet)
	int ret = data_map->async_update(DKapture::PROC_PID_STAT);
	EXPECT_EQ(ret, 0);
}