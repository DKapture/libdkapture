// #include "gtest/gtest.h"
// #include "data-map.h"

// class DataMapTest : public ::testing::Test
// {
// protected:
//     DataMap *data_map;

//     void SetUp() override
//     {
//         data_map = new DataMap();
//     }

//     void TearDown() override
//     {
//         delete data_map;
//     }
// };

// TEST_F(DataMapTest, PushAndFind)
// {
//     ulong bpf_idx = 1;
//     ulong hash = MK_KEY(1234, DKapture::PROC_PID_STAT);
//     ulong dsz = 128;

//     data_map->m_lock->lock();
//     // Push an entry into the DataMap
//     data_map->push(bpf_idx, hash, dsz);
//     data_map->m_lock->unlock();

//     // Find the entry
//     char buffer[256] = {};
//     int ret = data_map->find(hash, 1000, buffer, sizeof(buffer));

//     // Verify the result
//     EXPECT_GT(ret, 0);
//     EXPECT_EQ(((DKapture::DataHdr *)buffer)->type, DKapture::PROC_PID_STAT);
//     EXPECT_EQ(((DKapture::DataHdr *)buffer)->pid, 1234);
// }

// TEST_F(DataMapTest, Invalidate)
// {
//     ulong bpf_idx = 1;
//     ulong hash = MK_KEY(1234, DKapture::PROC_PID_STAT);
//     ulong dsz = 128;

//     data_map->m_lock->lock();
//     // Push an entry into the DataMap
//     data_map->push(bpf_idx, hash, dsz);

//     // Invalidate the entry
//     data_map->invalidate(bpf_idx, dsz);
//     data_map->m_lock->unlock();

//     // Try to find the invalidated entry
//     char buffer[256] = {};
//     int ret = data_map->find(hash, 1000, buffer, sizeof(buffer));

//     // Verify the entry is invalidated
//     EXPECT_EQ(ret, -ENOENT);
// }

// TEST_F(DataMapTest, ListAllEntries)
// {
//     ulong bpf_idx1 = 1;
//     ulong hash1 = MK_KEY(1234, DKapture::PROC_PID_STAT);
//     ulong dsz1 = 128;

//     ulong bpf_idx2 = 2;
//     ulong hash2 = MK_KEY(5678, DKapture::PROC_PID_IO);
//     ulong dsz2 = 256;

//     data_map->m_lock->lock();
//     // Push two entries into the DataMap
//     data_map->push(bpf_idx1, hash1, dsz1);
//     data_map->push(bpf_idx2, hash2, dsz2);
//     data_map->m_lock->unlock();

//     // Redirect stdout to capture the output of list_all_entrys
//     testing::internal::CaptureStdout();
//     data_map->list_all_entrys();
//     std::string output = testing::internal::GetCapturedStdout();

//     // Verify the output contains both entries
//     EXPECT_NE(output.find("hash: 0x"), std::string::npos);
//     EXPECT_NE(output.find("data_idx: 1"), std::string::npos);
//     EXPECT_NE(output.find("data_idx: 2"), std::string::npos);
// }

// TEST_F(DataMapTest, UpdateAndFind)
// {
//     ulong hash = MK_KEY(1234, DKapture::PROC_PID_STAT);

//     data_map->m_lock->lock();
//     // Call update to simulate data population
//     int ret = data_map->update(DKapture::PROC_PID_STAT);
//     data_map->m_lock->unlock();
//     EXPECT_EQ(ret, 0);

//     // Try to find the updated entry
//     char buffer[256] = {};
//     ret = data_map->find(hash, 1000, buffer, sizeof(buffer));

//     // Verify the result
//     EXPECT_GT(ret, 0);
//     EXPECT_EQ(((DKapture::DataHdr *)buffer)->type, DKapture::PROC_PID_STAT);
//     EXPECT_EQ(((DKapture::DataHdr *)buffer)->pid, 1234);
// }

// TEST_F(DataMapTest, AsyncUpdate)
// {
//     // Call async_update and verify it returns 0 (not implemented yet)
//     int ret = data_map->async_update(DKapture::PROC_PID_STAT);
//     EXPECT_EQ(ret, 0);
// }