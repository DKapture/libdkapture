#include "dkapture.h"
#include "Ulog.h"
#include "Ucom.h"
#include "gtest/gtest.h"

#include <sys/ipc.h>
#include <sys/shm.h>

#include <set>

#define BUF_SZ (1024 * 1024)
#define TIME_ns(ts) \
    ((ts.tv_sec & 0xffffffff) * 1000000000UL + ts.tv_nsec)

static char buf[BUF_SZ] = {};
extern FILE *gtest_fp;

int dkcallback(void *ctx, const void *_data, size_t data_sz)
{
    long type = (long)ctx;
    const DKapture::DataHdr *data = (typeof(data))_data;
    while (data_sz > (int)sizeof(DKapture::DataHdr))
    {
        DEBUG(0, "type: %ld vs %ld", type, data->type);
        if (data->type == type)
        {
            switch (data->type)
            {
            case DKapture::PROC_PID_STAT:
            {
                const struct ProcPidStat *stat = (typeof(stat))data->data;
                pr_info("PID: %d, Comm: %s, State: %d", data->pid, data->comm, stat->state);
            }
            break;
            case DKapture::PROC_PID_IO:
            {
                const struct ProcPidIo *io = (typeof(io))data->data;
                pr_info("PID: %d, Comm: %s, Read: %zu, Write: %zu", data->pid, data->comm, io->rchar, io->wchar);
            }
            break;
            case DKapture::PROC_PID_traffic:
            {
                const struct ProcPidTraffic *traffic = (typeof(traffic))data->data;
                if (traffic->rbytes == 0 && traffic->wbytes == 0)
                {
                    break;
                }
                pr_info("PID: %d, Comm: %s, Read: %zu, Write: %zu", data->pid, data->comm, traffic->rbytes, traffic->wbytes);
            }
            break;
            default:
                pr_info("Unknown type: %d", data->type);
                break;
            }
        }
        data_sz -= data->dsz;
        data = (DKapture::DataHdr *)((char *)data + data->dsz);
    }
    return 0;
}

template <class T>
class Releaser
{
private:
    T *obj;

public:
    Releaser(T *obj)
    {
        this->obj = obj;
    }
    ~Releaser()
    {
        delete obj;
    }
};

TEST(DKaptureTest, open_and_close)
{
    int ret;
    const key_t shm_key = 0x12345678; // 共享内存的键值
    DKapture *dk1 = DKapture::new_instance();
    DKapture *dk2 = DKapture::new_instance();
    Releaser r1(dk1);
    Releaser r2(dk2);

    ASSERT_EQ(dk1->open(gtest_fp, DKapture::DEBUG), 0);
    ASSERT_EQ(dk1->open(gtest_fp, DKapture::DEBUG), -EEXIST);
    ASSERT_EQ(dk2->open(gtest_fp, DKapture::DEBUG), 0);
    ASSERT_EQ(access("/sys/fs/bpf/dkapture", F_OK), 0);
    ASSERT_EQ(access("/sys/fs/bpf/dkapture/link-dump_task", F_OK), 0);
    ASSERT_EQ(access("/sys/fs/bpf/dkapture/map-dk_shared_mem", F_OK), 0);
    ASSERT_EQ(access("/sys/fs/bpf/dkapture/prog-dump_task", F_OK), 0);
    ASSERT_NE(shmget(shm_key, 0, 0), -1);
    dk2->close();
    ASSERT_EQ(access("/sys/fs/bpf/dkapture", F_OK), 0);
    ASSERT_EQ(access("/sys/fs/bpf/dkapture/link-dump_task", F_OK), 0);
    ASSERT_EQ(access("/sys/fs/bpf/dkapture/map-dk_shared_mem", F_OK), 0);
    ASSERT_EQ(access("/sys/fs/bpf/dkapture/prog-dump_task", F_OK), 0);
    ASSERT_NE(shmget(shm_key, 0, 0), -1);
    dk1->close();
    ASSERT_NE(access("/sys/fs/bpf/dkapture", F_OK), 0);
    ASSERT_NE(access("/sys/fs/bpf/dkapture/link-dump_task", F_OK), 0);
    ASSERT_NE(access("/sys/fs/bpf/dkapture/map-dk_shared_mem", F_OK), 0);
    ASSERT_NE(access("/sys/fs/bpf/dkapture/prog-dump_task", F_OK), 0);
    ASSERT_EQ(shmget(shm_key, 0, 0), -1);
}

TEST(DKaptureTest, read_overload1)
{
    int ret;
    DKapture *dk = DKapture::new_instance();
    Releaser r(dk);
    ASSERT_EQ(dk->open(gtest_fp, DKapture::DEBUG), 0);
    dk->lifetime(1000000);
    DKapture::DataHdr *dh = (DKapture::DataHdr *)buf;
    ret = dk->read(DKapture::PROC_PID_STAT, 1 /* systemd */, dh, BUF_SZ);
    ASSERT_EQ(ret, sizeof(DKapture::DataHdr) + sizeof(ProcPidStat));

    ProcPidStat *stat = (struct ProcPidStat *)dh->data;
    ASSERT_EQ(dh->pid, 1);
    ASSERT_EQ(dh->dsz, ret);
    ASSERT_EQ(dh->type, DKapture::PROC_PID_STAT);
    ASSERT_EQ(stat->ppid, 0);
    dk->close();
}

TEST(DKaptureTest, read_overload5)
{
    int ret;
    size_t dsz;
    DKapture *dk = DKapture::new_instance();
    Releaser r(dk);
    ASSERT_EQ(dk->open(gtest_fp, DKapture::DEBUG), 0);
    dk->lifetime(1000000);
    std::vector<pid_t> pids;
    pids.push_back(1);
    pids.push_back(getpid());
    DKapture::DataHdr *dh = (DKapture::DataHdr *)buf;
    ret = dk->read(DKapture::PROC_PID_STAT, pids, dh, BUF_SZ);
    dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidStat);
    dsz *= pids.size();
    ASSERT_EQ(ret, dsz);

    std::set<pid_t> pids_got;
    while (ret > (int)sizeof(DKapture::DataHdr))
    {
        ProcPidStat *stat = (struct ProcPidStat *)dh->data;
        pids_got.insert(dh->pid);
        ASSERT_EQ(dh->dsz, sizeof(DKapture::DataHdr) + sizeof(ProcPidStat));
        ASSERT_EQ(dh->type, DKapture::PROC_PID_STAT);
        ret -= dh->dsz;
        dh = (DKapture::DataHdr *)((char *)dh + dh->dsz);
    }

    ASSERT_TRUE(pids_got.find(1) != pids_got.end());
    ASSERT_TRUE(pids_got.find(getpid()) != pids_got.end());

    dk->close();
}

TEST(DKaptureTest, read_overload2)
{
    int ret;
    size_t dsz;
    DKapture *dk = DKapture::new_instance();
    Releaser r(dk);
    DKapture::DataHdr *dh = (DKapture::DataHdr *)buf;
    dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidStat);
    ASSERT_EQ(dk->open(gtest_fp, DKapture::DEBUG), 0);
    ret = dk->read("/proc/1/stat1", dh, BUF_SZ);
    ASSERT_EQ(ret, -ENOSYS);
    ret = dk->read("sdfasdf", dh, BUF_SZ);
    ASSERT_EQ(ret, -EINVAL);
    ret = dk->read(nullptr, dh, BUF_SZ);
    ASSERT_EQ(ret, -EINVAL);
    ret = dk->read("/proc/1/stat", nullptr, BUF_SZ);
    ASSERT_EQ(ret, -EINVAL);
    ret = dk->read("/proc/1/stat", dh, 0);
    ASSERT_EQ(ret, -EINVAL);
    ret = dk->read("/proc/1/stat", dh, BUF_SZ);
    ASSERT_EQ(ret, dsz);
    dk->close();
}

TEST(DKaptureTest, lifetime)
{
    int ret;
    size_t dsz;
    DKapture *dk = DKapture::new_instance();
    Releaser r(dk);
    ASSERT_EQ(dk->open(gtest_fp, DKapture::DEBUG), 0);
    dk->lifetime(100);
    DKapture::DataHdr *dh = (DKapture::DataHdr *)buf;
    struct timespec ts_start, ts_end;
    uint64_t delta_time1, delta_time2, delta_time3;
    dsz = sizeof(DKapture::DataHdr) + sizeof(ProcPidIo);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    ret = dk->read(DKapture::PROC_PID_IO, 1, dh, BUF_SZ);
    ASSERT_EQ(ret, dsz);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    delta_time1 = TIME_ns(ts_end) - TIME_ns(ts_start);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    ret = dk->read(DKapture::PROC_PID_IO, 1, dh, BUF_SZ);
    ASSERT_EQ(ret, dsz);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    delta_time2 = TIME_ns(ts_end) - TIME_ns(ts_start);

    // 验证缓存读，速度快10倍。不严谨
    ASSERT_GT(delta_time1, delta_time2 * 10);
    usleep(100000);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    ret = dk->read(DKapture::PROC_PID_IO, 1, dh, BUF_SZ);
    ASSERT_EQ(ret, dsz);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    delta_time3 = TIME_ns(ts_end) - TIME_ns(ts_start);

    // 验证缓存失效，重新刷新数据读，速度差不多。不严谨
    ASSERT_GT(delta_time3, delta_time2 * 0.9); // 不严谨

    dk->close();
}

TEST(DKaptureTest, read_PROC_PID_IO)
{
    int ret;
    DKapture *dk = DKapture::new_instance();
    Releaser r(dk);
    ASSERT_EQ(dk->open(gtest_fp, DKapture::DEBUG), 0);
    // DKapture::DataHdr *dh = (DKapture::DataHdr *)buf;
    ret = dk->read(DKapture::PROC_PID_IO, dkcallback, (void *)DKapture::PROC_PID_IO);
    if (ret < 0)
    {
        pr_error("dkapture::read failed: %s", strerror(-ret));
    }
    dk->close();
}

TEST(DKaptureTest, read_PROC_PID_traffic)
{
    int ret;
    DKapture *dk = DKapture::new_instance();
    Releaser r(dk);
    ASSERT_EQ(dk->open(gtest_fp, DKapture::DEBUG), 0);
    // DKapture::DataHdr *dh = (DKapture::DataHdr *)buf;
    ret = dk->read(DKapture::PROC_PID_traffic, dkcallback, (void *)DKapture::PROC_PID_traffic);
    if (ret < 0)
    {
        pr_error("dkapture::read failed: %s", strerror(-ret));
    }
    dk->close();
}
