#include "dkapture.h"
#include "Ulog.h"
#include "Ucom.h"
#include "gtest/gtest.h"
#include "bpf/libbpf.h"
#include <sched.h>
#include <sys/mount.h>

#include <fstream>

FILE *gtest_fp;

static int libbpf_user_print(enum libbpf_print_level level, const char *format,
                             va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(gtest_fp, format, args);
}

void clean_up(void)
{
    system("ipcrm -a");
    system("rm -r /sys/fs/bpf/dkapture");
}

void set_up(void)
{
    uid_t ori_uid = getuid();
    /**
     * 切换挂载空间和用户空间
     */
    if (unshare(CLONE_NEWNS | CLONE_NEWUSER) != 0)
    {
        pr_error("unshare: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    /**
     * 将自己在当前用户空间映射成root
     */
    char buf[32];
    sprintf(buf, "0 %d 1", ori_uid);
    int fd = open("/proc/self/uid_map", O_WRONLY);
    assert(fd > 0);
    ssize_t wsz = write(fd, buf, strlen(buf));
    assert(wsz > 0);
    // 确保 /tmp/bpf 目录存在
    if (system("mkdir -p /tmp/bpf") != 0)
    {
        pr_error("mkdir /tmp/bpf");
        exit(EXIT_FAILURE);
    }

    // 挂载 /tmp/bpf 到 /sys/bpf
    if (mount("/tmp/bpf", "/sys/fs/bpf", NULL, MS_BIND, NULL) != 0)
    {
        pr_error("mount: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    pr_info("Mounted /tmp/bpf to /sys/bpf in a new mount namespace.\n");
}

int main(int argc, char **argv)
{
    set_up();
    clean_up();
    pr_warn("log message is redirected to file /tmp/dkapture.log");
    gtest_fp = fopen("/tmp/dkapture.log", "w");
    assert(gtest_fp != NULL);
    libbpf_set_print(libbpf_user_print);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}