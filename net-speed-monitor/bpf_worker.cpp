// 引入 BpfWorker 类声明
#include "bpf_worker.h"

// Qt 定时器，每 1 秒触发一次 calculateSpeed 计算速率
#include <QTimer>
// Qt 互斥锁 RAII 包装器，作用域结束自动释放锁
#include <QMutexLocker>
// Qt 集合容器，用于合并上传/下载键集合
#include <QSet>

// POSIX 系统调用：readlink（读取 /proc/<pid>/exe 符号链接）
#include <unistd.h>
// errno 全局变量及其字符串转换函数 strerror
#include <errno.h>
// memset、strncpy 等 C 字符串操作函数
#include <string.h>
// PATH_MAX 常量，定义路径最大长度
#include <limits.h>
// 网络相关系统调用和数据结构（inet_addr、htons 等）
#include <sys/socket.h>
// IP 地址转换函数（inet_addr）
#include <arpa/inet.h>
// libbpf 核心 API：BPF 程序加载、map 操作、ring buffer
#include <bpf/libbpf.h>
// BPF 系统调用封装：bpf_map_update_elem 等
#include <bpf/bpf.h>
// BTF（BPF Type Format）API：用于查询内核符号信息
#include <bpf/btf.h>

// 引入由 bpftool gen skeleton 从 .bpf.o 生成的 BPF skeleton 头文件
// 该文件通过 patch_skel.py 修改为运行时 mmap .bpf.o 加载，而非内嵌字节码
#include "net-traffic.skel.h"

// 定义调试日志宏，输出到 stderr 并立即刷新缓冲区
// 使用 do-while(0) 确保宏在 if/else 语句中使用时语义正确
#define LOG(fmt, ...) do { fprintf(stderr, "[BPF] " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while(0)

// ---------------------------------------------------------------
// 检查内核中是否存在指定的 BPF 跟踪点函数
// 通过 BTF（BPF Type Format）查找 vmlinux 中的符号名
// 返回 true 表示该跟踪点可用，BPF 程序可以挂载
static bool bpf_attachable(const char *name)
{
    // 加载 vmlinux 的 BTF 信息，包含内核所有类型和函数符号
    struct btf *vmlinux_btf = btf__load_vmlinux_btf();
    // 如果加载失败（例如系统没有 BTF 支持），返回 false
    if (libbpf_get_error(vmlinux_btf))
        return false;
    // 在 BTF 中按名称和类型查找函数符号
    int id = btf__find_by_name_kind(vmlinux_btf, name, BTF_KIND_FUNC);
    // 释放 BTF 对象，避免内存泄漏
    btf__free(vmlinux_btf);
    // id > 0 表示找到了该符号
    return id > 0;
}

// 根据内核版本选择合适的 BPF 挂载点
// 较新内核（5.6+）支持 __sock_sendmsg 跟踪点，效率更高
// 较旧内核需要使用替代的多个跟踪点组合
static void fixAttachPoint(net_traffic_bpf *obj)
{
    // 检查内核是否有 __sock_sendmsg 符号
    if (!bpf_attachable("__sock_sendmsg"))
    {
        // 内核不支持 __sock_sendmsg，禁用该程序
        // libbpf 将自动加载其余兼容的 BPF 程序
        LOG("__sock_sendmsg not found, using alternative hooks");
        bpf_program__set_autoload(obj->progs.__sock_sendmsg, false);
    }
    else
    {
        // 内核支持 __sock_sendmsg，使用此单一跟踪点
        // 禁用所有替代的跟踪点程序，避免重复计数
        LOG("__sock_sendmsg found, using primary hook");
        bpf_program__set_autoload(obj->progs.sock_sendmsg, false);
        bpf_program__set_autoload(obj->progs.sock_write_iter, false);
        bpf_program__set_autoload(obj->progs.__sys_sendto_entry, false);
        bpf_program__set_autoload(obj->progs.socket_sendmsg, false);
        bpf_program__set_autoload(obj->progs.__sys_sendto_exit, false);
        bpf_program__set_autoload(obj->progs.____sys_sendmsg, false);
    }
}

// ---------------------------------------------------------------
// 构造函数：初始化基类 QObject，所有成员使用类内默认初始化
BpfWorker::BpfWorker(QObject *parent) : QObject(parent) {}

// 析构函数：确保 BPF 资源被正确释放
BpfWorker::~BpfWorker()
{
    stop();
}

// 加载 eBPF 程序到内核
// 执行完整的 BPF 生命周期：skeleton open -> 修复挂载点 -> load -> attach -> 创建 ring buffer
bool BpfWorker::loadBpf()
{
    // 设置 libbpf 日志回调，过滤掉 DEBUG 级别的详细输出
    // 只显示 WARN 和 ERROR 级别的 libbpf 内部消息
    libbpf_set_print([](enum libbpf_print_level level,
                      const char *format, va_list args) -> int {
        // 忽略 DEBUG 及以下级别的日志
        if (level >= LIBBPF_DEBUG)
            return 0;
        // 输出 WARN/ERROR 级别的 libbpf 消息到 stderr
        fprintf(stderr, "[libbpf] ");
        vfprintf(stderr, format, args);
        return 0;
    });

    // 步骤1：打开 BPF skeleton，解析 .bpf.o 文件中的 BPF 程序和 map 定义
    // patch_skel.py 修改后的 skeleton 会 mmap .bpf.o 文件而非内嵌字节码
    LOG("opening BPF skeleton...");
    m_obj = net_traffic_bpf::open();
    if (!m_obj)
    {
        LOG("FAILED to open BPF object");
        emit bpfError("failed to open BPF object");
        return false;
    }

    // 步骤2：根据当前内核版本选择合适的跟踪点
    // 避免在不支持某些 kprobe 的内核上加载失败
    fixAttachPoint(m_obj);

    // 步骤3：将 BPF 程序加载到内核
    // 内核会验证 BPF 字节码的安全性（指令集、内存访问等）
    LOG("loading BPF programs...");
    if (net_traffic_bpf::load(m_obj) < 0)
    {
        LOG("FAILED to load BPF programs (errno=%d: %s)", errno, strerror(errno));
        emit bpfError(QString("failed to load BPF: %1").arg(strerror(errno)));
        return false;
    }

    // 步骤4：将 BPF 程序挂载到内核跟踪点（kprobe/tracepoint）
    // 挂载后 BPF 程序会在对应的内核函数被调用时执行
    LOG("attaching BPF programs...");
    if (net_traffic_bpf::attach(m_obj) != 0)
    {
        LOG("FAILED to attach BPF programs (errno=%d: %s)", errno, strerror(errno));
        emit bpfError(QString("failed to attach BPF: %1").arg(strerror(errno)));
        return false;
    }

    // 步骤5：获取 BPF map 的文件描述符
    // filter map：用户态写入过滤规则，BPF 程序读取进行过滤
    m_filterFd = bpf_object__find_map_fd_by_name(m_obj->obj, "filter");
    // logs map：BPF_MAP_TYPE_RINGBUF 类型，内核 BPF 程序向其写入事件数据
    int logMapFd = bpf_object__find_map_fd_by_name(m_obj->obj, "logs");
    LOG("maps: logs=%d filter=%d", logMapFd, m_filterFd);
    // logs map 是必须的，没有它无法接收 BPF 事件
    if (logMapFd < 0)
    {
        emit bpfError("failed to find 'logs' map");
        return false;
    }

    // 步骤6：创建 ring buffer 消费者
    // ring buffer 是内核与用户态之间的高性能数据通道
    // handleEvent 是回调函数，this 作为上下文传递给回调
    LOG("creating ring buffer...");
    m_rb = ring_buffer__new(logMapFd, handleEvent, this, NULL);
    if (!m_rb)
    {
        LOG("FAILED to create ring buffer (errno=%d: %s)", errno, strerror(errno));
        emit bpfError(QString("failed to create ring buffer: %1").arg(strerror(errno)));
        return false;
    }

    LOG("BPF loaded successfully");
    return true;
}

// 卸载 BPF 程序并释放所有相关资源
// 必须在轮询线程停止后调用，避免 use-after-free
void BpfWorker::unloadBpf()
{
    // 设置运行标志为 false，通知轮询线程退出
    m_running = false;

    // 等待轮询线程结束
    // join() 会阻塞直到 pollLoop() 中的 while 循环检测到 m_running==false 退出
    if (m_pollThread)
    {
        if (m_pollThread->joinable())
            m_pollThread->join();
        delete m_pollThread;
        m_pollThread = nullptr;
    }

    // 释放 ring buffer 对象
    if (m_rb)
    {
        ring_buffer__free(m_rb);
        m_rb = nullptr;
    }
    // 从内核分离并销毁 BPF 程序
    // detach: 取消 BPF 程序与跟踪点的绑定
    // destroy: 释放 skeleton 分配的所有资源
    if (m_obj)
    {
        net_traffic_bpf::detach(m_obj);
        net_traffic_bpf::destroy(m_obj);
        m_obj = nullptr;
    }
    // 重置 filter map 文件描述符
    m_filterFd = -1;
}

// ring buffer 事件回调函数（静态成员）
// 由 libbpf 在 pollLoop 的 ring_buffer__poll 调用中被触发
// ctx: 创建 ring buffer 时传入的 BpfWorker 实例指针
// data: 内核 BPF 程序写入的 BpfData 结构体数据
// data_sz: 数据长度（字节）
int BpfWorker::handleEvent(void *ctx, void *data, size_t data_sz)
{
    // 将通用上下文指针转换回 BpfWorker 实例
    auto *self = static_cast<BpfWorker *>(ctx);
    // 将数据指针转换为 BpfData 结构体
    const auto *log = static_cast<const BpfData *>(data);

    // 忽略无效 PID 的事件
    if (log->pid <= 0)
        return 0;

    // 使用 /proc/<pid>/exe 符号链接获取进程真实可执行文件名
    // 优先显示真实程序名（如 "chrome"），而非内核 comm（如 "Chrome_ChildIOT"）
    // 静态变量 pidNames 作为 PID 到名称的缓存，避免重复 readlink 系统调用
    static QMap<int, QString> pidNames;
    QString name = pidNames.value(log->pid);
    if (name.isEmpty())
    {
        char exePath[PATH_MAX] = {};
        char link[64];
        // 构建 /proc/<pid>/exe 路径，该符号链接指向进程的可执行文件
        snprintf(link, sizeof(link), "/proc/%d/exe", log->pid);
        // readlink 读取符号链接指向的真实路径
        ssize_t len = readlink(link, exePath, sizeof(exePath) - 1);
        if (len > 0)
        {
            exePath[len] = 0;
            // 取路径最后一段作为进程显示名（如 /usr/bin/google-chrome -> google-chrome）
            name = QString(exePath).split('/').last();
        }
        else
            // readlink 失败时回退到内核 comm 字段
            name = log->comm;
        // 缓存 PID 到名称的映射
        pidNames.insert(log->pid, name);
    }

    // 加锁保护：此回调在轮询线程中运行，calculateSpeed 在主线程中运行
    // QMutexLocker 在作用域结束时自动释放锁（RAII 模式）
    QMutexLocker locker(&self->m_mutex);

    // 构建显示键名，格式为 "进程名[PID]"，例如 "chrome[1234]"
    QString key = QString("%1[%2]").arg(name).arg(log->pid);

    // 根据流量方向累计到对应的当前周期计数器
    // dir==1 表示上传（进程发送数据），dir==0 表示下载（进程接收数据）
    if (log->dir == 1)
        self->m_currUpload[key] += log->traffic;
    else
        self->m_currDownload[key] += log->traffic;

    // 无论方向，都累计到总量计数器（用于显示总上传/总下载）
    // 注意：总量分别累计，上传和下载分开统计
    self->m_totalUpload[key] += log->traffic;
    self->m_totalDownload[key] += log->traffic;

    return 0;
}

// 后台轮询线程的主循环
// 持续调用 ring_buffer__poll 从内核 ring buffer 中消费事件
// 当 m_running 被设为 false 时退出循环（由 stop()/unloadBpf() 触发）
void BpfWorker::pollLoop()
{
    LOG("poll thread: started");
    while (m_running.load())
    {
        // 从 ring buffer 中拉取事件数据
        // 超时 1000ms：如果没有新事件，1 秒后返回
        // 在超时期间会调用 handleEvent 回调处理每个事件
        int err = ring_buffer__poll(m_rb, 1000);
        if (err < 0 && err != -EINTR)
        {
            // -EINTR 表示被信号中断（正常情况），忽略
            // 其他负值表示真正的错误
            LOG("poll error: err=%d errno=%d (%s)", err, errno, strerror(errno));
            // 等待 5 秒后重试，避免错误时 busy loop
            sleep(5);
        }
    }
    LOG("poll thread: exiting");
}

// 计算每秒速率
// 由 QTimer 每 1 秒触发一次
// 核心算法：速率 = 当前周期累计字节数 - 上一周期累计字节数
void BpfWorker::calculateSpeed()
{
    // 如果 BPF 已停止，不再计算
    if (!m_running.load())
        return;

    // 存储本秒所有进程的速率结果
    SpeedMap result;

    // 加锁读取共享数据（回调线程可能正在写入）
    QMutexLocker locker(&m_mutex);

    // 合并上传和下载中的所有进程键名
    QSet<QString> allKeys;
    for (auto it = m_currUpload.constBegin(); it != m_currUpload.constEnd(); ++it)
        allKeys.insert(it.key());
    for (auto it = m_currDownload.constBegin(); it != m_currDownload.constEnd(); ++it)
        allKeys.insert(it.key());

    // 遍历每个进程，计算速率
    for (const auto &key : allKeys)
    {
        SpeedInfo info;
        // 当前周期和上一周期的上传累计值
        unsigned long long cu = m_currUpload.value(key, 0);
        unsigned long long pu = m_prevUpload.value(key, 0);
        // 当前周期和上一周期的下载累计值
        unsigned long long cd = m_currDownload.value(key, 0);
        unsigned long long pd = m_prevDownload.value(key, 0);

        // 计算速率：当前累计 - 上次累计 = 本秒增量
        // 使用条件判断防止 uint 溢出（理论上 curr >= prev，但防御性编程）
        info.upload_bytes = cu > pu ? cu - pu : 0;
        info.download_bytes = cd > pd ? cd - pd : 0;
        // 从总量 map 中获取全生命周期累计值
        info.total_upload = m_totalUpload.value(key, 0);
        info.total_download = m_totalDownload.value(key, 0);

        // 从键名 "进程名[PID]" 中解析出 PID 整数值
        int lb = key.lastIndexOf('[');
        int rb = key.lastIndexOf(']');
        if (lb > 0 && rb > lb)
            info.pid = key.mid(lb + 1, rb - lb - 1).toInt();

        // 只插入有流量数据的进程（过滤掉全零行）
        if (info.upload_bytes || info.download_bytes ||
            info.total_upload || info.total_download)
            result.insert(key, info);
    }

    // 保存当前周期累计值，作为下一周期计算速率的基准
    m_prevUpload = m_currUpload;
    m_prevDownload = m_currDownload;

    // 计算完成，释放锁后再发射信号
    // 避免在持有锁时触发跨线程信号传递
    locker.unlock();
    // 发射信号通知 UI 刷新表格数据
    emit speedUpdated(result);
}

// 启动 BPF 监控
// 加载 BPF 程序、创建轮询线程、启动速率计算定时器
void BpfWorker::start()
{
    // 防止重复启动
    if (m_running.load())
        return;

    // 加载 eBPF 程序到内核
    if (!loadBpf())
        return;

    // 设置运行标志
    m_running = true;
    LOG("starting poll thread...");

    // 创建后台轮询线程
    // 使用 std::thread 而非 QThread::create（后者在此项目中存在生命周期问题）
    m_pollThread = new std::thread([this]() { pollLoop(); });

    // 创建 1 秒定时器，用于周期性计算速率
    // 父对象设为 this，确保 BpfWorker 销毁时定时器自动删除
    auto *timer = new QTimer(this);
    // 每次超时触发 calculateSpeed 计算速率并更新 UI
    connect(timer, &QTimer::timeout, this, &BpfWorker::calculateSpeed);
    timer->start(1000);

    // 通知 UI BPF 已启动（用于更新按钮和状态栏）
    emit activeChanged(true);
}

// 停止 BPF 监控
// 设置停止标志、卸载 BPF 程序、清理所有累计数据
void BpfWorker::stop()
{
    // 如果未在运行，直接返回
    if (!m_running.load())
        return;

    // 设置停止标志（unloadBpf 内部也会设置）
    m_running = false;
    // 卸载 BPF：join 轮询线程、释放 ring buffer、detach/destroy BPF 程序
    unloadBpf();

    // 清理所有流量累计数据
    {
        QMutexLocker locker(&m_mutex);
        m_currUpload.clear();
        m_currDownload.clear();
        m_prevUpload.clear();
        m_prevDownload.clear();
    }

    // 通知 UI BPF 已停止
    emit activeChanged(false);
}

// 重置统计数据
// 清零所有累计值（包括速率基准和总量），但不清空当前周期的累计值
// 这样下一秒的速率计算会基于重置后的 prev 值
void BpfWorker::resetStats()
{
    QMutexLocker locker(&m_mutex);
    // 清零上一周期基准值
    m_prevUpload.clear();
    m_prevDownload.clear();
    // 清零全生命周期累计值
    m_totalUpload.clear();
    m_totalDownload.clear();
}

// 设置 BPF 过滤规则
// 将过滤条件写入 BPF filter map，内核 BPF 程序会读取该规则过滤事件
// 只有匹配规则的流量事件才会被写入 ring buffer
void BpfWorker::setFilter(const QString &comm, int pid,
                           const QString &remoteIp, int port, int dir)
{
    // filter map 尚未初始化（BPF 未加载）
    if (m_filterFd < 0)
        return;

    // 定义过滤规则结构体，布局必须与内核 BPF 程序中的 struct Rule 一致
    struct
    {
        unsigned int remote_ip;     // 过滤目标 IP 地址
        unsigned short remote_port; // 过滤目标端口号
        unsigned short dir;         // 过滤流量方向
        unsigned int not_pid;       // PID 排除标志（暂未使用）
        int pid;                    // 过滤目标 PID（-1 表示不过滤）
        char comm[16];              // 过滤目标进程名（空表示不过滤）
    } rule = {};

    // 设置进程名过滤
    if (!comm.isEmpty())
    {
        // 将 QString 转为本地 8 位编码并拷贝到 comm 字段
        strncpy(rule.comm, comm.toLocal8Bit().constData(), sizeof(rule.comm) - 1);
    }
    else
    {
        // 不按进程名过滤时，设 PID 为 -1 表示不过滤
        rule.not_pid = 0;
        rule.pid = -1;
    }

    // 设置 PID 过滤（优先级高于进程名）
    if (pid > 0)
    {
        rule.not_pid = 0;
        rule.pid = pid;
    }

    // 设置远程 IP 过滤
    if (!remoteIp.isEmpty())
        // inet_addr 将点分十进制 IP 字符串转为网络字节序整数
        rule.remote_ip = inet_addr(remoteIp.toLocal8Bit().constData());

    // 设置远程端口过滤
    if (port > 0)
        // htons 将主机字节序转为网络字节序（大端）
        rule.remote_port = htons(port);

    // 设置流量方向过滤
    if (dir != 0)
        rule.dir = dir;

    // 将规则写入 BPF filter map
    // key=0 是 filter map 中的唯一条目
    // BPF_ANY 表示无论 key 是否存在都执行更新
    unsigned int key = 0;
    bpf_map_update_elem(m_filterFd, &key, &rule, BPF_ANY);
}
