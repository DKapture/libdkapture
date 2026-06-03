// 头文件保护，防止重复包含
#pragma once

// Qt 核心对象基类，用于信号槽机制
#include <QObject>
// Qt 键值对容器，存储每个进程的流量数据
#include <QMap>
// Qt 字符串类，支持 UTF-16 编码
#include <QString>
// Qt 互斥锁，保护多线程共享数据
#include <QMutex>
// C++11 线程库，用于创建 BPF 轮询后台线程
#include <thread>
// C++11 原子操作，实现无锁的运行状态标志
#include <atomic>

// 前向声明：libbpf 的 ring_buffer 结构体
// 避免在头文件中引入 libbpf 公共头文件，减少编译依赖
struct ring_buffer;

// 前向声明：由 bpftool 从 .bpf.o 自动生成的 skeleton 结构体
// 包含 open/load/attach/destroy 等 BPF 生命周期管理接口
struct net_traffic_bpf;

// BPF ring buffer 回调事件的数据结构
// 与内核 BPF 程序中写入 ring buffer 的结构体布局必须一致
struct BpfData
{
    int pid;                  // 产生网络流量的进程 PID
    unsigned int traffic;     // 本次事件的流量字节数
    unsigned int remote_ip;   // 对端 IP 地址（网络字节序）
    unsigned short remote_port; // 对端端口号（网络字节序）
    short dir;                // 流量方向：1=上传(发送)，0=下载(接收)
    char comm[16];            // 内核 task->comm，进程名（最多 15 字符 + '\0'）
};

// 每个进程的速率统计信息
struct SpeedInfo
{
    unsigned long long upload_bytes = 0;     // 本周期上传字节数（速率）
    unsigned long long download_bytes = 0;  // 本周期下载字节数（速率）
    unsigned long long total_upload = 0;    // 累计总上传字节数
    unsigned long long total_download = 0;  // 累计总下载字节数
    int pid = 0;                            // 进程 PID
};

// 进程键名 -> 速率信息的映射表
// 键名格式："进程名[PID]"，例如 "chrome[1234]"
using SpeedMap = QMap<QString, SpeedInfo>;

// BPF 后台工作类
// 负责：加载/卸载 eBPF 程序、管理 ring buffer 轮询线程、
//       累计流量数据、计算每秒速率、通过 Qt 信号通知 UI 刷新
class BpfWorker : public QObject
{
    Q_OBJECT

  public:
    explicit BpfWorker(QObject *parent = nullptr);
    ~BpfWorker();

    // 设置 BPF filter map 过滤规则
    // comm: 进程名过滤（空字符串表示不过滤）
    // pid: 指定进程 PID 过滤（0 表示不过滤）
    // remoteIp: 对端 IP 过滤（空字符串表示不过滤）
    // port: 对端端口过滤（0 表示不过滤）
    // dir: 流量方向过滤（0=双向，1=仅上传，2=仅下载）
    void setFilter(const QString &comm, int pid,
                   const QString &remoteIp, int port, int dir);

    // 查询 BPF 监控是否正在运行
    bool isActive() const { return m_running.load(); }

  signals:
    // 每秒速率计算完成后发射，携带所有进程的速率数据
    void speedUpdated(const SpeedMap &speeds);
    // BPF 加载/挂载失败时发射错误信息
    void bpfError(const QString &msg);
    // BPF 启动/停止状态变化时发射
    void activeChanged(bool active);

  public slots:
    // 启动 BPF 监控：加载 BPF 程序、创建轮询线程、启动速率定时器
    void start();
    // 停止 BPF 监控：卸载 BPF 程序、终止轮询线程、清理数据
    void stop();
    // 重置所有累计统计数据（总量归零）
    void resetStats();

  private:
    // 加载 eBPF 程序到内核并挂载到跟踪点
    bool loadBpf();
    // 卸载 eBPF 程序并释放所有资源
    void unloadBpf();

    // ring buffer 回调函数（静态，由 libbpf 在轮询线程中调用）
    // 解析 BPF 事件数据，按进程累计流量
    static int handleEvent(void *ctx, void *data, size_t sz);
    // 后台轮询线程入口，持续调用 ring_buffer__poll 消费内核事件
    void pollLoop();
    // 每 1 秒由 QTimer 触发，计算速率并发射 speedUpdated 信号
    void calculateSpeed();

    // BPF skeleton 对象，管理 BPF 程序的生命周期
    net_traffic_bpf *m_obj = nullptr;
    // libbpf ring buffer 对象，用于消费内核发送的事件数据
    struct ring_buffer *m_rb = nullptr;
    // BPF filter map 的文件描述符，用于向内核写入过滤规则
    int m_filterFd = -1;
    // 后台轮询线程指针，pollLoop 在此线程中运行
    std::thread *m_pollThread = nullptr;
    // 原子布尔标志，控制轮询线程的运行/停止
    std::atomic<bool> m_running{false};
    // 互斥锁，保护下方的 QMap 在回调和定时器之间的并发访问
    QMutex m_mutex;

    // 当前周期累计上传/下载字节数（ring buffer 回调中累加）
    QMap<QString, unsigned long long> m_currUpload;
    QMap<QString, unsigned long long> m_currDownload;
    // 上一周期的累计值（用于计算差值得出速率）
    QMap<QString, unsigned long long> m_prevUpload;
    QMap<QString, unsigned long long> m_prevDownload;
    // 全生命周期累计总上传/下载字节数
    QMap<QString, unsigned long long> m_totalUpload;
    QMap<QString, unsigned long long> m_totalDownload;
};
