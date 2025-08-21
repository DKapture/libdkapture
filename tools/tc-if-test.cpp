#include <iostream>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <iomanip>
#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <ifaddrs.h>

/*
 * 如果要测试其他限速模块，需要更改配置路径 
 */
// 测试配置常量
#define TC_IF_PATH "../filter/tc-if"
#define TEST_DURATION_SEC 20       // 总测试时间：20秒
#define INGRESS_TEST_DURATION 10   // 接收限速测试时间：10秒
#define EGRESS_TEST_DURATION 10    // 发送限速测试时间：10秒
#define LOCAL_PORT 8888
#define MAX_PACKET_SIZE 1500       // 最大数据包大小
#define MIN_PACKET_SIZE 64         // 最小数据包大小
#define BUFFER_SIZE 10240          // 接收缓冲区大小
#define SHARED_MEM_NAME "/tc_if_test_stats"  // 共享内存名称
#define TC_CLEANUP_DELAY 1000     // TC清理延迟(毫秒)
#define PROCESS_STARTUP_DELAY 500  // 进程启动延迟(毫秒)
#define TC_IF_STARTUP_DELAY 2000  // tc-if启动延迟(毫秒)


#define TCP_CLIENT_PORT 8080
#define TCP_CLIENT_BUFFER_SIZE 8192
#define SERVER_IP "127.0.0.1"

static volatile int tcp_client_running = 1;
static pid_t tcp_client_current_pid;

#define TCP_PORT 8080
#define TCP_BUFFER_SIZE 8192
#define MAX_DATA_SIZE 8192

static volatile int tcp_running = 1;
static pid_t tcp_current_pid;

// 错误码定义
#define SUCCESS 0
#define ERROR_INVALID_PERMISSION -1
#define ERROR_TC_IF_NOT_FOUND -2
#define ERROR_SHARED_MEMORY_FAILED -3
#define ERROR_PROCESS_CREATION_FAILED -4
#define ERROR_SOCKET_CREATION_FAILED -5
#define ERROR_BIND_FAILED -6
#define ERROR_TC_IF_STARTUP_FAILED -7

// 限速验证常量
#define TARGET_RATE_MBPS 1.0       // 目标限速：1 MB/s
#define MAX_ALLOWED_RATE_MBPS 1.2  // 最大允许速率：1.2 MB/s (20%容差)
#define RATE_CHECK_INTERVAL 1      // 速率检查间隔(秒)

// 共享内存结构体 - 用于进程间通信
struct SharedStats 
{
    // 总体统计信息
    uint64_t total_bytes_received;     // 总接收字节数
    uint64_t total_packets_received;   // 总接收包数
    uint64_t total_bytes_sent;         // 总发送字节数
    uint64_t total_packets_sent;       // 总发送包数
    
    // 阶段统计 - 分别记录ingress和egress阶段的流量
    uint64_t ingress_bytes;            // 接收限速阶段接收的字节数
    uint64_t ingress_packets;          // 接收限速阶段接收的包数
    uint64_t egress_bytes;             // 发送限速阶段接收的字节数
    uint64_t egress_packets;           // 发送限速阶段接收的包数
    
    // 时间戳信息
    time_t test_start_time;            // 测试开始时间
    time_t ingress_start_time;         // ingress阶段开始时间
    time_t egress_start_time;          // egress阶段开始时间
    
    // 状态标志
    volatile sig_atomic_t test_running;    // 测试运行状态
    volatile sig_atomic_t ingress_active;  // ingress阶段激活状态
    volatile sig_atomic_t egress_active;   // egress阶段激活状态
    
    // 错误计数
    uint32_t error_count;              // 错误计数
    uint32_t warning_count;            // 警告计数
    
    // 性能指标
    double peak_ingress_rate;          // ingress阶段峰值速率
    double peak_egress_rate;           // egress阶段峰值速率
    double avg_ingress_rate;           // ingress阶段平均速率
    double avg_egress_rate;            // egress阶段平均速率
};

// 全局变量用于进程管理和状态跟踪
pid_t tc_if_pid = -1;                 // tc-if进程ID
pid_t udp_receiver_pid = -1;          // UDP接收器进程ID
pid_t udp_sender_pid = -1;            // UDP发送器进程ID
SharedStats* shared_stats = nullptr;   // 共享内存指针
volatile sig_atomic_t main_process_pid = 0;  // 主进程PID

// 全局标志，防止重复清理和确保程序正确退出
static volatile sig_atomic_t cleanup_done = 0;        // 清理完成标志
static volatile sig_atomic_t test_completed = 0;      // 测试完成标志
static volatile sig_atomic_t graceful_shutdown_requested = 0;  // 优雅关闭请求标志

// 全局错误状态
static volatile sig_atomic_t global_error_count = 0;  // 全局错误计数
static volatile sig_atomic_t critical_error_occurred = 0;  // 严重错误发生标志

// 全局IP地址变量
static std::string local_ip_address;

// 前向声明 - 函数原型
void cleanup_and_exit(int sig);
void graceful_shutdown(int sig);
int udp_receiver_main(void);
int udp_sender_main(void);
bool validate_system_requirements(void);
bool initialize_shared_memory(void);
bool cleanup_shared_memory(void);
bool start_tc_if_process(const std::string& direction, uint32_t rate_mbps);
bool stop_tc_if_process(void);
bool cleanup_tc_rules(void);
bool start_tc_if_process(const std::string& direction, uint32_t rate_mbps);
bool stop_tc_if_process(void);
void print_test_header(void);
void print_test_footer(void);
void log_error(const std::string& message, int error_code);
void log_warning(const std::string& message);
void log_info(const std::string& message);
void log_success(const std::string& message);
std::string get_local_ip_address(void);

// 测试程序头部信息打印函数
void print_test_header(void) 
{
    std::cout << "🚀 TC-IF 限速功能集成测试程序" << std::endl;
    std::cout << "=================================" << std::endl;
    std::cout << "版本: 2.0.0" << std::endl;
    std::cout << "作者: DKapture Team" << std::endl;
    std::cout << "描述: 集成测试tc-if模块的双向限速功能" << std::endl;
    std::cout << "=================================" << std::endl;
    std::cout << std::endl;
}

// 测试程序尾部信息打印函数
void print_test_footer(void) 
{
    std::cout << std::endl;
    std::cout << "=================================" << std::endl;
    std::cout << "🎉 TC-IF 限速功能测试完成" << std::endl;
    std::cout << "=================================" << std::endl;
}

// 日志记录函数 - 提供统一的日志输出格式
void log_error(const std::string& message, int error_code) 
{
    std::cerr << "❌ [ERROR] " << message;
    if (error_code != 0) 
    {
        std::cerr << " (错误码: " << error_code << ", " << strerror(error_code) << ")";
    }
    std::cerr << std::endl;
    global_error_count++;
}

void log_warning(const std::string& message) 
{
    std::cout << "⚠️  [WARN] " << message << std::endl;
}

void log_info(const std::string& message) 
{
    std::cout << "ℹ️  [INFO] " << message << std::endl;
}

void log_success(const std::string& message) 
{
    std::cout << "✅ [SUCCESS] " << message << std::endl;
}

// 获取本机IP地址函数 - 动态获取本机可用的IP地址
std::string get_local_ip_address(void) 
{
    log_info("开始获取本机IP地址...");
    
    // 首先尝试连接外部地址来获取本机IP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) 
    {
        log_warning("无法创建socket，尝试备用方法");
        return "127.0.0.1";  // 返回回环地址作为备用
    }
    
    // 连接到一个外部地址（不会实际发送数据）
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);  // DNS端口
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);  // Google DNS
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
    {
        log_warning("无法连接外部地址，尝试枚举网络接口");
        close(sock);
        
        // 备用方法：枚举网络接口
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) 
        {
            log_error("获取网络接口失败，使用默认地址", errno);
            return "127.0.0.1";
        }
        
        std::string result_ip = "127.0.0.1";
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
        {
            if (ifa->ifa_addr == NULL) continue;
            
            if (ifa->ifa_addr->sa_family == AF_INET) 
            {
                struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
                
                std::string ip(ip_str);
                // 跳过回环地址，选择第一个有效的非回环地址
                if (ip != "127.0.0.1" && ip.substr(0, 3) != "127") 
                {
                    log_success("通过网络接口获取到IP地址: " + ip + " (接口: " + std::string(ifa->ifa_name) + ")");
                    result_ip = ip;
                    break;
                }
            }
        }
        
        freeifaddrs(ifaddr);
        return result_ip;
    }
    
    // 获取连接后的本地地址
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) < 0) 
    {
        log_error("获取本地socket地址失败", errno);
        close(sock);
        return "127.0.0.1";
    }
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
    
    close(sock);
    
    std::string result(ip_str);
    log_success("动态获取到本机IP地址: " + result);
    return result;
}

// 优雅关闭函数 - 处理信号中断，确保测试完成后再退出
void graceful_shutdown(int sig) 
{
    if (test_completed) 
    {
        // 测试已完成，执行清理
        log_info("测试已完成，执行清理退出");
        cleanup_and_exit(sig);
    } 
    else 
    {
        // 测试未完成，设置标志等待测试完成
        graceful_shutdown_requested = 1;
        log_warning("收到信号 " + std::to_string(sig) + "，等待测试完成...");
        cleanup_done = 1;
    }
}

// 信号处理函数 - 强制清理和退出
void cleanup_and_exit(int sig) 
{
    if (cleanup_done) 
    {
        return;  // 已经清理过了，直接返回
    }
    
    cleanup_done = 1;
    log_info("收到信号 " + std::to_string(sig) + "，正在清理...");
    
    // 关闭所有进程 - 使用SIGTERM进行优雅关闭
    if (udp_sender_pid > 0) 
    {
        if (kill(udp_sender_pid, SIGTERM) == 0) 
        {
            log_info("已发送SIGTERM到UDP发送器 (PID: " + std::to_string(udp_sender_pid) + ")");
        } 
        else 
        {
            log_warning("发送SIGTERM到UDP发送器失败: " + std::string(strerror(errno)));
        }
    }
    
    if (udp_receiver_pid > 0) 
    {
        if (kill(udp_receiver_pid, SIGTERM) == 0) 
        {
            log_info("已发送SIGTERM到UDP接收器 (PID: " + std::to_string(udp_receiver_pid) + ")");
        } 
        else 
        {
            log_warning("发送SIGTERM到UDP接收器失败: " + std::string(strerror(errno)));
        }
    }
    
    if (tc_if_pid > 0) 
    {
        if (kill(tc_if_pid, SIGTERM) == 0) 
        {
            log_info("已发送SIGTERM到tc-if (PID: " + std::to_string(tc_if_pid) + ")");
        } 
        else 
        {
            log_warning("发送SIGTERM到tc-if失败: " + std::string(strerror(errno)));
        }
    }
    
    // 等待进程退出 - 给进程一些时间进行优雅关闭
    log_info("等待进程优雅退出...");
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // 强制杀死仍在运行的进程 - 使用pkill确保清理干净
    log_info("强制清理残留进程...");
    int result = system("pkill -f 'tc-if' 2>/dev/null");
    if (result == 0) 
    {
        log_info("tc-if进程清理完成");
    }
    
    result = system("pkill -f 'udp' 2>/dev/null");
    if (result == 0) 
    {
        log_info("UDP进程清理完成");
    }
    
    // 清理共享内存 - 确保资源不泄露
    if (shared_stats != nullptr) 
    {
        if (munmap(shared_stats, sizeof(SharedStats)) == 0) 
        {
            log_info("共享内存映射清理完成");
        } 
        else 
        {
            log_warning("共享内存映射清理失败: " + std::string(strerror(errno)));
        }
        shared_stats = nullptr;
    }
    
    // 清理共享内存文件
    if (shm_unlink(SHARED_MEM_NAME) == 0) 
    {
        log_info("共享内存文件清理完成");
    } 
    else 
    {
        log_warning("共享内存文件清理失败: " + std::string(strerror(errno)));
    }
    
    // 清理TC规则 - 确保网络配置恢复
    cleanup_tc_rules();
    
    log_success("清理完成，退出程序");
    exit(1);
}

// 系统要求验证函数 - 检查运行环境是否满足要求
bool validate_system_requirements(void) 
{
    log_info("开始验证系统要求...");
    
    // 检查root权限
    if (getuid() != 0) 
    {
        log_error("此测试需要root权限，请使用sudo运行", ERROR_INVALID_PERMISSION);
        return false;
    }
    log_success("root权限验证通过");
    
    // 检查tc-if程序是否存在且可执行
    if (access(TC_IF_PATH, X_OK) != 0) 
    {
        log_error("tc-if程序未找到或不可执行: " + std::string(TC_IF_PATH), ERROR_TC_IF_NOT_FOUND);
        return false;
    }
    log_success("tc-if程序检查通过");
    
    // 检查网络接口lo是否存在
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        log_error("无法创建socket进行网络接口检查", errno);
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) 
    {
        log_error("网络接口lo不存在或无法访问", errno);
        close(sockfd);
        return false;
    }
    close(sockfd);
    log_success("网络接口lo检查通过");
    
    // 检查系统资源限制
    struct rlimit rlim;
    if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0) 
    {
        if (rlim.rlim_cur < 1024 * 1024)  // 小于1MB
        {
            log_warning("RLIMIT_MEMLOCK较小 (" + std::to_string(rlim.rlim_cur) + ")，可能影响BPF程序加载");
        } 
        else 
        {
            log_success("RLIMIT_MEMLOCK检查通过 (" + std::to_string(rlim.rlim_cur) + ")");
        }
    } 
    else 
    {
        log_warning("无法获取RLIMIT_MEMLOCK信息");
    }
    
    // 检查tc命令是否可用
    int result = system("tc -help >/dev/null 2>&1");
    if (result != 0) 
    {
        log_error("tc命令不可用，请安装iproute2包", result);
        return false;
    }
    log_success("tc命令检查通过");
    
    log_success("所有系统要求验证通过");
    return true;
}

// 共享内存初始化函数
bool initialize_shared_memory(void) 
{
    log_info("开始初始化共享内存...");
    
    // 创建共享内存文件
    int shm_fd = shm_open(SHARED_MEM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) 
    {
        log_error("共享内存文件创建失败", errno);
        return false;
    }
    
    // 设置文件大小
    if (ftruncate(shm_fd, sizeof(SharedStats)) == -1) 
    {
        log_error("共享内存文件大小设置失败", errno);
        close(shm_fd);
        return false;
    }
    
    // 映射共享内存
    shared_stats = (SharedStats*)mmap(NULL, sizeof(SharedStats), 
                                     PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_stats == MAP_FAILED) 
    {
        log_error("共享内存映射失败", errno);
        close(shm_fd);
        return false;
    }
    
    close(shm_fd);  // 关闭文件描述符，映射仍然有效
    
    // 初始化共享内存内容
    memset(shared_stats, 0, sizeof(SharedStats));
    shared_stats->test_start_time = time(NULL);
    shared_stats->test_running = 1;
    shared_stats->ingress_active = 0;
    shared_stats->egress_active = 0;
    shared_stats->error_count = 0;
    shared_stats->warning_count = 0;
    shared_stats->peak_ingress_rate = 0.0;
    shared_stats->peak_egress_rate = 0.0;
    shared_stats->avg_ingress_rate = 0.0;
    shared_stats->avg_egress_rate = 0.0;
    
    log_success("共享内存初始化完成");
    return true;
}

// 共享内存清理函数
bool cleanup_shared_memory(void) 
{
    log_info("开始清理共享内存...");
    
    if (shared_stats != nullptr) 
    {
        if (munmap(shared_stats, sizeof(SharedStats)) == 0) 
        {
            log_success("共享内存映射清理完成");
        } 
        else 
        {
            log_warning("共享内存映射清理失败: " + std::string(strerror(errno)));
        }
        shared_stats = nullptr;
    }
    
    if (shm_unlink(SHARED_MEM_NAME) == 0) 
    {
        log_success("共享内存文件清理完成");
    } 
    else 
    {
        log_warning("共享内存文件清理失败: " + std::string(strerror(errno)));
    }
    
    return true;
}

// TC规则清理函数
bool cleanup_tc_rules(void) 
{
    log_info("开始清理TC规则...");
    
    // 清理根队列规则
    int result = system("tc qdisc del dev lo root 2>/dev/null");
    if (result == 0) 
    {
        log_info("根队列规则清理完成");
    }
    
    // 清理ingress队列规则
    result = system("tc qdisc del dev lo ingress 2>/dev/null");
    if (result == 0) 
    {
        log_info("ingress队列规则清理完成");
    }
    
    // 清理egress队列规则
    result = system("tc qdisc del dev lo egress 2>/dev/null");
    if (result == 0) 
    {
        log_info("egress队列规则清理完成");
    }
    
    log_success("TC规则清理完成");
    return true;
}

/*  
 * 如果想测试tc-ip, tc-process, tc-cgroup等程序，需要在构建启动命令这里加入要执行的命令，默认测试限速是1M/s.
 * 目前只有tc-if程序的限速功能测试
 *
 */
// TC-IF进程启动函数 - 启动指定方向的tc-if进程
bool start_tc_if_process(const std::string& direction, uint32_t rate_mbps) 
{
    log_info("启动tc-if进程，方向: " + direction + "，限速: " + std::to_string(rate_mbps) + " MB/s");
    
    // 构建启动命令
    std::string rate_str = std::to_string(rate_mbps) + "M";
    /*
     * 在下面这里可以添加需要测试的模块对应的命令，这样就可以测试不同的模块的限速功能
     */
    std::string tc_cmd = std::string(TC_IF_PATH) + " -I lo -r " + rate_str + " -d " + direction + " -t 1 &";
    
    log_info("执行命令: " + tc_cmd);
    
    // 执行启动命令
    int result = system(tc_cmd.c_str());
    if (result != 0) 
    {
        log_error("tc-if程序启动失败，返回码: " + std::to_string(result), result);
            return false;
        }

    // 等待tc-if启动
    log_info("等待tc-if进程启动...");
    std::this_thread::sleep_for(std::chrono::milliseconds(TC_IF_STARTUP_DELAY));
    
    // 查找tc-if进程
    std::string find_cmd = "pgrep -f '" + std::string(TC_IF_PATH) + "'";
    result = system(find_cmd.c_str());
    if (result != 0) 
    {
        log_error("tc-if程序未找到运行中的进程", ERROR_TC_IF_STARTUP_FAILED);
                return false;
            }
    
    log_success("tc-if程序启动成功，方向: " + direction);
    return true;
}

// TC-IF进程停止函数 - 停止当前运行的tc-if进程
bool stop_tc_if_process(void) 
{
    log_info("停止tc-if进程...");
    
    // 使用pkill停止tc-if进程
    std::string kill_cmd = "pkill -f '" + std::string(TC_IF_PATH) + "'";
    int result = system(kill_cmd.c_str());
    
    if (result == 0) 
    {
        log_success("tc-if进程停止成功");
    } 
    else 
    {
        // pkill返回非0通常意味着没有找到进程，这是正常情况
        // 因为tc-if可能已经正常退出
        log_info("tc-if进程已退出或未找到，这是正常情况");
    }
    
    // 等待进程完全退出
    std::this_thread::sleep_for(std::chrono::milliseconds(TC_CLEANUP_DELAY));
    
    return true;
}


void tcp_signal_handler(int sig) {
    log_info("[PID: " + std::to_string(tcp_current_pid) + "] 收到信号 " + std::to_string(sig) + ", 正在退出...");
    tcp_running = 0;
}

// 生成随机数据包大小 (TCP版本)
int generate_tcp_packet_size() {
    double u = (double)rand() / RAND_MAX;
    
    // 确保数据包大小合理，避免分片
    if (u < 0.4) {
        // 40% 小包 (64-512字节)
        return 64 + (rand() % (512 - 64 + 1));
    } else if (u < 0.7) {
        // 30% 中等包 (512-1024字节)
        return 512 + (rand() % (1024 - 512 + 1));
    } else if (u < 0.9) {
        // 20% 大包 (1024-1400字节)
        return 1024 + (rand() % (1400 - 1024 + 1));
    } else {
        // 10% 超大包 (1400-1472字节) - 接近但不超过MTU
        return 1400 + (rand() % (1472 - 1400 + 1));
    }
}

// 生成随机发送间隔
int generate_send_interval() {
    double u = (double)rand() / RAND_MAX;
    
    if (u < 0.3) {
        // 30% 极速发送 (0.001-0.01ms) - 突发流量
        return 1 + (rand() % 9);
    } else if (u < 0.6) {
        // 30% 快速发送 (0.01-0.1ms) - 高负载
        return 10 + (rand() % 90);
    } else if (u < 0.8) {
        // 20% 正常发送 (0.1-1ms) - 正常负载
        return 100 + (rand() % 900);
    } else {
        // 20% 慢速发送 (1-10ms) - 低负载
        return 1000 + (rand() % 9000);
    }
}

int tcp_server_main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[TCP_BUFFER_SIZE];
    char data[MAX_DATA_SIZE];
    int bytes_sent, total_sent = 0;
    time_t start_time, current_time;
    
    tcp_current_pid = getpid();
    
    // 初始化随机数生成器
    srand(time(NULL));
    
    // 设置信号处理
    signal(SIGINT, tcp_signal_handler);
    signal(SIGTERM, tcp_signal_handler);
    
    // 创建socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        log_error("创建socket失败", errno);
        perror("创建socket失败");
        exit(EXIT_FAILURE);
    }
    
    // 设置socket选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_error("设置socket选项失败", errno);
        perror("设置socket选项失败");
        exit(EXIT_FAILURE);
    }
    
    // 配置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);
    
    // 绑定socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("绑定socket失败", errno);
        perror("绑定socket失败");
        exit(EXIT_FAILURE);
    }
    
    // 监听连接
    if (listen(server_fd, 5) < 0) {
        log_error("监听失败", errno);
        perror("监听失败");
        exit(EXIT_FAILURE);
    }
    
    log_info("TCP服务器启动，监听端口 " + std::to_string(TCP_PORT));
    log_info("等待客户端连接...");
    
    // 接受客户端连接
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        log_error("接受连接失败", errno);
        perror("接受连接失败");
        exit(EXIT_FAILURE);
    }
    
    log_info("客户端已连接: " + std::string(inet_ntoa(client_addr.sin_addr)) + ":" + std::to_string(ntohs(client_addr.sin_port)));
    
    // 准备随机测试数据
    for (int i = 0; i < MAX_DATA_SIZE; i++) {
        data[i] = 'A' + (rand() % 26);
    }
    
    start_time = time(NULL);
    log_info("开始发送随机数据...");
    log_info("时间     发送包数    发送字节数    带宽(MiB/s)");
    
    int packets_sent = 0;
    time_t last_report_time = start_time;
    int burst_count = 0;  // 突发计数器
    int burst_mode = 0;   // 突发模式标志
    double current_rate_multiplier = 1.0;  // 当前速率倍数
    time_t last_rate_change = start_time;
    
    // 持续发送数据
    while (tcp_running) {
        // 每秒更新速率倍数
        time_t current_time = time(NULL);
        if (current_time - last_rate_change >= 1) {
            double u = (double)rand() / RAND_MAX;
            if (u < 0.2) {
                current_rate_multiplier = 10.0;  // 20%概率极高速模式
            } else if (u < 0.4) {
                current_rate_multiplier = 5.0;   // 20%概率高速模式
            } else if (u < 0.6) {
                current_rate_multiplier = 2.0;   // 20%概率中速模式
            } else if (u < 0.8) {
                current_rate_multiplier = 1.0;   // 20%概率正常模式
            } else {
                current_rate_multiplier = 0.5;   // 20%概率低速模式
            }
            last_rate_change = current_time;
        }
        
        // 生成随机数据包大小
        int packet_size = generate_tcp_packet_size();
        
        // 生成随机数据内容
        for (int i = 0; i < packet_size; i++) {
            data[i] = 'A' + (rand() % 26);
        }
        
        bytes_sent = send(client_fd, data, packet_size, 0);
        if (bytes_sent < 0) {
            log_error("发送数据失败", errno);
            perror("发送数据失败");
            break;
        } else if (bytes_sent == 0) {
            log_info("客户端断开连接");
            break;
        }
        
        total_sent += bytes_sent;
        packets_sent++;
        current_time = time(NULL);
        
        // 每秒显示一次统计信息
        if (current_time != last_report_time) {
            double rate_mibps = total_sent / (1024.0 * 1024.0);
            time_t elapsed = current_time - start_time;  // 计算运行时间
            
            log_info("时间: " + std::to_string(elapsed / 60) + ":" + std::to_string(elapsed % 60) + 
                    "    发送包数: " + std::to_string(packets_sent) + 
                    "    发送字节数: " + std::to_string(total_sent) + 
                    "    带宽: " + std::to_string(rate_mibps) + " MiB/s");
            
            // 重置计数器
            last_report_time = current_time;
            total_sent = 0;
            packets_sent = 0;
            
            // 随机进入突发模式
            if ((double)rand() / RAND_MAX < 0.3) {  // 30%概率进入突发模式
                burst_mode = 1;
                burst_count = 0;
            }
        }
        
        // 生成随机发送间隔
        int delay_us;
        if (burst_mode && burst_count < 50) {
            // 突发模式：极速发送
            delay_us = 0;  // 无延迟，最大速度
            burst_count++;
        } else {
            // 正常模式：随机间隔，根据速率倍数调整
            delay_us = (int)(generate_send_interval() / current_rate_multiplier);
            burst_mode = 0;  // 退出突发模式
        }
        
        usleep(delay_us);
    }
    
    log_info("服务器关闭");
    close(client_fd);
    close(server_fd);
    return 0;
}



void tcp_client_signal_handler(int sig) {
    log_info("收到信号 " + std::to_string(sig) + ", 正在退出...");
    tcp_client_running = 0;
}

int tcp_client_main() {
    int client_fd;
    struct sockaddr_in server_addr;
    char buffer[TCP_CLIENT_BUFFER_SIZE];
    int bytes_received, total_received = 0;
    int packets_received = 0;
    time_t start_time, current_time, last_report_time;
    
    tcp_client_current_pid = getpid();
    
    // 设置信号处理
    signal(SIGINT, tcp_client_signal_handler);
    signal(SIGTERM, tcp_client_signal_handler);
    
    // 创建socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        log_error("创建socket失败", errno);
        perror("创建socket失败");
        exit(EXIT_FAILURE);
    }
    
    // 配置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TCP_CLIENT_PORT);
    
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        log_error("无效的服务器地址", errno);
        perror("无效的服务器地址");
        exit(EXIT_FAILURE);
    }
    
    log_info("TCP客户端启动");
    log_info("连接到服务器 " + std::string(SERVER_IP) + ":" + std::to_string(TCP_CLIENT_PORT));
    
    // 连接到服务器
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("连接服务器失败", errno);
        perror("连接服务器失败");
        exit(EXIT_FAILURE);
    }
    
    log_info("已连接到服务器");
    log_info("开始接收数据...");
    log_info("时间     接收包数    接收字节数    带宽(MiB/s)");
    
    start_time = time(NULL);
    last_report_time = start_time;
    
    // 持续接收数据
    while (tcp_client_running) {
        bytes_received = recv(client_fd, buffer, TCP_CLIENT_BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            log_error("接收数据失败", errno);
            perror("接收数据失败");
            break;
        } else if (bytes_received == 0) {
            log_info("服务器断开连接");
            break;
        }
        
        total_received += bytes_received;
        packets_received++;
        current_time = time(NULL);
        
        // 每秒显示一次统计信息
        if (current_time != last_report_time) {
            double rate_mibps = total_received / (1024.0 * 1024.0);
            time_t elapsed = current_time - start_time;  // 计算运行时间
            
            log_info("时间: " + std::to_string(elapsed / 60) + ":" + std::to_string(elapsed % 60) + 
                    "    接收包数: " + std::to_string(packets_received) + 
                    "    接收字节数: " + std::to_string(total_received) + 
                    "    带宽: " + std::to_string(rate_mibps) + " MiB/s");
            
            // 重置计数器
            last_report_time = current_time;
            total_received = 0;
            packets_received = 0;
        }
    }
    
    log_info("客户端关闭");
    close(client_fd);
    return 0;
} 

// UDP接收器函数 - 接收UDP数据包并统计流量
int udp_receiver_main(void) 
{
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int bytes_received = 0;
    int packets_received = 0;
    time_t last_report_time = 0;
    time_t start_time = 0;
    
    pid_t current_pid = getpid();
    
    // 映射到共享内存文件
    int shm_fd = shm_open(SHARED_MEM_NAME, O_RDWR, 0666);
    if (shm_fd == -1) 
    {
        log_error("共享内存文件打开失败", errno);
        perror("shm_open失败");
        return ERROR_SHARED_MEMORY_FAILED;
    }
    
    SharedStats* stats = (SharedStats*)mmap(NULL, sizeof(SharedStats), 
                                           PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (stats == MAP_FAILED) 
    {
        log_error("共享内存映射失败", errno);
        perror("mmap失败");
        close(shm_fd);
        return ERROR_SHARED_MEMORY_FAILED;
    }
    
    close(shm_fd);  // 关闭文件描述符，映射仍然有效
    
    log_info("=== UDP接收端 ===");
    log_info("绑定端口: " + std::to_string(LOCAL_PORT));
    log_info("等待数据包...");
    log_info("");
    
    // 创建UDP socket - 使用IPv4和UDP协议
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        log_error("socket创建失败", errno);
        perror("socket创建失败");
        return ERROR_SOCKET_CREATION_FAILED;
    }
    
    // 设置socket选项 - 允许地址重用，避免"地址已在使用"错误
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) 
    {
        log_error("setsockopt失败", errno);
        perror("setsockopt失败");
        close(sockfd);
        return ERROR_SOCKET_CREATION_FAILED;
    }
    
    // 设置接收缓冲区大小 - 提高大数据量接收性能
    int rcvbuf_size = BUFFER_SIZE * 10;  // 10倍缓冲区大小
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) 
    {
        log_error("设置接收缓冲区大小失败", errno);
        perror("SO_RCVBUF设置失败");
        // 不致命错误，继续执行
    } 
    else 
    {
        log_info("接收缓冲区大小设置为: " + std::to_string(rcvbuf_size) + " 字节");
    }
    
    // 设置绑定地址 - 监听所有网络接口的指定端口
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(LOCAL_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    // 绑定socket到指定地址和端口
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) 
    {
        log_error("bind失败", errno);
        perror("bind失败");
        close(sockfd);
        return ERROR_BIND_FAILED;
    }
    
    // 验证绑定是否成功
    socklen_t addr_len = sizeof(server_addr);
    if (getsockname(sockfd, (struct sockaddr*)&server_addr, &addr_len) == 0) 
    {
        log_info("成功绑定到端口: " + std::to_string(ntohs(server_addr.sin_port)));
    } 
    else 
    {
        log_error("无法获取绑定端口信息", errno);
    }
    
    log_info("UDP接收端已启动");
    log_info("时间     接收包数    接收字节数    带宽(MiB/s)");
    
    // 记录开始时间并初始化统计
    start_time = time(NULL);
    last_report_time = start_time;
    
    // 更新共享内存中的接收器启动时间
    stats->ingress_start_time = start_time;
    
    // 主接收循环 - 持续接收UDP数据包并统计流量
    while (true) 
    {
        // 检查是否需要优雅关闭
        if (graceful_shutdown_requested) 
        {
            log_info("收到优雅关闭请求，退出接收循环");
            break;
        }
        
        // 清空客户端地址结构 - 确保每次接收都使用干净的地址
        memset(&client_addr, 0, sizeof(client_addr));
        client_len = sizeof(client_addr);
        
        // 接收数据包 - 使用MSG_DONTWAIT避免阻塞
        int received = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT,
                               (struct sockaddr*)&client_addr, &client_len);
        
        if (received > 0) 
        {
            // 数据包接收成功，更新统计信息
            bytes_received += received;
            packets_received++;
            stats->total_bytes_received += received;  // 累计总字节数
            stats->total_packets_received++;         // 累计总包数
            
            // 根据测试阶段记录统计 - 区分ingress和egress阶段
            time_t current_time = time(NULL);
            time_t elapsed = current_time - start_time;
            
            if (elapsed < INGRESS_TEST_DURATION) 
            {
                // 接收限速阶段 (ingress) - tc-if限制接收流量
                stats->ingress_bytes += received;
                stats->ingress_packets++;
                stats->ingress_active = 1;
                
                // 注意：这里不更新峰值速率，因为单次接收的字节数不是速率
                // 峰值速率将在每秒统计时更新
            } 
            else if (elapsed >= (INGRESS_TEST_DURATION + 4)) 
            {
                // 发送限速阶段 (egress) - 延迟4秒开始统计，tc-if完全启动需要4秒
                stats->egress_bytes += received;
                stats->egress_packets++;
                stats->egress_active = 1;
                
                // 注意：这里不更新峰值速率，因为单次接收的字节数不是速率
                // 峰值速率将在每秒统计时更新
            }
            
            // 每秒显示一次统计信息 - 实时监控流量变化
            if (current_time != last_report_time) 
            {
                double rate_mibps = bytes_received / (1024.0 * 1024.0);
                double total_rate_mibps = (stats->total_bytes_received / (1024.0 * 1024.0)) / (elapsed + 1);
                
                // 正确更新峰值速率 - 每秒的瞬时速率
                if (elapsed < INGRESS_TEST_DURATION) 
                {
                    // ingress阶段：更新ingress峰值速率
                    if (rate_mibps > stats->peak_ingress_rate) 
                    {
                        stats->peak_ingress_rate = rate_mibps;
                    }
                } 
                else if (elapsed >= (INGRESS_TEST_DURATION + 4)) 
                {
                    // egress阶段：更新egress峰值速率
                    if (rate_mibps > stats->peak_egress_rate) 
                    {
                        stats->peak_egress_rate = rate_mibps;
                    }
                }
                
                log_info("时间: " + std::to_string(elapsed / 60) + ":" + std::to_string(elapsed % 60) + 
                        "    接收包数: " + std::to_string(packets_received) + 
                        "    接收字节数: " + std::to_string(bytes_received) + 
                        "    带宽: " + std::to_string(rate_mibps) + " MiB/s (累计: " + std::to_string(total_rate_mibps) + " MiB/s)");
                
                // 重置计数器 - 准备下一秒的统计
                last_report_time = current_time;
                bytes_received = 0;
                packets_received = 0;
            }
        } 
        else if (received < 0) 
        {
            // 接收失败处理 - 区分不同类型的错误
            if (errno == EAGAIN || errno == EWOULDBLOCK) 
            {
                // 非阻塞模式下没有数据可读，短暂休眠避免CPU占用过高
                usleep(1000);  // 1ms
                continue;
            } 
            else 
            {
                log_error("recvfrom失败: " + std::string(strerror(errno)), errno);
                perror("recvfrom失败");
                
                // 记录错误到共享内存
                stats->error_count++;
                
                // 如果是严重错误，考虑退出
                if (errno == EBADF || errno == ENOTSOCK) 
                {
                    log_error("检测到严重socket错误，退出接收循环", errno);
                    break;
                }
            }
        }
        
        // 检查测试是否应该结束
        time_t current_time = time(NULL);
        time_t elapsed = current_time - start_time;
        if (elapsed >= TEST_DURATION_SEC + 10)  // 额外10秒缓冲时间
        {
            log_info("测试时间已到，退出接收循环");
            break;
        }
    }
    
    // 清理资源
    log_info("UDP接收器正在关闭...");
    close(sockfd);
    
    // 更新最终统计信息
    if (stats != nullptr) 
    {
        time_t total_time = time(NULL) - start_time;
        if (total_time > 0) 
        {
            stats->avg_ingress_rate = (stats->ingress_bytes / (1024.0 * 1024.0)) / 
                                    (INGRESS_TEST_DURATION > 0 ? INGRESS_TEST_DURATION : 1);
            stats->avg_egress_rate = (stats->egress_bytes / (1024.0 * 1024.0)) / 
                                   ((TEST_DURATION_SEC - INGRESS_TEST_DURATION) > 0 ? 
                                    (TEST_DURATION_SEC - INGRESS_TEST_DURATION) : 1);
        }
    }
    
    log_info("UDP接收器已关闭");
    return SUCCESS;
}

// 数据包生成工具函数 - 生成各种大小的测试数据包
int generate_packet_size(void) 
{
    // 使用正态分布生成更真实的数据包大小分布
    double u = (double)rand() / RAND_MAX;
    
    if (u < 0.4) 
    {
        // 40%概率：小包 (64-512字节) - 控制包、ACK等
        return MIN_PACKET_SIZE + (rand() % (512 - MIN_PACKET_SIZE + 1));
    } 
    else if (u < 0.7) 
    {
        // 30%概率：中等包 (512-1024字节) - 普通数据包
        return 512 + (rand() % (1024 - 512 + 1));
    } 
    else if (u < 0.9) 
    {
        // 20%概率：大包 (1024-1400字节) - 文件传输等
        return 1024 + (rand() % (1400 - 1024 + 1));
    } 
    else 
    {
        // 10%概率：超大包 (1400-1472字节) - 接近MTU限制
        return 1400 + (rand() % (MAX_PACKET_SIZE - 1400 + 1));
    }
}

// 生成发送间隔 - 根据目标速率计算数据包发送间隔
int generate_send_interval(double target_rate_mbps) 
{
    // 基于平均数据包大小计算每秒需要发送的包数
    double avg_packet_size = 1024.0;  // 假设平均包大小1KB
    double packets_per_second = (target_rate_mbps * 1024 * 1024) / avg_packet_size;
    double interval_us = 1000000.0 / packets_per_second;
    
    // 添加随机变化，模拟真实网络环境的不确定性
    double variation = 0.3;  // 30%的变化范围
    double random_factor = 1.0 + (rand() % 200 - 100) / 100.0 * variation;
    interval_us *= random_factor;
    
    // 限制发送间隔范围，避免过快或过慢
    if (interval_us < 5) interval_us = 5;        // 最小5微秒
    if (interval_us > 100000) interval_us = 100000;  // 最大100毫秒
    
    return (int)interval_us;
}

// 生成目标传输速率 - 动态变化以测试限速效果
double generate_target_rate(void) 
{
    // 使用分层概率分布生成不同的目标速率
    double u = (double)rand() / RAND_MAX;
    
    if (u < 0.25) 
    {
        // 25%概率：高负载 (3.0-10.0 MB/s) - 测试限速上限
        return 3.0 + (rand() % 700) / 100.0;
    } 
    else if (u < 0.45) 
    {
        // 20%概率：中等负载 (1.0-3.0 MB/s) - 正常流量
        return 1.0 + (rand() % 200) / 100.0;
    } 
    else if (u < 0.65) 
    {
        // 20%概率：低负载 (0.3-1.0 MB/s) - 轻量级流量
        return 0.3 + (rand() % 70) / 100.0;
    } 
    else if (u < 0.80) 
    {
        // 15%概率：极低负载 (0.1-0.3 MB/s) - 背景流量
        return 0.1 + (rand() % 20) / 100.0;
    } 
    else 
    {
        // 20%概率：突发流量 (0.01-0.1 MB/s) - 突发情况
        return 0.01 + (rand() % 9) / 100.0;
    }
}

// 数据包内容生成函数 - 创建有意义的测试数据
void generate_packet_content(char* buffer, int size) 
{
    // 生成包含时间戳、序列号和随机数据的测试包
    if (size < 16) 
    {
        // 小包只填充随机字符
        for (int i = 0; i < size; i++) 
        {
            buffer[i] = 'A' + (rand() % 26);
        }
        return;
    }
    
    // 大包包含结构化数据
    uint32_t timestamp = (uint32_t)time(NULL);
    uint32_t sequence = rand();
    uint16_t packet_size = (uint16_t)size;
    uint16_t checksum = 0;
    
    // 写入头部信息
    memcpy(buffer, &timestamp, sizeof(timestamp));
    memcpy(buffer + 4, &sequence, sizeof(sequence));
    memcpy(buffer + 8, &packet_size, sizeof(packet_size));
    memcpy(buffer + 10, &checksum, sizeof(checksum));
    
    // 填充剩余空间为随机数据
    for (int i = 16; i < size; i++) 
    {
        buffer[i] = 'A' + (rand() % 26);
    }
    
    // 计算简单的校验和
    for (int i = 0; i < size; i++) 
    {
        checksum += (uint8_t)buffer[i];
    }
    memcpy(buffer + 10, &checksum, sizeof(checksum));
}

// UDP发送器函数 - 生成并发送UDP数据包以测试限速效果
int udp_sender_main(void) 
{
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[MAX_PACKET_SIZE];
    int bytes_sent = 0;
    int packets_sent = 0;
    time_t last_report_time = 0;
    time_t start_time = 0;
    
    pid_t current_pid = getpid();
    
    // 映射到共享内存文件 - 用于统计信息共享
    int shm_fd = shm_open(SHARED_MEM_NAME, O_RDWR, 0666);
    if (shm_fd == -1) 
    {
        log_error("共享内存文件打开失败", errno);
        perror("shm_open失败");
        return ERROR_SHARED_MEMORY_FAILED;
    }
    
    SharedStats* stats = (SharedStats*)mmap(NULL, sizeof(SharedStats), 
                                           PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (stats == MAP_FAILED) 
    {
        log_error("共享内存映射失败", errno);
        perror("mmap失败");
        close(shm_fd);
        return ERROR_SHARED_MEMORY_FAILED;
    }
    
    close(shm_fd);  // 关闭文件描述符，映射仍然有效
    
    // 初始化随机数生成器 - 使用当前时间作为种子
    srand(time(NULL) + current_pid);  // 添加PID避免多个进程使用相同种子
    
    log_info("=== UDP发送端 ===");
    log_info("开始发送UDP数据包...");
    log_info("目标地址: " + local_ip_address + ":" + std::to_string(LOCAL_PORT));
    log_info("最大包大小: " + std::to_string(MAX_PACKET_SIZE) + " 字节");
    log_info("时间     发送包数    发送字节数    带宽(MiB/s)    目标速率(MB/s)");
    
    // 创建UDP socket - 使用IPv4和UDP协议
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        log_error("socket创建失败", errno);
        perror("socket创建失败");
        return ERROR_SOCKET_CREATION_FAILED;
    }
    
    // 设置socket选项 - 提高发送性能
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) 
    {
        log_error("设置SO_REUSEADDR失败", errno);
        perror("SO_REUSEADDR设置失败");
        // 不致命错误，继续执行
    }
    
    // 设置发送缓冲区大小
    int sndbuf_size = MAX_PACKET_SIZE * 100;  // 100个包的缓冲区
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size)) < 0) 
    {
        log_error("设置发送缓冲区大小失败", errno);
        perror("SO_SNDBUF设置失败");
    } 
    else 
    {
        log_info("发送缓冲区大小设置为: " + std::to_string(sndbuf_size) + " 字节");
    }
    
    // 设置目标地址 - 指定接收端的IP和端口
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(LOCAL_PORT);
    
    // 使用动态获取的IP地址
    if (inet_pton(AF_INET, local_ip_address.c_str(), &server_addr.sin_addr) <= 0) 
    {
        log_error("无效的目标IP地址: " + local_ip_address, ERROR_SOCKET_CREATION_FAILED);
        close(sockfd);
        return ERROR_SOCKET_CREATION_FAILED;
    }
    
    log_info("已设置目标地址: " + local_ip_address + ":" + std::to_string(LOCAL_PORT));
    
    // 初始化时间统计
    start_time = time(NULL);
    last_report_time = start_time;
    
    // 动态速率控制变量 - 每秒更新目标传输速率
    double current_target_rate = generate_target_rate();
    time_t last_rate_change = start_time;
    int high_load_duration = 0;
    int max_high_load_duration = 5;
    
    // 性能统计变量
    uint64_t total_bytes_sent = 0;
    uint64_t total_packets_sent = 0;
    double peak_send_rate = 0.0;
    double avg_send_rate = 0.0;
    
    // 主发送循环 - 持续生成并发送UDP数据包
    while (true) 
    {
        // 检查是否需要优雅关闭
        if (graceful_shutdown_requested) 
        {
            log_info("收到优雅关闭请求，退出发送循环");
            break;
        }
        
        // 每秒更新目标传输速率 - 模拟真实网络流量的动态变化
        time_t current_time = time(NULL);
        if (current_time != last_rate_change) 
        {
            if (current_target_rate >= 3.0 && high_load_duration < max_high_load_duration) 
            {
                // 高负载持续时间控制 - 避免长时间高负载
                high_load_duration++;
                current_target_rate = 3.0 + (rand() % 500) / 100.0;
                                        log_info("[PID: " + std::to_string(tcp_current_pid) + "] 高负载模式 #" + std::to_string(high_load_duration) + "，目标速率: " + std::to_string(current_target_rate) + " MB/s");
            } 
            else 
            {
                // 生成新的随机目标速率
                current_target_rate = generate_target_rate();
                if (current_target_rate >= 3.0) 
                {
                    high_load_duration = 1;
                } 
                else 
                {
                    high_load_duration = 0;
                }
            }
            last_rate_change = current_time;
        }
        
        // 动态生成数据包大小 - 模拟真实网络的数据包大小分布
        int packet_size = generate_packet_size();
        
        // 生成数据包内容 - 包含结构化数据和校验信息
        generate_packet_content(buffer, packet_size);
        
        // 发送数据包 - 使用sendto发送到指定目标
        int sent = sendto(sockfd, buffer, packet_size, 0,
                         (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        if (sent > 0) 
        {
            // 发送成功，更新统计信息
            bytes_sent += sent;
            packets_sent++;
            total_bytes_sent += sent;
            total_packets_sent++;
            stats->total_bytes_sent += sent;      // 累计总字节数
            stats->total_packets_sent++;          // 累计总包数
            
            // 注意：egress限速效果应该通过接收器接收到的流量来判断
            // 这里不统计发送量，因为发送量无法反映限速效果
            
            // 每秒显示一次统计信息 - 实时监控发送性能
            if (current_time != last_report_time) 
            {
                double rate_mibps = bytes_sent / (1024.0 * 1024.0);
                time_t elapsed = current_time - start_time;
                
                // 更新峰值发送速率
                if (rate_mibps > peak_send_rate) 
                {
                    peak_send_rate = rate_mibps;
                }
                
                // 计算平均发送速率
                if (elapsed > 0) 
                {
                    avg_send_rate = (total_bytes_sent / (1024.0 * 1024.0)) / elapsed;
                }
                
                log_info("[PID: " + std::to_string(current_pid) + "] " + 
                        std::string(elapsed / 60 < 10 ? "0" : "") + std::to_string(elapsed / 60) + ":" + 
                        std::string(elapsed % 60 < 10 ? "0" : "") + std::to_string(elapsed % 60) + 
                        "    " + std::to_string(packets_sent) + "    " + std::to_string(bytes_sent) + 
                        "    " + std::to_string(rate_mibps) + "    " + std::to_string(current_target_rate));
                
                // 重置计数器 - 准备下一秒的统计
                last_report_time = current_time;
                bytes_sent = 0;
                packets_sent = 0;
            }
        } 
        else if (sent < 0) 
        {
            // 发送失败处理 - 区分不同类型的错误
            if (errno == EAGAIN || errno == EWOULDBLOCK) 
            {
                // 发送缓冲区满，短暂等待
                usleep(1000);  // 1ms
                continue;
            } 
            else 
            {
                log_error("[PID: " + std::to_string(current_pid) + "] sendto失败: " + std::string(strerror(errno)), errno);
                perror("sendto失败");
                
                // 记录错误到共享内存
                stats->error_count++;
                
                // 如果是严重错误，考虑退出
                if (errno == EBADF || errno == ENOTSOCK) 
                {
                    log_error("[PID: " + std::to_string(current_pid) + "] 检测到严重socket错误，退出发送循环", 0);
                    break;
                }
            }
        }
        
        // 根据目标传输速率生成发送间隔 - 控制发送速率
        int delay_us = generate_send_interval(current_target_rate);
        usleep(delay_us);
        
        // 检查测试是否应该结束
        time_t elapsed = current_time - start_time;
        if (elapsed >= TEST_DURATION_SEC + 10)  // 额外10秒缓冲时间
        {
            log_info("[PID: " + std::to_string(current_pid) + "] 测试时间已到，退出发送循环");
            break;
        }
    }
    
    // 清理资源并输出最终统计
    log_info("[PID: " + std::to_string(current_pid) + "] UDP发送器正在关闭...");
    log_info("[PID: " + std::to_string(current_pid) + "] 最终统计:");
    log_info("[PID: " + std::to_string(current_pid) + "]   - 总发送字节: " + std::to_string(total_bytes_sent));
    log_info("[PID: " + std::to_string(current_pid) + "]   - 总发送包数: " + std::to_string(total_packets_sent));
    log_info("[PID: " + std::to_string(current_pid) + "]   - 峰值发送速率: " + std::to_string(peak_send_rate) + " MB/s");
    log_info("[PID: " + std::to_string(current_pid) + "]   - 平均发送速率: " + std::to_string(avg_send_rate) + " MB/s");
    
    close(sockfd);
    log_info("[PID: " + std::to_string(current_pid) + "] UDP发送器已关闭");
    return SUCCESS;
}

// 主函数 - TC-IF限速功能集成测试程序入口点
int main(void) 
{
    // 记录主进程PID
    main_process_pid = getpid();
    
    // 打印测试程序头部信息
    print_test_header();
    
    // 系统要求验证 - 检查运行环境是否满足要求
    if (!validate_system_requirements()) 
    {
        log_error("系统要求验证失败，程序无法继续运行", ERROR_INVALID_PERMISSION);
        return ERROR_INVALID_PERMISSION;
    }
    
    // 设置信号处理 - 使用优雅关闭，让程序完成测试
    signal(SIGINT, graceful_shutdown);
    signal(SIGTERM, graceful_shutdown);
    
    log_success("系统要求验证通过，开始初始化测试环境");
    
    // 获取本机IP地址
    local_ip_address = get_local_ip_address();
    if (local_ip_address.empty() || local_ip_address == "127.0.0.1") 
    {
        log_warning("未能获取有效的网络IP地址，将使用回环地址127.0.0.1进行测试");
        local_ip_address = "127.0.0.1";
    }
    
    // 清理可能存在的TC规则 - 确保网络配置干净
    if (!cleanup_tc_rules()) 
    {
        log_warning("TC规则清理失败，可能影响测试结果");
    }
    
    // 初始化共享内存 - 用于进程间通信
    if (!initialize_shared_memory()) 
    {
        log_error("共享内存初始化失败，程序无法继续", ERROR_SHARED_MEMORY_FAILED);
        return ERROR_SHARED_MEMORY_FAILED;
    }
    
    // 验证共享内存初始化结果
    if (shared_stats == nullptr) 
    {
        log_error("共享内存指针无效，初始化失败", ERROR_SHARED_MEMORY_FAILED);
        return ERROR_SHARED_MEMORY_FAILED;
    }
    
    log_success("测试环境初始化完成");
    
    // 输出测试配置信息
    log_info("测试配置信息:");
    log_info("  - 测试总时长: " + std::to_string(TEST_DURATION_SEC) + " 秒");
    log_info("  - Ingress测试时长: " + std::to_string(INGRESS_TEST_DURATION) + " 秒");
    log_info("  - Egress测试时长: " + std::to_string(EGRESS_TEST_DURATION) + " 秒");
    log_info("  - 目标限速: " + std::to_string(TARGET_RATE_MBPS) + " MB/s");
    log_info("  - 最大允许速率: " + std::to_string(MAX_ALLOWED_RATE_MBPS) + " MB/s");
    log_info("  - 本地IP地址: " + local_ip_address);
    log_info("  - 本地端口: " + std::to_string(LOCAL_PORT));
    
    // 记录测试开始时间
    shared_stats->test_start_time = time(NULL);
    shared_stats->test_running = 1;
    
    log_info("开始启动测试组件...");
    
    // 1. 启动tc-if程序 (ingress模式)
    log_info("开始启动tc-if程序 (ingress模式)...");
    if (!start_tc_if_process("ingress", TARGET_RATE_MBPS)) 
    {
        log_error("tc-if程序启动失败，无法继续测试", ERROR_TC_IF_STARTUP_FAILED);
        return ERROR_TC_IF_STARTUP_FAILED;
    }
    
    // 更新共享内存状态
    shared_stats->ingress_active = 1;
    shared_stats->ingress_start_time = time(NULL);
    
    // 2. 启动UDP接收器
    log_info("启动UDP接收器...");
    udp_receiver_pid = fork();
    if (udp_receiver_pid == 0) 
    {
        /*
         *在这里可以替换为tcp接收函数进行测试，与此同时，下面也要替换为tcp发送函数
         * 
         */
        // 子进程：运行UDP接收器
        exit(udp_receiver_main());
    } 
    else if (udp_receiver_pid < 0) 
    {
        log_error("创建UDP接收器进程失败", ERROR_PROCESS_CREATION_FAILED);
        return ERROR_PROCESS_CREATION_FAILED;
    }
    
    log_success("UDP接收器已启动 (PID: " + std::to_string(udp_receiver_pid) + ")");
    
    // 等待接收器启动
    std::this_thread::sleep_for(std::chrono::milliseconds(PROCESS_STARTUP_DELAY));
    
    // 3. 启动UDP发送器
    log_info("启动UDP发送器...");
    udp_sender_pid = fork();
    if (udp_sender_pid == 0) 
    {
        // 子进程：运行UDP发送器
        exit(udp_sender_main());
    } 
    else if (udp_sender_pid < 0) 
    {
        log_error("创建UDP发送器进程失败", ERROR_PROCESS_CREATION_FAILED);
        return ERROR_PROCESS_CREATION_FAILED;
    }
    
    log_success("UDP发送器已启动 (PID: " + std::to_string(udp_sender_pid) + ")");
    
    // 4. 开始动态切换测试
    log_info("开始" + std::to_string(TEST_DURATION_SEC) + "秒双向限速测试...");
    log_info("监控流量统计...");
    
    // 第一阶段：接收限速测试 (ingress)
    log_info("🔴 第一阶段：接收限速测试 (0-" + std::to_string(INGRESS_TEST_DURATION) + "秒)");
    log_info("📡 tc-if配置：-d ingress (限制接收流量)");
    
    // 执行ingress阶段测试
    for (int i = 1; i <= INGRESS_TEST_DURATION; i++) 
    {
        // 检查是否需要优雅关闭
        if (graceful_shutdown_requested) 
        {
            log_warning("收到优雅关闭请求，提前结束ingress阶段测试");
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        log_info("⏱️  第" + std::to_string(i) + "秒 (接收限速)");
        
        // 每秒检查进程状态
        if (kill(udp_receiver_pid, 0) != 0) 
        {
            log_error("UDP接收器进程意外退出", ERROR_PROCESS_CREATION_FAILED);
            return ERROR_PROCESS_CREATION_FAILED;
        }
        
        if (kill(udp_sender_pid, 0) != 0) 
        {
            log_error("UDP发送器进程意外退出", ERROR_PROCESS_CREATION_FAILED);
            return ERROR_PROCESS_CREATION_FAILED;
        }
    }
    
    // 切换tc-if配置：从ingress改为egress
    log_info("🔄 切换限速方向...");
    log_info("🛑 关闭当前tc-if进程 (ingress模式)...");
    
    // 停止ingress模式的tc-if进程
    if (!stop_tc_if_process()) 
    {
        log_warning("停止ingress模式tc-if进程失败，继续执行");
    }
    
    // 清理TC规则，避免分离错误
    if (!cleanup_tc_rules()) 
    {
        log_warning("TC规则清理失败，可能影响后续测试");
    }
    
    // 启动egress模式的tc-if进程
    log_info("🔧 启动新的tc-if进程 (egress模式)...");
    if (!start_tc_if_process("egress", TARGET_RATE_MBPS)) 
    {
        log_error("tc-if程序(egress)启动失败，无法继续测试", ERROR_TC_IF_STARTUP_FAILED);
        return ERROR_TC_IF_STARTUP_FAILED;
    }
    
    // 更新共享内存状态
    shared_stats->ingress_active = 0;
    shared_stats->egress_active = 1;
    shared_stats->egress_start_time = time(NULL);
    
    // 第二阶段：发送限速测试 (egress)
    log_info("🔵 第二阶段：发送限速测试 (" + std::to_string(INGRESS_TEST_DURATION) + "-" + std::to_string(TEST_DURATION_SEC) + "秒)");
    log_info("📤 tc-if配置：-d egress (限制发送流量)");
    
    // 执行egress阶段测试
    for (int i = INGRESS_TEST_DURATION + 1; i <= TEST_DURATION_SEC; i++) 
    {
        // 检查是否需要优雅关闭
        if (graceful_shutdown_requested) 
        {
            log_warning("收到优雅关闭请求，提前结束egress阶段测试");
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        log_info("⏱️  第" + std::to_string(i) + "秒 (发送限速)");
        
        // 每秒检查进程状态
        if (kill(udp_receiver_pid, 0) != 0) 
        {
            log_error("UDP接收器进程意外退出", ERROR_PROCESS_CREATION_FAILED);
            return ERROR_PROCESS_CREATION_FAILED;
        }
        
        if (kill(udp_sender_pid, 0) != 0) 
        {
            log_error("UDP发送器进程意外退出", ERROR_PROCESS_CREATION_FAILED);
            return ERROR_PROCESS_CREATION_FAILED;
        }
    }
    
    // 5. 测试完成，关闭所有组件
    log_info("🛑 测试完成，开始关闭所有组件...");
    
    // 设置测试完成标志
    test_completed = 1;
    shared_stats->test_running = 0;
    
    // 关闭UDP发送器
    if (udp_sender_pid > 0) 
    {
        if (kill(udp_sender_pid, SIGTERM) == 0) 
        {
            log_success("已发送SIGTERM到UDP发送器");
        } 
        else 
        {
            log_warning("发送SIGTERM到UDP发送器失败: " + std::string(strerror(errno)));
        }
    }
    
    // 关闭UDP接收器
    if (udp_receiver_pid > 0) 
    {
        if (kill(udp_receiver_pid, SIGTERM) == 0) 
        {
            log_success("已发送SIGTERM到UDP接收器");
        } 
        else 
        {
            log_warning("发送SIGTERM到UDP接收器失败: " + std::string(strerror(errno)));
        }
    }
    
    // 关闭tc-if程序
    if (!stop_tc_if_process()) 
    {
        log_warning("停止tc-if程序失败");
    }
    
    // 检查进程状态
    log_info("🔍 进程状态检查:");
    if (udp_sender_pid > 0) 
    {
        std::string status = (kill(udp_sender_pid, 0) == 0) ? "运行中" : "已退出";
        log_info("UDP发送器PID: " + std::to_string(udp_sender_pid) + " (状态: " + status + ")");
    }
    
    if (udp_receiver_pid > 0) 
    {
        std::string status = (kill(udp_receiver_pid, 0) == 0) ? "运行中" : "已退出";
        log_info("UDP接收器PID: " + std::to_string(udp_receiver_pid) + " (状态: " + status + ")");
    }
    
    // 等待进程退出
    log_info("等待进程优雅退出...");
    std::this_thread::sleep_for(std::chrono::milliseconds(TC_CLEANUP_DELAY));
    
    // 添加调试信息
    log_info("🔍 调试信息:");
    log_info("共享内存指针: " + std::string(shared_stats ? "有效" : "无效"));
    if (shared_stats) 
    {
        log_info("总接收字节: " + std::to_string(shared_stats->total_bytes_received));
        log_info("总发送字节: " + std::to_string(shared_stats->total_bytes_sent));
        log_info("Ingress字节: " + std::to_string(shared_stats->ingress_bytes));
        log_info("Egress字节: " + std::to_string(shared_stats->egress_bytes));
        log_info("错误计数: " + std::to_string(shared_stats->error_count));
        log_info("警告计数: " + std::to_string(shared_stats->warning_count));
    } 
    else 
    {
        log_error("共享内存无效，无法读取统计信息", ERROR_SHARED_MEMORY_FAILED);
        return ERROR_SHARED_MEMORY_FAILED;
    }
    
    // 计算测试结果和限速验证
    log_info("📊 双向限速测试结果分析");
    log_info("=================================");
    
    // 从共享内存读取统计信息
    uint64_t final_bytes_received = shared_stats->total_bytes_received;
    uint64_t final_packets_received = shared_stats->total_packets_received;
    uint64_t final_bytes_sent = shared_stats->total_bytes_sent;
    uint64_t final_packets_sent = shared_stats->total_packets_sent;
    
    // 阶段统计
    uint64_t ingress_bytes = shared_stats->ingress_bytes;
    uint64_t ingress_packets = shared_stats->ingress_packets;
    uint64_t egress_bytes = shared_stats->egress_bytes;
    uint64_t egress_packets = shared_stats->egress_packets;
    
    // 计算各阶段平均速率
    double ingress_rate = (ingress_bytes / (1024.0 * 1024.0)) / INGRESS_TEST_DURATION;
    double egress_test_duration = EGRESS_TEST_DURATION;  
    double egress_rate = (egress_bytes / (1024.0 * 1024.0)) / egress_test_duration;
    
    // 输出详细统计
    log_info("测试持续时间: " + std::to_string(TEST_DURATION_SEC) + " 秒");
    log_info("🔴 第一阶段：接收限速测试 (0-" + std::to_string(INGRESS_TEST_DURATION) + "秒)");
    log_info("  - 数据包: " + std::to_string(ingress_packets) + " 个");
    log_info("  - 字节数: " + std::to_string(ingress_bytes) + " 字节");
    log_info("  - 平均速率: " + std::to_string(ingress_rate) + " MB/s");
    log_info("  - 峰值速率: " + std::to_string(shared_stats->peak_ingress_rate) + " MB/s");
    
    log_info("🔵 第二阶段：发送限速测试 (" + std::to_string(INGRESS_TEST_DURATION) + "-" + std::to_string(TEST_DURATION_SEC) + "秒)");
    log_info("  - 实际测试时间: " + std::to_string(egress_test_duration) + " 秒");
    log_info("  - 数据包: " + std::to_string(egress_packets) + " 个");
    log_info("  - 字节数: " + std::to_string(egress_bytes) + " 字节");
    log_info("  - 平均速率: " + std::to_string(egress_rate) + " MB/s");
    log_info("  - 峰值速率: " + std::to_string(shared_stats->peak_egress_rate) + " MB/s");
    
    // 双向限速验证
    log_info("🔍 双向限速效果验证");
    log_info("=================================");
    log_info("目标限速: " + std::to_string(TARGET_RATE_MBPS) + " MB/s");
    log_info("最大允许: " + std::to_string(MAX_ALLOWED_RATE_MBPS) + " MB/s");
    
    // 接收限速验证
    log_info("📡 接收限速验证 (ingress):");
    log_info("实际接收: " + std::to_string(ingress_rate) + " MB/s");
    bool ingress_success = ingress_rate <= MAX_ALLOWED_RATE_MBPS;
    
    if (ingress_success) 
    {
        log_success("接收限速成功！速率在允许范围内");
    } 
    else 
    {
        log_error("接收限速失败！速率超过允许范围", 0);
    }
    
    // 发送限速验证 (通过接收器接收到的流量判断)
    log_info("📤 发送限速验证 (egress):");
    log_info("实际接收: " + std::to_string(egress_rate) + " MB/s");
    log_info("说明：此阶段tc-if在egress方向限速，接收器接收到的流量应该被限制在" + std::to_string(TARGET_RATE_MBPS) + " MB/s左右");
    bool egress_success = egress_rate <= MAX_ALLOWED_RATE_MBPS;
    
    if (egress_success) 
    {
        log_success("发送限速成功！接收到的流量在允许范围内");
    } 
    else 
    {
        log_error("发送限速失败！接收到的流量超过允许范围", 0);
    }
    
    // 总体测试结果
    bool rate_limit_success = ingress_success && egress_success;
    
    if (rate_limit_success) 
    {
        log_success("🎉 双向限速测试全部成功！");
        log_success("✅ tc-if在ingress和egress方向都能正确限速");
    } 
    else 
    {
        log_warning("⚠️  双向限速测试部分失败！");
        if (!ingress_success) 
        {
            log_error("ingress方向限速未生效", 0);
        }
        if (!egress_success) 
        {
            log_error("egress方向限速未生效", 0);
        }
    }
    
    // 打印测试完成信息
    print_test_footer();
    log_success("🎉 测试完成！所有组件已自动关闭");
    
    // 输出最终统计摘要
    log_info("📊 最终统计摘要:");
    log_info("  - 总接收字节: " + std::to_string(final_bytes_received));
    log_info("  - 总接收包数: " + std::to_string(final_packets_received));
    log_info("  - 总发送字节: " + std::to_string(final_bytes_sent));
    log_info("  - 总发送包数: " + std::to_string(final_packets_sent));
    log_info("  - 全局错误计数: " + std::to_string(global_error_count));
    
    // 清理共享内存
    if (!cleanup_shared_memory()) 
    {
        log_warning("共享内存清理失败");
    }
    
    // 清理TC规则
    if (!cleanup_tc_rules()) 
    {
        log_warning("TC规则清理失败");
    }
    
    // 设置测试完成标志，允许信号处理
    test_completed = 1;
    
    // 根据测试结果返回相应的退出码
    if (rate_limit_success) 
    {
        log_success("测试成功完成，返回码: 0");
        return SUCCESS;
    } 
    else 
    {
        log_error("测试失败完成，返回码: 1", 1);
        return 1;
    }
} 