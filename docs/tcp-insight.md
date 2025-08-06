# tcp-insight

TCP子系统观测工具，用于实时监控和分析TCP协议栈的各种事件。

## 功能描述

`tcp-insight` 是一个基于eBPF的TCP监控工具，能够深度观测TCP协议栈的运行状态。它通过监控内核中的TCP tracepoint事件，提供全面的TCP连接生命周期、数据传输、性能指标和错误处理的可观测性。

### 主要功能特性

- **TCP连接生命周期监控**：跟踪连接建立、接受、关闭和重置事件
- **数据传输监控**：监控TCP数据发送、接收和重传事件
- **性能指标分析**：实时跟踪拥塞窗口变化、RTT测量和窗口更新
- **错误和异常检测**：捕获TCP超时、SACK事件和连接异常
- **多维度过滤**：支持基于进程、地址、端口、事件类型等的灵活过滤
- **连接统计分析**：提供连接级别的统计信息和性能汇总
- **实时流式输出**：支持时间戳、详细信息和统计模式

## 监控的TCP事件类型

| 事件类型 | 描述 | 触发场景 |
|---------|------|----------|
| CONNECT | TCP连接发起 | 客户端发起连接时 |
| ACCEPT | TCP连接接受 | 服务端接受连接时 |
| SEND | TCP数据发送 | 应用层发送数据时 |
| RECEIVE | TCP数据接收 | 接收到TCP数据时 |
| RETRANSMIT | TCP重传 | 发生数据重传时 |
| CLOSE | TCP连接关闭 | 连接正常关闭时 |
| RESET | TCP连接重置 | 连接异常重置时 |
| CWND_CHANGE | 拥塞窗口变化 | 拥塞控制算法调整窗口时 |
| RTT_UPDATE | RTT测量更新 | 收到ACK更新RTT时 |
| SLOW_START | 慢启动阶段 | 进入慢启动状态时 |
| CONG_AVOID | 拥塞避免阶段 | 进入拥塞避免状态时 |
| FAST_RECOVERY | 快速恢复阶段 | 进入快速恢复状态时 |
| WINDOW_UPDATE | 接收窗口更新 | 调整接收窗口大小时 |
| SACK | 选择性确认 | 发送/接收SACK选项时 |
| TIMEOUT | RTO超时 | 重传定时器超时时 |

## 命令行参数

### 基本过滤选项

- `-p, --pid PID`  
  按进程ID过滤事件

- `-c, --comm COMM`  
  按进程名过滤事件（支持部分匹配）

- `-s, --saddr ADDR`  
  按源IP地址过滤

- `-d, --daddr ADDR`  
  按目标IP地址过滤

- `--sport PORT`  
  按源端口过滤

- `--dport PORT`  
  按目标端口过滤

### 事件类型过滤

- `-e, --events MASK`  
  按事件类型过滤（位掩码）
  - 可以使用十进制、十六进制（0x前缀）或八进制（0前缀）
  - 各事件类型对应的位值参见下表

### 性能和状态过滤

- `--min-duration MS`  
  最小连接持续时间（毫秒）

- `--max-duration MS`  
  最大连接持续时间（毫秒）

- `--min-bytes BYTES`  
  最小传输字节数

- `--max-bytes BYTES`  
  最大传输字节数

- `--min-rtt US`  
  最小RTT（微秒）

- `--max-rtt US`  
  最大RTT（微秒）

- `-S, --state STATE`  
  按TCP状态过滤（1-12，对应各TCP状态）

### 输出控制选项

- `-v, --verbose`  
  详细输出模式

- `-t, --timestamp`  
  显示时间戳

- `-T, --stats`  
  程序结束时显示统计信息

- `-h, --help`  
  显示帮助信息

## 事件类型位掩码

| 事件类型 | 位值 | 十六进制 | 说明 |
|---------|------|----------|------|
| CONNECT | 1 | 0x1 | TCP连接发起 |
| ACCEPT | 2 | 0x2 | TCP连接接受 |
| SEND | 4 | 0x4 | TCP数据发送 |
| RECEIVE | 8 | 0x8 | TCP数据接收 |
| RETRANSMIT | 16 | 0x10 | TCP重传 |
| CLOSE | 32 | 0x20 | TCP连接关闭 |
| RESET | 64 | 0x40 | TCP连接重置 |
| CWND_CHANGE | 128 | 0x80 | 拥塞窗口变化 |
| RTT_UPDATE | 256 | 0x100 | RTT测量更新 |
| SLOW_START | 512 | 0x200 | 慢启动阶段 |
| CONG_AVOID | 1024 | 0x400 | 拥塞避免阶段 |
| FAST_RECOVERY | 2048 | 0x800 | 快速恢复阶段 |
| WINDOW_UPDATE | 4096 | 0x1000 | 接收窗口更新 |
| SACK | 8192 | 0x2000 | 选择性确认 |
| TIMEOUT | 16384 | 0x4000 | RTO超时 |

### 预定义掩码组合

- **连接生命周期事件**: `0x63` (CONNECT|ACCEPT|CLOSE|RESET)
- **数据传输事件**: `0x1C` (SEND|RECEIVE|RETRANSMIT)  
- **性能监控事件**: `0x1180` (CWND_CHANGE|RTT_UPDATE|WINDOW_UPDATE)
- **所有事件**: `0xFFFF`

## 输出格式

### 标准输出列

| 列名 | 描述 |
|------|------|
| TIME | 事件时间戳（可选，使用-t选项） |
| COMM | 进程名称 |
| PID | 进程ID |
| TID | 线程ID |
| EVENT | 事件类型 |
| SADDR:SPORT | 源地址:端口 |
| DADDR:DPORT | 目标地址:端口 |
| STATE | TCP连接状态 |
| CWND | 拥塞窗口大小 |
| RTT | 往返时间（微秒） |
| BYTES | 传输字节数 |
| DETAILS | 事件详细信息 |

### TCP状态说明

| 状态值 | 状态名 | 描述 |
|--------|--------|------|
| 1 | ESTABLISHED | 连接已建立 |
| 2 | SYN_SENT | 已发送SYN，等待匹配的连接请求 |
| 3 | SYN_RECV | 已收到并发送SYN，等待确认 |
| 4 | FIN_WAIT1 | 等待远程TCP连接中断请求 |
| 5 | FIN_WAIT2 | 等待远程TCP连接中断请求 |
| 6 | TIME_WAIT | 等待足够时间确保远程TCP收到FIN |
| 7 | CLOSE | 连接已关闭 |
| 8 | CLOSE_WAIT | 等待本地用户的连接中断请求 |
| 9 | LAST_ACK | 等待原来发向远程TCP的FIN的确认 |
| 10 | LISTEN | 监听来自远程TCP端口的连接请求 |
| 11 | CLOSING | 等待远程TCP对连接中断的确认 |
| 12 | NEW_SYN_RECV | 新的SYN接收状态 |

## 使用示例

### 基础监控示例

```bash
# 监控所有TCP事件
sudo ./tcp-insight

# 监控指定进程的TCP事件
sudo ./tcp-insight -p 1234

# 监控指定进程名的TCP事件
sudo ./tcp-insight -c nginx

# 显示时间戳和详细信息
sudo ./tcp-insight -v -t
```

### 网络连接过滤示例

```bash
# 监控特定源地址的连接
sudo ./tcp-insight -s 192.168.1.100

# 监控特定目标地址和端口的连接
sudo ./tcp-insight -d 10.0.0.1 --dport 80

# 监控HTTP流量（端口80和443）
sudo ./tcp-insight --dport 80
sudo ./tcp-insight --dport 443

# 监控特定IP之间的通信
sudo ./tcp-insight -s 192.168.1.100 -d 10.0.0.1
```

### 事件类型过滤示例

```bash
# 只监控连接生命周期事件
sudo ./tcp-insight -e 0x63

# 只监控数据传输事件
sudo ./tcp-insight -e 0x1C

# 只监控性能相关事件
sudo ./tcp-insight -e 0x1180

# 只监控连接建立和关闭
sudo ./tcp-insight -e 0x23

# 只监控重传事件
sudo ./tcp-insight -e 0x10
```

### 性能分析示例

```bash
# 监控高延迟连接（RTT > 10ms）
sudo ./tcp-insight --min-rtt 10000

# 监控大数据传输（> 1MB）
sudo ./tcp-insight --min-bytes 1048576

# 监控长连接（持续时间 > 60秒）
sudo ./tcp-insight --min-duration 60000

# 监控特定状态的连接
sudo ./tcp-insight -S 1  # 只监控ESTABLISHED状态

# 性能监控模式
sudo ./tcp-insight -e 0x1180 -v -t
```

### 高级监控示例

```bash
# 监控Web服务器性能（结合多个过滤条件）
sudo ./tcp-insight -c httpd --dport 80 -e 0x1C -v -t

# 监控数据库连接性能
sudo ./tcp-insight --dport 3306 --min-rtt 1000 -T

# 监控网络问题诊断
sudo ./tcp-insight -e 0x6050 -v -t  # 重传、超时、重置事件

# 监控负载均衡器连接
sudo ./tcp-insight -c haproxy -e 0x63 -T

# 详细的连接分析
sudo ./tcp-insight -p 1234 -v -t -T
```

## 性能考虑

### 系统开销

- **CPU开销**: 在高频TCP事件环境下，eBPF程序会消耗一定的CPU资源
- **内存使用**: 工具会在内核空间维护连接跟踪表和统计信息
- **网络影响**: 监控本身不会影响网络性能，但大量输出可能影响系统

### 优化建议

1. **使用过滤条件**: 通过PID、地址、端口等过滤减少事件数量
2. **选择性监控**: 使用事件掩码只监控关心的事件类型
3. **避免高频输出**: 在生产环境中避免监控所有事件
4. **定期清理**: 长时间运行时注意内存使用情况

### 适用场景

- **网络性能调优**: 分析TCP拥塞控制和RTT变化
- **应用程序调试**: 排查TCP连接问题和数据传输异常
- **系统监控**: 实时监控TCP连接状态和流量
- **容量规划**: 分析TCP连接模式和资源使用
- **安全分析**: 检测异常的TCP连接行为

## 故障排除

### 常见问题

1. **权限错误**
   ```
   Failed to load BPF skeleton: Permission denied
   ```
   解决方案：使用sudo运行或确保用户有BPF权限

2. **内核版本不兼容**
   ```
   libbpf: CO-RE relocations failed
   ```
   解决方案：确保内核版本支持BTF和CO-RE（>=5.4）

3. **资源限制**
   ```
   Failed to increase RLIMIT_MEMLOCK limit
   ```
   解决方案：调整系统的MEMLOCK限制或使用更高权限运行

4. **tracepoint不存在**
   ```
   Failed to attach BPF skeleton
   ```
   解决方案：检查内核是否启用了相应的TCP tracepoint

### 调试技巧

- 使用`-v`选项查看详细的调试信息
- 检查`/sys/kernel/debug/tracing/available_events`确认tracepoint可用性
- 使用`dmesg`查看内核日志中的BPF相关错误
- 通过`bpftool`命令检查BPF程序加载状态

## 相关工具

- **ss**: 查看当前TCP连接状态
- **netstat**: 显示网络连接和统计信息
- **tcpdump**: 网络包捕获和分析
- **iftop**: 实时网络流量监控
- **bcc/tcptracer**: 类似的TCP跟踪工具

## 注意事项

1. **权限要求**: 需要root权限或CAP_BPF能力
2. **内核版本**: 要求Linux内核版本 >= 5.4（支持BTF和CO-RE）
3. **性能影响**: 在高负载环境下谨慎使用，建议先在测试环境验证
4. **输出量**: 某些过滤条件可能产生大量输出，注意磁盘空间
5. **tracepoint稳定性**: 内核tracepoint可能在不同版本间有所变化 