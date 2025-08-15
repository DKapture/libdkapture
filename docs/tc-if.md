# tc-if

## 功能描述

`tc-if` 是一个基于 eBPF 的网络接口级流量控制工具，通过 Linux TC（Traffic Control）钩子实现网络接口的速率限制和流量监控。与进程级限速工具不同，tc-if 工作在网络接口层面，对所有经过该接口的网络流量进行统一的速率控制和统计。

## 主要特性

- **接口级限速**：基于令牌桶（Token Bucket）算法对网络接口进行速率控制
- **双向监控**：同时支持入站（ingress）和出站（egress）方向的流量控制
- **协议识别**：自动识别 IPv4、IPv6、ARP、VLAN、MPLS、PPPoE 等协议类型
- **实时统计**：提供每协议类型的流量统计和速率计算
- **平滑算法**：使用指数移动平均（EMA）算法提供稳定的流量速率读数
- **灵活配置**：支持多种时间尺度配置，适应不同的突发容忍需求

## 构建

```bash
cd filter
make tc-if
```

依赖：libbpf、clang/LLVM、bpftool、内核头文件（详见 `filter/Makefile`）。

## 使用方法

```bash
sudo ./filter/tc-if -h
```

### 参数说明

- `-I, --interface <if>`：网络接口名称（必需）
- `-r, --rate <rate>`：速率限制，支持 K/M/G 后缀（如 `100K`、`1M`、`2G`）
- `-d, --direction <egress|ingress>`：匹配方向
  - `egress`：出站流量（发送到目标）
  - `ingress`：入站流量（从源接收）
- `-t, --timescale <sec>`：时间尺度（秒），控制突发容忍度
- `-h, --help`：显示帮助信息

### 使用示例

```bash
# 将 eth0 接口的出站流量限速到 100 Mbps，时间尺度 60s（允许短期突发）
sudo ./filter/tc-if -I eth0 -r 100M -d egress -t 60

# 将 eth0 接口的入站流量限速到 50 Mbps，时间尺度 1s（严格限速）
sudo ./filter/tc-if -I eth0 -r 50M -d ingress -t 1

# 将 wlan0 接口的双向流量都限速到 10 Mbps
sudo ./filter/tc-if -I wlan0 -r 10M -d egress -t 30
sudo ./filter/tc-if -I wlan0 -r 10M -d ingress -t 30
```

## 工作原理

### 架构概述

tc-if 使用 TC 钩子挂载 eBPF 程序到网络接口，实现以下功能：

1. **流量解析**：解析以太网头部，提取源/目标 MAC 地址、以太网类型等信息
2. **协议分类**：根据以太网类型识别数据包协议类型
3. **速率控制**：基于令牌桶算法实现流量整形
4. **统计收集**：收集和更新各种协议类型的流量统计信息
5. **事件报告**：通过 ring buffer 向用户空间报告流量事件

### 核心算法

#### 令牌桶算法
- **基本限速**：标准令牌桶实现，严格控制流量
- **突发容忍**：支持 2x 突发倍数的令牌桶，允许短期流量突发
- **时间尺度**：通过配置时间尺度控制令牌桶容量和突发容忍度

#### 流量统计算法
- **滑动窗口**：1秒时间窗口的流量统计
- **指数移动平均**：使用 EMA 算法平滑流量速率读数
- **峰值记录**：记录观察到的峰值流量速率

### 协议支持

| 协议类型 | 以太网类型 | 描述 |
|---------|-----------|------|
| IPv4    | 0x0800    | 互联网协议版本4 |
| ARP     | 0x0806    | 地址解析协议 |
| IPv6    | 0x86DD    | 互联网协议版本6 |
| VLAN    | 0x8100    | 802.1Q 虚拟局域网 |
| MPLS    | 0x8847    | 多协议标签交换 |
| PPPoE   | 0x8864    | 以太网上的点对点协议 |

## 输出示例

### 实时流量事件

根据实际运行日志，tc-if 会显示以下格式的流量事件：

```
[DKapture][tc-if.cpp:520][info] Interface Traffic: 
[DKapture][tc-if.cpp:532][info] [MATCH]
[DKapture][tc-if.cpp:536][info]   Ethernet Header:
[DKapture][tc-if.cpp:537][info]     Source MAC: 52:54:00:59:c1:be
[DKapture][tc-if.cpp:538][info]     Dest MAC:   52:54:00:c3:dd:72
[DKapture][tc-if.cpp:539][info]     EtherType:  0x800 (IPv4)
[DKapture][tc-if.cpp:540][info]     Packet Size: 230 bytes
[DKapture][tc-if.cpp:543][info]   Packet Type Statistics:
[DKapture][tc-if.cpp:544][info]     Type: IPv4 (ID: 1)
[DKapture][tc-if.cpp:545][info]     Current Flow Rate: 551 Kbps
[DKapture][tc-if.cpp:546][info]     Smooth Flow Rate: 517 Kbps (EMA)

[DKapture][tc-if.cpp:520][info] Interface Traffic: 
[DKapture][tc-if.cpp:528][info] [PASS] 66 bytes, 1 packets
[DKapture][tc-if.cpp:536][info]   Ethernet Header:
[DKapture][tc-if.cpp:537][info]     Source MAC: 52:54:00:c3:dd:72
[DKapture][tc-if.cpp:538][info]     Dest MAC:   52:54:00:59:c1:be
[DKapture][tc-if.cpp:539][info]     EtherType:  0x800 (IPv4)
[DKapture][tc-if.cpp:540][info]     Packet Size: 66 bytes
[DKapture][tc-if.cpp:543][info]   Packet Type Statistics:
[DKapture][tc-if.cpp:544][info]     Type: IPv4 (ID: 1)
[DKapture][tc-if.cpp:545][info]     Current Flow Rate: 551 Kbps
[DKapture][tc-if.cpp:546][info]     Smooth Flow Rate: 517 Kbps (EMA)
```

### 事件类型说明

根据实际运行日志，tc-if 会显示以下三种事件类型：

- **`[MATCH]`**：数据包匹配到规则但未进行速率限制（通常用于监控模式）
- **`[PASS]`**：数据包通过速率限制检查，正常转发（显示字节数和包数）
- **`[DROP]`**：数据包因超出速率限制而被丢弃（显示字节数和包数）

每个事件都包含：
- **以太网头部信息**：源/目标 MAC 地址、以太网类型、数据包大小
- **协议类型统计**：数据包类型（IPv4、ARP、IPv6 等）及其 ID
- **流量速率信息**：当前流量速率和平滑流量速率（使用 EMA 算法）

### 日志格式说明

所有日志输出都使用 `Ulog.h` 的统一格式：
- `[DKapture]`：工具标识
- `[tc-if.cpp:行号]`：源文件和行号信息
- `[info]`：日志级别（info、debug、warn、error）
- 具体内容：流量事件详情

### 统计信息摘要

根据实际运行，tc-if 会显示以下格式的统计信息：

```
=== Traffic Control Statistics ===
Network interface: 2
Rate limit: 100000000 B/s (95.37 MB/s)
Time scale: 60 seconds
Direction: EGRESS
Max bucket capacity: 5722.05 MB
===================================

=== PACKET TYPE STATISTICS SUMMARY ===
Timestamp: 1703123456
This would show statistics for each packet type:
  - IPv4 packets and flow rate
  - ARP packets and flow rate
  - IPv6 packets and flow rate
  - VLAN packets and flow rate
  - MPLS packets and flow rate
  - PPPoE packets and flow rate
  - Unknown/Other packets and flow rate
=====================================

=== SMOOTH FLOW RATE ALGORITHM INFO ===
Exponential Moving Average (EMA) Algorithm:
  Formula: smooth = (smooth - smooth/8) + (new_rate * 2^13)
  Weight: 1/8 = 12.5% for new measurements
  Scaling: 2^13 = 8192x for precision
  Benefits:
    - Reduces noise and sudden spikes
    - Maintains responsiveness to trends
    - Provides stable flow rate readings
  Time Window: 1 second sliding window
  Update Frequency: Every second
=========================================
```

## 配置参数详解

### 时间尺度配置

- **1秒**：严格限速，低突发容忍度，适合实时应用
- **60秒**：允许短期突发，长期平均限速，适合一般应用
- **3600秒**：允许长期突发，适合长期带宽管理

### 速率配置

支持多种单位后缀：
- `1000`：1000 bps
- `100K`：100 Kbps
- `1M`：1 Mbps
- `2G`：2 Gbps

## 技术实现细节

### BPF 程序结构

- **tc_egress**：处理出站流量
- **tc_ingress**：处理入站流量
- **流量统计映射**：`flow_rate_stats` 存储各协议类型的统计信息
- **规则配置映射**：`traffic_rules` 存储流量控制规则
- **令牌桶映射**：`buckets` 实现速率限制

### 错误处理

- 完整的错误日志系统
- 自动重试机制
- 优雅的资源清理
- 详细的错误上下文信息

### 日志系统集成

tc-if 使用 `Ulog.h` 统一日志系统，提供：
- **结构化日志**：包含时间戳、文件位置、日志级别
- **颜色编码**：不同级别的日志使用不同颜色（info=白色，warn=黄色，error=红色，debug=灰色）
- **统一格式**：`[DKapture][文件:行号][级别] 消息内容`
- **性能优化**：支持日志级别过滤和文件输出重定向

## 注意事项与限制

- 需要 root 权限运行
- 内核版本要求：6.6.0 以上，且开启 BPF、BTF 相关配置
- 支持架构：x86_64、ARM64、Loong64、sw64
- 当前仅支持以太网接口
- 令牌桶算法基于数据包大小，而非数据包数量

## 性能特点

- **低延迟**：eBPF 程序在内核空间执行，最小化用户态开销
- **高吞吐**：优化的数据包处理路径，支持高带宽网络
- **内存效率**：使用哈希映射和环形缓冲区，内存占用可控
- **实时性**：毫秒级的流量控制响应

## 相关文档

- `docs/traffic-control.md`：进程级流量控制
- `docs/net-traffic.md`：网络流量观测
- `docs/net-filter.md`：网络包过滤
- `docs/dkapture-api.md`：DKapture API 接口

## 故障排除

### 常见问题

1. **权限不足**：确保以 root 权限运行
2. **接口不存在**：检查网络接口名称是否正确
3. **内核不支持**：确认内核版本和 BPF 支持
4. **TC 钩子冲突**：检查是否已有其他 TC 规则

### 调试信息

使用 `-d` 参数可以启用调试模式，查看详细的执行信息：

```bash
sudo ./filter/tc-if -I eth0 -r 100M -d egress -t 60 -d 1
```

### 日志分析

tc-if 的日志输出包含丰富的调试信息：

1. **流量事件日志**：每个数据包的处理结果
2. **统计信息日志**：定期显示的流量统计摘要
3. **算法信息日志**：EMA 算法的详细说明
4. **错误日志**：操作失败时的详细错误信息

所有日志都包含源文件和行号信息，便于问题定位和调试。

## 版本历史

- **v1.1.0**：日志系统集成和输出优化
  - 集成 `Ulog.h` 统一日志系统
  - 替换所有 `std::cout`/`std::cerr` 输出
  - 提供结构化、颜色编码的日志输出
  - 增强调试信息和错误报告

- **v1.0.0**：初始版本，支持基本的接口级流量控制
  - 支持 IPv4/IPv6/ARP/VLAN/MPLS/PPPoE 协议识别
  - 实现令牌桶算法和流量统计
  - 集成错误处理和资源管理 