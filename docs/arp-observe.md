# ARP Observe ARP观察器

## 功能描述

ARP Observe 是一个基于 eBPF XDP 的 ARP 数据包监控工具，能够实时捕获和分析网络接口上的 ARP（地址解析协议）请求和响应包。该工具使用 XDP（eXpress Data Path）技术在内核网络栈早期进行数据包处理，提供高效的 ARP 监控能力。

### 主要功能

1. **实时监控**：实时捕获网络接口上的所有 ARP 数据包
2. **协议解析**：解析 ARP 请求和响应包，显示源/目标 MAC 地址和 IP 地址
3. **选择性显示**：支持根据 IP 地址过滤显示内容，只显示涉及特定 IP 的 ARP 包
4. **高性能**：使用 XDP 技术，在数据包处理早期进行捕获，性能影响最小

## 命令选项说明

```bash
./arp-observe -h
Usage: ./observe/arp-observe <interface> [options]
  ARP packet monitoring tool.

Arguments:
  <interface>        Network interface name (e.g., eth0, lo)

Options:
  -i, --ip <ip>     Show only ARP packets involving this IP (e.g., 192.168.1.1)
  -h, --help        Show help information

Examples:
  ./observe/arp-observe eth0
  ./observe/arp-observe lo -i 192.168.1.1
  ./observe/arp-observe eth0 --ip 10.0.0.1
```

### 参数说明

- **interface**：必需参数，指定要监控的网络接口名称（如 eth0、lo、wlan0 等）
- **-i, --ip**：可选参数，指定 IP 地址，只显示涉及该 IP 的 ARP 包
- **-h, --help**：显示帮助信息

## 字段说明

输出格式为：
```
[TIME]     SOURCE_IP       DEST_IP         SOURCE_MAC        DEST_MAC         OPCODE
```

### 字段详细说明

- **TIME**：事件发生的时间戳，格式为 HH:MM:SS
- **SOURCE_IP**：ARP 包中源 IP 地址
- **DEST_IP**：ARP 包中目标 IP 地址
- **SOURCE_MAC**：ARP 包中源 MAC 地址，格式为 XX:XX:XX:XX:XX:XX
- **DEST_MAC**：ARP 包中目标 MAC 地址，格式为 XX:XX:XX:XX:XX:XX
- **OPCODE**：ARP 操作码，包括：
  - `ARP_REQUEST`：ARP 请求包
  - `ARP_REPLY`：ARP 响应包
  - `RARP_REQUEST`：RARP 请求包
  - `RARP_REPLY`：RARP 响应包
  - `UNKNOWN`：未知操作码

## 运行示例

### 监控所有 ARP 包

```bash
sudo ./observe/arp-observe eth0
```

输出示例：
```
=== eBPF XDP ARP Monitor Started ===
Press Ctrl+C to stop monitoring

Filtering: Show all ARP packets

ARP Events:
Time      Source IP       Dest IP         Source MAC        Dest MAC         Opcode
16:41:42  192.168.1.100  192.168.1.1     00:11:22:33:44:55  ff:ff:ff:ff:ff:ff  ARP_REQUEST
16:41:42  192.168.1.1    192.168.1.100   00:aa:bb:cc:dd:ee  00:11:22:33:44:55  ARP_REPLY
16:41:45  192.168.1.101  192.168.1.1     00:11:22:33:44:56  ff:ff:ff:ff:ff:ff  ARP_REQUEST
```

### 只监控特定 IP 的 ARP 包

```bash
sudo ./observe/arp-observe eth0 -i 192.168.1.1
```

输出示例：
```
=== eBPF XDP ARP Monitor Started ===
Press Ctrl+C to stop monitoring

Filtering: Show only ARP packets involving 192.168.1.1

ARP Events:
Time      Source IP       Dest IP         Source MAC        Dest MAC         Opcode
16:41:42  192.168.1.100  192.168.1.1     00:11:22:33:44:55  ff:ff:ff:ff:ff:ff  ARP_REQUEST
16:41:42  192.168.1.1    192.168.1.100   00:aa:bb:cc:dd:ee  00:11:22:33:44:55  ARP_REPLY
```

### 监控回环接口

```bash
sudo ./observe/arp-observe lo
```

## 技术原理

### XDP 技术

ARP Observe 使用 XDP（eXpress Data Path）技术，这是一种高性能的数据包处理框架：

1. **早期处理**：XDP 在数据包进入网络栈的最早期进行处理
2. **高性能**：绕过传统的网络栈处理路径，减少 CPU 开销
3. **零拷贝**：直接在数据包缓冲区上操作，避免内存拷贝

### eBPF 程序

内核态的 eBPF 程序负责：

1. **数据包过滤**：只处理 ARP 协议包（以太网类型 0x0806）
2. **协议解析**：解析 ARP 头部，提取 MAC 和 IP 地址
3. **事件生成**：将解析结果发送到用户态程序

### 用户态处理

用户态程序负责：

1. **事件接收**：通过 ring buffer 接收内核发送的事件
2. **数据格式化**：将原始数据格式化为可读的输出
3. **过滤显示**：根据用户指定的 IP 地址进行选择性显示

## 使用场景

### 网络故障排查

```bash
# 监控网关的 ARP 活动
sudo ./observe/arp-observe eth0 -i 192.168.1.1

# 监控特定主机的 ARP 活动
sudo ./observe/arp-observe eth0 -i 192.168.1.100
```

### 网络安全监控

```bash
# 监控所有 ARP 包，检测 ARP 欺骗攻击
sudo ./observe/arp-observe eth0
```

### 网络性能分析

```bash
# 分析 ARP 请求频率和响应时间
sudo ./observe/arp-observe eth0
```

## 注意事项

1. **权限要求**：需要 root 权限运行，因为需要加载 eBPF 程序和访问网络接口
2. **网络接口**：确保指定的网络接口存在且处于活动状态
3. **性能影响**：虽然使用 XDP 技术，但仍可能对网络性能产生轻微影响
4. **数据包丢失**：在高流量环境下，ring buffer 可能满，导致部分 ARP 包丢失
