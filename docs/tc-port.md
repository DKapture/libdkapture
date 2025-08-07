# TC Port Traffic Controller

## 功能描述

TC Port 是一个基于 eBPF TC（Traffic Control）的流量控制工具，能够对特定IP地址和端口的网络流量进行精确的带宽限制。该工具使用令牌桶算法实现流量控制，支持TCP和UDP协议，并能够在egress（出站）和ingress（入站）两个方向进行流量控制。

### 主要功能

1. **精确流量控制**：基于IP地址和端口的精确匹配
2. **双向控制**：支持egress（出站）和ingress（入站）方向
3. **令牌桶算法**：使用令牌桶算法实现平滑的流量控制
4. **时间刻度配置**：支持不同的时间刻度来控制突发流量容忍度
5. **实时监控**：实时显示流量统计和丢包信息

## 工作原理

### 方向说明

- **Egress方向**：控制从本地发出的流量，目标IP是远程主机
- **Ingress方向**：控制发往本地的流量，目标IP是本地机器

无论哪个方向，程序都是匹配数据包中的**目标IP地址**：
- Egress：匹配数据包的目标IP（远程主机）
- Ingress：匹配数据包的目标IP（本地机器）


## 命令选项说明

```bash
./tc-port -h
Usage: ./filter/tc-port [options]
Options:
  -I, --interface <if>  Network interface name
  -i, --ip <ip>         IP address to match
  -p, --port <port>     Port to match
  -r, --rate <rate>     Rate limit (supports K/M/G suffixes)
  -d, --direction <dir> Match direction (egress/ingress)
  -t, --timescale <sec> Time scale (seconds, controls burst tolerance)
  -h, --help            Show help information

Direction Configuration:
  -d egress  : Match destination IP:port (outgoing traffic)
  -d ingress : Match source IP:port (incoming traffic to local machine)

Time Scale Examples:
  -t 1     : 1 second scale, strict rate limiting, low burst tolerance
  -t 60    : 1 minute scale, allows short-term bursts, long-term average rate limiting
  -t 3600  : 1 hour scale, allows long-term bursts, suitable for long-term bandwidth management
```

### 参数说明

- **-I, --interface**：必需参数，指定要控制的网络接口名称
- **-i, --ip**：必需参数，指定要匹配的IP地址
- **-p, --port**：必需参数，指定要匹配的端口号
- **-r, --rate**：可选参数，指定带宽限制，支持K/M/G后缀（如1M表示1MB/s）
- **-d, --direction**：可选参数，指定匹配方向（egress/ingress）
- **-t, --timescale**：可选参数，指定时间刻度（秒），控制突发流量容忍度
- **-h, --help**：显示帮助信息

## 使用示例

### 限制出站流量

```bash
# 限制发往192.168.1.100:80的流量为1MB/s
sudo ./filter/tc-port -I eth0 -i 192.168.1.100 -p 80 -r 1M -d egress

# 限制发往10.0.0.1:443的流量为500KB/s，严格限速
sudo ./filter/tc-port -I eth0 -i 10.0.0.1 -p 443 -r 500K -d egress -t 1
```

### 限制入站流量

```bash
# 限制发往本地80端口的流量为2MB/s
sudo ./filter/tc-port -I eth0 -i 192.168.1.1 -p 80 -r 2M -d ingress

# 限制发往本地22端口的SSH流量为100KB/s
sudo ./filter/tc-port -I eth0 -i 192.168.1.1 -p 22 -r 100K -d ingress
```

### 输出示例

```
Network interface: 2
Match IP: 192.168.1.100
Match port: 80
Match direction: EGRESS (destination IP:port)
Rate limit: 1048576 B/s (1.0 MB/s)
Time scale: 1 seconds (max bucket capacity: 1.0 MB)

Successfully created TC hook (egress direction)
Successfully created TC hook (ingress direction)
Successfully attached TC program to interface 2 (egress direction)
Successfully attached TC program to interface 2 (ingress direction)
Match IP: 192.168.1.100
Match port: 80
Match direction: EGRESS (destination IP:port)
Rate limit: 1048576 B/s

Starting traffic monitoring...

Traffic: 192.168.1.1:12345 -> 192.168.1.100:80 [SEND] 1024 bytes
Traffic: 192.168.1.1:12346 -> 192.168.1.100:80 [DROP] 2048 bytes
```

## 技术原理

### TC（Traffic Control）技术

TC是Linux内核的网络流量控制框架：
1. **Qdisc**：队列规则，管理数据包的排队和调度
2. **Filter**：过滤器，根据规则匹配数据包
3. **eBPF程序**：在TC框架中执行自定义逻辑

### 令牌桶算法

令牌桶算法的核心思想：
1. **令牌生成**：以固定速率向桶中添加令牌
2. **令牌消耗**：数据包需要消耗相应数量的令牌才能通过
3. **突发容忍**：桶有最大容量，允许短时间的突发流量
4. **时间刻度**：通过时间刻度控制桶的最大容量

### eBPF程序结构

内核态eBPF程序负责：
1. **数据包解析**：解析以太网、IP、TCP/UDP头部
2. **规则匹配**：根据配置的IP和端口进行匹配
3. **流量控制**：使用令牌桶算法进行流量控制
4. **事件上报**：将流量统计信息发送到用户态

### 用户态程序

用户态程序负责：
1. **配置管理**：解析命令行参数，配置流量控制规则
2. **TC管理**：创建和管理TC钩子
3. **事件处理**：接收和处理来自内核的事件
4. **统计显示**：显示流量统计和丢包信息

## 配置说明

### 方向配置

- **Egress（出站）**：
  - 控制从本地发出的流量
  - 匹配数据包的目标IP和端口
  - 适用于限制对特定服务器的访问

- **Ingress（入站）**：
  - 控制发往本地的流量
  - 匹配数据包的目标IP和端口（本地IP）
  - 适用于限制对本地服务的访问

### 时间刻度配置

- **1秒**：严格限速，突发容忍度低，适合精确控制
- **60秒**：允许短期突发，长期平均限速，适合一般应用
- **3600秒**：允许长期突发，适合长期带宽管理

### 带宽配置

支持多种带宽单位：
- **数字**：直接指定字节/秒（如1000000表示1MB/s）
- **K后缀**：千字节/秒（如1K表示1KB/s）
- **M后缀**：兆字节/秒（如1M表示1MB/s）
- **G后缀**：吉字节/秒（如1G表示1GB/s）

## 注意事项

1. **权限要求**：需要root权限运行，因为需要加载eBPF程序和配置TC
2. **网络接口**：确保指定的网络接口存在且处于活动状态
3. **性能影响**：TC程序会对网络性能产生一定影响
4. **规则冲突**：避免与其他TC规则产生冲突
5. **内核版本**：需要支持eBPF和TC的Linux内核版本

