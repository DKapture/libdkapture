# net-snoop

## 功能描述

net-snoop用于实时监控系统网络数据包传输事件，它可以跟踪网络设备上的数据包队列、发送开始、实际发送和接收等关键事件。工具支持L2/L3/L4层协议深度解析，包括IPv4/IPv6、TCP/UDP协议详细信息，并具备应用层协议识别能力（HTTP、DNS、SSH等）。通过丰富的过滤选项（进程、设备、协议、端口、IP地址等），用户可以精确定位网络活动，深入了解系统的网络性能状况和协议行为。

## 参数说明

```bash
# ./observe/net-snoop -h
Usage: ./observe/net-snoop [option]
  To monitor network packet transmission events with L3/L4 protocol analysis.

Options:
  -p, --pid [pid]
        filter output by the pid

  -c, --comm [comm]
        filter output by the process comm.

  -d, --dev [dev]
        filter output by network device name (e.g., eth0, lo)

  -m, --min-len [len]
        filter output by minimum packet length

  -M, --max-len [len]
        filter output by maximum packet length

  -P, --protocol [protocol]
        filter output by protocol number (e.g., 0x0800 for IPv4)

  -e, --events [mask]
        event mask: 1=queue, 2=start_xmit, 4=xmit, 8=receive (default: 15=all)

  -i, --interval [interval]
        statistic interval

  --protocol-filter [tcp|udp|icmp]
        filter by L4 protocol type

  --port-filter [port]
        filter by TCP/UDP port number

  --ip-filter [ip]
        filter by source or destination IP address

  --show-details
        show detailed L3/L4 protocol information

  --protocol-stats
        show protocol statistics summary

  -h, --help 
        print this help message
```

### 传统参数
- -p：过滤指定的进程PID。
- -c：过滤指定的进程名。
- -d：过滤指定的网络设备名（如eth0、lo等）。
- -m：过滤最小数据包长度，只显示大于等于指定长度的数据包。
- -M：过滤最大数据包长度，只显示小于等于指定长度的数据包。
- -P：过滤指定协议号（如0x0800表示IPv4，0x86DD表示IPv6）。
- -e：事件类型掩码，用位掩码控制监控哪些事件：1=队列事件，2=发送开始事件，4=发送完成事件，8=接收事件，默认15表示监控所有事件。
- -i：统计时间间隔，目前主要用于兼容性。
- -h：打印帮助信息。

### 新增高级参数
- --protocol-filter：按L4协议类型过滤（tcp、udp、icmp），支持精确的传输层协议监控。
- --port-filter：按TCP/UDP端口号过滤，支持监控特定服务的网络活动。
- --ip-filter：按源或目标IP地址过滤，支持监控特定主机的网络通信。
- --show-details：显示详细的L3/L4协议信息，包括IP头部、TCP/UDP头部等详细字段。
- --protocol-stats：显示协议统计摘要信息，包括各协议的数据包数量和流量分布。

## 字段说明

- TIME：事件发生的时间戳，格式为HH:MM:SS。
- COMM：产生网络事件的进程名。
- PID：产生网络事件的进程ID。
- TID：产生网络事件的线程ID。
- EVENT：网络事件类型，包括：
  - QUEUE：数据包进入发送队列
  - START_XMIT：开始网络发送操作
  - XMIT：网络发送完成
  - RECEIVE：网络数据包接收
- DEV：网络设备名称。
- LEN：数据包长度（字节）。
- DETAILS：事件详细信息，根据事件类型和协议显示不同内容：
  - 基本信息：协议类型（IPv4/IPv6/ARP/OTHER）、队列ID、GSO大小、VLAN信息等
  - L3层信息（--show-details）：源/目标IP地址、协议类型、TOS、TTL等
  - L4层信息（--show-details）：TCP/UDP端口、TCP标志位、序列号、窗口大小等
  - 应用层信息：HTTP、DNS、SSH等协议识别
  - 性能信息：延迟时间、返回码等
- SKB：内核sk_buff结构体地址，用于调试和关联分析。

## 使用示例

### 监控所有网络事件

```bash
# sudo ./observe/net-snoop
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:32:15 ssh              1959   1959   RECEIVE    eth0     84     IPv4                 0xffff888012345678
14:32:15 ssh              1959   1959   START_XMIT eth0     60     IPv4 Q:0   GSO:0     0xffff888012345678
14:32:15 ssh              1959   1959   XMIT       eth0     60     RC:0 LAT:45us        0xffff888012345678
14:32:16 chrome           3271   3271   START_XMIT eth0     517    IPv4 Q:0   GSO:0     0xffff888087654321
14:32:16 chrome           3271   3271   XMIT       eth0     517    RC:0 LAT:23us        0xffff888087654321
14:32:16 chrome           3271   3271   RECEIVE    eth0     4408   IPv4                 0xffff888087654321
```

### 过滤指定进程

```bash
# sudo ./observe/net-snoop -c ssh
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:33:20 ssh              1959   1959   RECEIVE    eth0     84     IPv4                 0xffff888012345678
14:33:20 ssh              1959   1959   START_XMIT eth0     60     IPv4 Q:0   GSO:0     0xffff888012345678
14:33:20 ssh              1959   1959   XMIT       eth0     60     RC:0 LAT:45us        0xffff888012345678
```

### 过滤指定设备和协议

```bash
# sudo ./observe/net-snoop -d eth0 -P 0x0800
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:34:25 wget             12345  12345  START_XMIT eth0     66     IPv4 Q:0   GSO:0     0xffff888098765432
14:34:25 wget             12345  12345  XMIT       eth0     66     RC:0 LAT:28us        0xffff888098765432
14:34:25 wget             12345  12345  RECEIVE    eth0     1500   IPv4                 0xffff888098765432
```

### 按L4协议过滤

```bash
# sudo ./observe/net-snoop --protocol-filter tcp
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:35:30 curl             23456  23456  START_XMIT eth0     78     IPv4 Q:0   GSO:0     0xffff888011223344
14:35:30 curl             23456  23456  XMIT       eth0     78     RC:0 LAT:32us        0xffff888011223344
14:35:31 curl             23456  23456  RECEIVE    eth0     1460   IPv4                 0xffff888011223344
```

### 按端口过滤

```bash
# sudo ./observe/net-snoop --port-filter 80
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:36:35 firefox          34567  34567  START_XMIT eth0     512    IPv4 Q:0   GSO:0     0xffff888055667788
14:36:35 firefox          34567  34567  XMIT       eth0     512    RC:0 LAT:25us        0xffff888055667788
14:36:35 firefox          34567  34567  RECEIVE    eth0     768    IPv4                 0xffff888055667788
```

### 显示详细协议信息

```bash
# sudo ./observe/net-snoop --show-details --protocol-filter tcp
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:37:40 wget             45678  45678  START_XMIT eth0     66     IPv4 192.168.1.100→93.184.216.34 TCP 45678→80 [SYN] Seq:12345 Win:65535 Q:0 GSO:0  0xffff888099887766
14:37:40 wget             45678  45678  XMIT       eth0     66     RC:0 LAT:18us        0xffff888099887766
14:37:40 wget             45678  45678  RECEIVE    eth0     66     IPv4 93.184.216.34→192.168.1.100 TCP 80→45678 [SYN,ACK] Seq:67890 Ack:12346 Win:29200  0xffff888099887766
```

### 按IP地址过滤

```bash
# sudo ./observe/net-snoop --ip-filter 192.168.1.100
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:38:45 ssh              56789  56789  START_XMIT eth0     84     IPv4 Q:0   GSO:0     0xffff888077665544
14:38:45 ssh              56789  56789  XMIT       eth0     84     RC:0 LAT:35us        0xffff888077665544
14:38:45 ssh              56789  56789  RECEIVE    eth0     132    IPv4                 0xffff888077665544
```

### 显示协议统计信息

```bash
# sudo ./observe/net-snoop --protocol-stats
TIME     COMM             PID    TID    EVENT      DEV      LEN    DETAILS              SKB
14:39:50 [STATS]          -      -      STATS      -        -      TCP:156pkts UDP:23pkts HTTP:89pkts DNS:12pkts SSH:45pkts  -
14:39:50 chrome           67890  67890  START_XMIT eth0     1460   IPv4 Q:0   GSO:0     0xffff888033221100
14:39:50 chrome           67890  67890  XMIT       eth0     1460   RC:0 LAT:15us        0xffff888033221100
```

## 事件类型说明

net-snoop监控四种关键的网络事件：

1. **QUEUE**：数据包进入网络设备的发送队列，表示准备发送的数据包。
2. **START_XMIT**：网络驱动开始发送数据包，此时会显示详细的网络层信息，包括L3/L4协议解析结果。
3. **XMIT**：网络发送操作完成，会显示发送结果和延迟信息。
4. **RECEIVE**：网络设备接收到数据包，表示从网络上收到的数据，包含协议解析信息。

通过观察这些事件的时序和详情，可以分析网络性能瓶颈、数据包丢失、延迟问题、协议行为等网络相关问题。

## 协议支持

### L2层协议支持
- IPv4 (0x0800)：Internet Protocol version 4
- IPv6 (0x86DD)：Internet Protocol version 6  
- ARP (0x0806)：Address Resolution Protocol
- VLAN (0x8100)：Virtual LAN tagging
- OTHER：其他协议类型

### L3层协议解析
- **IPv4头部**：源/目标IP地址、协议类型、TOS、TTL、标识符等
- **IPv6头部**：源/目标IPv6地址、下一头部、跳数限制等
- **协议识别**：TCP (6)、UDP (17)、ICMP (1)、ICMPv6 (58)等

### L4层协议解析
- **TCP协议**：源/目标端口、序列号、确认号、窗口大小、标志位（SYN、ACK、FIN、RST、PSH、URG）
- **UDP协议**：源/目标端口、长度、校验和

### 应用层协议识别
- **HTTP**：端口80/8080检测，HTTP请求/响应识别
- **HTTPS**：端口443检测，TLS流量识别
- **DNS**：端口53检测，DNS查询/响应识别
- **SSH**：端口22检测，SSH连接识别
- **FTP**：端口21检测，FTP控制连接识别
- **SMTP**：端口25检测，邮件传输协议识别
- **POP3**：端口110检测，邮件接收协议识别
- **IMAP**：端口143检测，邮件访问协议识别

## 性能优化

工具采用高效的eBPF内核态处理和用户态缓存机制，支持：
- 零拷贝数据传输
- 智能协议解析（按需解析）
- 高效的过滤算法
- 低开销的统计计算

在高负载网络环境下仍能保持良好性能，适合生产环境使用。 