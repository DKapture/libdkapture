# net-traffic

## 功能描述

net-traffic工具用于检测系统的网络流量，它可以分别检测每进程、每端口、每IP、每网卡设备的流量数据，并且可以实时流量数据输出或统计速率输出。

## 使用方法

```bash
$ sudo ./observe/net-traffic -h
Usage: ./observe/net-traffic [option]
  protect system files from malicious opening according to the policy file

Options:
  -c, --comm <process name>
        process name to filter

  -p, --pid <process id>
        process id to filter

  -r, --remote <remote ip>
        remote ip to filter

  -P, --port <remote port>
        remote port to filter

  -d, --dir <direction>
        traffic direction to filter

  -h, --help 
        print this help message
```

- -c：指定需要过滤的进程名。
- -p：指定需要过滤的进程pid。
- -r：指定需要过滤的远端ip地址。
- -P：指定需要过滤的远端端口号。
- -d：指定需要过滤的包方向，-1指入包，1指出包，不指定时，两个方向都包含。
- -h：打印帮助信息。

## 运行示例

```bash
$ sudo ./observe/net-traffic 
[20:21:53] code[3300] to 20.189.172.73:443, traffic: 24
[20:21:53] code[3271] to 20.189.172.73:443, traffic: 298
[20:21:53] code[3271] to 20.189.172.73:443, traffic: 24
[20:21:53] code[3271] to 20.189.172.73:443, traffic: 517
[20:21:53] code[3300] to 20.189.172.73:443, traffic: 517
[20:21:53] code[3271] to 20.189.172.73:443, traffic: 446
[20:21:53] code[3300] to 20.189.172.73:443, traffic: 446
[20:21:53] code[3271] from 20.189.172.73:443, traffic: 4408
[20:21:53] code[3271] to 20.189.172.73:443, traffic: 298
[20:21:53] code[3300] from 20.189.172.73:443, traffic: 4408
[20:21:53] code[3300] to 20.189.172.73:443, traffic: 298
[20:21:53] code[3271] from 20.189.172.73:443, traffic: 479
[20:21:53] code[3271] to 20.189.172.73:443, traffic: 24
[20:21:53] code[3300] from 20.189.172.73:443, traffic: 103
[20:21:53] code[3300] from 20.189.172.73:443, traffic: 376
[20:21:53] code[3300] to 20.189.172.73:443, traffic: 24
[20:21:53] ssh[1959355] from 10.20.64.43:22, traffic: 84
[20:21:54] code[3318] to 10.20.0.10:53, traffic: 59
```
