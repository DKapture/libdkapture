# net-limit

## 功能描述

net-limit 是基于 BPF 的网络限流/整形组件。可以实现对进程和cgroup进行限速

## 使用方式

```bash
$ sudo ./build/filter/net-limit help
Usage:
  net-limit load (--egress --dev <ifname> | --ingress [--attach-root auto|<cgroup-path>]) [--pin]
                 [--rate <rate>] [--burst <bytes>] [--tgid <tgid>|--pid <pid>|--cgroup-path <path>|--cgroup-id <id>]
  net-limit add (--tgid <tgid>|--pid <pid>|--cgroup-path <path>|--cgroup-id <id>) --rate <rate> (--egress --dev <ifname>|--ingress) [--burst <bytes>]
  net-limit del (--tgid <tgid>|--pid <pid>|--cgroup-path <path>|--cgroup-id <id>) (--egress [--dev <ifname>]|--ingress)
  net-limit list (--egress|--ingress)
  net-limit stats (--egress [--dev <ifname>]|--ingress)
  net-limit help

Note:
  Run 'net-limit load ... --pin' before add/del/list/stats.
  The load command pins maps under /sys/fs/bpf and must keep running.

Rate units: B/s by default, K/M/G for bytes, or kbit/mbit/gbit/mbit/s.
shape only supports egress; police mode only supports ingress.
cgroup-path may be absolute under /sys/fs/cgroup, absolute inside cgroup v2, or relative.
```
## 参数说明
- load 子命令：
  - 用途：加载并附着 net-limit 的 BPF 程序到目标（TC 或 cgroup），可同时准备全局或默认规则。
  - 语法要点：
    - 必选其一：--egress 与 --ingress 二选一（见下文具体说明）。
    - 当使用 --egress 时必须同时指定 --dev <ifname>（要附着到的网络接口名）。
    - 当使用 --ingress 时可选指定 --attach-root auto 或 --attach-root <cgroup-path>，用于指定将 BPF attach 到哪个 cgroup（见下文）。
    - 可选 --pin：将加载的 BPF 对象或 maps pin 到 bpffs（持久化，便于后续单独管理）。
    - 可选通过 --rate/--burst/--tgid/--pid/--cgroup-path/--cgroup-id 指定初始规则（见下文具体字段说明）。
- add 子命令：
  - 用途：为指定目标（按 tgid/pid/cgroup 路径或 id）新增一条限速规则（不会重新加载程序，只在 map 中新增规则）。
  - 要求：
    - 必须指定目标：--tgid <tgid> 或 --pid <pid> 或 --cgroup-path <path> 或 --cgroup-id <id>（四选一）。
    - 必须指定限速：--rate <rate>。
    - 指定方向：--egress 时需带 --dev <ifname>（表示该规则关联到接口的 egress 分类/shape），或使用 --ingress（表示针对该 cgroup 的 ingress policing）。
    - 可选 --burst <bytes> 指定突发大小。
- del 子命令：
  - 用途：删除之前为指定目标添加的限速规则。
  - 要求：
    - 必须指定目标：--tgid / --pid / --cgroup-path / --cgroup-id 中的一项。
    - 指定要删除的方向：--egress 或 --ingress。
- list 子命令：
  - 用途：列出当前已配置的规则条目。
  - 参数：
    - 必须指定方向：--egress 或 --ingress，用于区分列出 TC/egress 侧的规则或 cgroup/ingress 的规则。
- stats 子命令：
  - 用途：显示运行时统计（如通过/丢弃的字节与包数）。
  - 参数：
    - 对于 --egress，可选带上 --dev <ifname> 指定接口以显示该接口相关的统计；对于 --ingress，不需要接口参数。
- help 子命令：
  - 用途：打印帮助信息与用法。

## 使用示例

### 示例输出

1) 加载并附着 net-limit 的 BPF 程序到目标：
```bash
$ yuKing@yuKing-PC:~/libdkapture$ sudo ./build/filter/net-limit load --ingress --pin --rate 125000000 --cgroup-path dkapture-net-limit

cgroup 24666 limited: rate=125000000B/s burst=125000000B direction=ingress
net-limit loaded on /sys/fs/cgroup (ingress), maps pinned
keep this process running; use add/del/list/stats in another shell
```
2) 为指定目标（按 tgid/pid/cgroup 路径或 id）新增一条限速规则
```bash
$ sudo ./build/filter/net-limit add --cgroup-path dkapture-net-limit --rate 125000000

cgroup 24666 limited: rate=125000000B/s burst=125000000B direction=ingress
```
3) 删除之前为指定目标添加的限速规则。
```bash
$ sudo ./build/filter/net-limit del --cgroup-path dkapture-net-limit --ingress

cgroup 24666 rule deleted
```
4) 列出当前已配置的规则条目
```bash
$ sudo ./build/filter/net-limit list

Cgroup rules:
cgroup 24666      rate=125000000B/s burst=125000000B direction=ingress
```
5) 显示运行时统计（如通过/丢弃的字节与包数）
```bash
$ sudo ./build/filter/net-limit stats --egress

class htb 1:ffff root prio 0 rate 100Gbit ceil 100Gbit burst 2400b cburst 2400b
 Sent 8476 bytes 80 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
 lended: 80 borrowed: 0 giants: 0
 tokens: 2 ctokens: 2

class htb 1:dae3 root prio 0 rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b
 Sent 25081314 bytes 20210 pkt (dropped 0, overlimits 20194 requeues 0) 
 backlog 0b 0p requeues 0
 lended: 20210 borrowed: 0 giants: 0
 tokens: 19175 ctokens: 19175

tc_class=1:dae3 tc_delta=25081314B
```