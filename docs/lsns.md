# lsns

## 功能描述

lsns 用于枚举并展示系统中的命名空间实例及其“所有者”信息，以及当前被该命名空间实例使用的进程数者 uid，以及该命名空间实例。

## 使用方式

```bash
$ sudo ./observe/lsns -h
Usage:
  ./build/observe/lsns [option] [<namespace>]
list the Linux namespaces that the system is using

Options:
  -J, --json 
        use JSON output format
  -h, --help 
        print this help message
```
## 参数说明
- -J: 以JSON格式输出。
- -h: 打印帮助信息。

## 使用示例

### 示例输出

1) 列出所有命名空间实例（默认）：
```bash
$ sudo ./build/observe/lsns
NS              TYPE              PROCS   USER                PID         COMMAND
4026531834      time              305     root                1           /sbin/init splash
4026531835      cgroup            305     root                1           /sbin/init splash
4026531836      pid               305     root                1           /sbin/init splash
4026531837      user              303     root                1           /sbin/init splash
4026531838      uts               298     root                1           /sbin/init splash
4026531839      ipc               303     root                1           /sbin/init splash
4026531840      net               301     root                1           /sbin/init splash
4026531841      mnt               283     root                1           /sbin/init splash
```
2) 命名空间实例使用JSON格式输出
```bash
$ sudo ./build/observe/lsns -J
{
  "namespaces": [
    {
       "ns": 4026531834,
       "type": "time",
       "nprocs": 303,
       "pid": 1,
       "user": "root",
       "command": "/sbin/init splash",
       "children": [
          {
             "ns": 4026532413,
             "type": "mnt",
             "nprocs": 1,
             "pid": 555,
             "user": "root",
             "command": "/usr/lib/systemd/systemd-udevd"
          },
          {
             "ns": 4026532414,
             "type": "uts",
             "nprocs": 1,
             "pid": 555,
             "user": "root",
             "command": "/usr/lib/systemd/systemd-udevd"
          },
          {
             "ns": 4026532486,
             "type": "mnt",
             "nprocs": 1,
             "pid": 697,
             "user": "systemd-timesync",
             "command": "/usr/lib/systemd/systemd-timesyncd"
          },
          {
             "ns": 4026532487,
             "type": "uts",
             "nprocs": 1,
             "pid": 697,
             "user": "systemd-timesync",
             "command": "/usr/lib/systemd/systemd-timesyncd"
          },
```

