# trace-exec

## 功能描述

    该工具可以根据程序文件路径，跟踪由该文件创建进程的父进程路径。此工具在应对捕获那些频繁拉起的进程时非常有效，比如，您发现系统中bash进程频繁被运行，但由很快就退出，常规捕获方法，如遍历/proc/[pid]进程目录根本来不及，因此本工具可以提供对这一类程序的捕获能力，并且打印其族谱，便于排查是谁在频率调用bash进程，之所以这么做，是因为，很多程序本身是无害，有问题的是那些非法调用它们的父进程（或更上级）。

## 使用方式

```bash
$ sudo ./observe/trace-exec -h
Usage: ./observe/trace-exec [option]
  trace exec event on the system, support filter with process image file name and uid.
  This tool is useful for tracing processes that run and exit fast, traditional methods, like traversing through the proc dir, cannot catch such events in time.

options:
  -u, --uid <uid>
        filter with uid

  -d, --depth <depth>
        set the printed task chain length

  -t, --target [target]
        filter with process file path

  -h, --help 
        print this help message
```

- -u：指定需要过滤的用户id。
- -t：指定需要跟踪的目标进程文件路径。
- -d：指定追踪父进程时，最大的跟踪深度，支持的最大值为128。

## 运行示例

```bash
$ sudo ./observe/trace-exec -t /usr/bin/ls
ls(2046365)<-bash(835202)<-su(835201)<-sudo(835200)<-sudo(835196)<-bash(4697)<-deepin-terminal(4689)<-systemd(1471)<-systemd(1)
```
