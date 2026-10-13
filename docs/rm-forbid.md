# rm-forbid

## 功能描述

提供类似windows的"占用文件不可删除"的行为。在目前linux上，如果我们打开一个文件（占用它)，然后在另一个进程中去删除它，这个操作是被系统允许的，但是，在windows上，这个行为是不被允许的。本工具提供类windows文件删除行为的特性，给予用户更多选择。

## 使用方法

```c
sudo ./filter/rm-forbid -h
Usage: ./filter/rm-forbid [option]
  Forbid deletion (unlink/rmdir) of files that are currently
  held open by processes. The protection scope is selected by
  device number and/or inode, not by directory path.

Options:
  -p, --path [path]
        stat <path> and use its filesystem device number as the
        protection scope: all open files on that filesystem are
        protected. This is a shortcut for -d $(stat -c %d <path>);
        it does not scope protection to the directory tree of <path>.

  -d, --dev [dev]
        device number of the filesystem to protect: all open files on
        it are protected. Get it by running 'stat -c %d <file>'.

  -i, --inode [inode]
        inode of the file to protect: only that exact file is
        protected. Use it with -d to restrict the rule to one
        filesystem; used alone, the inode is matched on every
        filesystem.

  -h, --help 
        print this help message
```

- -p：`stat <path>` 取该路径所在文件系统的设备号作为保护范围，该文件系统上所有被占用的文件都不可删除。它只是 `-d $(stat -c %d <path>)` 的快捷方式，**不会**把保护范围限定在 `<path>` 目录树下。
- -d：指定文件系统的设备号（可通过 stat 命令查询），该设备上所有被占用的文件不可删除。
- -i：指定文件 inode 号，只保护 inode 精确匹配的那一个文件。建议结合 -d 使用以限定单个文件系统；单独使用时会在所有文件系统上匹配该 inode 号。

## 获取设备号的方法

要获取文件系统的设备号，可以使用以下命令：

```bash
# 获取文件的设备号
stat -c %d <file_path>

# 或者使用ls命令
ls -l <file_path>
# 输出中的主次设备号，例如：8,1 表示主设备号为8，次设备号为1
```

## 使用示例

```bash
$ stat -c %d /tmp
2050
$ sudo ./filter/rm-forbid -d 2050 &
[1] 1035650
$ echo 111 > /tmp/111
$ tail -f /tmp/111 &
[2] 1035664
111
$ rm -f /tmp/111 
rm: 无法删除 '/tmp/111': 设备或资源忙
$ kill %1
$ rm -f /tmp/111 
[1]-  已终止               sudo ./filter/rm-forbid -d 2050
$
```

1. 首先我们通过stat命令获取需要保护的文件系统的设备号，例如 `/tmp` 目录的设备号是2050。
2. 然后将设备号传递给工具 `./filter/rm-forbid -d 2050`。
3. 然后用任意编辑器占用一个文件，例如 `tail -f file`。
4. 然后尝试删除刚占用的文件，可以看到结果是"无法删除"。
5. 最后我们取消保护，将bpf程序退出 `kill %1`。
6. 再次删除，可以成功删除。
