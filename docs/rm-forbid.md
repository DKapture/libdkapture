# rm-forbid

## 功能描述

提供类似windows的"占用文件不可删除"的行为。在目前linux上，如果我们打开一个文件（占用它)，然后在另一个进程中去删除它，这个操作是被系统允许的，但是，在windows上，这个行为是不被允许的。本工具提供类windows文件删除行为的特性，给予用户更多选择。

## 使用方法

```c
sudo ./filter/rm-forbid -h
Usage: ./filter/rm-forbid [option]
  To query who are occupying the specified file.

Options:
  -p, --path [path]
        path of the file to watch on

  -d, --dev [dev]
        the device number of filesystem to which the inode belong.
        you can get the dev by running command 'stat -c %d <file>'

  -i, --inode [inode]
        inode of the file to watch on

  -h, --help 
        print this help message
```

- -p：可以指定某个路径的文件不允许在占用时被删除，不指定则涵括全系统文件。
- -d：-p的延伸版本，指定文件系统的设备号（可通过stat命令查询)，所有在该指定文件系统上的文件不允许在占用时被删除。
- -i：指定文件inode号，建议结合-d选项使用，文件inode编号为指定值的文件不允许在占用时被删除。

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
