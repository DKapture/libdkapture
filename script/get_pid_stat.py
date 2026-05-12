#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

import os
import sys

from proc_stat_parser import parse_stat_content

def read_stat_file(stat_path):
    """读取并解析stat文件"""
    try:
        with open(stat_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return None

        return parse_stat_content(content)

    except (OSError, ValueError):
        # 可选：记录日志
        return None

def main():
    print(f"{'PID':>8} {'TGID':>8} {'UTIME':>10} {'STIME':>10} {'COMMAND'}")
    print("-" * 50)
    
    proc_dir = '/proc'
    
    if not os.path.exists(proc_dir):
        print(f"错误: {proc_dir} 目录不存在", file=sys.stderr)
        sys.exit(1)
    
    # 遍历所有进程目录
    for entry in os.listdir(proc_dir):
        if not entry.isdigit():
            continue
            
        tgid = int(entry)
        task_dir = os.path.join(proc_dir, entry, 'task')
        
        if not os.path.exists(task_dir):
            continue
            
        # 遍历该进程的所有线程
        try:
            for task_entry in os.listdir(task_dir):
                if not task_entry.isdigit():
                    continue
                
                pid = int(task_entry)
                task_stat_path = os.path.join(task_dir, task_entry, 'stat')
                
                if not os.path.exists(task_stat_path):
                    continue
                    
                stat_fields = read_stat_file(task_stat_path)

                if stat_fields:
                    try:
                        task_pid = pid
                        task_name, task_utime, task_stime = stat_fields
                        
                        # 对于task目录下的stat文件，TGID应该是线程组的PID
                        # 但在某些情况下，我们需要从进程目录获取正确的TGID
                        task_tgid = tgid
                        
                        print(f"{task_pid:>8} {task_tgid:>8} {task_utime:>10} {task_stime:>10} {task_name}")
                        
                    except (IndexError, ValueError) as e:
                        continue
                        
        except PermissionError:
            continue
        except Exception as e:
            continue

if __name__ == '__main__':
    main()
