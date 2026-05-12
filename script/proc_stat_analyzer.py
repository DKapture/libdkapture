#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

"""
进程统计信息分析器
遍历/proc/pid/stat文件，统计utime和stime为0的进程数量
"""

import os
import sys
from pathlib import Path

from proc_stat_parser import parse_stat_content

def parse_proc_stat(stat_content):
    """
    解析/proc/pid/stat文件内容
    返回(utime, stime)元组
    """
    try:
        _, utime, stime = parse_stat_content(stat_content)
        return utime, stime
    except ValueError as e:
        print(f"解析stat文件失败: {e}")
        return None, None

def get_process_name(stat_content):
    """
    从stat内容中提取进程名
    """
    try:
        comm, _, _ = parse_stat_content(stat_content)
        return comm
    except ValueError:
        return "unknown"

def analyze_process_stats():
    """
    分析所有进程的统计信息
    """
    proc_path = Path("/proc")
    total_processes = 0
    utime_zero_count = 0
    stime_zero_count = 0
    both_zero_count = 0
    
    # 存储详细信息
    utime_zero_processes = []
    stime_zero_processes = []
    both_zero_processes = []
    
    print("正在分析进程统计信息...")
    
    # 遍历所有进程目录
    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue
            
        pid = pid_dir.name
        stat_file = pid_dir / "stat"
        
        if not stat_file.exists():
            continue
            
        try:
            with open(stat_file, 'r') as f:
                stat_content = f.read()
                
            utime, stime = parse_proc_stat(stat_content)
            
            if utime is None or stime is None:
                continue
                
            total_processes += 1
            process_name = get_process_name(stat_content)
            process_info = f"PID:{pid} ({process_name})"
            
            # 统计utime为0的进程
            if utime == 0:
                utime_zero_count += 1
                utime_zero_processes.append(process_info)
            
            # 统计stime为0的进程
            if stime == 0:
                stime_zero_count += 1
                stime_zero_processes.append(process_info)
            
            # 统计utime和stime都为0的进程
            if utime == 0 and stime == 0:
                both_zero_count += 1
                both_zero_processes.append(process_info)
                
        except (IOError, OSError) as e:
            # 忽略权限不足或文件不存在的错误
            continue
    
    # 打印统计结果
    print(f"\n=== 进程统计信息分析结果 ===")
    print(f"总进程数: {total_processes}")
    print(f"utime为0的进程数: {utime_zero_count}")
    print(f"stime为0的进程数: {stime_zero_count}")
    print(f"utime和stime都为0的进程数: {both_zero_count}")
    
    # 打印详细信息
    if utime_zero_processes:
        print(f"\n=== utime为0的进程列表 ===")
        for process in utime_zero_processes[:20]:  # 只显示前20个
            print(f"  {process}")
        if len(utime_zero_processes) > 20:
            print(f"  ... 还有 {len(utime_zero_processes) - 20} 个进程")
    
    if stime_zero_processes:
        print(f"\n=== stime为0的进程列表 ===")
        for process in stime_zero_processes[:20]:  # 只显示前20个
            print(f"  {process}")
        if len(stime_zero_processes) > 20:
            print(f"  ... 还有 {len(stime_zero_processes) - 20} 个进程")
    
    if both_zero_processes:
        print(f"\n=== utime和stime都为0的进程列表 ===")
        for process in both_zero_processes[:20]:  # 只显示前20个
            print(f"  {process}")
        if len(both_zero_processes) > 20:
            print(f"  ... 还有 {len(both_zero_processes) - 20} 个进程")

def main():
    """
    主函数
    """
    print("进程统计信息分析器")
    print("=" * 50)
    
    try:
        analyze_process_stats()
    except KeyboardInterrupt:
        print("\n用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
