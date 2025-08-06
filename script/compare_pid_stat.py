#!/usr/bin/env python3
import subprocess
import re
import os
import sys

def parse_proc_script_output(output):
    """解析第一个脚本的输出"""
    processes = {}
    lines = output.strip().split('\n')
    
    for line in lines[2:]:  # 跳过表头
        if line.strip() and not line.startswith('-'):
            match = re.match(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$', line)
            if match:
                pid = int(match.group(1))
                tgid = int(match.group(2))
                utime = int(match.group(3))
                stime = int(match.group(4))
                comm = match.group(5).strip()
                
                processes[pid] = {
                    'pid': pid,
                    'tgid': tgid,
                    'comm': comm,
                    'utime': utime,
                    'stime': stime
                }
    
    return processes

def parse_dk_demo_output(output):
    """解析dk-demo -pstat的输出"""
    processes = {}
    lines = output.strip().split('\n')
    
    data_started = False
    for line in lines:
        if "======== Procfs Combined Reading ========" in line:
            data_started = True
            continue
            
        if data_started and line.startswith("pid:"):
            match = re.match(r'pid:\s*(\d+)\s+tgid:\s*(\d+)\s+comm:\s*([^ ]+)\s+.*utime:\s*(\d+)\s+stime:\s*(\d+)', line)
            if match:
                pid = int(match.group(1))
                tgid = int(match.group(2))
                comm = match.group(3)
                utime = int(match.group(4))
                stime = int(match.group(5))
                
                processes[pid] = {
                    'pid': pid,
                    'tgid': tgid,
                    'comm': comm,
                    'utime': utime,
                    'stime': stime
                }
    
    return processes

def calculate_percentage_diff(val1, val2):
    """计算百分比差异"""
    if val1 == 0 and val2 == 0:
        return 0
    if val1 == 0:
        return 100
    return abs((val1 - val2) / val1) * 100

def main():
    if os.geteuid() != 0:
        print("错误: 此脚本需要root权限运行", file=sys.stderr)
        print("请使用 'sudo' 命令运行此脚本:", file=sys.stderr)
        print(f"  sudo {sys.argv[0]}", file=sys.stderr)
        sys.exit(1)
    # 执行两个命令
    proc_result = subprocess.run(['./get_pid_stat.py'], 
                               capture_output=True, text=True)
    dk_result = subprocess.run(['dk-demo', '-pstat'], 
                             capture_output=True, text=True)
    
    if proc_result.returncode != 0 or dk_result.returncode != 0:
        print("命令执行失败")
        return
    
    # 解析输出
    proc_processes = parse_proc_script_output(proc_result.stdout)
    dk_processes = parse_dk_demo_output(dk_result.stdout)
    
    # 打印表头
    print(f"{'PID':>8} {'TGID':>8} {'COMMAND':<20} {'UTIME':>12} {'STIME':>12} {'DK-UTIME':>12} {'DK-STIME':>12} {'DIFF':>20}")
    print("-" * 111)
    
    # 对比并输出
    for pid in sorted(proc_processes.keys()):
        if pid in dk_processes:
            proc_data = proc_processes[pid]
            dk_data = dk_processes[pid]
            
            # 计算dk值（除以10^7）
            dk_utime = dk_data['utime'] // 10000000
            dk_stime = dk_data['stime'] // 10000000
            
            # 原始值
            proc_utime = proc_data['utime']
            proc_stime = proc_data['stime']
            
            # 计算差异
            utime_diff = calculate_percentage_diff(proc_utime, dk_utime)
            stime_diff = calculate_percentage_diff(proc_stime, dk_stime)
            
            # 判断是否标红
            should_highlight = utime_diff > 10 or stime_diff > 10
            
            # 输出
            comm = dk_data['comm'][:20]
            diff_info = f"U:{utime_diff:.1f}% S:{stime_diff:.1f}%"
            
            output_line = f"{pid:>8} {proc_data['tgid']:>8} {comm:<20} {proc_utime:>12} {proc_stime:>12} {dk_utime:>12} {dk_stime:>12} {diff_info:>20}"
            
            if should_highlight:
                print(f"\033[91m{output_line}\033[0m")
            else:
                print(output_line)

if __name__ == '__main__':
    main()
