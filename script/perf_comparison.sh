#!/bin/bash

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1-only

# 配置参数
TEST_FILE="/tmp/test_file"
EVENT_COUNT=1000
OUTPUT_DIR="perf_results"

# 准备输出目录
mkdir -p "$OUTPUT_DIR"

# 获取测试文件信息
prepare_test_file() {
    dd if=/dev/zero of="$TEST_FILE" bs=1M count=1 2>/dev/null
    local dev=$(stat -c '%d' "$TEST_FILE")
    local inode=$(stat -c '%i' "$TEST_FILE")
    major=$((($dev >> 8) & 0xfff))
    minor=$(($dev & 0xff))
    echo "$major $minor $inode"
}

# 生成文件操作事件
generate_events() {
    local count=0
    while [ $count -lt $EVENT_COUNT ]; do
        echo "test data" > "$TEST_FILE"
        cat "$TEST_FILE" > /dev/null
        count=$((count + 1))
        if [ $((count % 100)) -eq 0 ]; then
            echo "[*] 已生成 $count 个事件..."
        fi
    done
}

# 测试单个工具
test_tool() {
    local name=$1
    local cmd=$2
    echo -e "\n====== 测试 $name ======"
    
    # 准备测试文件
    local file_info=$(prepare_test_file)
    
    # 启动工具并记录开始时间
    echo "[+] 启动 $name..."
    eval "$cmd" > "$OUTPUT_DIR/${name}_output.log" 2>&1 & 
    tool_pid=$!
    
    # 验证进程是否成功启动
    if ! ps -p $tool_pid > /dev/null; then
        echo "[!] $name 启动失败"
        return 1
    fi

    echo "[*] $name 进程ID: $tool_pid"
    sleep 20  # 等待工具初始化,stap初始化过慢
    start_time=$(date +%s.%N)
    
    # 生成事件
    generate_events
    
    # 停止工具并计算耗时
    sleep 0.1  # 确保所有事件都被收集
    end_time=$(date +%s.%N)
    # 正确终止进程
    echo "[*] 正在停止 $name (PID: $tool_pid)..."
    case $name in
        "dkapture")
            kill -INT $tool_pid 2>/dev/null
            ;;
        "sysdig")
            kill -TERM $tool_pid 2>/dev/null
            ;;
        "systemtap")
            kill -TERM $tool_pid 2>/dev/null
            # 清理可能的残留stap进程
            pkill -f "stap" 2>/dev/null
            ;;
    esac

    # 等待进程结束，最多等待10秒
    sleep 1
    echo "[!] $name 进程未响应，强制终止"
    kill -9 $tool_pid 2>/dev/null

    duration=$(echo "$end_time - $start_time" | bc)
    
    local events=0
    case $name in
        "dkapture")
            events=$(grep -a -E "event: (read|write)" "$OUTPUT_DIR/${name}_output.log" | grep -v "ret: 0" | wc -l)
            ;;
        "sysdig")
            # 修改为正确匹配 sysdig 输出格式的事件统计
            events=$(grep -a -E "[0-9]+\.[0-9]+ .+ [RW] [0-9]+[KMG]?B $TEST_FILE" "$OUTPUT_DIR/${name}_output.log" | grep -v " R 0B " | wc -l)
            ;;
        "systemtap")
            events=$(grep -a -E "(vfs_read|vfs_write)" "$OUTPUT_DIR/${name}_output.log" | uniq |wc -l)
            ;;
    esac

    # 输出结果
    echo "[*] $name 完成测试"
    printf "[*] 耗时: %.2f 秒\n" "$duration"
    echo "[*] 收集到的read/write事件数: $events"
    printf "[*] 每秒处理read/write事件数: %.2f\n" "$(echo "$events / $duration" | bc -l)"
    
    # 保存结果到临时文件
    printf "%s|%.2f|%d|%.2f\n" "$name" "$duration" "$events" "$(echo "$events / $duration" | bc -l)" >> "$OUTPUT_DIR/results.tmp"
}

# 生成报告
generate_report() {
    {
        echo "# 性能分析工具数据收集性能对比报告"
        echo "测试时间: $(date '+%Y-%m-%d %H:%M')"
        echo
        echo "测试参数:"
        echo "- 文件操作次数: $EVENT_COUNT"
        echo "- 预期总事件数: $((EVENT_COUNT * 2)) (每次操作产生一个read和一个write事件)"
        echo
        echo "## 测试结果"
        echo "| 工具 | 总耗时(秒) | 收集事件数 | 事件采样率 | 每秒处理事件数 | 每秒文件操作数 |"
        echo "|------|------------|------------|------------|----------------|----------------|"
        
        # 读取结果文件的每一行
        while IFS='|' read -r tool duration events rate; do
            # 计算事件采样率（相对于预期事件数）
            sampling_rate=$(echo "scale=2; $events / ($EVENT_COUNT * 2)" | bc)
            # 计算每秒处理的文件操作数
            ops_per_sec=$(echo "scale=2; $EVENT_COUNT / $duration" | bc)
            printf "| %s | %.2f | %d | %.2fx | %.2f | %.2f |\n" \
                "$tool" "$duration" "$events" "$sampling_rate" "$rate" "$ops_per_sec"
        done < "$OUTPUT_DIR/results.tmp"

        echo
        echo "### 指标说明"
        echo "- 事件采样率：实际收集的事件数/预期事件数"
        echo "- 每秒处理事件数：实际收集的事件数/总耗时"
        echo "- 每秒文件操作数：完成的文件操作次数/总耗时"
    } > "$OUTPUT_DIR/collection_perf_report.md"
    
    # 清理临时文件
    rm -f "$OUTPUT_DIR/results.tmp"
}

# 主测试流程
main() {
    # 清理上次的日志文件和临时结果文件
    rm -f "$OUTPUT_DIR"/*_output.log
    rm -f "$OUTPUT_DIR"/results.tmp
    rm -f "$OUTPUT_DIR"/collection_perf_report.md
    
    # 获取文件信息用于systemtap
    file_info=$(prepare_test_file)
    read major minor inode <<< "$file_info"
    
    # 测试dkapture
    test_tool "dkapture" "/home/rwen/dkapture/observe/trace-file -p $TEST_FILE"
    
    # 测试sysdig，修改过滤条件
    test_tool "sysdig" "sysdig -c spy_file \"fd.name=$TEST_FILE\""
    
    # 测试systemtap，使用正确的脚本路径
    test_tool "systemtap" "stap -v /var/usrlocal/share/systemtap/examples/io/inodewatch.stp $major $minor $inode"
    
    # 生成报告
    generate_report
    echo -e "\n✅ 测试完成，报告已生成至 $OUTPUT_DIR/collection_perf_report.md"
}

# 运行测试
main