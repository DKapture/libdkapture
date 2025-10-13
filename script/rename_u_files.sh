#!/bin/bash

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1-only

# 脚本用于将 include 目录下以 U 开头的文件重命名，去掉 U 字母
# 使用方法: ./rename_u_files.sh [--dry-run]

# set -e  # 注释掉，避免单个命令失败导致脚本退出

# 获取脚本所在目录的父目录作为项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INCLUDE_DIR="$PROJECT_ROOT/include"

# 检查是否为 dry-run 模式
DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "=== DRY RUN 模式 - 不会实际重命名文件 ==="
fi

echo "项目根目录: $PROJECT_ROOT"
echo "Include 目录: $INCLUDE_DIR"
echo

# 检查目录是否存在
if [[ ! -d "$INCLUDE_DIR" ]]; then
    echo "错误: 目录 $INCLUDE_DIR 不存在"
    exit 1
fi

# 切换到 include 目录
cd "$INCLUDE_DIR"

echo "当前目录: $(pwd)"
echo

# 查找所有以 U 开头的 .h 文件
u_files=($(ls U*.h 2>/dev/null || true))

if [[ ${#u_files[@]} -eq 0 ]]; then
    echo "没有找到以 U 开头的 .h 文件"
    exit 0
fi

echo "找到以下以 U 开头的文件:"
for file in "${u_files[@]}"; do
    echo "  - $file"
done
echo

# 执行重命名
renamed_count=0
for file in "${u_files[@]}"; do
    # 去掉开头的 U 字母
    new_name="${file#U}"
    
    # 检查新文件名是否已存在
    if [[ -f "$new_name" ]]; then
        echo "警告: 目标文件 $new_name 已存在，跳过 $file"
        continue
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "DRY RUN: $file -> $new_name"
    else
        echo "重命名: $file -> $new_name"
        mv "$file" "$new_name"
        if [[ $? -eq 0 ]]; then
            echo "  ✓ 成功"
            ((renamed_count++))
        else
            echo "  ✗ 失败"
        fi
    fi
done

echo
if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN 完成 - 共找到 ${#u_files[@]} 个文件"
else
    echo "重命名完成 - 成功重命名 $renamed_count 个文件"
fi

# 显示重命名后的文件列表
echo
echo "重命名后的文件列表:"
ls -la *.h 2>/dev/null || echo "没有找到 .h 文件"
