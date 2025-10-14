#!/bin/bash

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

CLANG_FORMAT_VERSION=$(clang-format --version | grep -oP '[0-9]+' | head -1)
if [ -z "$CLANG_FORMAT_VERSION" ]; then
  echo "Error: clang-format not found"
  exit 1
fi

if [ "$CLANG_FORMAT_VERSION" -lt 17 ]; then
  echo "Error: clang-format version must be >= 17 (found version $CLANG_FORMAT_VERSION)"
  exit 1
fi

if ! git rev-parse --is-inside-work-tree &> /dev/null; then
  echo "Error: Not in a git repo"
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
if [ $? -ne 0 ]; then
  echo "Error: Cannot get repo root"
  exit 1
fi

cd "$REPO_ROOT" || exit 1

FILES=$(find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" \) \
  ! -path "./build/*" ! -path "./googletest/*")

if [ -z "$FILES" ]; then
  echo "No C/C++ files found"
  exit 0
fi

echo "Formatting all C/C++ files:"
echo "Found $(echo "$FILES" | wc -l) files to format"

read -p "Are you sure you want to format all C/C++ files? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Operation cancelled"
  exit 0
fi

echo "$FILES" | while IFS= read -r file; do
  echo "  • $file"
  clang-format -i "$file"
done

echo "Done. Formatted $(echo "$FILES" | wc -l) files."