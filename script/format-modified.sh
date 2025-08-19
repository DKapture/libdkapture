#!/bin/bash

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

FILES=$(git diff --name-only --diff-filter=M \
  | grep -E '\.(c|h|cpp)$')

if [ -z "$FILES" ]; then
  echo "No unstaged C/C++ files"
  exit 0
fi

echo "Formatting:"
echo "$FILES" | while IFS= read -r file; do
  echo "  • $file"
  clang-format -i "$file"
done

echo "Done."