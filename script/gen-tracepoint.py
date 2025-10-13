# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1-only

import os
import re
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <tp_dir>")
    sys.exit(1)

tp_dir = sys.argv[1]

def extract_variables(line):
    pattern = r'field:([^;]+);'
    
    match = re.search(pattern, line)
    if match:
        declaration = match.group(1).strip()
        # 查找最后一个空格位置来分离类型和变量名
        last_space_index = declaration.rfind(' ')
        
        if last_space_index == -1:
            # 如果没有空格，整个字符串作为变量名，类型为空
            var_type = ''
            var_name = declaration
        else:
            var_type = declaration[:last_space_index].strip()
            var_name = declaration[last_space_index+1:].strip()

        return f"    {var_type} {var_name};"
    
    return None

for subdir in sorted(os.listdir(tp_dir)):
    subpath = os.path.join(tp_dir, subdir)
    format_path = os.path.join(subpath, "format")
    if not os.path.isdir(subpath) or not os.path.isfile(format_path):
        continue

    struct_lines = []
    with open(format_path) as f:
        in_format = False
        for line in f:
            if line.strip().startswith("format:"):
                in_format = True
                continue
            if in_format:
                if not line.strip():
                    continue
                if line.startswith("print fmt:"):
                    break
                field_line = extract_variables(line)
                if field_line:
                    struct_lines.append(field_line)

    struct_name = f"tp_{subdir}_t"
    print(f"struct {struct_name} {{")
    for l in struct_lines:
        print(l)
    print("};\n")

    print(f'SEC("tracepoint/{tp_dir}/{subdir}")')
    print(f"int tp_{subdir}(struct {struct_name} *ctx)")
    print("{")
    print("    // TODO: 实现事件处理逻辑")
    print("    return 0;")
    print("}\n")