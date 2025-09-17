#!/usr/bin/env python3
"""
Rewrite xxx__elf_bytes() in a BPF skeleton header (xxx.skel.h) to map the
corresponding xxx.bpf.o file into memory and return its address.

Usage:
  patch_skel_elf_bytes.py /abs/path/to/file.skel.h [--dry-run]

Notes:
- The function to patch is detected by the pattern '__elf_bytes(size_t *sz)'.
- The mapped object file path is inferred by replacing '.skel.h' with '.bpf.o'
  and resolved to an absolute path. That absolute path is embedded into the
  generated function body.
- Required system includes are injected if missing.
"""

import argparse
import os
import re
import sys
from typing import Tuple


INCLUDES_TO_ENSURE = [
    "#include <sys/types.h>",
    "#include <sys/stat.h>",
    "#include <sys/mman.h>",
    "#include <fcntl.h>",
    "#include <unistd.h>",
]


def find_function_span(src: str) -> Tuple[int, int, str]:
    """Find the byte-span [start_idx, end_idx) of the xxx__elf_bytes function body,
    including the signature and braces, and return the function prefix name.

    Returns: (start_index, end_index, func_name)
    Raises ValueError if not found or malformed.
    """
    # Match the function signature, capturing the function name prefix
    sig_re = re.compile(
        r"static\s+inline\s+const\s+void\s*\*\s*(?P<name>[A-Za-z0-9_]+__elf_bytes)\s*\(\s*size_t\s*\*\s*sz\s*\)",
        re.MULTILINE,
    )

    def next_non_space(idx: int) -> int:
        n = len(src)
        while idx < n and src[idx] in "\r\n\t ":
            idx += 1
        return idx

    m = None
    for cand in sig_re.finditer(src):
        j = next_non_space(cand.end())
        if j < len(src) and src[j] == '{':
            m = cand
            break
    if not m:
        raise ValueError("__elf_bytes() function signature not found")
    start = m.start()
    name = m.group("name")

    # Find the opening brace following the signature (on same or next line)
    brace_start = src.find("{", m.end())
    if brace_start == -1:
        raise ValueError("Opening brace not found after signature")
    depth = 0
    i = brace_start
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                # include the closing brace and trailing newline if any
                end = i + 1
                # Swallow following newlines/spaces to keep formatting stable
                while end < n and src[end] in "\r\n\t ":
                    end += 1
                return start, end, name
        i += 1
    raise ValueError("Matching closing brace for function not found")


def ensure_includes(src: str) -> str:
    """Ensure the required system includes are present. Insert them after the last
    existing #include line near the top of the file.
    """
    lines = src.splitlines(keepends=True)
    present = set()
    last_include_idx = -1
    for idx, line in enumerate(lines):
        if line.lstrip().startswith('#include '):
            last_include_idx = idx
            present.add(line.strip())
        # Stop scanning includes if we reach a non-include after includes start
        elif last_include_idx != -1 and line.strip() and not line.strip().startswith('#'):
            break

    missing = [inc for inc in INCLUDES_TO_ENSURE if inc not in present]
    if not missing:
        return src

    insertion = ''.join(inc + "\n" for inc in missing)
    if last_include_idx == -1:
        # Insert after the header guard and any initial comments; default to start
        return insertion + src
    else:
        insert_pos = 0
        for i in range(last_include_idx + 1):
            insert_pos += len(lines[i])
        return src[:insert_pos] + insertion + src[insert_pos:]


def make_replacement_body(func_name: str, abs_obj_path: str) -> str:
    """Generate the replacement function implementation body.

    Indentation uses tabs to match the auto-generated style.
    """
    prefix = func_name.rsplit("__elf_bytes", 1)[0]
    mapped_addr = f"{prefix}__mapped_addr"
    mapped_size = f"{prefix}__mapped_size"

    return (
        f"static inline const void *{func_name}(size_t *sz)\n"
        "{\n"
        f"\tif (!{mapped_addr}) {{\n"
        f"\t\tconst char *path = \"{abs_obj_path}\";\n"
        "\t\tint fd = open(path, O_RDONLY);\n"
        "\t\tif (fd < 0) {\n"
        "\t\t\treturn NULL;\n"
        "\t\t}\n"
        "\t\tstruct stat st;\n"
        "\t\tif (fstat(fd, &st) != 0) {\n"
        "\t\t\tclose(fd);\n"
        "\t\t\treturn NULL;\n"
        "\t\t}\n"
        f"\t\t{mapped_size} = (size_t)st.st_size;\n"
        f"\t\tvoid *addr = mmap(NULL, {mapped_size}, PROT_READ, MAP_PRIVATE, fd, 0);\n"
        "\t\tclose(fd);\n"
        "\t\tif (addr == MAP_FAILED) {\n"
        f"\t\t\t{mapped_addr} = NULL;\n"
        f"\t\t\t{mapped_size} = 0;\n"
        "\t\t\treturn NULL;\n"
        "\t\t}\n"
        f"\t\t{mapped_addr} = addr;\n"
        "\t}\n"
        f"\t*sz = {mapped_size};\n"
        f"\treturn {mapped_addr};\n"
        "}\n"
    )


def ensure_globals(src: str, mapped_addr: str, mapped_size: str) -> str:
    """Ensure a single declaration of the static globals exists after includes.
    - Remove any existing duplicate declarations anywhere in the file
    - Insert exactly one pair after the last #include line
    """
    # Remove any existing declarations (robust to whitespace)
    pattern_addr = re.compile(rf"^\s*static\s+void\s*\*\s*{re.escape(mapped_addr)}\s*=\s*NULL\s*;\s*$", re.MULTILINE)
    pattern_size = re.compile(rf"^\s*static\s+size_t\s+{re.escape(mapped_size)}\s*=\s*0\s*;\s*$", re.MULTILINE)
    src = pattern_addr.sub("", src)
    src = pattern_size.sub("", src)

    # Also collapse multiple consecutive newlines left behind
    src = re.sub(r"\n{3,}", "\n\n", src)

    # Find insertion point (after last include)
    lines = src.splitlines(keepends=True)
    last_include_idx = -1
    for idx, line in enumerate(lines):
        if line.lstrip().startswith('#include '):
            last_include_idx = idx
        elif last_include_idx != -1 and line.strip() and not line.strip().startswith('#'):
            break

    insertion = (
        f"\nstatic void *{mapped_addr} = NULL;\n"
        f"static size_t {mapped_size} = 0;\n"
        f"\n"
    )
    if last_include_idx == -1:
        return insertion + src
    insert_pos = 0
    for i in range(last_include_idx + 1):
        insert_pos += len(lines[i])
    return src[:insert_pos] + insertion + src[insert_pos:]


def find_destroy_span(src: str, struct_name: str) -> Tuple[int, int, int]:
    """Find span of '<name>__destroy(' function and return (start, body_start, end)."""
    needle = f"{struct_name}__destroy("
    idx = src.find(needle)
    if idx == -1:
        raise ValueError("__destroy() function signature not found")
    # Move left to include optional preceding 'static void' line break
    start = idx
    # Find the opening brace after the signature
    brace_start = src.find('{', idx)
    if brace_start == -1:
        raise ValueError("Opening brace for __destroy not found")
    # Balance braces to find end
    depth = 0
    i = brace_start
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                return start, brace_start + 1, end
        i += 1
    raise ValueError("Matching closing brace for __destroy not found")


def patch_header(header_path: str, dry_run: bool = False, obj_dir: str | None = None) -> None:
    if not header_path.endswith('.skel.h'):
        raise ValueError("Input file must end with .skel.h")
    with open(header_path, 'r', encoding='utf-8') as f:
        src = f.read()

    start, end, func_name = find_function_span(src)

    # Infer the corresponding object file path and ensure it exists
    if obj_dir:
        stem = os.path.basename(header_path)[:-len('.skel.h')]
        obj_path = os.path.join(obj_dir, stem + '.bpf.o')
    else:
        obj_path = header_path[:-len('.skel.h')] + '.bpf.o'
    abs_obj_path = os.path.abspath(obj_path)

    # Prepare new function body with mmap logic
    new_func = make_replacement_body(func_name, abs_obj_path)

    # Replace function implementation
    new_src = src[:start] + new_func + src[end:]

    # Patch __destroy to munmap if we added globals
    struct_name = func_name.rsplit("__elf_bytes", 1)[0]
    mapped_addr = f"{struct_name}__mapped_addr"
    mapped_size = f"{struct_name}__mapped_size"
    # Ensure globals are present near top includes
    new_src = ensure_globals(new_src, mapped_addr, mapped_size)
    try:
        d_start, d_body_start, d_end = find_destroy_span(new_src, struct_name)
        # Insert munmap logic at the beginning of the destroy body
        munmap_code = (
            "\n\tif ({mapped_addr}) {{\n"
            "\t\tmunmap({mapped_addr}, {mapped_size});\n"
            "\t\t{mapped_addr} = NULL;\n"
            "\t\t{mapped_size} = 0;\n"
            "\t}}\n"
        ).format(mapped_addr=mapped_addr, mapped_size=mapped_size)
        new_src = new_src[:d_body_start] + munmap_code + new_src[d_body_start:]
    except ValueError:
        # If __destroy not found, proceed without patching it
        pass

    # Fallback: if munmap not present, try simple brace insertion based on function name
    if "munmap(" not in new_src:
        needle = f"{struct_name}__destroy("
        pos = new_src.find(needle)
        if pos != -1:
            brace = new_src.find('{', pos)
            if brace != -1:
                munmap_code = (
                    "\n\tif ({mapped_addr}) {{\n"
                    "\t\tmunmap({mapped_addr}, {mapped_size});\n"
                    "\t\t{mapped_addr} = NULL;\n"
                    "\t\t{mapped_size} = 0;\n"
                    "\t}}\n"
                ).format(mapped_addr=mapped_addr, mapped_size=mapped_size)
                insert_at = brace + 1
                new_src = new_src[:insert_at] + munmap_code + new_src[insert_at:]

    # Ensure required includes are present
    new_src = ensure_includes(new_src)

    if dry_run:
        sys.stdout.write(new_src)
        return

    with open(header_path, 'w', encoding='utf-8') as f:
        f.write(new_src)


def main() -> None:
    parser = argparse.ArgumentParser(description="Patch xxx__elf_bytes in .skel.h to mmap xxx.bpf.o")
    parser.add_argument('header', help='Path to the .skel.h file (absolute or relative)')
    parser.add_argument('--dry-run', action='store_true', help='Print result to stdout without writing')
    parser.add_argument('--obj-dir', dest='obj_dir', default=None,
                        help='Directory containing <stem>.bpf.o; overrides default alongside header')
    args = parser.parse_args()

    header_path = args.header
    if not os.path.isabs(header_path):
        header_path = os.path.abspath(header_path)
    patch_header(header_path, dry_run=args.dry_run, obj_dir=args.obj_dir)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


