// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef __BTF_PREPROCESSOR_H__
#define __BTF_PREPROCESSOR_H__

#include <string>
#include <vector>

#include <bpf/libbpf.h>

/**
 * @brief 从 BTF 中提取的 extern map 元信息，供 check_extern_maps 返回
 */
struct ExternMapInfo {
    std::string name;
    std::string type_name;
    int map_type = 0;
    __u32 key_size = 0;
    __u32 value_size = 0;
    __u32 max_entries = 0;
    int btf_var_id = 0;
    int btf_type_id = 0;
};

/**
 * @brief 预处理阶段从 extern 声明中提取的每个 map 的元信息
 *
 * 包含每个 extern map 变量原始 BTF 类型 ID 和 struct 大小，
 * 用于 ELF 修改逻辑创建 .maps section 和修复符号表条目。
 */
struct ExternVarInfo {
    std::string name;        ///< 变量名（如 "data_map"）
    int var_btf_id;          ///< BTF_KIND_VAR 条目的 BTF 类型 ID
    int struct_btf_id;       ///< 底层 struct 的 BTF 类型 ID
    int struct_size;         ///< struct 大小（字节，用于 .maps section 数据区）
    size_t offset;           ///< 在 .maps section 内的偏移（字节）
    int map_type;            ///< BPF_MAP_TYPE_*（预留，尚未填充）
    int key_size;            ///< 键大小（字节，预留）
    int value_size;          ///< 值大小（字节，预留）
    int max_entries;         ///< 最大条目数（预留）
};

/**
 * @brief 预处理含 extern map 声明的 ELF .o 文件
 *
 * 执行 ELF 手术将 extern map 声明转为 libbpf 可处理的常规定义。
 * 转换步骤：
 *   1. BTF：将 BTF_VAR_GLOBAL_EXTERN 改为 BTF_VAR_GLOBAL_ALLOCATED
 *   2. BTF：添加 .maps DATASEC，引用这些 extern 变量
 *   3. 符号表：将 SHN_UNDEF 符号改为指向新的 .maps section
 *   4. Libelf：创建零初始化的 .maps ELF section
 *
 * 预处理后，修补过的 .o 文件可用 bpf_object__open_file() 正常打开，
 * 由 libbpf 处理。
 */
class BtfPreprocessor {
public:
    /**
     * @brief 从 ELF 文件解析 BTF，查找 extern map 变量
     *
     * 无需 bpf_object__open_file()（该函数在 extern map 声明时会失败）。
     * 用于早期检测和向用户展示友好的错误信息。
     *
     * @param bpf_obj_path .bpf.o ELF 文件路径
     * @param ext_info     输出参数，找到的 extern map 信息列表
     * @return 成功返回 0，解析失败返回负 errno
     */
    int check_extern_maps(const char *bpf_obj_path,
                          std::vector<ExternMapInfo> *ext_info);

    /**
     * @brief 完整预处理：将 extern map 转为定义
     *
     * 在 output_path 创建输入 .o 文件的修补副本，包含：
     *   - BTF linkage 从 EXTERN 改为 ALLOCATED
     *   - BTF 中添加 .maps DATASEC（如尚不存在）
     *   - 创建 .maps ELF section（零填充）
     *   - 符号表条目更新为指向新的 .maps section
     *
     * 修补后的文件可用 bpf_object__open_file() 打开，
     * 再通过 bpf_map__reuse_fd() 解析 map fd 后加载。
     *
     * @param input_path  含 extern 声明的源 .bpf.o 文件
     * @param output_path 修补后的 .bpf.o 文件输出路径
     * @param ext_vars    输出参数，已处理的 extern 变量元信息列表
     * @return 成功返回修补的 extern 变量数量，失败返回负 errno
     */
    int preprocess(const char *input_path, const char *output_path,
                   std::vector<ExternVarInfo> *ext_vars);

    const char *last_error() const { return m_last_error.c_str(); }

private:
    std::string m_last_error;

    int copy_file(const char *src, const char *dst);
    int count_extern_and_get_info(struct btf *btf,
                                  std::vector<ExternVarInfo> *ext_vars);
};

#endif
