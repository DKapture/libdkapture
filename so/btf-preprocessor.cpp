// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "btf-preprocessor.h"

#define SHN_UNDEF 0       // ELF 符号未定义（extern）
#define STB_GLOBAL 1      // ELF 符号全局绑定
#define STT_NOTYPE 0      // ELF 符号无类型
#define STT_OBJECT 1      // ELF 符号是数据对象
#ifndef ELF64_ST_INFO
#define ELF64_ST_INFO(b, t) (((b) << 4) + ((t) & 0xF))  // 组装绑定+类型
#endif

// 用 btf__parse_elf 直接解析 ELF 中的 BTF
int BtfPreprocessor::check_extern_maps(
    const char *bpf_obj_path, 
    std::vector<ExternMapInfo> *ext_info)
{
    struct btf *btf = btf__parse_elf(bpf_obj_path, NULL);
    
    if (!btf) { 
        m_last_error = "failed to parse BTF"; 
        return -EINVAL; 
    }

    auto add = [&](int vid, int tid, const char *n, const char *tn) {
         ExternMapInfo e; 
         e.name=n; 
         e.btf_var_id=vid;
         e.btf_type_id=tid; 
         e.type_name=tn?tn:""; 
         ext_info->push_back(e);
    };

    // 优先查 .maps DATASEC 中的 extern 变量
    int sid = btf__find_by_name_kind(btf, ".maps", BTF_KIND_DATASEC);
    if (sid >= 0) {
        const struct btf_type *sec = btf__type_by_id(btf, sid);
        const struct btf_var_secinfo *inf = btf_var_secinfos(sec);
        for (int i = 0; i < btf_vlen(sec); i++) {
            const struct btf_type *v = btf__type_by_id(btf, inf[i].type);
            if (!v||!btf_is_var(v)) continue;
            if (btf_var(v)->linkage!=BTF_VAR_GLOBAL_EXTERN) continue;
            const char *n = btf__name_by_offset(btf, v->name_off); if(!n) continue;
            const char *tn=""; auto p=btf__type_by_id(btf,v->type); if(p) tn=btf__name_by_offset(btf,p->name_off)?:"";
            add(inf[i].type, v->type, n, tn);
        }
    } else {
        // 无 .maps DATASEC：扫描所有 extern struct 类型变量
        int nt = btf__type_cnt(btf);
        for (int t = 1; t < nt; t++) {
            const struct btf_type *x = btf__type_by_id(btf, t);
            if (!x||!btf_is_var(x)) continue;
            if (btf_var(x)->linkage!=BTF_VAR_GLOBAL_EXTERN) continue;
            const char *n = btf__name_by_offset(btf, x->name_off); if(!n||!n[0]) continue;
            auto val = btf__type_by_id(btf, x->type); if(!val||!btf_is_composite(val)) continue;
            add(t, x->type, n, btf__name_by_offset(btf,val->name_off));
        }
    }
    btf__free(btf); return 0;
}

// 完整的 ELF 手术：
// 1. BTF linkage EXTERN → ALLOCATED + 添加 .maps DATASEC
// 2. 拷贝输入文件到输出
// 3. libelf 打开输出 → 创建 .maps section + 修复符号表 + 替换 BTF 数据
int BtfPreprocessor::preprocess(
    const char *input_path, const char *output_path,
    std::vector<ExternVarInfo> *ext_vars)
{
    // ── 第 1 步：BTF 预处理 ─────────────────────────────────

    // 解析 BTF，记录 extern map 信息
    struct btf *btf = btf__parse_elf(input_path, NULL);
    if (!btf) { m_last_error = "failed to parse BTF"; return -EINVAL; }
    std::vector<ExternVarInfo> lv;
    int e = count_extern_and_get_info(btf, &lv);
    if (e) { btf__free(btf); return e; }
    if (lv.empty()) { btf__free(btf); return copy_file(input_path, output_path); }

    // 将 linkage 从 GLOBAL_EXTERN 改为 GLOBAL_ALLOCATED
    // 注意：btf__type_by_id 返回 const，但 libbpf 未提供修改 linkage 的公开 API，
    // 此处修改后立即通过 btf__raw_data 取出再 btf__free，不会与 libbpf 内部操作冲突
    for (auto &v : lv) {
        auto t = btf__type_by_id(btf, v.var_btf_id);
        if (t) {
            btf_var((struct btf_type *)t)->linkage = BTF_VAR_GLOBAL_ALLOCATED;
        }
    }

    // 提取修改后的裸 BTF 数据（linkage 已改，offset 修正由 BpfLinker 在运行时处理）
    const void *rb;
    __u32 rsz;
    rb = btf__raw_data(btf, &rsz);
    if (!rb||!rsz) { btf__free(btf); m_last_error="btf__raw_data failed"; return -EINVAL; }
    void *bc = malloc(rsz); if (!bc) { btf__free(btf); return -ENOMEM; }
    memcpy(bc, rb, rsz);
    btf__free(btf);

    // ── 第 2 步：拷贝文件 + libelf 打开 ─────────────────────

    e = copy_file(input_path, output_path);
    if (e) { free(bc); return e; }
    int fd = open(output_path, O_RDWR);
    if (fd < 0) { free(bc); return -errno; }
    elf_version(EV_CURRENT);
    Elf *elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (!elf) { close(fd); free(bc); m_last_error="elf_begin failed"; return -EINVAL; }

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        elf_end(elf); close(fd); free(bc);
        m_last_error="elf_getshdrstrndx failed"; return -EINVAL;
    }

    // ── 第 3 步：定位 .BTF 和 .symtab section ──────────────

    Elf_Scn *btf_scn=nullptr, *symtab_scn=nullptr;
    int symtab_link = 0;
    Elf_Scn *scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr sh; gelf_getshdr(scn, &sh);
        const char *n = elf_strptr(elf, shstrndx, sh.sh_name);
        if (!n) continue;
        if (strcmp(n,".BTF")==0) btf_scn=scn;
        if (strcmp(n,".symtab")==0) { symtab_scn=scn; symtab_link=sh.sh_link; }
    }
    if (!btf_scn||!symtab_scn) {
        elf_end(elf); close(fd); free(bc);
        m_last_error=".BTF or .symtab not found"; return -ENOENT;
    }

    // ── 第 4 步：查找或创建 .maps ELF section ────────────────

    // 计算 extern 转换后需要的数据大小
    size_t extern_sz = 0;
    for (auto &v : lv) {
        v.offset = extern_sz;
        extern_sz += (v.struct_size < 16) ? 16 : v.struct_size;
    }
    if (extern_sz == 0) extern_sz = 16;

    // 查找已有 .maps section（BPF 代码中同时有定义 + extern 时存在）
    Elf_Scn *maps_scn = nullptr;
    size_t maps_existing_sz = 0;
    bool has_existing_maps = false;
    Elf_Scn *s = nullptr;
    while ((s = elf_nextscn(elf, s)) != nullptr) {
        GElf_Shdr sh; gelf_getshdr(s, &sh);
        const char *n = elf_strptr(elf, shstrndx, sh.sh_name);
        if (n && strcmp(n, ".maps") == 0) {
            maps_scn = s;
            maps_existing_sz = sh.sh_size;
            has_existing_maps = true;
            break;
        }
    }

    if (!maps_scn) {
        // 无已有 .maps section → 新建
        maps_scn = elf_newscn(elf);
        if (!maps_scn) { elf_end(elf); close(fd); free(bc); m_last_error="elf_newscn failed"; return -EINVAL; }

        // 将 ".maps" 名称注册到 section header string table
        size_t maps_name_off = 0;
        Elf_Scn *shstrtab_scn = elf_getscn(elf, shstrndx);
        if (shstrtab_scn) {
            Elf_Data *sd = elf_getdata(shstrtab_scn, nullptr);
            if (sd && sd->d_buf) {
                const char *needle = ".maps";
                size_t slen = strlen(needle) + 1;
                const char *p = (const char *)sd->d_buf;
                int found = 0;
                if (sd->d_size >= slen) {
                    for (size_t i = 0; i < sd->d_size - slen; i++) {
                        if (memcmp(p + i, needle, slen) == 0) {
                            maps_name_off = i; found = 1; break;
                        }
                    }
                }
                if (!found) {
                    void *nb = realloc(sd->d_buf, sd->d_size + slen);
                    if (!nb) { elf_end(elf); close(fd); free(bc); return -ENOMEM; }
                    memcpy((char *)nb + sd->d_size, needle, slen);
                    maps_name_off = sd->d_size;
                    sd->d_buf = nb;
                    sd->d_size += slen;
                    GElf_Shdr ssh; gelf_getshdr(shstrtab_scn, &ssh);
                    ssh.sh_size = sd->d_size;
                    gelf_update_shdr(shstrtab_scn, &ssh);
                }
            }
        }

        GElf_Shdr msh; memset(&msh, 0, sizeof(msh));
        msh.sh_name = maps_name_off;
        msh.sh_type = SHT_PROGBITS;
        msh.sh_flags = SHF_WRITE | SHF_ALLOC;
        msh.sh_size = extern_sz;
        msh.sh_addralign = 4;
        gelf_update_shdr(maps_scn, &msh);
    } else {
        // 已有 .maps section → 扩展现有数据 buffer，末尾追加零填充
        // 取出已有的数据描述符，将 d_buf 重新分配为更大尺寸
        Elf_Data *existing = elf_getdata(maps_scn, nullptr);  /* <libelf.h> */
        if (!existing) {
            elf_end(elf); close(fd); free(bc);
            m_last_error = "elf_getdata(.maps) returned NULL"; return -EINVAL;
        }
        // 旧 d_buf 由 libelf 管理，直接 realloc 扩展
        void *new_buf = realloc(existing->d_buf, maps_existing_sz + extern_sz);  /* <stdlib.h> */
        if (!new_buf) {
            elf_end(elf); close(fd); free(bc);
            m_last_error = "realloc for .maps append failed"; return -ENOMEM;
        }
        // 追加的 extern 区域初始化为零
        memset((char *)new_buf + maps_existing_sz, 0, extern_sz);  /* <string.h> */
        existing->d_buf = new_buf;
        existing->d_size = maps_existing_sz + extern_sz;
        elf_flagdata(existing, ELF_C_SET, ELF_F_DIRTY);  /* <libelf.h> */

        GElf_Shdr msh; gelf_getshdr(maps_scn, &msh);
        msh.sh_size = maps_existing_sz + extern_sz;
        gelf_update_shdr(maps_scn, &msh);  /* <gelf.h> */
    }

    // 新建分支：写入零填充的 extern map 数据（已有分支已在上方处理）
    if (!has_existing_maps) {
        Elf_Data *md = elf_newdata(maps_scn);  /* <libelf.h> */
        if (md) {
            md->d_buf = calloc(1, extern_sz);  /* <stdlib.h> */
            md->d_size = extern_sz;
            md->d_type = ELF_T_BYTE;
            md->d_version = EV_CURRENT;  /* <libelf.h> */
        }
    }

    size_t maps_shndx = elf_ndxscn(maps_scn);

    // ── 第 5 步：修复符号表 ──────────────────────────────────
    // 将 SHN_UNDEF 的 extern 符号改为指向新建的 .maps section

    Elf_Data *symd = elf_getdata(symtab_scn, nullptr);
    if (symd && symd->d_buf && symd->d_size > 0) {
        int nsym = symd->d_size / sizeof(Elf64_Sym);
        Elf64_Sym *syms = (Elf64_Sym *)symd->d_buf;
        for (int i = 0; i < nsym; i++) {
            if (syms[i].st_shndx != SHN_UNDEF) continue;
            const char *sn = elf_strptr(elf, symtab_link, syms[i].st_name);
            if (!sn) continue;
            for (auto &v : lv) {
                if (strcmp(sn, v.name.c_str()) == 0) {
                    // 从 STT_NOTYPE 改为 STT_OBJECT，从 SHN_UNDEF 改为 .maps
                    syms[i].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
                    syms[i].st_shndx = maps_shndx;
                    syms[i].st_value = v.offset;
                    syms[i].st_size = v.struct_size;
                    fprintf(stdout, "  [prep] '%s' -> .maps[%zu] size=%d\n",
                            sn, maps_shndx, v.struct_size);
                    break;
                }
            }
        }
    }

    // ── 第 6 步：替换 .BTF section 数据 ──────────────────────
    // 将修改后的 BTF 写回 ELF
    //
    // elf_getdata 返回的 Elf_Data 中 d_buf 由 libelf 管理，
    // 不能 free/realloc；必须用 elf_rawdata 或 elf_resizesection 调整大小。
    // 当新 BTF 比旧 BTF 大时，用 elf_resize 扩展 .BTF section，
    // 然后重新取 data 描述符再写入。

    Elf_Data *bd = elf_getdata(btf_scn, nullptr);
    if (!bd) {
        elf_end(elf); close(fd); free(bc);
        m_last_error = "elf_getdata(.BTF) returned NULL"; return -EINVAL;
    }
    if (bd->d_size >= rsz) {
        // 新 BTF 不超过旧 buffer，直接覆盖
        memcpy(bd->d_buf, bc, rsz);
        bd->d_size = rsz;
        elf_flagdata(bd, ELF_C_SET, ELF_F_DIRTY);
    } else {
        // 新 BTF 超出旧 buffer 大小
        // libelf 没有跨版本通用的 section resize API，
        // 直接替换 d_buf 为新分配的 buffer，elf_end 时由 libelf 释放。
        // 旧 bd->d_buf 的内存由 libelf 管理，替换后泄漏（一次性的构建工具可接受）。
        void *new_buf = malloc(rsz);  /* <stdlib.h> */
        if (!new_buf) {
            elf_end(elf); close(fd); free(bc);
            m_last_error = "malloc failed for BTF resize"; return -ENOMEM;
        }
        memcpy(new_buf, bc, rsz);  /* <string.h> */
        bd->d_buf = new_buf;
        bd->d_size = rsz;
        elf_flagdata(bd, ELF_C_SET, ELF_F_DIRTY);  /* <libelf.h> */
    }
    GElf_Shdr bsh; gelf_getshdr(btf_scn, &bsh);
    bsh.sh_size = rsz;
    gelf_update_shdr(btf_scn, &bsh);

    // ── 第 7 步：写入磁盘 ────────────────────────────────────

    if (elf_update(elf, ELF_C_WRITE) < 0) {
        elf_end(elf); close(fd); free(bc);
        m_last_error = "elf_update failed"; return -EINVAL;
    }
    elf_end(elf); close(fd); free(bc);

    int n = lv.size();
    if (ext_vars) *ext_vars = std::move(lv);
    fprintf(stdout, "  [prep] %d extern map(s) converted\n", n);
    return n;
}

// 从 BTF 中收集 extern map 变量信息：名称、类型 ID、struct 大小
int BtfPreprocessor::count_extern_and_get_info(
    struct btf *btf, std::vector<ExternVarInfo> *ev)
{
    auto add = [&](int vid, int sid, int sz, const char *n) {
        ExternVarInfo x;
        x.name = n ? n : "";
        x.var_btf_id = vid; 
        x.struct_btf_id = sid;
        x.struct_size = sz; 
        x.offset = 0; 
        x.map_type = 0; 
        x.key_size = 0; 
        x.value_size = 0; 
        x.max_entries = 0;
        ev->push_back(x);
    };
    // 先查 .maps DATASEC，再退化为扫描所有 extern struct 变量
    int sec = btf__find_by_name_kind(btf, ".maps", BTF_KIND_DATASEC);
    if (sec >= 0) {
        const struct btf_type *s = btf__type_by_id(btf, sec);
        const struct btf_var_secinfo *inf = btf_var_secinfos(s);
        for (int i = 0; i < btf_vlen(s); i++) {
            const struct btf_type *v = btf__type_by_id(btf, inf[i].type);
            if (!v||!btf_is_var(v)) continue;
            if (btf_var(v)->linkage!=BTF_VAR_GLOBAL_EXTERN) continue;
            const char *n = btf__name_by_offset(btf, v->name_off); if(!n) continue;
            auto st = btf__type_by_id(btf, v->type);
            add(inf[i].type, v->type, st ? st->size : 0, n);
        }
    } else {
        int nt = btf__type_cnt(btf);
        for (int t = 1; t < nt; t++) {
            const struct btf_type *x = btf__type_by_id(btf, t);
            if (!x||!btf_is_var(x)) continue;
            if (btf_var(x)->linkage!=BTF_VAR_GLOBAL_EXTERN) continue;
            const char *n = btf__name_by_offset(btf, x->name_off); if(!n||!n[0]) continue;
            auto val = btf__type_by_id(btf, x->type); if(!val||!btf_is_composite(val)) continue;
            add(t, x->type, val->size, n);
        }
    }
    for (auto &x : *ev) fprintf(stdout, "  [prep] extern '%s' size=%d\n", x.name.c_str(), x.struct_size);
    return 0;
}

// 普通文件拷贝，用于生成输出文件副本
int BtfPreprocessor::copy_file(const char *src, const char *dst)
{
    int fi = open(src, O_RDONLY); if (fi<0) return -errno;
    struct stat st; if (fstat(fi, &st)!=0) { close(fi); return -errno; }
    int fo = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0644); if (fo<0) { close(fi); return -errno; }
    char buf[65536]; ssize_t n;
    while ((n = read(fi, buf, sizeof(buf))) > 0) { ssize_t w = write(fo, buf, n); if (w!=n) { close(fi); close(fo); return -EIO; } }
    close(fi); close(fo); return 0;
}
