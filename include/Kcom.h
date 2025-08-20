/**
 * kernel space common header file.
 */
#ifndef __KCOM_H__
#define __KCOM_H__
#include "kconfig.h"

// read kernel memory to bpf memory
#define bpf_read_kmem(bpf_addr, kaddr)                                         \
	bpf_probe_read_kernel(bpf_addr, sizeof(*(bpf_addr)), kaddr)

#define bpf_read_kstr(bpf_addr, bsz, kaddr)                                    \
	bpf_probe_read_kernel_str(bpf_addr, bsz, kaddr)

#define bpf_read_umem(bpf_addr, uaddr)                                         \
	bpf_probe_read_user(bpf_addr, sizeof(*(bpf_addr)), uaddr)

#define bpf_read_ustr(bpf_addr, bsz, uaddr)                                    \
	bpf_probe_read_user_str(bpf_addr, bsz, uaddr)

#define bpf_dbg(fmt, args...)                                                  \
	bpf_printk("line:[%d] dbg: " fmt, __LINE__, ##args)

#define bpf_info(fmt, args...)                                                 \
	bpf_printk("line:[%d] info: " fmt, __LINE__, ##args)

#define bpf_warn(fmt, args...)                                                 \
	bpf_printk("line:[%d] warn: " fmt, __LINE__, ##args)

#define bpf_err(fmt, args...)                                                  \
	bpf_printk("line:[%d] err: " fmt, __LINE__, ##args)

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define NOP

// read kernel memory to bpf memory, return 'ret' while error
#define bpf_read_kmem_ret(bpf_addr, kaddr, ret)                                \
	do                                                                         \
	{                                                                          \
		int err = 0;                                                           \
		err = bpf_read_kmem(bpf_addr, kaddr);                                  \
		if (err < 0)                                                           \
		{                                                                      \
			bpf_err("bpf read kmem: %d", err);                                 \
			ret;                                                               \
		}                                                                      \
	} while (0)

#define bpf_read_kstr_ret(bpf_addr, bsz, kaddr, ret)                           \
	({                                                                         \
		long err = 0;                                                          \
		err = bpf_read_kstr(bpf_addr, bsz, kaddr);                             \
		if (err < 0)                                                           \
		{                                                                      \
			bpf_err("bpf read kstr: %d", err);                                 \
			err = 0;                                                           \
			ret;                                                               \
		}                                                                      \
		err;                                                                   \
	})

#define bpf_read_umem_ret(bpf_addr, uaddr, ret)                                \
	do                                                                         \
	{                                                                          \
		int err = 0;                                                           \
		err = bpf_read_umem(bpf_addr, uaddr);                                  \
		if (err < 0)                                                           \
		{                                                                      \
			bpf_err("bpf read umem: %d", err);                                 \
			ret;                                                               \
		}                                                                      \
	} while (0)

#define bpf_read_ustr_ret(bpf_addr, bsz, uaddr, ret)                           \
	({                                                                         \
		long err = 0;                                                          \
		err = bpf_read_ustr(bpf_addr, bsz, uaddr);                             \
		if (err < 0)                                                           \
		{                                                                      \
			bpf_err("bpf read ustr: %d", err);                                 \
			err = 0;                                                           \
			ret;                                                               \
		}                                                                      \
		err;                                                                   \
	})

#define swap(a, b)                                                             \
	do                                                                         \
	{                                                                          \
		if (sizeof(typeof(a)) != sizeof(typeof(b)))                            \
		{                                                                      \
			bpf_err("wrong usage for swap");                                   \
			while (1)                                                          \
			{                                                                  \
			}                                                                  \
		}                                                                      \
		struct __T__                                                           \
		{                                                                      \
			typeof(a) __data;                                                  \
		} __attribute__((__packed__));                                         \
		struct __T__ *__a = (struct __T__ *)&a;                                \
		struct __T__ *__b = (struct __T__ *)&b;                                \
		struct __T__ tmp = *__a;                                               \
		*__a = *__b;                                                           \
		*__b = tmp;                                                            \
	} while (0)

#define DEBUG(on, fmt, args...)                                                \
	do                                                                         \
	{                                                                          \
		if (on)                                                                \
		{                                                                      \
			bpf_dbg(fmt, ##args);                                              \
		}                                                                      \
	} while (0)

// debug process name start with "test"
#define filter_debug_proc(on, comm)                                            \
	do                                                                         \
	{                                                                          \
		if (on)                                                                \
		{                                                                      \
			long __ret;                                                        \
			char __comm[16];                                                   \
			__ret = bpf_get_current_comm(__comm, 16);                          \
			if (__ret)                                                         \
			{                                                                  \
				bpf_err("bpf_get_current_comm: %ld", __ret);                   \
			}                                                                  \
			if (bpf_strncmp(__comm, sizeof(comm) - 1, comm))                   \
				return 0;                                                      \
		}                                                                      \
	} while (0)

#define __user

#define task_stack_page(task) ((void *)(task)->stack)

#if defined(__x86_64__)

#define PAGE_SHIFT 12
#if defined(CONFIG_KASAN)
#define KASAN_STACK_ORDER 1
#else
#define KASAN_STACK_ORDER 0
#endif
#define THREAD_SIZE_ORDER (2 + KASAN_STACK_ORDER)
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

#define TOP_OF_KERNEL_STACK_PADDING 0
#define task_pt_regs(task)                                                     \
	({                                                                         \
		unsigned long __ptr = (unsigned long)task_stack_page(task);            \
		__ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;                    \
		((struct pt_regs *)__ptr) - 1;                                         \
	})

#define REG_SP(t) ((t)->thread.sp)
#define KSTK_EIP(task) BPF_CORE_READ(task_pt_regs(task), ip)

#elif defined(__aarch64__)

#define PAGE_SHIFT CONFIG_ARM64_PAGE_SHIFT
#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
#define KASAN_THREAD_SHIFT 1
#else
#define KASAN_THREAD_SHIFT 0
#endif

#define MIN_THREAD_SHIFT (14 + KASAN_THREAD_SHIFT)
#if defined(CONFIG_VMAP_STACK) && (MIN_THREAD_SHIFT < PAGE_SHIFT)
#define THREAD_SHIFT PAGE_SHIFT
#else
#define THREAD_SHIFT MIN_THREAD_SHIFT
#endif
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define THREAD_SIZE (1UL << THREAD_SHIFT)

#define task_pt_regs(p)                                                        \
	((struct pt_regs *)(THREAD_SIZE + task_stack_page(p)) - 1)
#define REG_SP(t) ((t)->thread.cpu_context.sp)
#define KSTK_EIP(tsk) BPF_CORE_READ(task_pt_regs(tsk), pc)

#elif defined(__loongarch__)

#ifdef CONFIG_PAGE_SIZE_4KB
#define PAGE_SHIFT 12
#endif
#ifdef CONFIG_PAGE_SIZE_16KB
#define PAGE_SHIFT 14
#endif
#ifdef CONFIG_PAGE_SIZE_64KB
#define PAGE_SHIFT 16
#endif

#define PAGE_SIZE (1 << PAGE_SHIFT)
#define THREAD_SIZE 0x00004000

#define __KSTK_TOS(tsk)                                                        \
	((unsigned long)task_stack_page(tsk) + THREAD_SIZE - sizeof(struct pt_regs))
#define task_pt_regs(tsk) ((struct pt_regs *)__KSTK_TOS(tsk))

#define REG_SP(t) ((t)->thread.reg03)
#define KSTK_EIP(tsk) BPF_CORE_READ(task_pt_regs(tsk), csr_era)

#elif defined(__sw64__)

#define PAGE_SHIFT 13
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define THREAD_SIZE (2 * PAGE_SIZE)

#define task_pt_regs(task) ((struct pt_regs *)(task->stack + THREAD_SIZE) - 1)
#define REG_SP(t) ((t)->thread.sp)
#define KSTK_EIP(tsk) BPF_CORE_READ(task_pt_regs(tsk), pc)

#else

#error "support only arch list: x86_64, aarch64, loongarch, sw64"

#endif

#ifdef CONFIG_THREAD_INFO_IN_TASK
#define CURRENT_CPU(t) (t->thread_info.cpu)
#else
#define CURRENT_CPU(t) (t->recent_used_cpu)
#endif

#endif