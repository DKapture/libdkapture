#ifndef __BPF_KFUNCS__
#define __BPF_KFUNCS__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern int bpf_dynptr_from_skb(
	struct sk_buff *skb,
	__u64 flags,
	struct bpf_dynptr *ptr__uninit
) __ksym;

extern int bpf_dynptr_from_xdp(
	struct xdp_md *xdp,
	__u64 flags,
	struct bpf_dynptr *ptr__uninit
) __ksym;
extern void *bpf_dynptr_slice(
	const struct bpf_dynptr *ptr,
	__u32 offset,
	void *buffer,
	__u32 buffer__szk
) __ksym;

extern void *bpf_dynptr_slice_rdwr(
	const struct bpf_dynptr *ptr,
	__u32 offset,
	void *buffer,
	__u32 buffer__szk
) __ksym;

extern int
bpf_dynptr_adjust(const struct bpf_dynptr *ptr, __u32 start, __u32 end) __ksym;

extern bool bpf_dynptr_is_null(const struct bpf_dynptr *ptr) __ksym;
extern bool bpf_dynptr_is_rdonly(const struct bpf_dynptr *ptr) __ksym;
extern __u32 bpf_dynptr_size(const struct bpf_dynptr *ptr) __ksym;
extern int bpf_dynptr_clone(
	const struct bpf_dynptr *ptr,
	struct bpf_dynptr *clone__init
) __ksym;

#endif
