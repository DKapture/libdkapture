#ifndef __URBLAT_H__
#define __URBLAT_H__

#define min(x, y)                                                              \
	({                                                                         \
		typeof(x) _min1 = (x);                                                 \
		typeof(y) _min2 = (y);                                                 \
		(void)(&_min1 == &_min2);                                              \
		_min1 < _min2 ? _min1 : _min2;                                         \
	})

#define DISK_NAME_LEN 32
#define MAX_SLOTS 27

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

struct hist_key
{
	__u32 cmd_flags;
	__u32 dev;
};

struct hist
{
	__u32 slots[MAX_SLOTS];
};

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = val)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static __always_inline __u64 log2(__u32 v)
{
	__u32 shift, r;

	r = (v > 0xFFFF) << 4;
	v >>= r;
	shift = (v > 0xFF) << 3;
	v >>= shift;
	r |= shift;
	shift = (v > 0xF) << 2;
	v >>= shift;
	r |= shift;
	shift = (v > 0x3) << 1;
	v >>= shift;
	r |= shift;
	r |= (v >> 1);

	return r;
}

static __always_inline __u64 log2l(__u64 v)
{
	__u32 hi = v >> 32;

	if (hi)
	{
		return log2(hi) + 32;
	}
	else
	{
		return log2(v);
	}
}
#pragma GCC diagnostic pop

struct partition
{
	char *name;
	unsigned int dev;
};

#endif
