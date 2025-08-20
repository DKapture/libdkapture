/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BLK_TYPES_H
#define __BLK_TYPES_H

/* From include/linux/blk_types.h */
#define __force

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

#define PAGE_SECTORS_SHIFT (PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS (1 << PAGE_SECTORS_SHIFT)
#define SECTOR_MASK (PAGE_SECTORS - 1)

#define BLK_STS_OK 0
#define BLK_STS_NOTSUPP ((__force blk_status_t)1)
#define BLK_STS_TIMEOUT ((__force blk_status_t)2)
#define BLK_STS_NOSPC ((__force blk_status_t)3)
#define BLK_STS_TRANSPORT ((__force blk_status_t)4)
#define BLK_STS_TARGET ((__force blk_status_t)5)
#define BLK_STS_RESV_CONFLICT ((__force blk_status_t)6)
#define BLK_STS_MEDIUM ((__force blk_status_t)7)
#define BLK_STS_PROTECTION ((__force blk_status_t)8)
#define BLK_STS_RESOURCE ((__force blk_status_t)9)
#define BLK_STS_IOERR ((__force blk_status_t)10)

/* hack for device mapper, don't use elsewhere: */
#define BLK_STS_DM_REQUEUE ((__force blk_status_t)11)
#define BLK_STS_AGAIN ((__force blk_status_t)12)
#define BLK_STS_DEV_RESOURCE ((__force blk_status_t)13)
#define BLK_STS_ZONE_RESOURCE ((__force blk_status_t)14)
#define BLK_STS_ZONE_OPEN_RESOURCE ((__force blk_status_t)15)
#define BLK_STS_ZONE_ACTIVE_RESOURCE ((__force blk_status_t)16)
#define BLK_STS_OFFLINE ((__force blk_status_t)17)
#define BLK_STS_DURATION_LIMIT ((__force blk_status_t)18)

#define BIO_ISSUE_RES_BITS 1
#define BIO_ISSUE_SIZE_BITS 12
#define BIO_ISSUE_RES_SHIFT (64 - BIO_ISSUE_RES_BITS)
#define BIO_ISSUE_SIZE_SHIFT (BIO_ISSUE_RES_SHIFT - BIO_ISSUE_SIZE_BITS)
#define BIO_ISSUE_TIME_MASK ((1ULL << BIO_ISSUE_SIZE_SHIFT) - 1)
#define BIO_ISSUE_SIZE_MASK                                                    \
	(((1ULL << BIO_ISSUE_SIZE_BITS) - 1) << BIO_ISSUE_SIZE_SHIFT)
#define BIO_ISSUE_RES_MASK (~((1ULL << BIO_ISSUE_RES_SHIFT) - 1))

/* Reserved bit for blk-throtl */
#define BIO_ISSUE_THROTL_SKIP_LATENCY (1ULL << 63)

#define BLK_QC_T_NONE -1U
#define BIO_RESET_BYTES offsetof(struct bio, bi_max_vecs)
#define BIO_MAX_SECTORS (UINT_MAX >> SECTOR_SHIFT)

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)
#define REQ_FLAG_BITS 24

#ifndef __VMLINUX_H__
enum req_opf
{
	/* read sectors from the device */
	REQ_OP_READ = 0,
	/* write sectors to the device */
	REQ_OP_WRITE = 1,
	/* flush the volatile write cache */
	REQ_OP_FLUSH = 2,
	/* discard sectors */
	REQ_OP_DISCARD = 3,
	/* securely erase sectors */
	REQ_OP_SECURE_ERASE = 5,
	/* reset a zone write pointer */
	REQ_OP_ZONE_RESET = 6,
	/* write the same sector many times */
	REQ_OP_WRITE_SAME = 7,
	/* reset all the zone present on the device */
	REQ_OP_ZONE_RESET_ALL = 8,
	/* write the zero filled sector many times */
	REQ_OP_WRITE_ZEROES = 9,
	/* Open a zone */
	REQ_OP_ZONE_OPEN = 10,
	/* Close a zone */
	REQ_OP_ZONE_CLOSE = 11,
	/* Transition a zone to full */
	REQ_OP_ZONE_FINISH = 12,

	/* SCSI passthrough using struct scsi_request */
	REQ_OP_SCSI_IN = 32,
	REQ_OP_SCSI_OUT = 33,
	/* Driver private requests */
	REQ_OP_DRV_IN = 34,
	REQ_OP_DRV_OUT = 35,

	REQ_OP_LAST,
};

enum req_flag_bits
{
	__REQ_FAILFAST_DEV = /* no driver retries of device errors */
		REQ_OP_BITS,
	__REQ_FAILFAST_TRANSPORT, /* no driver retries of transport errors */
	__REQ_FAILFAST_DRIVER,	  /* no driver retries of driver errors */
	__REQ_SYNC,				  /* request is sync (sync write or read) */
	__REQ_META,				  /* metadata io request */
	__REQ_PRIO,				  /* boost priority in cfq */
	__REQ_NOMERGE,			  /* don't touch this for merging */
	__REQ_IDLE,				  /* anticipate more IO after this one */
	__REQ_INTEGRITY,		  /* I/O includes block integrity payload */
	__REQ_FUA,				  /* forced unit access */
	__REQ_PREFLUSH,			  /* request for cache flush */
	__REQ_RAHEAD,			  /* read ahead, can fail anytime */
	__REQ_BACKGROUND,		  /* background IO */
	__REQ_NOWAIT,			  /* Don't wait if request will block */
	__REQ_NOWAIT_INLINE,	  /* Return would-block error inline */
	/*
	 * When a shared kthread needs to issue a bio for a cgroup, doing
	 * so synchronously can lead to priority inversions as the kthread
	 * can be trapped waiting for that cgroup.  CGROUP_PUNT flag makes
	 * submit_bio() punt the actual issuing to a dedicated per-blkcg
	 * work item to avoid such priority inversions.
	 */
	__REQ_CGROUP_PUNT,

	/* command specific flags for REQ_OP_WRITE_ZEROES: */
	__REQ_NOUNMAP, /* do not free blocks when zeroing */

	__REQ_HIPRI,

	/* for driver use */
	__REQ_DRV,
	__REQ_SWAP,	   /* swapping request. */
	__REQ_NR_BITS, /* stops here */
};
#endif

#define REQ_FAILFAST_DEV (1ULL << __REQ_FAILFAST_DEV)
#define REQ_FAILFAST_TRANSPORT (1ULL << __REQ_FAILFAST_TRANSPORT)
#define REQ_FAILFAST_DRIVER (1ULL << __REQ_FAILFAST_DRIVER)
#define REQ_SYNC (1ULL << __REQ_SYNC)
#define REQ_META (1ULL << __REQ_META)
#define REQ_PRIO (1ULL << __REQ_PRIO)
#define REQ_NOMERGE (1ULL << __REQ_NOMERGE)
#define REQ_IDLE (1ULL << __REQ_IDLE)
#define REQ_INTEGRITY (1ULL << __REQ_INTEGRITY)
#define REQ_FUA (1ULL << __REQ_FUA)
#define REQ_PREFLUSH (1ULL << __REQ_PREFLUSH)
#define REQ_RAHEAD (1ULL << __REQ_RAHEAD)
#define REQ_BACKGROUND (1ULL << __REQ_BACKGROUND)
#define REQ_NOWAIT (1ULL << __REQ_NOWAIT)
#define REQ_NOWAIT_INLINE (1ULL << __REQ_NOWAIT_INLINE)
#define REQ_CGROUP_PUNT (1ULL << __REQ_CGROUP_PUNT)

#define REQ_NOUNMAP (1ULL << __REQ_NOUNMAP)
#define REQ_HIPRI (1ULL << __REQ_HIPRI)

#define REQ_DRV (1ULL << __REQ_DRV)
#define REQ_SWAP (1ULL << __REQ_SWAP)

#define REQ_FAILFAST_MASK                                                      \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)

#define REQ_NOMERGE_FLAGS (REQ_NOMERGE | REQ_PREFLUSH | REQ_FUA)

#endif /* __BLK_TYPES_H */
