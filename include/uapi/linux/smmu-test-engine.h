/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __UAPI_LINUX_SMMU_TEST_ENGINE_H
#define __UAPI_LINUX_SMMU_TEST_ENGINE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define SMMUTE_VERSION_MAJOR	0x0
#define SMMUTE_VERSION_MINOR	0x23

/*
 * We have 8 bits of ioctl numbers. Let's allocate ioctls 1-31 for transaction
 * modes, and put miscellaneous ioctls above.
 * Number 0 is reserved for version query.
 */
#define SMMUTE_IOCTL_TYPE	'~'
#define SMMUTE_IOCTL_BASE	0

#define SMMUTE_IOCTL_VERSION	_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 0)

/*
 * smmute_version - query smmute version.
 *
 * User sets the version it supports in the structure. If the driver doesn't
 * support this version, the ioctl fails. Otherwise, the driver sets the version
 * it supports in the structure, and returns success.
 */
struct smmute_version {
	__u16 major;
	__u16 minor;
	__u8 pad[12];
};

/**
 * smmute_common_params - parameters common to transaction ioctls
 *
 * Common inputs:
 * @input_start:	userspace address of the input region
 * @size:		size of the region
 * @attr:		memory attributes of the transaction (see SMMUTE_ATTR_*)
 * @stride:		see SMMUv3TestEngine.h
 * @seed:		see SMMUv3TestEngine.h
 * @flags		additional flags SMMUTE_FLAG_*
 * @pasid:		in some cases, for instance when talking to a userspace
 *			driver, user needs to specify its own PASID
 *
 * Outputs:
 * @transaction_id:	if the transaction was successfully launched, contains
 * 			its ID, that can be passed to SMMUTE_GET_RESULT.
 *
 * Returns 0 if the transaction was successfully launched.
 */
struct smmute_common_params
{
	__u64 input_start;
	__u64 size;
	__u32 attr;

	__u32 stride;
	__u32 seed;

	__u32 flags;
	__u32 pasid;

	__u8 pad0[4];

	__u64 transaction_id;

	__u8 pad1[16];
};

/* use Shared Virtual Addressing if available */
#define SMMUTE_FLAG_SVA		(1 << 0)
/* Inject access fault */
#define SMMUTE_FLAG_FAULT	(1 << 1)

#define SMMUTE_FLAG_MASK	(SMMUTE_FLAG_SVA | SMMUTE_FLAG_FAULT)

#define SMMUTE_IOCTL_MEMCPY	_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 1)

/**
 * smmute_memcpy_params - SMMUTE_MEMCPY
 *
 * Extra input parameters:
 * @output_start:	address of the output region, obtained with mmap
 */
struct smmute_memcpy_params
{
	struct smmute_common_params common;

	__u64 output_start;

	__u8 pad[24];
};

#define SMMUTE_IOCTL_RAND48	_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 2)

/**
 * smmute_rand_params - SMMUTE_RAND48
 */
struct smmute_rand_params
{
	struct smmute_common_params common;

	__u8 pad[32];
};

#define SMMUTE_IOCTL_SUM64	_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 3)

/**
 * smmute_sum_params - SMMUTE_SUM64
 */
struct smmute_sum_params
{
	struct smmute_common_params common;

	__u8 pad[32];
};

/**
 * smmute_p2p_params - SMMUTE_P2P
 *
 * Launch (fake) peer-to-peer transactions. For simplicity, we'll limit
 * ourselves to one engine writing to itself. All traffic still goes through
 * the SMMU, and actual peer-to-peer traffic would just complicate the driver
 * without any testing benefit.
 *
 * Driver allocates and initialises two transactions that we'll call A and B.
 * Frame A is initialised like a normal memcpy transaction, except that its
 * destination DMA region is the frame of transaction B (ie. PCIe config space
 * mapped through the SMMU).
 * Frame B is initialised similarity. Its source is a DRAM regions reserved
 * with mmap containing a command specified as argument, and its destination
 * is frame A.
 * Driver fills both source DRAM regions. It then launches transaction A; the
 * engine copies DRAM A into frame B, which launches transaction B; the engine
 * copies DRAM B into frame A, which launches transaction A'.
 *
 * For the moment, both primary (frame A) and secondary (frame B) arguments
 * must be:
 * - size	8
 * - stride	1
 * - src attr	Normal etc.
 * - dst attr	Dev-nGnRnE
 *
 * Extra params:
 * @secondary: second set of parameters
 * @command: command of transaction A' (one of the primary ioctls numbers
 *           defined in here). Unless you want the model to enter a glorious
 *           transaction loop, I advise to use SMMUTE_SUM or SMMUTE_RAND here.
 */
#define SMMUTE_IOCTL_P2P	_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 4)

struct smmute_p2p_params
{
	struct smmute_common_params primary;
	struct smmute_common_params secondary;

	__u32 command;

	__u8 pad[28];
};

union smmute_transaction_params
{
	struct smmute_common_params		common;
	struct smmute_memcpy_params		memcpy;
	struct smmute_sum_params		sum;
	struct smmute_rand_params		rand;
	struct smmute_p2p_params		p2p;
	__u8					pad[256];
};

#define SMMUTE_IOCTL_GET_RESULT	_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 32)

/**
 * smmute_transaction_result - SMMUTE_GET_RESULT, SMMUTE_GET_ALL
 *
 * Inputs:
 * @transaction_id:	a valid ID of the transaction to query
 * @blocking:		wait until transaction finished
 * @keep:		don't free transaction resources when it is finished
 *			(will be done when closing the fd)
 *
 * Outputs:
 * @status:		final status of the transaction
 * 			- 0		success
 * 			- EINVAL	frame misconfigured
 * 			- EIO		engine error
 * 			- EFAULT	unknown
 * @value:		for a SUM64 transaction, contains the resulting sum
 *			in case of a fault, contain the faulting address
 *
 * Returns 0 on success.
 * If `transaction_id` is invalid, errno is set to EINVAL.
 * If the transaction is not finished and `blocking` is 0, errno is set to
 * EAGAIN.
 */
struct smmute_transaction_result
{
	__u64 transaction_id;
	__u32 blocking;
	__u32 keep;

	__u8 pad0[16];
	/*
	 * Uses status numbering from errno.h:
	 * Notes:
	 * - if the ioctl parameters are wrong (e.g. transaction_id == 0) the
	 *   structure is not modified, but errno will be EINVAL;
	 * - if blocking is 0, errno will be EAGAIN
	 */
	__u64 value;
	__u32 status;

	__u8 pad1[20];
};

/**
 * Bind the current task, allowing to share the address space with the device
 */
#define SMMUTE_IOCTL_BIND_TASK		_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 33)
#define SMMUTE_IOCTL_UNBIND_TASK	_IO(SMMUTE_IOCTL_TYPE, SMMUTE_IOCTL_BASE + 34)

/* Use the AXI4 encoding for transactions, but the architectural naming */

#define SMMUTE_ACACHE_DEV_NGNRNE		0x0
/* Alone, this is nGnRE. G and R attributes can be set by ATTR[2:3]. */
#define SMMUTE_ACACHE_DEV_E			0x1
#define SMMUTE_ACACHE_NCNB			0x2
#define SMMUTE_ACACHE_NC			0x3
#define SMMUTE_ACACHE_RAWT			0x6
#define SMMUTE_ACACHE_RAWB			0x7
#define SMMUTE_ACACHE_WAWT			0xa
#define SMMUTE_ACACHE_WAWB			0xb
#define SMMUTE_ACACHE_RAWAWT			0xe
#define SMMUTE_ACACHE_RAWAWB			0xf

/* Shareability domain */
#define SMMUTE_ATTR_NON_SH			(0x0 << 14)
#define SMMUTE_ATTR_INNER_SH			(0x1 << 14)
#define SMMUTE_ATTR_OUTER_SH			(0x2 << 14)
#define SMMUTE_ATTR_OUTER_TRANSIENT		(1 << 13)
#define SMMUTE_ATTR_INNER_TRANSIENT		(1 << 12)
/* Instruction access instead of data */
#define SMMUTE_ATTR_INSN			(1 << 10)
/* Non-secure access */
#define SMMUTE_ATTR_NS				(1 << 9)
/* Privileged access */
#define SMMUTE_ATTR_PRIVILEGED			(1 << 8)
#define SMMUTE_ATTR_OUTER_CACHE(val)		(((val) & 0xf) << 4)
/* When outer CACHE attributes is dev: */
#define SMMUTE_ATTR_GATHERING			(1 << 3)
#define SMMUTE_ATTR_REORDER			(1 << 2)
/* Otherwise: */
#define SMMUTE_ATTR_INNER_CACHE(val)		(((val) & 0xf) << 0)

/* Common shortcuts */
#define SMMUTE_ATTR_DEVICE	(SMMUTE_ATTR_OUTER_CACHE(SMMUTE_ACACHE_DEV_E) | \
				 SMMUTE_ATTR_NS)

#define SMMUTE_ATTR_WBRAWA_SH	(SMMUTE_ATTR_OUTER_CACHE(SMMUTE_ACACHE_RAWAWB) | \
				 SMMUTE_ATTR_INNER_CACHE(SMMUTE_ACACHE_RAWAWB) | \
				 SMMUTE_ATTR_INNER_SH | \
				 SMMUTE_ATTR_NS)

#define SMMUTE_TRANSACTION_ATTR(src, dst)	((src) | (dst) << 16)

#endif /* __UAPI_LINUX_SMMU_TEST_ENGINE_H */
