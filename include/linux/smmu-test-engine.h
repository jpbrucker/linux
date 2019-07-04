/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SMMU_TEST_ENGINE_H
#define __LINUX_SMMU_TEST_ENGINE_H

#include <uapi/linux/smmu-test-engine.h>

#define DRV_NAME		"smmu-te"
#define VENDOR_ID		0x13b5
#define DEVICE_ID		0xff80

#define SMMUTE_FIRST_MINOR	0
#define SMMUTE_MAX_DEVICES	8
/*
 * Delay between transaction checks, in jiffies. Since this is a safety net
 * (transaction results are notified by MSIs), we can set a somewhat long
 * timeout.
 */
#define SMMUTE_POLL_DELAY	msecs_to_jiffies(500)

/* 128 bytes */
struct smmute_uframe
{
	uint32_t     cmd;

#define SMMUTE_UCTRL_MSI_ABORTED	(1 << 0)
#define SMMUTE_UCTRL_RATE(r)		(((r) & 0xffff) << 16)
	uint32_t     uctrl;

	uint32_t     count_of_transactions_launched;
	uint32_t     count_of_transactions_returned;

	uint64_t     msiaddress; /* actually 'msienable' (0 or 1) */

	uint32_t     msidata; /* MSI-X vector */
	uint32_t     msiattr; /* ignored */

	/* The software model can use any kind of transaction attribute.
	 * In hardware, this would be restricted by PCIe. */
	uint32_t     attributes;
	uint32_t     seed;

	uint64_t     begin;
	uint64_t     end_incl;

	uint64_t     stride;

	uint64_t     udata[8];
};

/* 128 bytes */
struct smmute_pframe
{
#define SMMUTE_PCTRL_NS		(1 << 0)
#define SMMUTE_PCTRL_ATS_EN	(1 << 8)
#define SMMUTE_PCTRL_PRI_EN	(1 << 9)
	uint32_t		pctrl;
	uint32_t     		downstream_port_index; /* ignored (0) */

	uint32_t		streamid; /* ignored (RID) */
#define SMMUTE_NO_SUBSTREAMID	(~0u)
#define SMMUTE_SUBSTREAMID(s)	((s) & 0xfffff)
	uint32_t     		substreamid;

	uint64_t		pdata[14];
};

#define SMMUTE_FRAMES_PER_PAGE	(64 * 1024 / sizeof(struct smmute_uframe))

/* This is a pair of 64kB pages (so 128kB in total) */
struct smmute_page_pair
{
	struct smmute_uframe	user[SMMUTE_FRAMES_PER_PAGE];
	struct smmute_pframe	privileged[SMMUTE_FRAMES_PER_PAGE];
};

/* Find pair corresponding to the global frame index */
#define _smmute_pair(pair, idx)						\
	((struct smmute_page_pair *)(pair) + (idx) / SMMUTE_FRAMES_PER_PAGE)

/*
 * Get the address of a "struct smmute_u/pframe" defined by its global frame
 * index. Here, 'pair' is a pointer to a struct smmute_page_pair.
 */
#define smmute_user_frame(pair, idx)					\
	((struct smmute_uframe *)&_smmute_pair(pair, idx)->user		\
	 + (idx) % SMMUTE_FRAMES_PER_PAGE)

#define smmute_privileged_frame(pair, idx)				\
	((struct smmute_pframe *)&_smmute_pair(pair, idx)->privileged	\
	 + (idx) % SMMUTE_FRAMES_PER_PAGE)

enum smmute_cmd
{
    /* invalid arguments */
    ENGINE_FRAME_MISCONFIGURED = ~0u - 1,

    /* transaction aborted */
    ENGINE_ERROR  = ~0u,

    /* unimplemented frame, or secure-only */
    ENGINE_NO_FRAME = 0,

    /* idle state */
    ENGINE_HALTED = 1,

    /*
     * Commands
     */
    ENGINE_MEMCPY = 2,
    ENGINE_RAND48 = 3,
    ENGINE_SUM64 = 4
};

struct smmute_msi_info {
	unsigned long			vector;
	u64				doorbell;
	u32				data;
};

struct smmute_msi_pool {
	spinlock_t			lock;
	struct list_head		transactions;
};

struct smmute_device {
	/*
	 * Pairs of 64kB pages, each containing 512 user frames in the first
	 * page, and 512 privileged frames in the second one.
	 */
	struct smmute_page_pair		*pairs;
	size_t				nr_pairs;

	struct device			*dev;

	/* character device interfacing this smmute with userspace */
	struct device			*chrdev;
	unsigned int			minor;

	/* MSI info, depending on dev_is_pci(dev) */
	union {
		struct msix_entry	*msix_entries;
		struct smmute_msi_info	*plat_msi_entries;
	};

	size_t				nr_msix_entries;

	struct smmute_msi_pool		*msi_pools;
	unsigned int			current_pool;

	struct kmem_cache		*dma_regions_cache;
	struct kmem_cache		*transaction_cache;
	struct kmem_cache		*file_desc_cache;

	/* bitmap of the frames currently reserved by transactions */
	unsigned long			*reserved_frames;
	/* Common lock for frames and MSIs */
	struct mutex			resources_mutex;

	/* Collections of transactions. Currently represented by file
	 * descriptors, but can easily be generalized in the future to abstract
	 * collections and index them with unique IDs. */
	struct kset			*files_set;
	atomic64_t			files_ida;

	struct kset			*tasks_set;
	struct list_head		tasks;
	struct mutex			task_mutex;

	/* index into smmute_devices */
	struct list_head		list;

	bool				dev_feat[3];
};

/*
 * struct smmute_dma - Keep track of all the memory and mappings flying around
 */
struct smmute_dma {
	u64				id;
	struct smmute_device		*smmute;

	/* For mmap */
	struct mm_struct		*mm;
	void				*kaddr;
	void				*uaddr;
	struct list_head		list;

	dma_addr_t			iova;
	size_t				size;
	bool				is_msi;

	struct smmute_task		*task;
	struct smmute_file_desc		*fd;
	struct kobject			kobj;
};

struct smmute_task {
	struct kobject			kobj;
	struct smmute_device		*smmute;
	struct list_head		smmute_head;
	struct iommu_sva		*handle;
	struct pid			*pid;
	u32				ssid;

	struct list_head		msi_mappings;
	spinlock_t			msi_mappings_lock;
};

struct smmute_task_fd {
	struct list_head		list;
	struct smmute_task		*task;
};

enum smmute_transaction_state {
	/* transaction content is invalid (initial state) */
	TRANSACTION_INVALID		= 0x01,

	/*
	 * All resources required by the transaction are allocated and bound to
	 * this transaction.
	 * - one MSI,
	 * - one engine frame,
	 * - one or two DMA regions
	 */
	TRANSACTION_READY		= 0x02,

	/* Transaction info are registered in the engine */
	TRANSACTION_REGISTERED		= 0x04,

	/* Launch command has been sent to the engine */
	TRANSACTION_INFLIGHT		= 0x08,

	/*
	 * Transaction either reached the destination, or crashed
	 * - engine frame is still bound to the transaction
	 * - MSI is still bound to the transaction
	 * - input and output dma regions are valid
	 *
	 * MSI has been observed
	 */
	TRANSACTION_NOTIFIED		= 0x10,

	/* Result has been collected */
	TRANSACTION_FINISHED		= 0x20,
};

struct smmute_transaction {
	u64				id;
	unsigned int			command;

	unsigned int			msi;
	unsigned long			frame;
	struct smmute_uframe		*uframe;

	atomic_t			state;

	struct smmute_dma		*dma_in;
	struct smmute_dma		*dma_out;

	off_t				offset_in;
	off_t				offset_out;

	size_t				size;
	unsigned int			attr;
	unsigned long			stride;
	unsigned long			seed;

	/* User flags */
	u64				flags;

	struct smmute_file_desc		*fd;

	/* index into smmute_file_desc.transactions */
	struct list_head		list;
	/* index into smmute_msi_pool.transactions */
	struct list_head		msi_head;

	struct kobject			kobj;
};

/*
 * In devpipe mode, we need to store pages taken from a pipe temporarily before
 * re-using them in a transaction, and feeding the result into another pipe.
 */
struct smmute_dma_page {
	struct list_head		list;
	struct page			*page;
	size_t				size;
};

struct smmute_file_desc {
	/* Per-smmute unique identifier */
	u64				id;
	struct smmute_device		*smmute;
	struct file			*file;

	struct mutex			transactions_mutex;
	struct list_head		transactions;

	struct mutex			user_dma_mutex;
	struct list_head		user_dma;

	/* list of smmute_task_fd links */
	struct list_head		tasks;

	struct kset			*dma_regions;

	wait_queue_head_t		transaction_wait;

	struct kobject			kobj;
};

#endif /* __LINUX_SMMU_TEST_ENGINE_H */
