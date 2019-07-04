#ifndef SMMUTE_VFIO_H
#define SMMUTE_VFIO_H

#define VFIO_PATH_MAX	PATH_MAX

#define SMMUTE_IOMMU_TYPE	VFIO_TYPE1v2_IOMMU
//#define SMMUTE_IOMMU_TYPE	VFIO_TYPE1_NESTING_IOMMU

/*
 * All the low-level frame handling is copied directly from smmu-test-engine.h.
 * Would be better to make that header common.
 */
enum {
	ENGINE_FRAME_MISCONFIGURED	= ~0u - 1,
	ENGINE_ERROR			= ~0u,
	ENGINE_NO_FRAME			= 0,
	ENGINE_HALTED			= 1,
	ENGINE_MEMCPY			= 2,
	ENGINE_RAND48			= 3,
	ENGINE_SUM64			= 4,
};

#define SMMUTE_VFIO_FRAME_SIZE	128

struct smmute_vfio_uframe {
	uint32_t cmd;
	uint32_t uctrl;

	uint32_t launch_count;
	uint32_t return_count;

	uint64_t msi_enable;

	uint32_t msi_data; /* vector nr */
	uint32_t msi_attr; /* ignored */

	uint32_t attributes;
	uint32_t seed;

	uint64_t begin;
	uint64_t end_incl;

	uint64_t stride;

	uint64_t udata[8];
};

struct smmute_vfio_pframe {
	uint32_t pctrl;
#define SMMUTE_PCTRL_SSD_NS	(1 << 0)
	uint32_t unused[2];

#define SUBSTREAMID_INVALID	(~0u)
	uint32_t substreamid;

	uint64_t pdata[14];
};

/* The SMMU test engine config uses 64k pages. */
#define FRAMES_PER_PAGE	(0x10000 / sizeof(struct smmute_vfio_uframe))

struct smmute_page_pair {
	struct smmute_vfio_uframe	user[FRAMES_PER_PAGE];
	struct smmute_vfio_pframe	privileged[FRAMES_PER_PAGE];
};

#define _smmute_pair(pair, idx)						\
	((struct smmute_page_pair *)(pair) + (idx) / FRAMES_PER_PAGE)

#define smmute_vfio_get_uframe(pair, idx)				\
	((struct smmute_vfio_uframe *)&_smmute_pair(pair, idx)->user	\
	 + (idx) % FRAMES_PER_PAGE)

#define smmute_vfio_get_pframe(pair, idx)				\
	((struct smmute_vfio_pframe *)&_smmute_pair(pair, idx)->privileged	\
	 + (idx) % FRAMES_PER_PAGE)

struct smmute_vfio_container {
	int				fd;
	struct list_head		list;
	int				ref;
};

struct smmute_iommu_group {
	unsigned long			id;

	struct smmute_vfio_container	*container;
	int				fd;

	unsigned int			ref;
	struct list_head		list;
};

struct smmute_vfio_frames {
	size_t				size;
	/* Number of pairs (usr + priv) of frames */
	size_t				nr;

	/* Allocation stuff */
	pthread_mutex_t			lock;
	unsigned long			*bitmap;
	/* First frame that could be free */
	size_t				cursor;

	struct smmute_page_pair		*pages;
};

struct smmute_vfio_transaction {
	unsigned long long		id;
	int				frame;
	union smmute_transaction_params	params;
	struct list_head		list;
};

struct smmute_vfio_transactions {
	struct list_head		list;
	pthread_mutex_t			lock;
};

/* Structure is shared between child processes */
struct smmute_vdev_shared {
	struct smmute_vfio_frames	frames;
};

struct smmute_vdev {
	/* VFIO device fd */
	int				fd;
	/* Canonical absolute path of the device in sysfs */
	char				*path;
	/* Device name as needed by GET_DEVICE_FD */
	char				*name;
	struct smmute_iommu_group	*group;

	off_t				config_offset;
	struct smmute_vfio_transactions	transactions;
	struct smmute_vdev_shared	*shr;
};

#endif
