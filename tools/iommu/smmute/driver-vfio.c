#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <linux/list.h>

#include <linux/vfio.h>
#include <linux/pci.h>

#include "smmute-lib.h"
#include "smmute-vfio.h"

/* Temporary stubs */
#ifndef VFIO_IOMMU_BIND
struct vfio_iommu_type1_bind_process {
	__u32   flags;
#define VFIO_IOMMU_BIND_PID		(1 << 0)
	__u32   pasid;
	__s32   pid;
};

struct vfio_iommu_type1_bind {
	__u32   argsz;
	__u32   flags;
#define VFIO_IOMMU_BIND_PROCESS		(1 << 0)
	__u8    data[];
};

#define VFIO_IOMMU_BIND			(-1U)
#define VFIO_IOMMU_UNBIND		(-1U)
#endif

static pthread_mutex_t groups_mutex = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(iommu_groups);
static LIST_HEAD(vfio_containers); /* Also protected by groups_mutex */
static bool merge_containers;

static long long transaction_id = 0;

#define to_vdev(dev)	((struct smmute_vdev *)(dev)->private)

static void *smmute_vfio_alloc_buffer(struct smmute_dev *dev, size_t size,
				      int prot, struct smmute_mem_options *opts)
{
	size = PAGE_ALIGN(size);

	return smmute_lib_alloc_buffer(-1, size, prot, opts);
}

static void smmute_vfio_free_buffer(struct smmute_dev *dev, void *buf, size_t size,
				    struct smmute_mem_options *opts)
{
	smmute_lib_free_buffer(buf, size, opts);
}

static int smmute_vfio_map_buffer(struct smmute_dev *dev, void *va,
				  dma_addr_t *iova, size_t size, int prot,
				  struct smmute_mem_options *opts)
{
	int ret;
	struct smmute_vdev *vdev = to_vdev(dev);
	struct vfio_iommu_type1_dma_map map = {
		.argsz		= sizeof(map),
		.flags		= 0,
	};

	/*
	 * Use IOVA = VA for now. We should allocate IOVAs properly, according
	 * to the device's reserved regions. But there is no API for that at the
	 * moment, it's under discussion.
	 */
	*iova = (uint64_t)va;

	if (opts->unified)
		return 0;

	if (prot & PROT_READ)
		map.flags |= VFIO_DMA_MAP_FLAG_READ;
	if (prot & PROT_WRITE)
		map.flags |= VFIO_DMA_MAP_FLAG_WRITE;

	map.size	= PAGE_ALIGN(size);
	map.iova	= *iova;
	map.vaddr	= (uint64_t)va;

	ret = ioctl(vdev->group->container->fd, VFIO_IOMMU_MAP_DMA, &map);
	if (ret) {
		perror("VFIO_IOMMU_MAP_DMA");
		return errno;
	}

	return ret;
}

struct smmute_vfio_bind {
	struct vfio_iommu_type1_bind		head;
	struct vfio_iommu_type1_bind_process	body;
};

static int smmute_vfio_bind(struct smmute_dev *dev, pid_t pid, int *pasid)
{
	int ret;
	bool current = pid <= 0 || getpid() == pid;
	struct smmute_vdev *vdev = to_vdev(dev);
	struct smmute_vfio_bind svm = {
		.head.argsz	= sizeof(svm),
		.head.flags	= VFIO_IOMMU_BIND_PROCESS,
		.body.flags	= current ? 0 : VFIO_IOMMU_BIND_PID,
		.body.pid	= current ? -1 : pid,
	};

	/*
	 * Could optimize this by only sending bind once per container, but the
	 * IOMMU and VFIO drivers already keep track of things.
	 */
	ret = ioctl(vdev->group->container->fd, VFIO_IOMMU_BIND, &svm);
	if (ret) {
		perror("VFIO_IOMMU_BIND");
		return errno;
	}

	*pasid = svm.body.pasid;

	return ret;
}

static int smmute_vfio_unbind(struct smmute_dev *dev, pid_t pid, int pasid)
{
	int ret;
	bool current = pid <= 0 || getpid() == pid;
	struct smmute_vdev *vdev = to_vdev(dev);
	struct smmute_vfio_bind svm = {
		.head.argsz	= sizeof(svm),
		.head.flags	= VFIO_IOMMU_BIND_PROCESS,
		.body.flags	= current ? 0 : VFIO_IOMMU_BIND_PID,
		.body.pid	= current ? -1 : pid,
		.body.pasid	= pasid,
	};

	ret = ioctl(vdev->group->container->fd, VFIO_IOMMU_UNBIND, &svm);
	if (ret) {
		perror("VFIO_IOMMU_UNBIND");
		return errno;
	}

	return ret;
}

static int smmute_vfio_unmap_buffer(struct smmute_dev *dev, void *va,
				    dma_addr_t iova, size_t size,
				    struct smmute_mem_options *opts)
{
	int ret;
	struct smmute_vdev *vdev = to_vdev(dev);
	struct vfio_iommu_type1_dma_unmap unmap = {
		.argsz	= sizeof(unmap),
		.iova	= iova,
		.size	= ALIGN(size, PAGE_SIZE),
	};

	if (opts->unified)
		return 0;

	ret = ioctl(vdev->group->container->fd, VFIO_IOMMU_UNMAP_DMA, &unmap);
	if (ret) {
		perror("VFIO_IOMMU_UNMAP_DMA");
		return errno;
	}

	return ret;
}

static int smmute_vfio_alloc_frame(struct smmute_vdev *vdev)
{
	int i, ret = -ENOSPC;
	struct smmute_vfio_frames *frames = &vdev->shr->frames;

	pthread_mutex_lock(&frames->lock);

	for (i = frames->cursor; i < frames->nr; i++) {
		long mask = 1 << (i % BITS_PER_LONG);
		unsigned long *v = &frames->bitmap[i / BITS_PER_LONG];

		if (*v & mask)
			continue;

		*v |= mask;
		ret = i;
		break;
	}

	if (i != frames->nr)
		frames->cursor = i + 1;

	pthread_mutex_unlock(&frames->lock);

	return ret;
}

static void smmute_vfio_free_frame(struct smmute_vdev *vdev, int frame)
{
	struct smmute_vfio_frames *frames = &vdev->shr->frames;
	long mask = 1 << (frame % BITS_PER_LONG);

	pthread_mutex_lock(&frames->lock);

	frames->bitmap[frame / BITS_PER_LONG] &= ~mask;
	if (frame < frames->cursor)
		frames->cursor = frame;

	pthread_mutex_unlock(&frames->lock);
}

static int smmute_vfio_launch_transaction(struct smmute_dev *dev, int cmd,
					  union smmute_transaction_params *params)
{
	int ret, frame_nr;
	uint32_t smmute_cmd;
	uint64_t input_start, output_start;
	struct smmute_vdev *vdev = to_vdev(dev);
	struct smmute_vfio_transactions *transactions = &vdev->transactions;
	struct smmute_vfio_transaction *transaction;
	volatile struct smmute_vfio_uframe *uframe;
	volatile struct smmute_vfio_pframe *pframe;

	frame_nr = smmute_vfio_alloc_frame(vdev);
	if (frame_nr < 0)
		return -frame_nr;

	transaction = calloc(1, sizeof(*transaction));
	if (!transaction) {
		ret = errno;
		goto err_free_frame;
	}

	input_start = params->common.input_start;
	output_start = params->memcpy.output_start;
	if (params->common.flags & SMMUTE_FLAG_FAULT) {
		input_start = ~input_start;
		output_start = ~output_start;
	}

	transaction->frame = frame_nr;
	transaction->params = *params;

	switch (cmd) {
	case SMMUTE_IOCTL_MEMCPY:
		smmute_cmd = ENGINE_MEMCPY;
		break;
	case SMMUTE_IOCTL_RAND48:
		smmute_cmd = ENGINE_RAND48;
		break;
	case SMMUTE_IOCTL_SUM64:
		smmute_cmd = ENGINE_SUM64;
		break;
	default:
		ret = EINVAL;
		pr_err("unknown command\n");
		goto err_free_transaction;
	}

	pthread_mutex_lock(&transactions->lock);
	transaction->id = ++transaction_id;
	list_add(&transaction->list, &transactions->list);
	pthread_mutex_unlock(&transactions->lock);

	params->common.transaction_id = transaction->id;

	uframe = smmute_vfio_get_uframe(vdev->shr->frames.pages, frame_nr);
	pframe = smmute_vfio_get_pframe(vdev->shr->frames.pages, frame_nr);

	pr_debug("Launching transaction %llu on frame %u\n", transaction->id,
		 frame_nr);

	pframe->substreamid	= (params->common.flags & SMMUTE_FLAG_SVA ?
				   params->common.pasid : SUBSTREAMID_INVALID);
	pframe->pctrl		= SMMUTE_PCTRL_SSD_NS;

	uframe->cmd		= ENGINE_HALTED;

	uframe->uctrl		= 0;
	uframe->msi_enable	= 0;
	uframe->msi_data	= 0;
	uframe->msi_attr	= 0;
	uframe->begin		= input_start;
	uframe->end_incl	= input_start + params->common.size - 1;
	uframe->stride		= 1;
	uframe->seed		= params->common.seed;
	uframe->udata[0]	= output_start;
	uframe->udata[1]	= 0;
	uframe->udata[2]	= 0;

	uframe->cmd		= smmute_cmd;

	return 0;

err_free_transaction:
	free(transaction);

err_free_frame:
	smmute_vfio_free_frame(vdev, frame_nr);

	return ret;
}

static int smmute_vfio_get_result(struct smmute_dev *dev,
				  struct smmute_transaction_result *result)
{
	uint32_t cmd;
	bool done = false;
	volatile struct smmute_vfio_uframe *uframe;
	struct smmute_vfio_transaction *tmp;
	struct smmute_vfio_transaction *transaction = NULL;
	struct smmute_vdev *vdev = to_vdev(dev);
	struct smmute_vfio_transactions *transactions = &vdev->transactions;
	unsigned long long cnt = 0;
	unsigned long long poll_delay = 10000; // us
	unsigned long long timeout_cnt = 60000000 / poll_delay; // 60s

	pthread_mutex_lock(&transactions->lock);
	list_for_each_entry(tmp, &transactions->list, list) {
		if (tmp->id == result->transaction_id) {
			transaction = tmp;
			break;
		}
	}
	pthread_mutex_unlock(&transactions->lock);

	if (!transaction)
		return EINVAL;

	uframe = smmute_vfio_get_uframe(vdev->shr->frames.pages, transaction->frame);

	/* TODO: non-blocking */
	/* TODO: irqfd */
	do {
		cmd = uframe->cmd;

		if (cmd == ENGINE_RAND48 || cmd == ENGINE_MEMCPY || cmd == ENGINE_SUM64) {
			usleep(poll_delay);
			cnt++;
		} else {
			done = true;
		}
	} while (!done && cnt < timeout_cnt);

	if (cnt >= timeout_cnt)
		pr_err("Result poll timed out\n");

	switch (cmd) {
	case ENGINE_FRAME_MISCONFIGURED:
		result->status = EINVAL;
		break;
	case ENGINE_ERROR:
		result->status = EIO;
		result->value = uframe->udata[2];
		break;
	case ENGINE_HALTED:
		result->status = 0;
		break;
	default:
		result->status = EFAULT;
		break;
	}

	if (!result->status)
		/* Result of a SUM64 */
		result->value = uframe->udata[1];

	smmute_vfio_free_frame(vdev, transaction->frame);

	pthread_mutex_lock(&transactions->lock);
	list_del(&transaction->list);
	pthread_mutex_unlock(&transactions->lock);

	free(transaction);

	return 0;
}

static int smmute_vfio_init_dev(struct smmute_vdev *vdev)
{
	int ret;
	uint16_t ctl;
	uint8_t next_cap;
	size_t frames_in_long;
	pthread_mutexattr_t mutex_attr;
	struct smmute_vfio_frames *frames = &vdev->shr->frames;

	struct vfio_device_info device_info = {
		.argsz = sizeof(device_info),
	};
	struct vfio_region_info config_info = {
		.argsz = sizeof(config_info),
		.index = VFIO_PCI_CONFIG_REGION_INDEX,
	};
	struct vfio_region_info frames_info = {
		.argsz = sizeof(config_info),
		.index = VFIO_PCI_BAR0_REGION_INDEX,
	};

	ret = ioctl(vdev->fd, VFIO_DEVICE_GET_INFO, &device_info);
	if (ret) {
		perror("VFIO_DEVICE_GET_INFO");
		return errno;
	}

	if (device_info.flags & VFIO_DEVICE_FLAGS_RESET)
		ioctl(vdev->fd, VFIO_DEVICE_RESET);

	ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &config_info);
	if (ret) {
		perror("VFIO_DEVICE_GET_REGION_INFO(CONFIG)");
		return errno;
	}

	/*
	 * BAR0 is the engine frames, BAR1/2 are MSIX table and PBA respectively
	 */
	vdev->config_offset = config_info.offset;

	ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &frames_info);
	if (ret) {
		perror("VFIO_DEVICE_GET_REGION_INFO(BAR0)");
		return errno;
	}

	*frames = (struct smmute_vfio_frames) {
		.size	= frames_info.size,
		.nr	= frames_info.size / SMMUTE_VFIO_FRAME_SIZE / 2,
		.cursor	= 0,
	};

	/* Share the frame allocation mutex between children */
	if (pthread_mutexattr_init(&mutex_attr) ||
	    pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) ||
	    pthread_mutex_init(&frames->lock, &mutex_attr))
		return errno;

	frames->pages = mmap(NULL, frames_info.size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vdev->fd, frames_info.offset);
	if (frames->pages == MAP_FAILED) {
		pr_err("cannot mmap frames\n");
		return errno;
	}
	pr_debug("Mapped %zu pairs of frames at %p (%llx)\n", frames->nr,
		 frames->pages, frames_info.size);

	/* Round up to the nearest long */
	frames_in_long = (frames->nr + BITS_PER_LONG - 1) / BITS_PER_LONG;

	frames->bitmap = calloc(frames_in_long, sizeof(long));
	if (!frames->bitmap) {
		pr_err("cannot allocate frame bitmap\n");
		goto err_unmap_pages;
	}

	INIT_LIST_HEAD(&vdev->transactions.list);
	pthread_mutex_init(&vdev->transactions.lock, NULL);

	if (pread(vdev->fd, &next_cap, 1, vdev->config_offset + PCI_CAPABILITY_LIST) != 1) {
		pr_err("cannot read cap\n");
		goto err_free_bitmap;
	}

	while (next_cap) {
		uint16_t cap_hdr;
		if (pread(vdev->fd, &cap_hdr, 2, vdev->config_offset + next_cap) != 2) {
			pr_err("cannot read cap\n");
			goto err_free_bitmap;
		}

		pr_debug("Found cap %x at %x\n", cap_hdr & 0xff, next_cap);
		next_cap = cap_hdr >> 8 & 0xff;
	}

	ctl = PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
	if (pwrite(vdev->fd, &ctl, 2, vdev->config_offset + PCI_COMMAND) != 2) {
		pr_err("cannot write PCI command\n");
		goto err_free_bitmap;
	}

	return 0;

err_free_bitmap:
	free(frames->bitmap);

err_unmap_pages:
	munmap(frames->pages, frames->size);

	return errno;
}

static void smmute_vfio_destroy_dev(struct smmute_vdev *vdev)
{
	u16 ctl = 0;
	struct smmute_vfio_frames *frames = &vdev->shr->frames;

	free(frames->bitmap);

	if (frames->pages)
		munmap(frames->pages, frames->size);

	if (pwrite(vdev->fd, &ctl, 2, vdev->config_offset + PCI_COMMAND) != 2)
		pr_err("cannot write PCI command\n");
}

int smmute_vfio_get_container(struct smmute_iommu_group *group)
{
	int api;
	int ret = EINVAL;
	struct smmute_vfio_container *container;

	if (merge_containers) {
		list_for_each_entry(container, &vfio_containers, list) {
			if (ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd))
				continue;

			container->ref++;
			group->container = container;

			pr_debug("Reusing container %d for group %lu\n",
				 container->fd, group->id);
			return 0;
		}
	}

	container = calloc(1, sizeof(struct smmute_vfio_container));
	if (!container)
		return ENOMEM;

	container->ref = 1;

	container->fd = open("/dev/vfio/vfio", O_RDWR);
	if (container->fd < 0) {
		pr_err("unable to create VFIO container\n");
		goto err_free_container;
	}

	api = ioctl(container->fd, VFIO_GET_API_VERSION);
	if (api != VFIO_API_VERSION) {
		pr_err("unknown VFIO API version %d\n", api);
		goto err_close_container;
	}

	if (!ioctl(container->fd, VFIO_CHECK_EXTENSION, SMMUTE_IOMMU_TYPE)) {
		ret = errno;
		pr_err("VFIO doesn't support the right kind of IOMMU\n");
		goto err_close_container;
	}

	if (ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
		ret = errno;
		pr_err("cannot set container for group %lu\n", group->id);
		goto err_close_container;
	}

	if (ioctl(container->fd, VFIO_SET_IOMMU, SMMUTE_IOMMU_TYPE)) {
		ret = errno;
		pr_err("cannot set IOMMU\n");
		goto err_close_container;
	}

	group->container = container;

	if (merge_containers)
		list_add(&container->list, &vfio_containers);

	pr_debug("Allocated container %d for group %lu\n", container->fd,
		 group->id);

	return 0;

err_close_container:
	close(container->fd);

err_free_container:
	free(container);

	return ret;
}

void smmute_vfio_put_container(struct smmute_vfio_container *container)
{
	if (--container->ref == 0) {
		pr_debug("Freeing container %d\n", container->fd);
		close(container->fd);
		if (merge_containers)
			list_del(&container->list);
		free(container);
	}
}

static struct smmute_iommu_group *smmute_vfio_group_create(unsigned long group_id)
{
	int ret;
	char group_dev[VFIO_PATH_MAX];
	struct smmute_iommu_group *group;
	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status),
	};

	group = calloc(1, sizeof(*group));
	if (!group)
		return NULL;

	ret = snprintf(group_dev, VFIO_PATH_MAX, "/dev/vfio/%lu", group_id);
	if (ret <= 0)
		goto err_free;

	group->fd = open(group_dev, O_RDWR);
	if (group->fd < 0) {
		pr_err("cannot open %s\n", group_dev);
		goto err_free;
	}

	if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &group_status)) {
		pr_err("cannot get group %lu status\n", group_id);
		goto err_close;
	}

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		pr_err("group %lu is not viable\n", group_id);
		goto err_close;
	}

	group->id = group_id;
	group->ref = 0;

	if (smmute_vfio_get_container(group))
		goto err_close;

	return group;

err_close:
	close(group->fd);

err_free:
	free(group);

	return NULL;
}

static void smmute_vfio_group_destroy(struct smmute_iommu_group *group)
{
	if (ioctl(group->fd, VFIO_GROUP_UNSET_CONTAINER))
		perror("VFIO_GROUP_UNSET_CONTAINER");

	close(group->fd);
	smmute_vfio_put_container(group->container);
	free(group);
}

static struct smmute_iommu_group *smmute_vfio_group_get(unsigned long group_id)
{
	struct smmute_iommu_group *tmp;
	struct smmute_iommu_group *group = NULL;

	pthread_mutex_lock(&groups_mutex);
	list_for_each_entry(tmp, &iommu_groups, list) {
		if (tmp->id != group_id)
			continue;

		group = tmp;
		break;
	}

	if (!group) {
		group = smmute_vfio_group_create(group_id);
		if (!group)
			goto out_unlock;

		list_add(&group->list, &iommu_groups);
	}

	group->ref++;

out_unlock:
	pthread_mutex_unlock(&groups_mutex);

	return group;
}

static void smmute_vfio_group_put(struct smmute_iommu_group *group)
{
	pthread_mutex_lock(&groups_mutex);
	if (--group->ref == 0) {
		list_del(&group->list);

		smmute_vfio_group_destroy(group);
	}
	pthread_mutex_unlock(&groups_mutex);
}

static int smmute_vfio_open(struct smmute_dev *dev, const char *path, int flags)
{
	int ret;
	char *group_cpath;
	char *group_id_str;
	unsigned long group_id;
	char group_path[VFIO_PATH_MAX];
	struct smmute_vdev *vdev;

	vdev = calloc(1, sizeof(*vdev));
	if (!vdev)
		return ENOMEM;

	vdev->shr = mmap(NULL, PAGE_ALIGN(sizeof(*vdev->shr)), PROT_READ |
			 PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (vdev->shr == MAP_FAILED) {
		ret = errno;
		goto err_free_vdev;
	}

	vdev->path = realpath(path, NULL);
	if (!vdev->path) {
		pr_err("invalid device path '%s'\n", path);
		ret = errno;
		goto err_free_shr;
	}

	pr_debug("VFIO device path: %s\n", vdev->path);

	/* Find associated group */
	ret = snprintf(group_path, VFIO_PATH_MAX, "%s/iommu_group", vdev->path);
	if (ret <= 0) {
		pr_err("group path too long\n");
		goto err_free_dev_path;
	}

	group_cpath = realpath(group_path, NULL);
	if (!group_cpath) {
		ret = errno;
		pr_err("invalid group path '%s'\n", group_path);
		goto err_free_dev_path;
	}

	group_id_str = basename(group_cpath);
	errno = 0;
	group_id = strtoul(group_id_str, NULL, 10);
	if (errno) {
		ret = errno;
		pr_err("invalid group ID '%s'\n", group_id_str);
		goto err_free_group_path;
	}
	pr_debug("VFIO group ID: %lu\n", group_id);

	vdev->group = smmute_vfio_group_get(group_id);
	if (!vdev->group) {
		ret = errno;
		goto err_free_group_path;
	}

	vdev->name = strdup(basename(vdev->path));
	if (!vdev->name) {
		pr_err("strdup failed\n");
		ret = errno;
		goto err_release_group;
	}
	pr_debug("VFIO device name: %s\n", vdev->name);

	vdev->fd = ioctl(vdev->group->fd, VFIO_GROUP_GET_DEVICE_FD, vdev->name);
	if (vdev->fd < 0) {
		pr_err("cannot get new fd for device '%s'\n", vdev->name);
		ret = errno;
		goto err_free_name;
	}

	/* Start probing and setting up the PCI device */
	ret = smmute_vfio_init_dev(vdev);
	if (ret)
		return ret;

	dev->private = vdev;

	free(group_cpath);

	return 0;

err_free_name:
	free(vdev->name);

err_release_group:
	smmute_vfio_group_put(vdev->group);

err_free_group_path:
	free(group_cpath);

err_free_dev_path:
	free(vdev->path);

err_free_shr:
	munmap(vdev->shr, PAGE_ALIGN(sizeof(*vdev->shr)));

err_free_vdev:
	free(vdev);

	return ret;
}

static void smmute_vfio_close(struct smmute_dev *dev)
{
	struct smmute_vdev *vdev = to_vdev(dev);

	if (!vdev)
		return;

	smmute_vfio_destroy_dev(vdev);

	close(vdev->fd);

	free(vdev->name);

	smmute_vfio_group_put(vdev->group);

	free(vdev->path);
	munmap(vdev->shr, PAGE_ALIGN(sizeof(*vdev->shr)));
	free(vdev);
}

static int smmute_vfio_init(struct smmute_backend_options *opts)
{
	BUILD_BUG_ON(sizeof(struct smmute_vfio_uframe) != SMMUTE_VFIO_FRAME_SIZE);
	BUILD_BUG_ON(sizeof(struct smmute_vfio_pframe) != SMMUTE_VFIO_FRAME_SIZE);

	if (opts && opts->flags & SMMUTE_BACKEND_VFIO_FLAG_MERGE) {
		merge_containers = true;
		INIT_LIST_HEAD(&vfio_containers);
	}

	return 0;
}

static void smmute_vfio_exit(void)
{
}

struct smmute_device_ops vfio_ops = {
	.init			= smmute_vfio_init,
	.exit			= smmute_vfio_exit,

	.open			= smmute_vfio_open,
	.close			= smmute_vfio_close,

	.bind			= smmute_vfio_bind,
	.unbind			= smmute_vfio_unbind,

	.alloc_buffer		= smmute_vfio_alloc_buffer,
	.free_buffer		= smmute_vfio_free_buffer,

	.map_buffer		= smmute_vfio_map_buffer,
	.unmap_buffer		= smmute_vfio_unmap_buffer,

	.launch_transaction	= smmute_vfio_launch_transaction,
	.get_result		= smmute_vfio_get_result,
};
