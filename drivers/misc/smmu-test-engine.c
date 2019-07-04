// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for the SMMUv3 test engine
 *
 * Copyright (C) 2016 ARM Limited
 */

//#define DEBUG
//#define DEBUG_USER_FRAMES

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/kobject.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/pagemap.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/rbtree.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>

#include <linux/smmu-test-engine.h>

#define CREATE_TRACE_POINTS
#include <trace/events/smmute.h>

#define SMMUTE_MAX_MSIS		8

static void smmute_dma_release(struct kobject *kobj);
static void smmute_dma_put(struct smmute_dma *dma);
struct kobj_type smmute_dma_ktype = {
	.release = smmute_dma_release,
};

static void smmute_task_release(struct kobject *);
static struct kobj_type smmute_task_ktype = {
	.release	= smmute_task_release,
};

static void smmute_transaction_release(struct kobject *kobj);
struct kobj_type smmute_transaction_ktype = {
	.release = smmute_transaction_release,
};

static void smmute_fd_release(struct kobject *kobj);
struct kobj_type smmute_file_desc_ktype = {
	.release		= smmute_fd_release,
};

static int smmute_major;
static DEFINE_IDA(smmute_minor_ida);
static struct class *smmute_class;
static struct cdev smmute_cdev;

static DEFINE_MUTEX(smmute_devices_mutex);
static LIST_HEAD(smmute_devices);

static atomic64_t smmute_transactions_ida = ATOMIC_INIT(0);
static atomic64_t smmute_dma_ida = ATOMIC_INIT(0);

static const char *smmute_get_command_name(enum smmute_cmd command)
{
	switch (command) {
	case ENGINE_FRAME_MISCONFIGURED:
		return "ENGINE_FRAME_MISCONFIGURED";
	case ENGINE_ERROR:
		return "ENGINE_ERROR";
	case ENGINE_NO_FRAME:
		return "ENGINE_NO_FRAME";
	case ENGINE_HALTED:
		return "ENGINE_HALTED";
	case ENGINE_MEMCPY:
		return "ENGINE_MEMCPY";
	case ENGINE_SUM64:
		return "ENGINE_SUM64";
	case ENGINE_RAND48:
		return "ENGINE_RAND48";
	default:
		return "UNKNOWN";
	}
}

static enum smmute_cmd smmute_ioctl_to_command(long cmd)
{
	switch (cmd) {
	case SMMUTE_IOCTL_MEMCPY:
		return ENGINE_MEMCPY;
	case SMMUTE_IOCTL_RAND48:
		return ENGINE_RAND48;
	case SMMUTE_IOCTL_SUM64:
		return ENGINE_SUM64;
	default:
		pr_err("unknown command %ld\n", cmd);
		return ENGINE_ERROR;
	}
}

__attribute__((unused))
static void smmute_uframe_dump(size_t idx, struct smmute_uframe *frame)
{
	size_t i;

	pr_info("--------- User frame #%05zu ----------\n"
		" cmd                   = %s\n"
		" uctrl                 = 0x%x\n"
		" count_launch          = %u\n"
		" count_ret             = %u\n"
		" msi addr              = 0x%llx\n"
		" msi data              = 0x%x\n"
		" msi attr              = 0x%x\n"
		" attr                  = 0x%x\n"
		" seed                  = 0x%x\n"
		" begin                 = 0x%llx\n"
		" end                   = 0x%llx\n"
		" stride                = 0x%llu\n"
		" user data             =\n",
		idx,
		smmute_get_command_name(readl_relaxed(&frame->cmd)),
		readl_relaxed(&frame->uctrl),
		readl_relaxed(&frame->count_of_transactions_launched),
		readl_relaxed(&frame->count_of_transactions_returned),
		readq_relaxed(&frame->msiaddress),
		readl_relaxed(&frame->msidata),
		readl_relaxed(&frame->msiattr),
		readl_relaxed(&frame->attributes),
		readl_relaxed(&frame->seed),
		readq_relaxed(&frame->begin),
		readq_relaxed(&frame->end_incl),
		readq_relaxed(&frame->stride));

	for (i = 0; i < 4; i++)
		pr_info("  0x%016llx %016llx\n",
			readq_relaxed(frame->udata + i),
			readq(frame->udata + i + 1));
	pr_info("--------------------------------------\n");
}

static void smmute_transaction_set_state(struct smmute_transaction *transaction,
					 enum smmute_transaction_state state);

#define smmute_get_msi_vector(smmute, idx)					\
	(dev_is_pci((smmute)->dev) ? (smmute)->msix_entries[idx].vector :	\
	 (smmute)->plat_msi_entries[idx].vector)

static irqreturn_t smmute_msi_handler(int irq, void *opaque)
{
	u32 hwstate;
	struct smmute_msi_pool *pool = opaque;
	struct smmute_transaction *tsac, *next;

	spin_lock(&pool->lock);
	/* Signal all finished transactions */
	list_for_each_entry_safe(tsac, next, &pool->transactions, msi_head) {
		hwstate = readl_relaxed(&tsac->uframe->cmd);
		if (atomic_read(&tsac->state) == TRANSACTION_INFLIGHT &&
		    hwstate != tsac->command) {
			list_del_init(&tsac->msi_head);
			smmute_transaction_set_state(tsac, TRANSACTION_NOTIFIED);
			wake_up_interruptible(&tsac->fd->transaction_wait);
		}
	}
	spin_unlock(&pool->lock);

	return IRQ_HANDLED;
}

/**
 * smmute_msi_alloc - allocate an MSI for a transaction
 *
 * return the allocated MSI number (>= 0), or an error
 */
static int smmute_msi_alloc(struct smmute_device *smmute,
			     struct smmute_transaction *tsac)
{
	struct smmute_msi_pool *pool;
	unsigned long nr_msis = smmute->nr_msix_entries;

	mutex_lock(&smmute->resources_mutex);
	pool = &smmute->msi_pools[smmute->current_pool];

	spin_lock_irq(&pool->lock);
	list_add_tail(&tsac->msi_head, &pool->transactions);
	spin_unlock_irq(&pool->lock);

	tsac->msi = smmute->current_pool;
	smmute->current_pool = (smmute->current_pool + 1) % nr_msis;
	mutex_unlock(&smmute->resources_mutex);

	return tsac->msi;
}

static bool smmute_msi_free(struct smmute_device *smmute,
			    struct smmute_transaction *tsac)
{
	bool deleted = false;
	struct smmute_msi_pool *pool = &smmute->msi_pools[tsac->msi];

	spin_lock_irq(&pool->lock);
	/* Clean up if the MSI handler didn't already */
	if (!list_empty(&tsac->msi_head)) {
		deleted = true;
		list_del_init(&tsac->msi_head);
	}
	spin_unlock_irq(&pool->lock);

	return deleted;
}

/**
 * smmute_frame_alloc - reserve a pair of frames for a transaction
 */
static long smmute_frame_alloc(struct smmute_device *smmute)
{
	long frame;
	unsigned long nr_frames = smmute->nr_pairs * SMMUTE_FRAMES_PER_PAGE;

	mutex_lock(&smmute->resources_mutex);

	frame = find_first_zero_bit(smmute->reserved_frames, nr_frames);
	if (frame == nr_frames) {
		dev_err(smmute->dev, "no frame available\n");
		mutex_unlock(&smmute->resources_mutex);
		return -EBUSY;
	}
	set_bit(frame, smmute->reserved_frames);

	mutex_unlock(&smmute->resources_mutex);

	return frame;
}

/**
 * smmute_transaction_alloc - Allocate resources to perform one transaction
 *
 * Allocates
 * - a transaction struct, linked to the device
 * - one MSI, and request the associated IRQ if necessary
 * - one pair of frames
 *
 * Caller must intialize everything else:
 * - set command, size, stride, seed, attr
 * - attach DMA (one or two regions, depending on the command)
 * - launch the transaction
 */
static struct smmute_transaction *
smmute_transaction_alloc(struct smmute_file_desc *fd)
{
	int ret;
	long msi, frame;
	struct smmute_transaction *transaction;
	struct smmute_device *smmute = fd->smmute;

	transaction = kmem_cache_alloc(smmute->transaction_cache,
				       GFP_KERNEL | __GFP_ZERO);
	if (!transaction)
		return ERR_PTR(-ENOMEM);

	frame = smmute_frame_alloc(smmute);
	if (frame < 0) {
		ret = frame;
		goto err_free_transaction;
	}

	atomic_set(&transaction->state, TRANSACTION_INVALID);

	transaction->id = atomic64_inc_return(&smmute_transactions_ida);
	transaction->frame = frame;
	transaction->fd = fd;
	transaction->uframe = smmute_user_frame(smmute->pairs, frame);

	msi = smmute_msi_alloc(smmute, transaction);
	if (msi < 0) {
		ret = msi;
		goto err_release_frame;
	}

	ret = kobject_init_and_add(&transaction->kobj, &smmute_transaction_ktype,
				   &fd->kobj, "%llu", transaction->id);
	if (ret) {
		dev_err(smmute->dev, "could not create kobject\n");
		goto err_release_msi;
	}

	mutex_lock(&fd->transactions_mutex);
	list_add(&transaction->list, &fd->transactions);
	mutex_unlock(&fd->transactions_mutex);

	dev_dbg(smmute->dev, "allocated transaction %p\n", transaction);

	return transaction;

err_release_msi:
	smmute_msi_free(smmute, transaction);

err_release_frame:
	clear_bit(frame, smmute->reserved_frames);

err_free_transaction:
	kmem_cache_free(smmute->transaction_cache, transaction);

	return ERR_PTR(ret);
}

/* Called by kobject_cleanup */
static void smmute_transaction_release(struct kobject *kobj)
{
	struct smmute_transaction *transaction = container_of(kobj,
			struct smmute_transaction, kobj);
	struct smmute_file_desc *fd = transaction->fd;
	struct smmute_device *smmute = fd->smmute;

	smmute_transaction_set_state(transaction, TRANSACTION_INVALID);

	smmute_dma_put(transaction->dma_in);
	smmute_dma_put(transaction->dma_out);

	smmute_msi_free(smmute, transaction);
	clear_bit(transaction->frame, smmute->reserved_frames);

	list_del(&transaction->list);

	dev_dbg(smmute->dev, "freed transaction     %p\n", transaction);

	kmem_cache_free(smmute->transaction_cache, transaction);
}

static void smmute_transaction_free(struct smmute_file_desc *fd,
				    struct smmute_transaction *transaction)
{
	mutex_lock(&fd->transactions_mutex);
	kobject_put(&transaction->kobj);
	mutex_unlock(&fd->transactions_mutex);
}

void __smmute_task_put(struct smmute_task *smmute_task)
{
	put_pid(smmute_task->pid);
	kobject_put(&smmute_task->kobj);
}

static int smmute_task_fd_get(struct smmute_file_desc *fd,
			      struct smmute_task *task)
{
	struct smmute_task_fd *tfd;

	tfd = kzalloc(sizeof(*tfd), GFP_KERNEL);
	if (!tfd)
		return -ENOMEM;

	tfd->task = task;
	list_add(&tfd->list, &fd->tasks);
	return 0;
}

static int smmute_task_fd_put(struct smmute_file_desc *fd,
			      struct smmute_task *task)
{
	struct smmute_task_fd *tfd;

	list_for_each_entry(tfd, &fd->tasks, list) {
		if (tfd->task == task) {
			list_del(&tfd->list);
			kfree(tfd);
			return 1;
		}
	}
	return 0;
}

static struct smmute_task *__smmute_task_get(struct smmute_file_desc *fd,
					     const char *src)
{
	int ret;
	struct smmute_task *smmute_task;
	struct smmute_device *smmute = fd->smmute;
	/*
	 * Keep track of the TGID, not the PID, since threads share the same mm,
	 * and therefore the same PASID.
	 */
	struct pid *pid = get_task_pid(current, PIDTYPE_TGID);

	list_for_each_entry(smmute_task, &smmute->tasks, smmute_head) {
		if (smmute_task->pid != pid)
			continue;
		put_pid(pid);

		/*
		 * Add a ref to this fd, so we can put the right number of
		 * references when releasing the fd.
		 */
		ret = smmute_task_fd_get(fd, smmute_task);
		if (ret)
			return ERR_PTR(ret);
		trace_smmute_get_task(smmute_task, src);
		get_pid(smmute_task->pid);
		kobject_get(&smmute_task->kobj);
		return smmute_task;
	}

	smmute_task = kzalloc(sizeof(*smmute_task), GFP_KERNEL);
	if (!smmute_task) {
		ret = -ENOMEM;
		goto err_put_pid;
	}

	smmute_task->handle = iommu_sva_bind_device(smmute->dev, current->mm);
	if (IS_ERR(smmute_task->handle)) {
		ret = PTR_ERR(smmute_task->handle);
		goto err_free_task;
	}

	smmute_task->smmute	= smmute;
	smmute_task->pid	= pid;
	smmute_task->ssid	= iommu_sva_get_pasid(smmute_task->handle);
	smmute_task->kobj.kset	= smmute->tasks_set;

	ret = smmute_task_fd_get(fd, smmute_task);
	if (ret)
		goto err_unbind;

	ret = kobject_init_and_add(&smmute_task->kobj, &smmute_task_ktype, NULL,
				   "%u", smmute_task->ssid);
	if (ret)
		goto err_free_task_fd;

	list_add(&smmute_task->smmute_head, &smmute->tasks);
	trace_smmute_alloc_task(smmute_task);
	return smmute_task;

err_free_task_fd:
	smmute_task_fd_put(fd, smmute_task);
err_unbind:
	iommu_sva_unbind_device(smmute_task->handle);
err_free_task:
	kfree(smmute_task);
err_put_pid:
	put_pid(pid);
	return ERR_PTR(ret);
}

static int smmute_task_get(struct smmute_file_desc *fd,
			   struct smmute_task **out_task,
			   const char *src)
{
	struct smmute_device *smmute = fd->smmute;
	struct smmute_task *smmute_task = NULL;

	if (!smmute->dev_feat[IOMMU_DEV_FEAT_SVA])
		return -ENODEV;

	mutex_lock(&smmute->task_mutex);
	smmute_task = __smmute_task_get(fd, src);
	mutex_unlock(&smmute->task_mutex);

	if (IS_ERR(smmute_task))
		return PTR_ERR(smmute_task);

	if (out_task)
		*out_task = smmute_task;

	return 0;
}

void smmute_task_fd_put_all(struct smmute_file_desc *fd)
{
	struct smmute_task_fd *tfd, *next;

	mutex_lock(&fd->smmute->task_mutex);
	list_for_each_entry_safe(tfd, next, &fd->tasks, list) {
		trace_smmute_put_task(tfd->task, __func__);
		__smmute_task_put(tfd->task);
		list_del(&tfd->list);
		kfree(tfd);
	}
	mutex_unlock(&fd->smmute->task_mutex);
}

/*
 * Put reference of the task passed as argument if non-null, otherwise put the
 * reference to the current task.
 */
void smmute_task_put(struct smmute_file_desc *fd,
		     struct smmute_task *smmute_task,
		     const char *src)
{
	struct smmute_task_fd *tfd;
	struct smmute_device *smmute = fd->smmute;
	struct pid *pid;

	if (smmute_task)
		pid = get_pid(smmute_task->pid);
	else
		pid = get_task_pid(current, PIDTYPE_TGID);

	mutex_lock(&smmute->task_mutex);
	list_for_each_entry(tfd, &fd->tasks, list) {
		if (tfd->task->pid != pid)
			continue;

		trace_smmute_put_task(tfd->task, src);
		if (smmute_task && tfd->task != smmute_task) {
			trace_smmute_put_task(tfd->task, "BROK");
			dev_warn(smmute->dev, "OUCH! smmute_task %u != smmute_task %u\n", 
				 smmute_task->ssid, tfd->task->ssid);
			/* Sanity check, TODO remove */
			break;
		}
		__smmute_task_put(tfd->task);
		list_del(&tfd->list);
		kfree(tfd);
		break;
	}
	mutex_unlock(&smmute->task_mutex);

	put_pid(pid);
}

void smmute_task_release(struct kobject *kobj)
{
	struct smmute_task *smmute_task = container_of(kobj, struct smmute_task, kobj);
	struct smmute_device *smmute = smmute_task->smmute;

	WARN_ON(!mutex_is_locked(&smmute->task_mutex));

	list_del(&smmute_task->smmute_head);

	iommu_sva_unbind_device(smmute_task->handle);

	trace_smmute_free_task(smmute_task);
	kfree(smmute_task);
}

static struct smmute_dma *
smmute_dma_alloc_struct(struct smmute_file_desc *fd)
{
	int ret;
	struct smmute_dma *dma;
	struct smmute_device *smmute = fd->smmute;

	dma = kmem_cache_alloc(smmute->dma_regions_cache,
			       GFP_KERNEL | __GFP_ZERO);
	if (!dma)
		return NULL;

	dma->fd = fd;
	dma->id = atomic64_inc_return(&smmute_dma_ida);
	dma->smmute = smmute;
	dma->kobj.kset = fd->dma_regions;

	ret = kobject_init_and_add(&dma->kobj, &smmute_dma_ktype, NULL, "%llu",
				   dma->id);
	if (ret) {
		kmem_cache_free(smmute->dma_regions_cache, dma);
		return NULL;
	}

	return dma;
}

static void smmute_transaction_attach_dma(struct smmute_transaction *transaction,
					  struct smmute_dma *dma,
					  int direction)
{
	switch (direction) {
	case DMA_TO_DEVICE:
		transaction->dma_in = dma;
		break;
	case DMA_FROM_DEVICE:
		transaction->dma_out = dma;
		break;
	default:
		BUG();
	}

	/*
	 * Non-SVM:
	 * - mmap allocates smmute_dma, takes ref
	 * - attach_dma takes ref
	 * - transaction_release drops ref
	 * - munmap drops ref, frees smmute_dma
	 *
	 * SVM:
	 * - user_dma_get allocates smmute_dma, takes ref
	 * - transaction_release drops ref, frees smmute_dma
	 *
	 * Not very nice, I know, but it's the simplest
	 */
	if (!dma->task)
		kobject_get(&dma->kobj);
}

/* Called by kobject_cleanup */
static void smmute_dma_release(struct kobject *kobj)
{
	struct smmute_dma *dma = container_of(kobj, struct smmute_dma, kobj);
	struct smmute_device *smmute = dma->smmute;

	if (dma->task)
		smmute_task_put(dma->fd, dma->task, __func__);

	dma_free_attrs(smmute->dev, dma->size, dma->kaddr, dma->iova, 0);

	kmem_cache_free(smmute->dma_regions_cache, dma);
}

static void smmute_dma_put(struct smmute_dma *dma)
{
	if (dma)
		kobject_put(&dma->kobj);
}

/**
 * smmute_dma_get_user - find DMA region mmap'd in current address space
 *
 * @fd: file descriptor used when mapping that region
 * @addr: user pointer inside a DMA region
 * @size: size of the buffer
 * @off: if the region is found, this will contain the offset between @addr and
 *       the beginning of the region
 * @sva: use userspace pointer for device DMA
 */
static struct smmute_dma *
smmute_dma_get_user(struct smmute_file_desc *fd, void __user *addr, size_t size,
		    off_t *off, bool sva)
{
	int ret;
	struct smmute_dma *dma;
	struct smmute_task *smmute_task;
	struct smmute_dma *found_dma = NULL;
	struct smmute_device *smmute = fd->smmute;

	struct mm_struct *mm = current->mm;

	if (sva) {
		/* Allocate if necessary and get a ref to the smmute_task */
		ret = smmute_task_get(fd, &smmute_task, __func__);
		if (ret) {
			dev_err(smmute->dev, "unable to get task\n");
			return NULL;
		}

		dma = smmute_dma_alloc_struct(fd);
		if (!dma)
			return NULL;

		dma->iova = (unsigned long)addr;
		dma->size = size;
		dma->task = smmute_task;

		return dma;
	}

	mutex_lock(&fd->user_dma_mutex);
	list_for_each_entry(dma, &fd->user_dma, list) {
		if (dma->mm != mm)
			continue;

		if (addr >= dma->uaddr && addr < (dma->uaddr + dma->size)) {
			found_dma = dma;
			*off = addr - dma->uaddr;
			break;
		}
	}
	mutex_unlock(&fd->user_dma_mutex);

	return found_dma;
}

static struct smmute_file_desc *smmute_fd_alloc(struct smmute_device *smmute)
{
	int ret;
	struct smmute_file_desc *fd;

	fd = kmem_cache_alloc(smmute->file_desc_cache, GFP_KERNEL | __GFP_ZERO);
	if (!fd)
		return NULL;

	fd->id = atomic64_inc_return(&smmute->files_ida);

	mutex_init(&fd->user_dma_mutex);
	INIT_LIST_HEAD(&fd->user_dma);
	INIT_LIST_HEAD(&fd->transactions);
	INIT_LIST_HEAD(&fd->tasks);

	init_waitqueue_head(&fd->transaction_wait);

	fd->kobj.kset = smmute->files_set;

	ret = kobject_init_and_add(&fd->kobj, &smmute_file_desc_ktype, NULL,
				   "%llu", fd->id);
	if (ret)
		goto err_free_fd;

	mutex_init(&fd->transactions_mutex);

	fd->smmute = smmute;

	fd->dma_regions = kset_create_and_add("dma", NULL, &fd->kobj);
	if (!fd->dma_regions)
		goto err_release;

	return fd;

err_release:
	kobject_put(&fd->kobj);

err_free_fd:
	kmem_cache_free(smmute->file_desc_cache, fd);

	return NULL;
}

void smmute_fd_release(struct kobject *kobj)
{
	struct smmute_file_desc *fd = container_of(kobj, struct smmute_file_desc, kobj);
	struct smmute_device *smmute = fd->smmute;

	mutex_destroy(&fd->transactions_mutex);

	kmem_cache_free(smmute->file_desc_cache, fd);
}

/**
 * smmute_user_frame_init - Initialise a user frame
 *
 * With informations taken from a transaction and its parameters, initialise a
 * user frame in the PCI device.
 *
 * Returns a pointer to that frame on success, an error pointer on failure.
 */
static struct smmute_uframe *
smmute_user_frame_init(struct smmute_device *smmute,
		       struct smmute_transaction *transaction)
{
	size_t i = 0;
	struct smmute_uframe *frame = transaction->uframe;
	dma_addr_t iova_in = transaction->dma_in->iova + transaction->offset_in;
	dma_addr_t iova_out = 0;

	if (transaction->dma_out)
		iova_out = transaction->dma_out->iova + transaction->offset_out;

	if (transaction->flags & SMMUTE_FLAG_FAULT) {
		iova_in = ~iova_in;
		iova_out = ~iova_out;
	}

	/*
	 * cmd must be ENGINE_HALTED, ENGINE_ERROR or
	 * ENGINE_FRAME_MISCONFIGURED for the rest of the structure to be
	 * writeable
	 */
	writel_relaxed(ENGINE_HALTED, &frame->cmd);

	/* Get dma region associated with this virtual address */
	if (!transaction->dma_in)
		return ERR_PTR(-EINVAL);

	writel_relaxed(0, &frame->uctrl);
	writeq_relaxed(iova_in, &frame->begin);
	writeq_relaxed(iova_in + transaction->size - 1, &frame->end_incl);
	writel_relaxed(transaction->attr, &frame->attributes);
	writel_relaxed(transaction->seed, &frame->seed);
	if (!transaction->stride)
		transaction->stride = 1;
	writeq_relaxed(transaction->stride, &frame->stride);

	if (dev_is_pci(smmute->dev)) {
		writeq_relaxed(1, &frame->msiaddress);
		writel_relaxed(transaction->msi, &frame->msidata);
		writel_relaxed(0, &frame->msiattr);
	} else {
		struct smmute_msi_info *entry =
			&smmute->plat_msi_entries[transaction->msi];
		writeq_relaxed(entry->doorbell, &frame->msiaddress);
		writel_relaxed(entry->data, &frame->msidata);
		writel_relaxed(SMMUTE_ATTR_DEVICE, &frame->msiattr);
	}

	if (transaction->dma_out) {
		writeq_relaxed(iova_out, frame->udata);
		/* Skip first udata */
		i = 1;
	}

	for (; i < 8; i++)
		writeq_relaxed(0, frame->udata + i);

	return frame;
}

/**
 * smmute_priv_frame_init - initialise privileged frame for a transaction
 */
static struct smmute_pframe *
smmute_priv_frame_init(struct smmute_device *smmute,
		       struct smmute_transaction *transaction)
{
	u32 ssid = 0, sid = 0;
	u32 pctrl = SMMUTE_PCTRL_NS;
	struct smmute_pframe *frame;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(smmute->dev);

	if (transaction->dma_in->task) {
		ssid = transaction->dma_in->task->ssid;
	}

	if (transaction->dma_out && transaction->dma_out->task) {
		BUG_ON(ssid != transaction->dma_out->task->ssid);
	}

	frame = smmute_privileged_frame(smmute->pairs, transaction->frame);

	if (dev_is_pci(smmute->dev) && to_pci_dev(smmute->dev)->ats_enabled)
		pctrl |= SMMUTE_PCTRL_ATS_EN;

	/*
	 * For a platform device, retrieve the stream ID. As this ID isn't
	 * virtualizable, we can't assign the platform device to a guest
	 */
	if (fwspec && fwspec->num_ids)
		sid = fwspec->ids[0];

	writel_relaxed(pctrl, &frame->pctrl);
	writel_relaxed(0, &frame->downstream_port_index);
	writel_relaxed(sid, &frame->streamid); /* Ignored for PCI */
	writel_relaxed(ssid ? ssid : SMMUTE_NO_SUBSTREAMID, &frame->substreamid);

	return frame;
}

static const char *smmute_transaction_state_name(enum smmute_transaction_state state)
{
	switch (state) {
	case TRANSACTION_READY:
		return "READY";
	case TRANSACTION_REGISTERED:
		return "REGISTERED";
	case TRANSACTION_INFLIGHT:
		return "INFLIGHT";
	case TRANSACTION_NOTIFIED:
		return "NOTIFIED";
	case TRANSACTION_FINISHED:
		return "FINISHED";
	case TRANSACTION_INVALID:
		return "INVALID";
	}

	return "???";
}

static void smmute_transaction_set_state(struct smmute_transaction *transaction,
					 enum smmute_transaction_state state)
{
	enum smmute_transaction_state prev_state;
	enum smmute_transaction_state expect = TRANSACTION_INVALID;

	switch (state) {
	case TRANSACTION_READY:
		expect = TRANSACTION_INVALID;
		trace_smmute_transaction_ready(transaction);
		break;

	case TRANSACTION_REGISTERED:
		expect = TRANSACTION_READY;
		break;

	case TRANSACTION_INFLIGHT:
		expect = TRANSACTION_REGISTERED;
		trace_smmute_transaction_launch(transaction);
		break;

	case TRANSACTION_NOTIFIED:
		expect = TRANSACTION_INFLIGHT;
		trace_smmute_transaction_notify(transaction);
		break;

	case TRANSACTION_FINISHED:
		expect = TRANSACTION_NOTIFIED;
		trace_smmute_transaction_finish(transaction);
		break;

	case TRANSACTION_INVALID:
		/*
		 * Don't WARN when unregistering a transaction that didn't
		 * succeed. INVALID can be reached from any state.
		 */
		expect = -1U;
		trace_smmute_transaction_retire(transaction);
		break;
	}

	prev_state = atomic_xchg(&transaction->state, state);

	WARN(!(prev_state & expect),
	     "Transaction %llu state was %s (%x), expected %x, new %s (%x)",
	     transaction->id, smmute_transaction_state_name(prev_state),
	     prev_state, expect, smmute_transaction_state_name(state), state);
}

/**
 * smmute_transaction_launch - start a transaction
 *
 * It is the caller's responsibility to keep track of the transaction and query
 * its status periodically. Once the transaction finished, it will (hopefully)
 * trigger an MSI, which will set the 'finished' status
 *
 * If start is false, only fill the engine frame, but don't write the command.
 *
 * Return 0 when the transaction was successfully launched.
 */
static int smmute_transaction_launch(struct smmute_device *smmute,
				     struct smmute_transaction *transaction,
				     bool start)
{
	struct smmute_uframe *user_frame;
	struct smmute_pframe *priv_frame;

	smmute_transaction_set_state(transaction, TRANSACTION_READY);

	priv_frame = smmute_priv_frame_init(smmute, transaction);
	if (IS_ERR(priv_frame)) {
		dev_dbg(smmute->dev, "init_priv_frame\n");
		return PTR_ERR(priv_frame);
	}

	user_frame = smmute_user_frame_init(smmute, transaction);
	if (IS_ERR(user_frame)) {
		dev_dbg(smmute->dev, "init_user_frame\n");
		return PTR_ERR(user_frame);
	}

	smmute_transaction_set_state(transaction, TRANSACTION_REGISTERED);
	if (!start)
		return 0;

	/*
	 * Start the workload. Assume frame is mapped with Dev-nGnRE
	 * attributes, through pci_iomap.
	 */
	smmute_transaction_set_state(transaction, TRANSACTION_INFLIGHT);
	/* writel() ensures buffers are initialized before issuing the command */
	writel(transaction->command, &user_frame->cmd);

	if (readl_relaxed(&user_frame->cmd) != transaction->command) {
		/*
		 * In case of engine error, no MSI will be generated.
		 * Alternatively, the test engine might have been super fast and
		 * the transaction finished already. Set notified state unless
		 * the MSI handler took care of it.
		 */
		if (smmute_msi_free(smmute, transaction))
			smmute_transaction_set_state(transaction,
						     TRANSACTION_NOTIFIED);
	}

	return 0;
}

/**
 * smmute_result_get - get transaction result
 *
 * When blocking is not set, sleep and wait for the transaction to finish.
 * Fill 'result' with status and resulting value (in case of a SUM op).
 *
 * return -EAGAIN if the transaction is not finished and 'blocking' is false
 * return 0 on success, which means that the transaction can be freed.
 */
static int smmute_result_get(struct smmute_file_desc *fd,
			     struct smmute_transaction *transaction,
			     struct smmute_transaction_result *result,
			     bool blocking)
{
	int ret;
	u32 status;
	struct smmute_uframe *frame;
	struct smmute_device *smmute = fd->smmute;

retry_wait:
	if (blocking) {
		/*
		 * Set a timeout to check periodically if the transaction
		 * finished without generating an MSI (due to a broken MSI
		 * setup, most likely.)
		 */
		ret = wait_event_interruptible_timeout(fd->transaction_wait,
				atomic_read(&transaction->state) != TRANSACTION_INFLIGHT,
				SMMUTE_POLL_DELAY);

		if (ret == -ERESTARTSYS) {
			/* task interrupted by a signal */
			return ret;
		}
	}

	frame = transaction->uframe;
	/* readl() orders read of cmd against subsequent reads from buffers */
	status = readl(&frame->cmd);
	if (status == transaction->command) {
		/* Transaction is still running */
		if (blocking)
			goto retry_wait;
		else
			return -EAGAIN;
	}

	/*
	 * If we missed the notification, change the state ourselves or else
	 * we'll get a WARN splat in the next state transition.
	 */
	if (smmute_msi_free(smmute, transaction)) {
		smmute_transaction_set_state(transaction, TRANSACTION_NOTIFIED);
		dev_warn(smmute->dev, "missed MSI for transaction %llu\n",
			 transaction->id);
	}
	smmute_transaction_set_state(transaction, TRANSACTION_FINISHED);

	result->value = 0;

	switch (status) {
	case ENGINE_HALTED:
		result->status = 0;
		result->value = readq_relaxed(frame->udata + 1);
		break;
	case ENGINE_ERROR:
		result->status = EIO;
		result->value = readq_relaxed(frame->udata + 2);
		break;
	case ENGINE_FRAME_MISCONFIGURED:
		result->status = EINVAL;
		break;
	default:
		result->status = EFAULT;
		break;
	}

	/*
	 * There is a small chance of getting false positives here. If the MSI
	 * is masked in the MSI-X table (being serviced by the handler), then
	 * the TestEngine sets MSI_ABORTED. I could observe this when MSIs were
	 * handed in a thread.
	 */
	if (readl_relaxed(&frame->uctrl) & SMMUTE_UCTRL_MSI_ABORTED)
		dev_warn(smmute->dev, "MSI aborted\n");

#ifdef DEBUG_USER_FRAMES
	smmute_uframe_dump(transaction->frame, frame);
#endif

	return 0;
}

/**
 * smmute_result_get_all - collect all transactions of a given file
 *
 * Wait for all transactions to finish, freeing them. This function will sleep
 * if something is running.
 *
 * return 0 when all transactions associated to this file have been queried
 */
static int smmute_result_get_all(struct smmute_file_desc *fd)
{
	int ret;
	struct smmute_transaction *transaction, *next;
	struct smmute_transaction_result result = {};

	/* The fd is being released, no need to take the lock. */
	list_for_each_entry_safe(transaction, next, &fd->transactions, list) {
		do {
			ret = smmute_result_get(fd, transaction, &result, true);
			if (ret) {
				/*
				 * Interrupted by a signal. Not wanting any
				 * leaks I'll just go ahead and ignore it.
				 */
				cond_resched();
			}
		} while (ret == -ERESTARTSYS);

		smmute_transaction_free(fd, transaction);
	}
	return ret;
}

void smmute_vm_close(struct vm_area_struct *vma)
{
	struct smmute_file_desc *fd;
	struct file *file = vma->vm_file;
	struct smmute_dma *dma = vma->vm_private_data;

	BUG_ON(!file);

	fd = file->private_data;

	BUG_ON(!fd);
	BUG_ON(!dma);

	mutex_lock(&fd->user_dma_mutex);
	list_del(&dma->list);
	mutex_unlock(&fd->user_dma_mutex);

	smmute_dma_put(dma);
}


struct vm_operations_struct smmute_vm_ops = {
	.close		= smmute_vm_close,
};

/**
 * smmute_open - allocate the resources needed by a file descriptor
 */
static int smmute_open(struct inode *inode, struct file *file)
{
	struct smmute_device *smmute;
	struct smmute_file_desc *fd;

	mutex_lock(&smmute_devices_mutex);
	list_for_each_entry(smmute, &smmute_devices, list) {
		if (smmute->minor == iminor(inode))
			break;
	}
	mutex_unlock(&smmute_devices_mutex);

	if (unlikely(&smmute->list == &smmute_devices)) {
		/* device not found */
		return -ENOENT;
	}

	fd = smmute_fd_alloc(smmute);
	if (!fd)
		return -ENOMEM;

	fd->file = file;
	file->private_data = fd;

	return 0;
}

static int smmute_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	void *kaddr;
	struct smmute_dma *dma;
	struct smmute_file_desc *fd = file->private_data;
	struct device *dev = fd->smmute->dev;
	size_t size = vma->vm_end - vma->vm_start;

	dma = smmute_dma_alloc_struct(fd);
	if (!dma)
		return -ENOMEM;

	/* TODO: Argh! How do we specify prot flags without re-implementing the
	 * whole lot? It currently just assumes RW (DMA_BIDIRECTIONAL) */
	kaddr = dma_alloc_attrs(dev, size, &dma->iova, GFP_USER, 0);
	if (!kaddr) {
		ret = -ENOMEM;
		goto err_free_struct_dma;
	}

	dma->size = size;
	dma->kaddr = kaddr;
	dma->uaddr = (void *)vma->vm_start;
	dma->mm = vma->vm_mm;

	ret = dma_mmap_attrs(dev, vma, kaddr, dma->iova, size, 0);
	if (ret)
		goto err_free_attrs;

	vma->vm_private_data = dma;
	vma->vm_ops = &smmute_vm_ops;

	mutex_lock(&fd->user_dma_mutex);
	list_add(&dma->list, &fd->user_dma);
	mutex_unlock(&fd->user_dma_mutex);

	return 0;

err_free_attrs:
	dma_free_attrs(dev, size, kaddr, dma->iova, 0);

err_free_struct_dma:
	smmute_dma_put(dma);

	return ret;
}

/*
 * smmute_dma_map_frame - map PCI config space with the iommu
 */
static struct smmute_dma *smmute_dma_map_frame(struct smmute_file_desc *fd,
					     size_t frame_idx)
{
	int ret;
	size_t size = sizeof(struct smmute_uframe);
	struct smmute_dma *dma;
	phys_addr_t phys_base, phys;
	dma_addr_t iova;

	struct smmute_device *smmute = fd->smmute;
	struct device *dev = smmute->dev;

	if (!dev_is_pci(dev))
		return NULL; /* TODO: platform */

	dma = smmute_dma_alloc_struct(fd);
	if (!dma)
		return NULL;

	/* Find out physical address of BAR0 */
	phys_base = pci_resource_start(to_pci_dev(dev), 0);

	/* Physical address of user frame */
	phys = (phys_addr_t)smmute_user_frame(phys_base, frame_idx);
	if (phys > pci_resource_end(to_pci_dev(dev), 0)) {
		dev_err(dev, "frame %zu is out of bounds\n", frame_idx);
		ret = -EFAULT;
		goto err_free;
	}

	iova = dma_map_resource(dev, phys, size, DMA_FROM_DEVICE, 0);
	if (dma_mapping_error(dev, iova)) {
		dev_err(dev, "mapping error\n");
		goto err_free;
	}

	dma->iova = iova;
	dma->size = size;

	return dma;

err_free:
	smmute_dma_put(dma);
	return ERR_PTR(ret);
}

/**
 * smmute_p2p_prepare - prepare secondary transaction
 *
 * Allocate a secondary transaction, connect transactions 1 and 2 by creating a
 * DMA mapping of one frame and using it as output region for the other.
 */
static int smmute_p2p_prepare(struct smmute_file_desc *fd,
			      struct smmute_transaction *transaction_1,
			      struct smmute_p2p_params *params)
{
	int ret;
	enum smmute_cmd *command_1, *command_2;
	struct smmute_dma *dma;
	struct smmute_transaction *transaction_2;

	transaction_2 = smmute_transaction_alloc(fd);
	if (!transaction_2)
		return -ENOMEM;

	dma = smmute_dma_get_user(fd, (void *)params->secondary.input_start,
				  params->secondary.size,
				  &transaction_2->offset_in,
				  params->secondary.flags & SMMUTE_FLAG_SVA);
	if (!dma) {
		ret = -ESRCH;
		goto err_free_transaction;
	}

	smmute_transaction_attach_dma(transaction_2, dma, DMA_TO_DEVICE);

	/*
	 * Note that for user mem, we're stuck here. There is no simple way to
	 * create mappings of physical stuff into userspace, so this will fail.
	 * Would be good to create a transaction "read unprivileged, write
	 * privileged"
	 *
	 * drive-by idea dump: vm_iomap_memory
	 */
	dma = smmute_dma_map_frame(fd, transaction_2->frame);
	if (IS_ERR(dma)) {
		dev_err(fd->smmute->dev, "failed to map frame %zu\n",
			transaction_2->frame);
		ret = PTR_ERR(dma);
		goto err_free_transaction;
	}
	smmute_transaction_attach_dma(transaction_1, dma, DMA_FROM_DEVICE);

	dma = smmute_dma_map_frame(fd, transaction_1->frame);
	if (IS_ERR(dma)) {
		dev_err(fd->smmute->dev, "failed to map frame %zu\n",
			transaction_1->frame);
		ret = PTR_ERR(dma);
		goto err_free_transaction;
	}
	smmute_transaction_attach_dma(transaction_2, dma, DMA_FROM_DEVICE);

	transaction_2->stride = params->secondary.stride;
	transaction_2->seed = params->secondary.seed;
	transaction_2->attr = params->secondary.attr;
	transaction_2->size = params->secondary.size;

	if (params->primary.size > 8) {
		/* Command must be written in one 64-bit access */
		dev_err(fd->smmute->dev, "erroneous size %llu\n",
			params->primary.size);
		ret = -EINVAL;
		goto err_free_transaction;
	}

	/*
	 * Register the transaction in the engine (fill the frame) but don't
	 * start it.
	 */
	ret = smmute_transaction_launch(fd->smmute, transaction_2, false);
	if (ret) {
		dev_err(fd->smmute->dev, "init transaction 2 failed\n");
		goto err_free_transaction;
	}

	if (params->secondary.flags & SMMUTE_FLAG_SVA) {
		command_1 = (void *)transaction_1->dma_in->iova +
			    transaction_1->offset_in;
		command_2 = (void *)transaction_2->dma_in->iova +
			    transaction_2->offset_in;

		put_user(ENGINE_MEMCPY, command_1);
		put_user(smmute_ioctl_to_command(params->command), command_2);
	} else {
		command_1 = transaction_1->dma_in->kaddr + transaction_1->offset_in;
		command_2 = transaction_2->dma_in->kaddr + transaction_2->offset_in;

		*command_1 = ENGINE_MEMCPY;
		*command_2 = smmute_ioctl_to_command(params->command);
	}


	/* for get_result, to match against the current frame status */
	transaction_2->command = ENGINE_MEMCPY;

	/* fake state change to avoid surprising the IRQ thread */
	smmute_transaction_set_state(transaction_2, TRANSACTION_INFLIGHT);

	/* pass secondary ID back to user */
	params->secondary.transaction_id = transaction_2->id;

	return 0;

err_free_transaction:
	smmute_transaction_free(fd, transaction_2);

	return ret;
}

static long smmute_transaction_ioctl(struct smmute_file_desc *fd,
				     unsigned int cmd, void *argp)
{
	long ret;
	size_t size;
	struct smmute_dma *dma;
	union smmute_transaction_params params;
	struct smmute_transaction *transaction;
	union smmute_transaction_params __user *up = argp;

	switch (cmd) {
	case SMMUTE_IOCTL_MEMCPY:
		size = sizeof(params.memcpy);
		break;
	case SMMUTE_IOCTL_P2P:
		size = sizeof(params.p2p);
		break;
	default:
		size = sizeof(params.common);
	}

	ret = copy_from_user(&params, up, size);
	if (ret)
		return -EFAULT;

	if (params.common.flags & ~SMMUTE_FLAG_MASK)
		return -EINVAL;

	transaction = smmute_transaction_alloc(fd);
	if (IS_ERR(transaction))
		return PTR_ERR(transaction);

	dma = smmute_dma_get_user(fd, (void *)params.common.input_start,
				  params.common.size, &transaction->offset_in,
				  params.common.flags & SMMUTE_FLAG_SVA);
	if (!dma) {
		ret = -ESRCH;
		goto err_free_transaction;
	}

	smmute_transaction_attach_dma(transaction, dma, DMA_TO_DEVICE);

	transaction->stride = params.common.stride;
	transaction->seed = params.common.seed;
	transaction->attr = params.common.attr;
	transaction->size = params.common.size;
	transaction->flags = params.common.flags;

	switch (cmd) {
	case SMMUTE_IOCTL_MEMCPY:
		transaction->command = ENGINE_MEMCPY;

		dma = smmute_dma_get_user(fd,
					  (void *)params.memcpy.output_start,
					  params.common.size,
					  &transaction->offset_out,
					  params.common.flags & SMMUTE_FLAG_SVA);
		if (!dma) {
			ret = -ESRCH;
			break;
		}

		smmute_transaction_attach_dma(transaction, dma, DMA_FROM_DEVICE);
		break;
	case SMMUTE_IOCTL_SUM64:
		transaction->command = ENGINE_SUM64;
		break;
	case SMMUTE_IOCTL_RAND48:
		transaction->command = ENGINE_RAND48;
		break;
	case SMMUTE_IOCTL_P2P:
		transaction->command = ENGINE_MEMCPY;

		if (params.p2p.secondary.flags & ~SMMUTE_FLAG_MASK)
			return -EINVAL;

		ret = smmute_p2p_prepare(fd, transaction, &params.p2p);
		if (ret)
			goto err_free_transaction;
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		goto err_free_transaction;

	ret = smmute_transaction_launch(fd->smmute, transaction, true);
	if (ret)
		goto err_free_transaction;

	params.common.transaction_id = transaction->id;
	ret = copy_to_user(up, &params, size);
	if (ret) {
		/*
		 * Transaction is launched, but we can't inform the user. Let's
		 * forget about it and let smmute_release deal with the mess.
		 */
		ret = -EFAULT;
	}

	return 0;

err_free_transaction:
	smmute_transaction_free(fd, transaction);

	return ret;
}

static long smmute_result_ioctl(struct smmute_file_desc *fd, void *argp)
{
	long ret;
	struct smmute_transaction *transaction;
	struct smmute_transaction_result result;

	ret = copy_from_user(&result, argp, sizeof(result));
	if (ret)
		return -EFAULT;

	ret = -ENOENT;
	mutex_lock(&fd->transactions_mutex);
	list_for_each_entry(transaction, &fd->transactions, list) {
		if (transaction->id == result.transaction_id) {
			ret = 0;
			break;
		}
	}
	mutex_unlock(&fd->transactions_mutex);
	if (ret)
		return ret;

	/* Will sleep if result.blocking is true */
	ret = smmute_result_get(fd, transaction, &result, result.blocking);
	if (ret)
		return ret;

	if (!result.keep)
		smmute_transaction_free(fd, transaction);

	ret = copy_to_user(argp, &result, sizeof(result));
	if (ret)
		return -EFAULT;

	return 0;
}

static long smmute_check_version(struct smmute_file_desc *fd, void __user *argp)
{
	int ret;
	struct smmute_version version;

	ret = copy_from_user(&version, argp, sizeof(version));
	if (ret)
		return -EFAULT;

	if (version.major > SMMUTE_VERSION_MAJOR ||
	    (version.major == SMMUTE_VERSION_MAJOR &&
	     version.minor > SMMUTE_VERSION_MINOR)) {
		dev_dbg(fd->smmute->dev,
			"user version %u.%u incompatible with our %u.%u\n",
			version.major, version.minor, SMMUTE_VERSION_MAJOR,
			SMMUTE_VERSION_MINOR);
		return -ENODEV;
	}

	version.major = SMMUTE_VERSION_MAJOR;
	version.minor = SMMUTE_VERSION_MINOR;

	ret = copy_to_user(argp, &version, sizeof(version));
	if (ret)
		return -EFAULT;

	return 0;
}

static long smmute_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void *argp = (void __user *)arg;
	struct smmute_file_desc *fd = file->private_data;

	switch (cmd) {
	case SMMUTE_IOCTL_VERSION:
		return smmute_check_version(fd, argp);
	case SMMUTE_IOCTL_GET_RESULT:
		return smmute_result_ioctl(fd, argp);
	case SMMUTE_IOCTL_BIND_TASK:
		return smmute_task_get(fd, NULL, __func__);
	case SMMUTE_IOCTL_UNBIND_TASK:
		smmute_task_put(fd, NULL, __func__);
		return 0;
	default:
		return smmute_transaction_ioctl(fd, cmd, argp);
	}
}

/**
 * smmute_release - release a file descriptor
 *
 * Free all transactions associated to it. We *have* to wait until they
 * finished, otherwise we might end up with the device sending spurious MSIs
 * and writing to unmapped pages, which is much more critical than zombifying a
 * process.
 *
 * FIXME: are we allowed to sleep here? What happens when we return an error?
 *        What happens when we loop indefinitely?
 */
static int smmute_release(struct inode *inode, struct file *file)
{
	struct smmute_file_desc *fd = file->private_data;

	smmute_result_get_all(fd);
	smmute_task_fd_put_all(fd);

	kset_unregister(fd->dma_regions);
	kobject_put(&fd->kobj);

	return 0;
}

static const struct file_operations smmute_fops = {
	.unlocked_ioctl		= smmute_ioctl,
	.mmap			= smmute_mmap,
	.open			= smmute_open,
	.release		= smmute_release,
};

static int smmute_pci_msi_enable(struct pci_dev *pdev)
{
	int ret, i;
	int nr_msis;
	struct smmute_device *smmute;
	struct msix_entry *entries;

	smmute = pci_get_drvdata(pdev);
	if (!smmute)
		return -EINVAL;

	dev_dbg(&pdev->dev, "max number of MSI-X vectors: %d\n",
			pci_msix_vec_count(pdev));

	nr_msis = min_t(size_t, SMMUTE_MAX_MSIS,
			smmute->nr_pairs * SMMUTE_FRAMES_PER_PAGE);
	entries = devm_kmalloc(&pdev->dev, sizeof(struct msix_entry) * nr_msis,
			       GFP_KERNEL);

	if (!entries) {
		dev_err(&pdev->dev, "could not allocate MSI-X entries\n");
		return -ENOMEM;
	}

	smmute->msix_entries = entries;

	for (i = 0; i < nr_msis; i++)
		entries[i].entry = i;

	ret = pci_enable_msix_range(pdev, entries, 1, nr_msis);
	if (ret <= 0) {
		devm_kfree(&pdev->dev, entries);
		return ret;
	}

	smmute->nr_msix_entries = ret;
	dev_dbg(&pdev->dev, "requested %d MSIs, got %d\n", nr_msis, ret);

	return 0;
}

static int smmute_init_msi_pool(struct smmute_device *smmute)
{
	int vec, ret, i;
	struct smmute_msi_pool *pool;
	int nr_pools = smmute->nr_msix_entries;

	smmute->msi_pools = devm_kcalloc(smmute->dev, nr_pools, sizeof(*pool),
					 GFP_KERNEL);
	if (!smmute->msi_pools)
		return -ENOMEM;

	for (i = 0; i < nr_pools; i++) {
		pool = &smmute->msi_pools[i];
		spin_lock_init(&pool->lock);
		INIT_LIST_HEAD(&pool->transactions);

		vec = smmute_get_msi_vector(smmute, i);
		ret = request_irq(vec, smmute_msi_handler, 0,
				  dev_name(smmute->dev), pool);
		if (ret)
			break;
	}

	return ret;
}

static void smmute_free_msi_pool(struct smmute_device *smmute)
{
	int i;

	/*
	 * Other resources are managed (freed automatically), but we don't use
	 * devm for MSIs, because they have to be unregistered before MSIs are
	 * freed by pci_disable_msix.
	 */
	for (i = 0; i < smmute->nr_msix_entries; i++)
		free_irq(smmute_get_msi_vector(smmute, i),
			 &smmute->msi_pools[i]);
}

static const int dev_features[] = {
	IOMMU_DEV_FEAT_IOPF,
	IOMMU_DEV_FEAT_SVA,
};
static const char *dev_feature_names[] = {
	"IOPF", "SVA",
};

static void smmute_enable_dev_features(struct smmute_device *smmute)
{
	int ret, i;
	struct device *dev = smmute->dev;

	for (i = 0; i < ARRAY_SIZE(dev_features); i++) {
		ret = iommu_dev_enable_feature(dev, dev_features[i]);
		if (ret) {
			dev_warn(dev, "failed to enable %s (%d)\n",
				 dev_feature_names[i], ret);
		} else {
			dev_info(dev, "enabled %s feature\n",
				 dev_feature_names[i]);

			smmute->dev_feat[i] = true;
		}
	}
}

static void smmute_disable_dev_features(struct smmute_device *smmute)
{
	int ret, i;
	struct device *dev = smmute->dev;

	for (i = ARRAY_SIZE(dev_features) - 1; i >= 0; i--) {
		if (!smmute->dev_feat[i])
			continue;
		ret = iommu_dev_disable_feature(dev, dev_features[i]);
		if (ret) {
			dev_err(dev, "failed to disable %s (%d)\n",
				 dev_feature_names[i], ret);
			continue;
		}
		dev_info(dev, "disabled %s feature\n", dev_feature_names[i]);
		smmute->dev_feat[i] = false;
	}
}

static int smmute_common_probe(struct smmute_device *smmute)
{
	int minor;
	size_t nr_frames;
	int ret = -ENOMEM;
	int cache_flags = 0;
	struct device *dev = smmute->dev;

#ifdef DEBUG
	/* prevents merging caches, allows to get stats from /proc/slabinfo */
	cache_flags = SLAB_POISON | SLAB_CONSISTENCY_CHECKS;
#endif

	mutex_init(&smmute->task_mutex);
	mutex_init(&smmute->resources_mutex);
	INIT_LIST_HEAD(&smmute->tasks);

	nr_frames = smmute->nr_pairs * SMMUTE_FRAMES_PER_PAGE;
	smmute->reserved_frames = devm_kzalloc(dev, BITS_TO_LONGS(nr_frames),
					       GFP_KERNEL);
	if (!smmute->reserved_frames)
		return ret;

	smmute->transaction_cache = kmem_cache_create("smmute_transactions",
			sizeof(struct smmute_transaction), 0, cache_flags, NULL);
	if (!smmute->transaction_cache)
		goto err_free_frames;

	smmute->dma_regions_cache = kmem_cache_create("smmute_dma_regions",
			sizeof(struct smmute_dma), 0, cache_flags, NULL);
	if (!smmute->dma_regions_cache)
		goto err_destroy_transaction_cache;

	smmute->file_desc_cache = kmem_cache_create("smmute_file_descs",
			sizeof(struct smmute_file_desc), 0, cache_flags, NULL);
	if (!smmute->file_desc_cache)
		goto err_destroy_dma_cache;

	minor = ida_simple_get(&smmute_minor_ida, 0, SMMUTE_MAX_DEVICES,
			       GFP_KERNEL);
	if (minor < 0) {
		dev_dbg(dev, "idr_alloc failed with %d\n", minor);
		goto err_destroy_fd_cache;
	}

	smmute->chrdev = device_create(smmute_class, dev,
			MKDEV(smmute_major, minor), smmute,
			"smmute%d", minor);
	if (IS_ERR(smmute->chrdev)) {
		dev_err(dev, "unable to create char dev (%d, %d)\n",
			smmute_major, minor);
		ret = PTR_ERR(smmute->chrdev);
		goto err_free_minor;
	}
	smmute->minor = minor;

	atomic64_set(&smmute->files_ida, 0);
	smmute->files_set = kset_create_and_add("files", NULL, &smmute->chrdev->kobj);
	if (!smmute->files_set)
		goto err_device_destroy;

	smmute->tasks_set = kset_create_and_add("tasks", NULL, &smmute->chrdev->kobj);
	if (!smmute->tasks_set)
		goto err_release_files;

	smmute_enable_dev_features(smmute);

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_warn(dev, "failed to set requested DMA mask\n");
		ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (ret) {
			dev_err(dev, "failed to set DMA mask\n");
			goto err_release_tasks;
		}
	}

	ret = smmute_init_msi_pool(smmute);
	if (ret)
		goto err_release_tasks;

	mutex_lock(&smmute_devices_mutex);
	list_add(&smmute->list, &smmute_devices);
	mutex_unlock(&smmute_devices_mutex);

	dev_info(dev, "has %zux2 pages of %zu frames\n", smmute->nr_pairs,
		 SMMUTE_FRAMES_PER_PAGE);

	/* TODO: self-test */

	return 0;

err_release_tasks:
	kset_unregister(smmute->tasks_set);
err_release_files:
	kset_unregister(smmute->files_set);
err_device_destroy:
	device_destroy(smmute_class, MKDEV(smmute_major, smmute->minor));
err_free_minor:
	ida_simple_remove(&smmute_minor_ida, minor);
err_destroy_fd_cache:
	kmem_cache_destroy(smmute->file_desc_cache);
err_destroy_dma_cache:
	kmem_cache_destroy(smmute->dma_regions_cache);
err_destroy_transaction_cache:
	kmem_cache_destroy(smmute->transaction_cache);
err_free_frames:
	devm_kfree(smmute->dev, smmute->reserved_frames);

	return ret;
}

static void smmute_common_remove(struct smmute_device *smmute)
{
	mutex_lock(&smmute_devices_mutex);
	list_del(&smmute->list);
	mutex_unlock(&smmute_devices_mutex);

	smmute_disable_dev_features(smmute);

	smmute_free_msi_pool(smmute);

	kset_unregister(smmute->tasks_set);
	kset_unregister(smmute->files_set);

	device_destroy(smmute_class, MKDEV(smmute_major, smmute->minor));

	ida_simple_remove(&smmute_minor_ida, smmute->minor);

	kmem_cache_destroy(smmute->transaction_cache);
	kmem_cache_destroy(smmute->dma_regions_cache);
	kmem_cache_destroy(smmute->file_desc_cache);

	devm_kfree(smmute->dev, smmute->reserved_frames);
}

static int smmute_pci_probe(struct pci_dev *pdev, const struct pci_device_id *devid)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct smmute_device *smmute;

	smmute = devm_kzalloc(dev, sizeof(struct smmute_device), GFP_KERNEL);
	if (!smmute) {
		dev_err(dev, "failed to allocate smmute device");
		return -ENOMEM;
	}

	pci_set_drvdata(pdev, smmute);
	smmute->dev = &pdev->dev;

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(dev, "failed to enable device\n");
		goto err_free_device;
	}

	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret) {
		dev_err(dev, "failed to obtain resources\n");
		goto err_disable_device;
	}

	smmute->pairs = pci_iomap(pdev, 0, 0);
	if (!smmute->pairs) {
		dev_err(&pdev->dev, "pci_iomap failed");
		goto err_release_regions;
	}

	smmute->nr_pairs = pci_resource_len(pdev, 0) / sizeof(*smmute->pairs);

	pci_set_master(pdev);

	ret = smmute_pci_msi_enable(pdev);
	if (ret)
		goto err_unmap_pairs;

	ret = smmute_common_probe(smmute);
	if (ret)
		goto err_disable_msi;

	return 0;

err_disable_msi:
	pci_disable_msix(pdev);
	devm_kfree(dev, smmute->msix_entries);
err_unmap_pairs:
	pci_iounmap(pdev, smmute->pairs);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
err_free_device:
	devm_kfree(dev, smmute);

	return ret;
}

static void smmute_pci_remove(struct pci_dev *pdev)
{
	struct smmute_device *smmute = pci_get_drvdata(pdev);

	/* TODO: cancel all in-flight transactions */

	if (smmute) {
		pci_iounmap(pdev, smmute->pairs);
		smmute_common_remove(smmute);
	}

	pci_disable_msix(pdev);
	pci_disable_device(pdev);
	pci_release_regions(pdev);
}

static void smmute_plat_write_msi_msg(struct msi_desc *desc,
				      struct msi_msg *msg)
{
	struct smmute_msi_info *entry;
	struct device *dev = msi_desc_to_dev(desc);
	struct smmute_device *smmute = dev_get_drvdata(dev);

	if (desc->msi_index >= smmute->nr_msix_entries) {
		dev_err(dev, "invalid MSI index\n");
		return;
	}

	entry = &smmute->plat_msi_entries[desc->msi_index];
	entry->doorbell = (((u64)msg->address_hi) << 32) | msg->address_lo;
	entry->data = msg->data;
}

static int smmute_plat_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct smmute_msi_info *msi_entries;
	struct smmute_device *smmute;
	struct resource *mem;
	unsigned long nr_msis = SMMUTE_MAX_MSIS;
	int ret = -ENOMEM;
	int i;

	smmute = devm_kzalloc(dev, sizeof(struct smmute_device), GFP_KERNEL);
	if (!smmute)
		return ret;

	smmute->dev = dev;
	platform_set_drvdata(pdev, smmute);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		dev_err(dev, "unable to get resource\n");
		goto err_free_device;
	}

	smmute->pairs = devm_ioremap_resource(&pdev->dev, mem);
	if (IS_ERR(smmute->pairs)) {
		ret = PTR_ERR(smmute->pairs);
		dev_err(dev, "unable to map resource\n");
		goto err_free_device;
	}

	smmute->nr_pairs = resource_size(mem) / sizeof(*smmute->pairs);

	ret = platform_msi_domain_alloc_irqs(dev, nr_msis,
					     smmute_plat_write_msi_msg);
	if (ret) {
		dev_err(dev, "cannot alloc IRQs\n");
		goto err_unmap_resource;
	}

	ret = -ENOMEM;
	msi_entries = devm_kmalloc(dev, sizeof(struct smmute_msi_info) *
				   nr_msis, GFP_KERNEL);
	if (!msi_entries)
		goto err_free_irqs;

	for (i = 0; i < nr_msis; i++)
		msi_entries[i].vector = msi_get_virq(dev, i);

	smmute->plat_msi_entries = msi_entries;
	smmute->nr_msix_entries = nr_msis;

	dev_dbg(dev, "has %d SIDs\n", dev_iommu_fwspec_get(dev)->num_ids);

	ret = smmute_common_probe(smmute);
	if (ret)
		goto err_free_entries;

	return 0;

err_free_entries:
	devm_kfree(dev, msi_entries);
err_free_irqs:
	platform_msi_domain_free_irqs(dev);
err_unmap_resource:
	devm_iounmap(dev, smmute->pairs);
err_free_device:
	devm_kfree(dev, smmute);

	return ret;
}

static int smmute_plat_remove(struct platform_device *pdev)
{
	struct smmute_device *smmute = platform_get_drvdata(pdev);

	if (!smmute)
		return 0;

	smmute_common_remove(smmute);
	platform_msi_domain_free_irqs(smmute->dev);
	devm_iounmap(smmute->dev, smmute->pairs);

	return 0;
}

static const struct pci_device_id smmute_id_table[] = {
	{ PCI_DEVICE(VENDOR_ID, DEVICE_ID) },
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, smmute_id_table);

static struct pci_driver smmute_pci_driver = {
	.name		= "smmute-pci",
	.id_table	= smmute_id_table,
	.probe		= smmute_pci_probe,
	.remove		= smmute_pci_remove,
};

static const struct of_device_id smmute_of_table[] = {
	{ .compatible = "arm,smmute" },
	{ }
};
MODULE_DEVICE_TABLE(of, smmute_of_table);

static struct platform_driver smmute_plat_driver = {
	.driver = {
		.name = "smmute-platform",
		.of_match_table = of_match_ptr(smmute_of_table),
	},
	.probe = smmute_plat_probe,
	.remove = smmute_plat_remove,
};

static int __init smmute_init(void)
{
	int ret;
	dev_t dev_id;

	ret = alloc_chrdev_region(&dev_id, SMMUTE_FIRST_MINOR,
			SMMUTE_MAX_DEVICES, "smmute");
	if (ret)
		return ret;

	smmute_major = MAJOR(dev_id);

	smmute_class = class_create("smmute");
	if (IS_ERR(smmute_class)) {
		ret = PTR_ERR(smmute_class);
		goto out_unregister_chrdev;
	}

	cdev_init(&smmute_cdev, &smmute_fops);
	ret = cdev_add(&smmute_cdev, dev_id, SMMUTE_MAX_DEVICES);
	if (ret)
		goto out_class_destroy;

	ret = pci_register_driver(&smmute_pci_driver);
	if (ret)
		goto out_cdev_del;

	ret = platform_driver_register(&smmute_plat_driver);
	if (ret)
		goto out_unregister;

	return 0;

out_unregister:
	pci_unregister_driver(&smmute_pci_driver);
out_cdev_del:
	cdev_del(&smmute_cdev);
out_class_destroy:
	class_destroy(smmute_class);
out_unregister_chrdev:
	unregister_chrdev_region(dev_id, SMMUTE_MAX_DEVICES);
	pr_err("init failed with %d\n", ret);
	return ret;
}

static void __exit smmute_exit(void)
{
	dev_t dev_id = MKDEV(smmute_major, 0);

	platform_driver_unregister(&smmute_plat_driver);
	pci_unregister_driver(&smmute_pci_driver);

	cdev_del(&smmute_cdev);
	class_destroy(smmute_class);
	unregister_chrdev_region(dev_id, SMMUTE_MAX_DEVICES);
}

module_init(smmute_init);
module_exit(smmute_exit);

MODULE_DESCRIPTION("Driver for the SMMU Test Engine");
MODULE_AUTHOR("Jean-Philippe Brucker <jean-philippe.brucker@arm.com>");
MODULE_LICENSE("GPL v2");
