// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 Semihalf sp. z o.o.
 * Copyright (C) 2021 Linaro ltd.
 *
 * Author: Tomasz Nowicki <tn@semihalf.com>
 *         Jean-Philippe Brucker <jean-philippe@linaro.org>
 *
 * virtio-iommu accelerator in host kernel.
 *
 * Locking hierarchy:
 * - vhost_dev.mutex protects global vhost_dev state and vhost_iommu_device state.
 *  - vhost_virtqueue.mutex protects virtqueue state
 *   - vhost_dev_iommu_device.mutex protects 'endpoints' list
 * On the vhost endpoint side:
 * (- vhost_dev.mutex protects endpoint IOTLB)
 *  - vhost_virtqueue.mutex protects endpoint and meta IOTLB (avail, used and
 *    descriptor ring addresses)
 *
 * Synchronizing the various invalidations (unmap, invalidate, detach, release
 * endpoint or IOMMU) against access use the endpoint's vq->mutex, which
 * requires annotating the nested locking with VHOST_IOMMU_MUTEX_CLASS. We take
 * the endpoint's vq mutex while holding the IOMMU's vq mutex.
 */
#define pr_fmt(fmt) "vhost-iommu: " fmt

#include <linux/compat.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/virtio_iommu.h>

#include "vhost.h"

/*
 * Operations of the vhost-iommu, and locking notes.
 * - Translate:
 *   - vhost endpoints performs DMA while holding their vq->mutex.
 *     - meta_iotlb holds avail, used and descriptor ring addresses for each vq
 *     - endpoint IOTLB
 *   - userspace endpoints use the VHOST_IOMMU_XLATE ioctl
 *   - both take the domain->mappings_mutex
 *   - User memory dev->umem can be accessed while holding the endpoint
 *     vq->mutex
 * - virtio-iommu requests are handled while holding the vhost-iommu vq->mutex.
 *   The VHOST_IOMMU_MUTEX_CLASS lets lockdep know that this isn't the same
 *   vq->mutex that we take to invalidate vhost endpoint's IOTLBs
 * - unmap, detach, unregister endpoint and release vhost-iommu all need to
 *   invalidate those TLBs, which requires taking the endpoint's vq->mutex to
 *   synchronize against concurrent access.
 * - Since we manage the endpoint IOTLB, we rely on domain->mappings_mutex for
 *   synchronization.
 * - modification of vi->rbroot_domain and vi->endpoints take the vi->mutex.
 * - modification of domain->mappings takes the domain->mappings_mutex.
 * - access also takes those mutexes at the moment. The interval tree that
 *   stores mappings is not scalable or RCU-safe at the moment, but perhaps
 *   we'll move to maple tree in the future.
 */
#define VHOST_IOMMU_MUTEX_CLASS	7

/*
 * Max number of requests before requeuing the job.
 * Using this limit prevents one virtqueue from starving others with requests.
 */
#define VHOST_IOMMU_WEIGHT 256

enum {
    VHOST_IOMMU_VQ_REQUEST = 0,
    VHOST_IOMMU_VQ_EVENT = 1,
    VHOST_IOMMU_VQ_MAX = 2,
};

enum {
	VHOST_IOMMU_FEATURES = VHOST_FEATURES |
				(1ULL << VIRTIO_IOMMU_F_INPUT_RANGE) |
				(1ULL << VIRTIO_IOMMU_F_MAP_UNMAP)
};

#define VHOST_IOMMU_MAX_REQ_LEN	0x1000
/* Max size of a probe request */
#define VHOST_IOMMU_PROBE_SIZE 1024

struct vhost_iommu_endpoint {
	struct list_head		list_iommu;
	struct list_head		fds;
	void				*probe_buffer;
	uint32_t			probe_size;
	uint32_t			epid;
};

struct vhost_iommu_endpoint_fd {
	struct list_head		list;
	struct vhost_dev		*dev;
	int				fd;
};

struct vhost_iommu_device {
	struct vhost_dev		dev;
	struct list_head		endpoints;
	/* Protect rbtree and endpoints updates */
	struct mutex			mutex;
	struct vhost_virtqueue		vq_req;
	struct vhost_virtqueue		vq_evt;
	char				buf[VHOST_IOMMU_MAX_REQ_LEN];
	bool				running;
};

static struct vhost_iommu_endpoint *
vhost_iommu_get_endpoint(struct vhost_iommu_device *vi, uint32_t epid)
{
	struct vhost_iommu_endpoint *ep;

	lockdep_assert_held(&vi->mutex);

	list_for_each_entry(ep, &vi->endpoints, list_iommu) {
		if (ep->epid == epid)
			return ep;
	}
	return NULL;
}

static int vhost_iommu_handle_probe(struct vhost_iommu_device *vi,
				    struct vhost_virtqueue *vq, uint8_t *buf,
				    size_t buf_size,
				    struct virtio_iommu_req_probe *req)
{
	struct vhost_iommu_endpoint *ep;
	int ret = VIRTIO_IOMMU_S_OK;
	uint32_t epid;

	epid = vhost32_to_cpu(vq, req->endpoint);

	/* TODO check reserved */

	ep = vhost_iommu_get_endpoint(vi, epid);
	if (!ep)
		return VIRTIO_IOMMU_S_NOENT;

	if (ep->probe_size && ep->probe_size <= buf_size)
		memcpy(buf, ep->probe_buffer, ep->probe_size);
	else if (ep->probe_size)
		ret = VIRTIO_IOMMU_S_IOERR;

	return ret;
}

static void vhost_iommu_handle_req(struct vhost_iommu_device *vi,
				   struct vhost_virtqueue *vq)
{
	size_t req_sz, resp_tail_sz, out_sz, in_sz, payload_sz, sz;
	struct virtio_iommu_req_tail resp_tail;
	struct virtio_iommu_req_head *req;
	struct iov_iter out_iter, in_iter;
	unsigned int out = 0, in = 0;
	void *buf = vi->buf;
	int request_count = 0;
	int head;

	req = buf;
	req_sz = sizeof(struct virtio_iommu_req_head);
	resp_tail_sz = sizeof(struct virtio_iommu_req_tail);

	/*
	 * Response structure: |---response payload---|---resp_tail---|
	 *      payload_ptr ----^
	 * Payload exists for PROBE request only (see below), hence we push out
	 * response in two stages, first payload (if necessary) and then tail
	 * with operation status.
	 */
	payload_sz = 0;

	mutex_lock(&vi->mutex);
	mutex_lock_nested(&vq->mutex, VHOST_IOMMU_MUTEX_CLASS);
	vhost_disable_notify(&vi->dev, vq);

	do {
		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);
		if (unlikely(head < 0))
			break;

		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&vi->dev, vq))) {
				vhost_disable_notify(&vi->dev, vq);
				continue;
			}
			break;
		}

		out_sz = iov_length(vq->iov, out);
		in_sz = iov_length(&vq->iov[out], in);
		if (unlikely(out_sz < req_sz ||
			     out_sz > VHOST_IOMMU_MAX_REQ_LEN)) {
			vq_err(vq, "invalid request size\n");
			break;
		}

		iov_iter_init(&out_iter, WRITE, vq->iov, out, out_sz);
		if (unlikely(!copy_from_iter_full(buf, out_sz, &out_iter))) {
			vq_err(vq, "invalid out iter\n");
			break;
		}

		if (unlikely(in_sz < resp_tail_sz)) {
			vq_err(vq, "invalid tail size\n");
			break;
		}
		iov_iter_init(&in_iter, READ, &vq->iov[out], in, in_sz);

		switch (req->type) {
		case VIRTIO_IOMMU_T_PROBE: {
			uint8_t *payload_ptr;

			payload_sz = in_sz - resp_tail_sz;
			if (!payload_sz || payload_sz > VHOST_IOMMU_PROBE_SIZE) {
				vq_err(vq, "PROBE: invalid payload size\n");
				resp_tail.status = VIRTIO_IOMMU_S_INVAL;
				break;
			}
			payload_ptr = kzalloc(payload_sz, GFP_KERNEL);
			if (!payload_ptr) {
				iov_iter_advance(&in_iter, payload_sz);
				resp_tail.status = VIRTIO_IOMMU_S_INVAL;
				break;
			}

			resp_tail.status = vhost_iommu_handle_probe(vi, vq,
					    payload_ptr, payload_sz, buf);

			sz = copy_to_iter(payload_ptr, payload_sz, &in_iter);
			if (unlikely(sz != payload_sz)) {
				vq_err(vq, "PROBE: writeback failure\n");
				/* FIXME: where's iter at? */
				resp_tail.status = VIRTIO_IOMMU_S_INVAL;
			}

			kfree(payload_ptr);
		        break;
		}
		default:
			resp_tail.status = VIRTIO_IOMMU_S_UNSUPP;
		}

		/* Push out tail only */
		sz = copy_to_iter(&resp_tail, resp_tail_sz, &in_iter);
		if (unlikely(sz != resp_tail_sz)) {
			vq_err(vq, "invalid writeback size\n");
			break;
		}

		/* TODO some batching? */
		vhost_add_used_and_signal(&vi->dev, vq, head, in_sz);
	} while (!vhost_exceeds_weight(vq, ++request_count, 0));
	mutex_unlock(&vq->mutex);
	mutex_unlock(&vi->mutex);
}

static void vhost_iommu_handle_req_work(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_iommu_device *vi = container_of(vq->dev,
					     struct vhost_iommu_device, dev);

	vhost_iommu_handle_req(vi, vq);
}

/*
 * Add or remove the probe buffer for this endpoint.
 * On success @buf and @size contain the new buffer.
 */
static int vhost_iommu_prepare_probe(struct vhost_iommu_device *vi,
				     struct vhost_iommu_endpoint *ep,
				     struct vhost_iommu_register_endpoint *cfg,
				     void **buf, u32 *size)
{
	void __user *ubuf;

	if (!(cfg->flags & VHOST_IOMMU_SET_PROBE_BUFFER)) {
		*buf = ep->probe_buffer;
		*size = ep->probe_size;
		return 0;
	}

	ubuf = (void __user *)cfg->probe_buffer;
	if (!ubuf) {
		*buf = NULL;
		*size = 0;
		return 0;
	}

	if (!cfg->probe_size || cfg->probe_size > VHOST_IOMMU_PROBE_SIZE)
		return -EINVAL;

	*size = cfg->probe_size;
	*buf = kzalloc(*size, GFP_KERNEL);
	if (!*buf)
		return -ENOMEM;

	if (copy_from_user(*buf, ubuf, *size)) {
		kfree(*buf);
		return -EFAULT;
	}
	return 0;
}

static int vhost_iommu_remove_endpoint_fd(struct vhost_iommu_device *vi,
					  struct vhost_iommu_endpoint *ep,
					  int fd)
{
	struct vhost_iommu_endpoint_fd *epfd;

	list_for_each_entry(epfd, &ep->fds, list) {
		if (epfd->fd == fd) {
			list_del(&epfd->list);
			kfree(epfd);

			return 0;
		}
	}

	return -ESRCH;
}

static void vhost_iommu_remove_all_endpoint_fds(struct vhost_iommu_device *vi,
						struct vhost_iommu_endpoint *ep)
{
	struct vhost_iommu_endpoint_fd *epfd, *next_epfd;

	list_for_each_entry_safe(epfd, next_epfd, &ep->fds, list) {
		list_del(&epfd->list);
		kfree(epfd);
	}
}

static int vhost_iommu_update_endpoint_fd(struct vhost_iommu_device *vi,
					  struct vhost_iommu_endpoint *ep,
					  struct vhost_iommu_register_endpoint *cfg)
{
	int ret = 0;
	struct file *file;
	struct vhost_iommu_endpoint_fd *epfd;
	u32 mask = VHOST_IOMMU_ADD_FD | VHOST_IOMMU_DEL_FD;

	if (!(cfg->flags & mask))
		return 0;

	if ((cfg->flags & mask) == mask)
		return -EINVAL;

	if (cfg->flags & VHOST_IOMMU_DEL_FD)
		return vhost_iommu_remove_endpoint_fd(vi, ep, cfg->fd);

	list_for_each_entry(epfd, &ep->fds, list) {
		if (epfd->fd == cfg->fd)
			return -EEXIST;
	}

	file = fget(cfg->fd);
	if (!file)
		return -ENOENT;

	epfd = kzalloc(sizeof(*epfd), GFP_KERNEL);
	if (!epfd) {
		ret = -ENOMEM;
		goto out_fput;
	}

	/* FIXME: lifetime of this thing. When file is released, dev disappears */
	epfd->fd = cfg->fd;
	epfd->dev = vhost_net_get_dev(file);
	if (!epfd->dev) {
		ret = -EBADF;
		kfree(epfd);
		goto out_fput;
	}

	list_add(&epfd->list, &ep->fds);
out_fput:
	fput(file);
	return ret;
}

/*
 * Create a new endpoint or update an existing one from config.
 */
static int vhost_iommu_register_endpoint(struct vhost_iommu_device *vi,
					 struct vhost_iommu_register_endpoint *cfg)
{
	int ret = 0;
	u32 new_probe_size;
	void *new_probe_buffer;
	struct vhost_iommu_endpoint *ep, *old_ep;

	/*
	 * No concurrent attach/detach/register.
	 * But concurrent translate(), so beware!
	 */
	mutex_lock(&vi->mutex);

	ep = old_ep = vhost_iommu_get_endpoint(vi, cfg->id);
	if (!ep) {
		ep = kzalloc(sizeof(*ep), GFP_KERNEL);
		if (!ep) {
			ret = -ENOMEM;
			goto err_unlock;
		}

		ep->epid = cfg->id;
		INIT_LIST_HEAD(&ep->fds);
	}

	/* Prepare probe buffer, don't commit yet */
	ret = vhost_iommu_prepare_probe(vi, ep, cfg, &new_probe_buffer,
					&new_probe_size);
	if (ret)
		goto err_free;

	ret = vhost_iommu_update_endpoint_fd(vi, ep, cfg);
	if (ret)
		goto err_free;

	ep->probe_buffer = new_probe_buffer;
	ep->probe_size = new_probe_size;
	if (ep != old_ep)
		list_add(&ep->list_iommu, &vi->endpoints);

	mutex_unlock(&vi->mutex);
	return 0;

err_free:
	if (new_probe_buffer && new_probe_buffer != ep->probe_buffer)
		kfree(new_probe_buffer);
	if (ep != old_ep)
		kfree(ep);
err_unlock:
	mutex_unlock(&vi->mutex);
	return ret;
}

static void vhost_iommu_remove_endpoint(struct vhost_iommu_device *vi,
					struct vhost_iommu_endpoint *ep)
{
	vhost_iommu_remove_all_endpoint_fds(vi, ep);
	list_del(&ep->list_iommu);
	kfree(ep->probe_buffer);
	kfree(ep);
}

static int vhost_iommu_unregister_endpoint(struct vhost_iommu_device *vi,
					   struct vhost_iommu_register_endpoint *cfg)
{
	struct vhost_iommu_endpoint *ep;

	/* TODO: test this */
	WARN(1, "Remove me, this path now tested\n");
	if (cfg->flags & ~VHOST_IOMMU_UNREGISTER_ENDPOINT)
		return -EINVAL;

	mutex_lock(&vi->mutex);
	ep = vhost_iommu_get_endpoint(vi, cfg->id);
	if (!ep) {
		mutex_unlock(&vi->mutex);
		return 0;
	}

	vhost_iommu_remove_endpoint(vi, ep);
	mutex_unlock(&vi->mutex);
	return 0;
}

/*
 * Assumes
 * - no concurrent request
 * - no new request
 */
static void vhost_iommu_cleanup(struct vhost_iommu_device *vi)
{
	struct vhost_iommu_endpoint *ep, *next_ep;

	mutex_lock(&vi->mutex);
	/* Drop all endpoints */
	list_for_each_entry_safe(ep, next_ep, &vi->endpoints, list_iommu)
		vhost_iommu_remove_endpoint(vi, ep);
	mutex_unlock(&vi->mutex);
}


static int vhost_iommu_start_vq(struct vhost_iommu_device *vi,
				struct vhost_virtqueue *vq)
{
	int ret;

	mutex_lock(&vq->mutex);
	vhost_vq_set_backend(vq, vi);
	ret = vhost_vq_init_access(vq);
	if (ret)
		vhost_vq_set_backend(vq, NULL);
	mutex_unlock(&vq->mutex);
	return ret;
}

static void vhost_iommu_stop_vq(struct vhost_iommu_device *vi,
				struct vhost_virtqueue *vq)
{
	mutex_lock(&vq->mutex);
	vhost_vq_set_backend(vq, NULL);
	mutex_unlock(&vq->mutex);
}

static void vhost_iommu_stop_vq_poll(struct vhost_iommu_device *vi,
				     struct vhost_virtqueue *vq)
{
	mutex_lock(&vq->mutex);
	vhost_poll_stop(&vq->poll);
	mutex_unlock(&vq->mutex);
}

static void vhost_iommu_flush(struct vhost_iommu_device *vi)
{
	vhost_dev_flush(&vi->dev);
}

static int vhost_iommu_start(struct vhost_iommu_device *vi)
{
	int ret;

	ret = vhost_iommu_start_vq(vi, &vi->vq_req);
	if (ret)
		return ret;

	ret = vhost_iommu_start_vq(vi, &vi->vq_evt);
	if (ret) {
		vhost_iommu_stop_vq(vi, &vi->vq_req);
		return ret;
	}

	vi->running = true;
	return 0;
}

static int vhost_iommu_stop(struct vhost_iommu_device *vi)
{
	vhost_iommu_stop_vq(vi, &vi->vq_req);
	vhost_iommu_stop_vq(vi, &vi->vq_evt);
	vi->running = false;
	return 0;
}

static int vhost_iommu_set_status(struct vhost_iommu_device *vi, u8 status)
{
	int ret;
	bool start;

	start = status & VIRTIO_CONFIG_S_DRIVER_OK;
	if (vi->running == start)
		return 0;

	if (start)
		ret = vhost_iommu_start(vi);
	else
		ret = vhost_iommu_stop(vi);
	return ret;
}

static int vhost_iommu_set_features(struct vhost_iommu_device *vi, u64 features)
{
	struct vhost_virtqueue *vq;

	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vi->dev))
		return -EFAULT;

	vq = &vi->vq_req;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	vq = &vi->vq_evt;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	return 0;
}

static int vhost_iommu_reset_owner(struct vhost_iommu_device *vi)
{
	int ret;
	struct vhost_iotlb *umem;

	ret = vhost_dev_check_owner(&vi->dev);
	if (ret)
		return ret;

	umem = vhost_dev_reset_owner_prepare();
	if (!umem)
		return -ENOMEM;

	vhost_iommu_stop_vq_poll(vi, &vi->vq_req);
	vhost_iommu_stop_vq_poll(vi, &vi->vq_evt);
	vhost_iommu_flush(vi);
	vhost_iommu_cleanup(vi);

	vhost_dev_reset_owner(&vi->dev, umem);

	return 0;
}

static long vhost_iommu_ioctl(struct file *f, unsigned int ioctl,
			      unsigned long arg)
{
	struct vhost_iommu_device *vi = f->private_data;
	struct vhost_iommu_register_endpoint ep;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	u8 status;
	int ret = 0;

	pr_debug("%s n:0x%x d:0x%x t:0x%x s:%d\n", __func__, _IOC_NR(ioctl),
		 _IOC_DIR(ioctl), _IOC_TYPE(ioctl), _IOC_SIZE(ioctl));

	mutex_lock(&vi->dev.mutex);
	switch (ioctl) {
	case VHOST_IOMMU_REGISTER_ENDPOINT:
		if (copy_from_user(&ep, argp, sizeof(ep))) {
			ret = -EFAULT;
			break;
		}

		if (ep.flags & VHOST_IOMMU_UNREGISTER_ENDPOINT)
			ret = vhost_iommu_unregister_endpoint(vi, &ep);
		else
			ret = vhost_iommu_register_endpoint(vi, &ep);
		break;
	case VHOST_IOMMU_SET_STATUS:
		if (copy_from_user(&status, argp, sizeof(status))) {
			ret = -EFAULT;
			break;
		}
		ret = vhost_iommu_set_status(vi, status);
		break;
	case VHOST_GET_FEATURES:
		features = VHOST_IOMMU_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			ret = -EFAULT;
		break;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features))) {
			ret = -EFAULT;
			break;
		}
		ret = vhost_iommu_set_features(vi, features);
		break;
	case VHOST_RESET_OWNER:
		/* TODO: test this */
		WARN(1, "Remove me, this path is now tested\n");
		ret = vhost_iommu_reset_owner(vi);
		break;
	default:
		ret = vhost_dev_ioctl(&vi->dev, ioctl, argp);
		if (ret == -ENOIOCTLCMD)
			ret = vhost_vring_ioctl(&vi->dev, ioctl, argp);
	}
	mutex_unlock(&vi->dev.mutex);
	return ret;
}

static int vhost_iommu_open(struct inode *inode, struct file *f)
{
	struct vhost_iommu_device *vi;
	struct vhost_virtqueue **vqs;
	struct vhost_dev *dev;

	vi = kzalloc(sizeof(*vi), GFP_KERNEL);
	if (!vi)
		return -ENOMEM;

	vqs = kcalloc(VHOST_IOMMU_VQ_MAX, sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kfree(vi);
		return -ENOMEM;
	}

	dev = &vi->dev;
	INIT_LIST_HEAD(&vi->endpoints);
	mutex_init(&vi->mutex);
	vqs[VHOST_IOMMU_VQ_REQUEST] = &vi->vq_req;
	vqs[VHOST_IOMMU_VQ_EVENT] = &vi->vq_evt;
	vi->vq_req.handle_kick = vhost_iommu_handle_req_work;
	vhost_dev_init(dev, vqs, VHOST_IOMMU_VQ_MAX, UIO_MAXIOV,
		       VHOST_IOMMU_WEIGHT, 0, true, NULL);

	f->private_data = vi;

	return 0;
}

static int vhost_iommu_release(struct inode *inode, struct file *f)
{
	struct vhost_iommu_device *vi = f->private_data;

	vhost_iommu_stop_vq_poll(vi, &vi->vq_req);
	vhost_iommu_stop_vq_poll(vi, &vi->vq_evt);
	vhost_iommu_flush(vi);
	vhost_iommu_cleanup(vi);

	vhost_dev_stop(&vi->dev);
	vhost_dev_cleanup(&vi->dev);

	/* Make sure no callbacks are outstanding */
	//synchronize_rcu();
	kfree(vi->dev.vqs);
	kfree(vi);
	return 0;
}

#ifdef CONFIG_COMPAT
static long vhost_iommu_compat_ioctl(struct file *f, unsigned int ioctl,
				     unsigned long arg)
{
	return vhost_iommu_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_iommu_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_iommu_release,
	.unlocked_ioctl = vhost_iommu_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_iommu_compat_ioctl,
#endif
	.open           = vhost_iommu_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_iommu_misc = {
	.minor = VHOST_IOMMU_MINOR,
	.name = "vhost-iommu",
	.fops = &vhost_iommu_fops,
};

static int vhost_iommu_init(void)
{
	return misc_register(&vhost_iommu_misc);
}
module_init(vhost_iommu_init);

static void vhost_iommu_exit(void)
{
	/* FIXME: Also remove all IOMMU ops!
	 * How do we make sure IOMMU is removed after endpoints?
	 */
	misc_deregister(&vhost_iommu_misc);
}
module_exit(vhost_iommu_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tomasz Nowicki");
MODULE_AUTHOR("Jean-Philippe Brucker");
MODULE_DESCRIPTION("Host kernel accelerator for virtio iommu");
MODULE_ALIAS_MISCDEV(VHOST_IOMMU_MINOR);
MODULE_ALIAS("devname:vhost-iommu");
