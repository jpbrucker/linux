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
	struct list_head		list_domain;
	struct list_head		fds;
	struct mutex			domain_mutex;
	struct vhost_iommu_domain	*domain;
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
	struct rb_root			rbroot_domain;
	/* Protect rbtree and endpoints updates */
	struct mutex			mutex;
	struct vhost_virtqueue		vq_req;
	struct vhost_virtqueue		vq_evt;
	char				buf[VHOST_IOMMU_MAX_REQ_LEN];
	bool				running;
};

struct vhost_iommu_domain {
	struct vhost_iommu_device	*vi;
	struct vhost_iotlb		*mappings;
	struct mutex			mappings_mutex;
	struct rb_node			node;
	struct list_head		endpoints;
	uint32_t			id;
	struct kref			kref;
};

static struct vhost_iotlb_map *
vhost_iommu_domain_translate(struct vhost_iommu_domain *domain, u64 addr,
			     u64 end, int access)
{
	struct vhost_iotlb_map *map;

	lockdep_assert_held(&domain->mappings_mutex);

	map = vhost_iotlb_itree_first(domain->mappings, addr, end);
	if (!map || vhost_access_denied(access, map->perm)) {
		if (map)
			pr_debug("%s: permission fault got %x want %x\n",
				 __func__, map->perm, access);
		return NULL;
	}

	/* TODO: Enqueue page fault if necessary */

	return map;
}

static struct vhost_iotlb_map *vhost_iommu_translate(struct vhost_virtqueue *vq,
						     u64 addr, u64 len, int access)
{
	int ret;
	off_t off;
	u64 last = addr + len - 1;
	struct vhost_iotlb_map *map, *user_map, *new;
	struct vhost_iommu_endpoint *ep = vq->dev->iommu_cookie;

	lockdep_assert_held(&vq->mutex); /* Endpoint vq */

	/*
	 * ep is not going away while we hold vq->mutex.
	 * For now we rely on domain_mutex to synchronize against detach()
	 */
	mutex_lock(&ep->domain_mutex);
	if (!ep || !ep->domain) {
		/* TODO: allow bypass if enabled */
		vq_err(vq, "translation fault: no ep/domain\n");
		mutex_unlock(&ep->domain_mutex);
		return NULL;
	}

	mutex_lock(&ep->domain->mappings_mutex);
	map = vhost_iommu_domain_translate(ep->domain, addr, last, access);
	/*
	 * It's allowed for the mapping not to cover the end of the range.
	 * Caller will retry for the rest of the range.
	 */
	if (!map || WARN_ON(addr < map->start)) {
		vq_err(vq, "translation fault: no mapping for 0x%llx\n", addr);
		goto err_unlock;
	} else if (vhost_access_denied(access, map->perm)) { /* FIXME: parent returns NULL */
		vq_err(vq, "permission fault at 0x%llx\n", addr);
		goto err_unlock;
	}

	/* Great, we found the IOVA->GPA translation. Now find GPA->HVA. */
	user_map = vhost_iotlb_itree_first(vq->umem, map->addr,
					   map->addr + map->size - 1);
	if (!user_map) {
		vq_err(vq, "translation fault: no user mapping\n");
		goto err_unlock;
	} else if (vhost_access_denied(access, user_map->perm)) {
		vq_err(vq, "permission fault at 0x%llx (user)\n", addr);
		goto err_unlock;
	}

	/*
	 * For the moment, assume that the second-stage mapping contains all of
	 * the first one. If it didn't we'd just need to loop over the GPA
	 * range, but I'm feeling lazy and optimistic at the moment.
	 *
	 * The reasons we're using the device iotlb instead of directly
	 * modifying the mappings tree:
	 * - We'd need to update mappings here to add the gva, and a
	 *  'translated' flag.
	 * - We'd need to split mappings if multiple user_map cover this
	 *   gpa range.
	 * - User is allowed to switch umem at runtime, which will require to
	 *   invalidate the IOTLB (TODO). If we implemented the two points
	 *   above, there is no way we could roll back when umem gets switched.
	 */
	if (WARN_ON(user_map->start > map->addr ||
		    user_map->last < map->addr + map->size - 1))
		goto err_unlock;

	off = map->addr - user_map->start;
	ret = vhost_iotlb_add_range(vq->dev->iotlb, map->start, map->last,
			      user_map->addr + off, map->perm & user_map->perm);
	if (WARN_ON(ret))
		goto err_unlock;

	mutex_unlock(&ep->domain->mappings_mutex);
	mutex_unlock(&ep->domain_mutex);

	/* FIXME: faster to return the map we just allocated */
	new = vhost_iotlb_itree_first(vq->dev->iotlb, addr, last);
	WARN(!new, "%llx %llx - %llx %llx\n", addr, last, map->start, map->last);
	return new;

err_unlock:
	mutex_unlock(&ep->domain->mappings_mutex);
	mutex_unlock(&ep->domain_mutex);
	return NULL;
}

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

static struct vhost_iommu_domain *
vhost_iommu_find_domain(struct vhost_iommu_device *vi, uint32_t domain_id)
{
	struct vhost_iommu_domain *domain;
	struct rb_node *node = vi->rbroot_domain.rb_node;

	lockdep_assert_held(&vi->mutex);

	while (node) {
		domain = rb_entry(node, struct vhost_iommu_domain, node);

		if (domain->id > domain_id) {
			node = node->rb_left;
		} else if (domain->id < domain_id) {
			node = node->rb_right;
		} else {
			kref_get(&domain->kref);
			return domain;
		}
	}
	return NULL;
}

static void vhost_iommu_remove_domain(struct kref *kref);

static void vhost_iommu_put_domain(struct vhost_iommu_device *vi,
				   struct vhost_iommu_domain *domain)
{
	kref_put(&domain->kref, vhost_iommu_remove_domain);
}

static void vhost_iommu_inval_mapping(struct vhost_iommu_domain *domain,
				      uint64_t start, uint64_t last)
{
	struct vhost_iommu_endpoint_fd *epfd;
	struct vhost_iommu_endpoint *ep;
	struct vhost_iotlb_map *map;
	struct vhost_dev *vdev;
	int i;

	/*
	 * Can't hold the mappings mutex while invalidating, since it is taken
	 * in reverse order by translate() while holding vq->mutex. So take
	 * vq->mutex instead.
	 */
	lockdep_assert_held(&domain->vi->mutex);

	list_for_each_entry(ep, &domain->endpoints, list_domain) {
		list_for_each_entry(epfd, &ep->fds, list) {
			vdev = epfd->dev;

			for (i = 0; i < vdev->nvqs; ++i)
				mutex_lock_nested(&vdev->vqs[i]->mutex, i);

			while ((map = vhost_iotlb_itree_first(vdev->iotlb, start, last)) != NULL) {
				vhost_iotlb_map_free(vdev->iotlb, map);
				/*
				 * map is freed, but this function doesn't dereference
				 * it, only compares pointers.
				 */
				vhost_vq_meta_inval(vdev, map);
			}

			for (i = 0; i < vdev->nvqs; ++i)
				mutex_unlock(&vdev->vqs[i]->mutex);
		}
	}
}

static void vhost_iommu_inval_ep_all(struct vhost_iommu_endpoint *ep)
{
	struct vhost_dev *vdev;
	struct vhost_iommu_endpoint_fd *epfd;

	/* Invalidate endpoints IOTLBs */
	list_for_each_entry(epfd, &ep->fds, list) {
		vdev = epfd->dev;

		vhost_dev_lock_vqs(vdev);
		vhost_vq_meta_reset(vdev);
		vhost_iotlb_reset(vdev->iotlb);
		vhost_dev_unlock_vqs(vdev);
	}
}

static int vhost_iommu_handle_map(struct vhost_iommu_device *vi,
				  struct vhost_virtqueue *vq,
				  struct virtio_iommu_req_map *req)
{
	uint64_t phys_start, virt_start, virt_end;
	struct vhost_iommu_domain *domain;
	uint32_t domain_id, flags, perm;
	int ret;

	domain_id = vhost32_to_cpu(vq, req->domain);
	phys_start = vhost64_to_cpu(vq, req->phys_start);
	virt_start = vhost64_to_cpu(vq, req->virt_start);
	virt_end = vhost64_to_cpu(vq, req->virt_end);
	flags = vhost32_to_cpu(vq, req->flags);
	// TODO: check alignment

	if (flags & ~VIRTIO_IOMMU_MAP_F_MASK)
		return VIRTIO_IOMMU_S_INVAL;

	domain = vhost_iommu_find_domain(vi, domain_id);
	if (!domain)
		return VIRTIO_IOMMU_S_NOENT;

	perm = (flags & VIRTIO_IOMMU_MAP_F_READ ? VHOST_ACCESS_RO : 0) |
	       (flags & VIRTIO_IOMMU_MAP_F_WRITE ? VHOST_ACCESS_WO : 0) |
	       (flags & VIRTIO_IOMMU_MAP_F_MMIO ? VHOST_ACCESS_MMIO : 0);

	mutex_lock(&domain->mappings_mutex);
	if (vhost_iotlb_itree_first(domain->mappings, virt_start, virt_end)) {
		ret = VIRTIO_IOMMU_S_INVAL;
		goto out_unlock;
	}

	ret = vhost_iotlb_add_range(domain->mappings, virt_start, virt_end,
				    phys_start, perm);
	if (ret) {
		ret = VIRTIO_IOMMU_S_INVAL;
		goto out_unlock;
	}

	ret = VIRTIO_IOMMU_S_OK;
out_unlock:
	mutex_unlock(&domain->mappings_mutex);
	vhost_iommu_put_domain(vi, domain);

	return ret;
}

static int vhost_iommu_handle_unmap(struct vhost_iommu_device *vi,
				    struct vhost_virtqueue *vq,
				    struct virtio_iommu_req_unmap *req)
{
	uint64_t virt_start, virt_end, size;
	struct vhost_iommu_domain *domain;
	struct vhost_iotlb_map *map;
	uint32_t domain_id;
	int ret = VIRTIO_IOMMU_S_OK;

	domain_id = vhost32_to_cpu(vq, req->domain);
	virt_start = vhost64_to_cpu(vq, req->virt_start);
	virt_end = vhost64_to_cpu(vq, req->virt_end);
	size = virt_end - virt_start + 1;

	domain = vhost_iommu_find_domain(vi, domain_id);
	if (!domain)
		return VIRTIO_IOMMU_S_NOENT;

	mutex_lock(&domain->mappings_mutex);
	map = vhost_iotlb_itree_first(domain->mappings, virt_start, virt_end);
	if (!map) {
		ret = VIRTIO_IOMMU_S_OK;
		goto err_unlock;
	}

	while (map) {
		if (virt_start > map->start || virt_end < map->last) {
			/* Removing part of a mapping is not allowed */
			ret = VIRTIO_IOMMU_S_INVAL;
			break;
		}
		vhost_iotlb_map_free(domain->mappings, map);

		map = vhost_iotlb_itree_first(domain->mappings, virt_start,
					      virt_end);
	}
	mutex_unlock(&domain->mappings_mutex);

	vhost_iommu_inval_mapping(domain, virt_start, virt_end);

	vhost_iommu_put_domain(vi, domain);
	return ret;

err_unlock:
	mutex_unlock(&domain->mappings_mutex);
	vhost_iommu_put_domain(vi, domain);
	return ret;
}

static int vhost_iommu_insert_domain(struct vhost_iommu_device *vi,
				     struct vhost_iommu_domain *new_domain)
{
	struct rb_node **link = &vi->rbroot_domain.rb_node, *parent = NULL;
	uint32_t domain_id = new_domain->id;
	struct vhost_iommu_domain *domain;

	lockdep_assert_held(&vi->mutex);

	/* Go to the bottom of the tree */
	while (*link) {
		parent = *link;
		domain = rb_entry(parent, struct vhost_iommu_domain, node);

		if (domain->id > domain_id)
			link = &(*link)->rb_left;
		else if (domain->id < domain_id)
			link = &(*link)->rb_right;
		else
			return -EEXIST;
	}

	/* Put the new node there */
	rb_link_node(&new_domain->node, parent, link);
	rb_insert_color(&new_domain->node, &vi->rbroot_domain);
	return 0;
}

static struct vhost_iommu_domain *
vhost_iommu_get_domain(struct vhost_iommu_device *vi, uint32_t domain_id)
{
	struct vhost_iommu_domain *domain;

	domain = vhost_iommu_find_domain(vi, domain_id);
	if (domain)
		return domain;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	domain->vi = vi;
	domain->id = domain_id;
	domain->mappings = vhost_iotlb_alloc(0, 0);
	mutex_init(&domain->mappings_mutex);
	INIT_LIST_HEAD(&domain->endpoints);
	kref_init(&domain->kref);

	if (WARN_ON(vhost_iommu_insert_domain(vi, domain))) {
		kfree(domain);
		return NULL;
	}
	return domain;
}

static void vhost_iommu_remove_domain(struct kref *kref)
{
	struct vhost_iommu_domain *domain = container_of(kref,
					 struct vhost_iommu_domain, kref);
	struct vhost_iommu_device *vi = domain->vi;

	lockdep_assert_held(&vi->mutex);

	vhost_iotlb_free(domain->mappings);
	rb_erase(&domain->node, &vi->rbroot_domain);
	kfree(domain);
}

static int vhost_iommu_detach_endpoint(struct vhost_iommu_device *vi,
				       struct vhost_iommu_endpoint *ep)
{
	struct vhost_iommu_domain *domain = ep->domain;

	if (!domain)
		return 0;

	pr_debug("%s d=%x\n", __func__, domain->id);

	mutex_lock(&ep->domain_mutex); /* Sync against translate() */
	ep->domain = NULL;
	mutex_unlock(&ep->domain_mutex);

	vhost_iommu_inval_ep_all(ep);

	list_del(&ep->list_domain);
	vhost_iommu_put_domain(vi, domain);
	return 0;
}

static int vhost_iommu_handle_attach(struct vhost_iommu_device *vi,
				     struct vhost_virtqueue *vq,
				     struct virtio_iommu_req_attach *req)
{
	uint32_t domain_id, epid;
	struct vhost_iommu_endpoint *ep;
	struct vhost_iommu_domain *domain;

	domain_id = vhost32_to_cpu(vq, req->domain);
	epid = vhost32_to_cpu(vq, req->endpoint);

	pr_debug("%s e=%x d=%x\n", __func__, epid, domain_id);

	ep = vhost_iommu_get_endpoint(vi, epid);
	if (!ep) {
		pr_debug("%s no ep\n", __func__);
		return VIRTIO_IOMMU_S_NOENT;
	}

	domain = vhost_iommu_get_domain(vi, domain_id);
	if (!domain) {
		pr_debug("%s no domain\n", __func__);
		return VIRTIO_IOMMU_S_NOENT;
	}

	if (vhost_iommu_detach_endpoint(vi, ep)) {
		vhost_iommu_put_domain(vi, domain);
		return VIRTIO_IOMMU_S_DEVERR;
	}

	mutex_lock(&ep->domain_mutex);
	/* Holds reference to domain */
	ep->domain = domain;
	mutex_unlock(&ep->domain_mutex);

	list_add(&ep->list_domain, &domain->endpoints);

	return VIRTIO_IOMMU_S_OK;
}

static int vhost_iommu_handle_detach(struct vhost_iommu_device *vi,
				     struct vhost_virtqueue *vq,
				     struct virtio_iommu_req_detach *req)
{
	uint32_t epid;
	struct vhost_iommu_endpoint *ep;

	epid = vhost32_to_cpu(vq, req->endpoint);
	pr_debug("%s e=%x\n", __func__, epid);

	ep = vhost_iommu_get_endpoint(vi, epid);
	if (!ep)
		return VIRTIO_IOMMU_S_NOENT;

	if (vhost_iommu_detach_endpoint(vi, ep))
		return VIRTIO_IOMMU_S_NOENT;

	return VIRTIO_IOMMU_S_OK;
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
		case VIRTIO_IOMMU_T_ATTACH:
			resp_tail.status = vhost_iommu_handle_attach(vi, vq, buf);
			break;
		case VIRTIO_IOMMU_T_DETACH:
			resp_tail.status = vhost_iommu_handle_detach(vi, vq, buf);
			break;
		case VIRTIO_IOMMU_T_MAP:
			resp_tail.status = vhost_iommu_handle_map(vi, vq, buf);
			break;
		case VIRTIO_IOMMU_T_UNMAP:
			resp_tail.status = vhost_iommu_handle_unmap(vi, vq, buf);
			break;
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
			vhost_dev_set_iommu(epfd->dev, NULL, NULL);
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
		vhost_dev_set_iommu(epfd->dev, NULL, NULL);
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
	vhost_dev_set_iommu(epfd->dev, vhost_iommu_translate, ep);
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
	 * vhost_dev_set_iommu() must synchronize against translate().
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
		mutex_init(&ep->domain_mutex);
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
	vhost_iommu_detach_endpoint(vi, ep);
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
	struct vhost_iommu_domain *domain, *next_domain;

	mutex_lock(&vi->mutex);
	/* Drop all endpoints */
	list_for_each_entry_safe(ep, next_ep, &vi->endpoints, list_iommu)
		vhost_iommu_remove_endpoint(vi, ep);

	rbtree_postorder_for_each_entry_safe(domain, next_domain,
					     &vi->rbroot_domain, node) {
		/*
		 * Since we detached all endpoints, there shouldn't be any
		 * domain left
		 */
		WARN_ON_ONCE(1);
		vhost_iommu_put_domain(vi, domain);
	}
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
	struct vhost_iommu_endpoint *ep;

	vhost_iommu_stop_vq(vi, &vi->vq_req);
	vhost_iommu_stop_vq(vi, &vi->vq_evt);

	mutex_lock(&vi->mutex);
	list_for_each_entry(ep, &vi->endpoints, list_iommu)
		vhost_iommu_detach_endpoint(vi, ep);

	WARN_ON_ONCE(rb_first(&vi->rbroot_domain));
	mutex_unlock(&vi->mutex);

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
	vi->rbroot_domain = RB_ROOT;
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
