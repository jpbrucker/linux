/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TOPOLOGY_HELPERS_H_
#define TOPOLOGY_HELPERS_H_

#ifdef CONFIG_VIRTIO_IOMMU_TOPOLOGY_HELPERS

/* Identify a device node in the topology */
struct virt_topo_dev_id {
	unsigned int			type;
#define VIRT_TOPO_DEV_TYPE_PCI		1
#define VIRT_TOPO_DEV_TYPE_MMIO		2
	union {
		/* PCI endpoint or range */
		struct {
			u16		segment;
			u16		bdf_start;
			u16		bdf_end;
		};
		/* MMIO region */
		u64			base;
	};
};

/* Specification of an IOMMU */
struct virt_topo_iommu {
	struct virt_topo_dev_id		dev_id;
	struct device			*dev; /* transport device */
	struct fwnode_handle		*fwnode;
	struct iommu_ops		*ops;
	struct list_head		list;
};

/* Specification of an endpoint */
struct virt_topo_endpoint {
	struct virt_topo_dev_id		dev_id;
	u32				endpoint_id;
	struct virt_topo_iommu		*viommu;
	struct list_head		list;
};

void virt_topo_add_endpoint(struct virt_topo_endpoint *ep);
void virt_topo_add_iommu(struct virt_topo_iommu *viommu);

void virt_topo_set_iommu_ops(struct device *dev, struct iommu_ops *ops);

#else /* !CONFIG_VIRTIO_IOMMU_TOPOLOGY_HELPERS */
static inline void virt_topo_set_iommu_ops(struct device *dev, struct iommu_ops *ops)
{ }
#endif /* !CONFIG_VIRTIO_IOMMU_TOPOLOGY_HELPERS */
#endif /* TOPOLOGY_HELPERS_H_ */
