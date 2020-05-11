/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VIRT_IOMMU_H_
#define VIRT_IOMMU_H_

#ifdef CONFIG_VIRTIO_IOMMU_TOPOLOGY_HELPERS
int virt_dma_configure(struct device *dev);

#else /* !CONFIG_VIRTIO_IOMMU_TOPOLOGY_HELPERS */
static inline int virt_dma_configure(struct device *dev)
{
	/* Don't disturb the normal DMA configuration methods */
	return 0;
}
#endif /* !CONFIG_VIRTIO_IOMMU_TOPOLOGY_HELPERS */
#endif /* VIRT_IOMMU_H_ */
