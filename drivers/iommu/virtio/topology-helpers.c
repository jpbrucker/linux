// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/dma-iommu.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/virt_iommu.h>

#include "topology-helpers.h"

static LIST_HEAD(viommus);
static LIST_HEAD(pci_endpoints);
static LIST_HEAD(mmio_endpoints);
static DEFINE_MUTEX(viommus_lock);

static bool virt_topo_device_match(struct device *dev,
				   struct virt_topo_dev_id *id)
{
	if (id->type == VIRT_TOPO_DEV_TYPE_PCI && dev_is_pci(dev)) {
		struct pci_dev *pdev = to_pci_dev(dev);
		u16 dev_id = pci_dev_id(pdev);

		return pci_domain_nr(pdev->bus) == id->segment &&
			dev_id >= id->bdf_start &&
			dev_id <= id->bdf_end;
	} else if (id->type == VIRT_TOPO_DEV_TYPE_MMIO &&
		   dev_is_platform(dev)) {
		struct platform_device *plat_dev = to_platform_device(dev);
		struct resource *mem;

		mem = platform_get_resource(plat_dev, IORESOURCE_MEM, 0);
		if (!mem)
			return false;
		return mem->start == id->base;
	}
	return false;
}

static const struct iommu_ops *virt_iommu_setup(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct virt_topo_iommu *viommu = NULL;
	struct virt_topo_endpoint *ep;
	struct pci_dev *pci_dev = NULL;
	u32 epid;
	int ret;

	/* Already translated? */
	if (fwspec && fwspec->ops)
		return NULL;

	mutex_lock(&viommus_lock);
	if (dev_is_pci(dev)) {
		pci_dev = to_pci_dev(dev);
		list_for_each_entry(ep, &pci_endpoints, list) {
			if (virt_topo_device_match(dev, &ep->dev_id)) {
				epid = pci_dev_id(pci_dev) -
					ep->dev_id.bdf_start +
					ep->endpoint_id;
				viommu = ep->viommu;
				break;
			}
		}
	} else if (dev_is_platform(dev)) {
		list_for_each_entry(ep, &mmio_endpoints, list) {
			if (virt_topo_device_match(dev, &ep->dev_id)) {
				epid = ep->endpoint_id;
				viommu = ep->viommu;
				break;
			}
		}
	}
	mutex_unlock(&viommus_lock);
	if (!viommu)
		return NULL;

	/* We're not translating ourselves. */
	if (virt_topo_device_match(dev, &viommu->dev_id) ||
	    dev == viommu->dev)
		return NULL;

	/*
	 * If we found a PCI range managed by the viommu, we're the one that has
	 * to request ACS.
	 */
	if (pci_dev)
		pci_request_acs();

	if (!viommu->ops)
		return ERR_PTR(-EPROBE_DEFER);

	ret = iommu_fwspec_init(dev, viommu->fwnode, viommu->ops);
	if (ret)
		return ERR_PTR(ret);

	iommu_fwspec_add_ids(dev, &epid, 1);

	return viommu->ops;
}

/**
 * virt_topo_add_endpoint - Register endpoint specification
 * @ep: the endpoint specification
 */
void virt_topo_add_endpoint(struct virt_topo_endpoint *ep)
{
	mutex_lock(&viommus_lock);
	list_add(&ep->list,
		 ep->dev_id.type == VIRT_TOPO_DEV_TYPE_MMIO ?
		 &mmio_endpoints : &pci_endpoints);
	mutex_unlock(&viommus_lock);
}

/**
 * virt_topo_add_iommu - Register IOMMU specification
 * @viommu: the IOMMU specification
 */
void virt_topo_add_iommu(struct virt_topo_iommu *viommu)
{
	mutex_lock(&viommus_lock);
	list_add(&viommu->list, &viommus);
	mutex_unlock(&viommus_lock);
}

/**
 * virt_dma_configure - Configure DMA of virtualized devices
 * @dev: the endpoint
 *
 * Setup the DMA and IOMMU ops of a virtual device, for platforms without DT or
 * ACPI.
 *
 * Return: -EPROBE_DEFER if the device is managed by an IOMMU that hasn't been
 *   probed yet, 0 otherwise
 */
int virt_dma_configure(struct device *dev)
{
	const struct iommu_ops *iommu_ops;

	iommu_ops = virt_iommu_setup(dev);
	if (IS_ERR_OR_NULL(iommu_ops)) {
		int ret = PTR_ERR(iommu_ops);

		if (ret == -EPROBE_DEFER || ret == 0)
			return ret;
		dev_err(dev, "error %d while setting up virt IOMMU\n", ret);
		return 0;
	}

	/*
	 * If we have reason to believe the IOMMU driver missed the initial
	 * add_device callback for dev, replay it to get things in order.
	 */
	if (dev->bus && !device_iommu_mapped(dev))
		iommu_probe_device(dev);

	/* Assume coherent, as well as full 64-bit addresses. */
#ifdef CONFIG_ARCH_HAS_SETUP_DMA_OPS
	arch_setup_dma_ops(dev, 0, ~0ULL, iommu_ops, true);
#else
	iommu_setup_dma_ops(dev, 0, ~0ULL);
#endif
	return 0;
}

/**
 * virt_topo_set_iommu_ops - Set the IOMMU ops of a virtual IOMMU device
 * @dev: the IOMMU device (transport)
 * @ops: the new IOMMU ops or NULL
 *
 * Setup the iommu_ops associated to an IOMMU, once the driver is loaded
 * and the device probed.
 */
void virt_topo_set_iommu_ops(struct device *dev, struct iommu_ops *ops)
{
	struct virt_topo_iommu *viommu;

	mutex_lock(&viommus_lock);
	list_for_each_entry(viommu, &viommus, list) {
		/*
		 * In case the topology driver didn't have a dev handle when
		 * registering the topology, add it now.
		 */
		if (!viommu->dev &&
		    virt_topo_device_match(dev, &viommu->dev_id))
			viommu->dev = dev;

		if (viommu->dev == dev) {
			viommu->ops = ops;
			viommu->fwnode = ops ? dev->fwnode : NULL;
			break;
		}
	}
	mutex_unlock(&viommus_lock);
}
EXPORT_SYMBOL_GPL(virt_topo_set_iommu_ops);
