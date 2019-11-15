// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/io-64-nonatomic-hi-lo.h>
#include <linux/iopoll.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <uapi/linux/virtio_config.h>
#include <uapi/linux/virtio_iommu.h>

#include "topology-helpers.h"

struct viommu_cap_config {
	u8 bar;
	u32 length; /* structure size */
	u32 offset; /* structure offset within the BAR */
};

struct viommu_topo_header {
	u8 type;
	u8 reserved;
	u16 length;
};

static struct virt_topo_endpoint *
viommu_parse_node(void __iomem *buf, size_t len)
{
	int ret = -EINVAL;
	union {
		struct viommu_topo_header hdr;
		struct virtio_iommu_topo_pci_range pci;
		struct virtio_iommu_topo_mmio mmio;
	} __iomem *cfg = buf;
	struct virt_topo_endpoint *spec;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return ERR_PTR(-ENOMEM);

	switch (ioread8(&cfg->hdr.type)) {
	case VIRTIO_IOMMU_TOPO_PCI_RANGE:
		if (len < sizeof(cfg->pci))
			goto err_free;

		spec->dev_id.type = VIRT_TOPO_DEV_TYPE_PCI;
		spec->dev_id.segment = ioread16(&cfg->pci.segment);
		spec->dev_id.bdf_start = ioread16(&cfg->pci.bdf_start);
		spec->dev_id.bdf_end = ioread16(&cfg->pci.bdf_end);
		spec->endpoint_id = ioread32(&cfg->pci.endpoint_start);
		break;
	case VIRTIO_IOMMU_TOPO_MMIO:
		if (len < sizeof(cfg->mmio))
			goto err_free;

		spec->dev_id.type = VIRT_TOPO_DEV_TYPE_MMIO;
		spec->dev_id.base = ioread64(&cfg->mmio.address);
		spec->endpoint_id = ioread32(&cfg->mmio.endpoint);
		break;
	default:
		pr_warn("unhandled format 0x%x\n", ioread8(&cfg->hdr.type));
		ret = 0;
		goto err_free;
	}
	return spec;

err_free:
	kfree(spec);
	return ERR_PTR(ret);
}

static int viommu_parse_topology(struct device *dev,
				 struct virtio_iommu_config __iomem *cfg,
				 size_t max_len)
{
	int ret;
	u16 len;
	size_t i;
	LIST_HEAD(endpoints);
	size_t offset, count;
	struct virt_topo_iommu *viommu;
	struct virt_topo_endpoint *ep, *next;
	struct viommu_topo_header __iomem *cur;

	offset = ioread16(&cfg->topo_config.offset);
	count = ioread16(&cfg->topo_config.count);
	if (!offset || !count)
		return 0;

	viommu = kzalloc(sizeof(*viommu), GFP_KERNEL);
	if (!viommu)
		return -ENOMEM;

	viommu->dev = dev;

	for (i = 0; i < count; i++, offset += len) {
		if (offset + sizeof(*cur) > max_len) {
			ret = -EOVERFLOW;
			goto err_free;
		}

		cur = (void __iomem *)cfg + offset;
		len = ioread16(&cur->length);
		if (offset + len > max_len) {
			ret = -EOVERFLOW;
			goto err_free;
		}

		ep = viommu_parse_node((void __iomem *)cur, len);
		if (!ep) {
			continue;
		} else if (IS_ERR(ep)) {
			ret = PTR_ERR(ep);
			goto err_free;
		}

		ep->viommu = viommu;
		list_add(&ep->list, &endpoints);
	}

	list_for_each_entry_safe(ep, next, &endpoints, list)
		/* Moves ep to the helpers list */
		virt_topo_add_endpoint(ep);
	virt_topo_add_iommu(viommu);

	return 0;
err_free:
	list_for_each_entry_safe(ep, next, &endpoints, list)
		kfree(ep);
	kfree(viommu);
	return ret;
}

#define VPCI_FIELD(field) offsetof(struct virtio_pci_cap, field)

static int viommu_pci_find_capability(struct pci_dev *dev, u8 cfg_type,
				      struct viommu_cap_config *cap)
{
	int pos;
	u8 bar;

	for (pos = pci_find_capability(dev, PCI_CAP_ID_VNDR);
	     pos > 0;
	     pos = pci_find_next_capability(dev, pos, PCI_CAP_ID_VNDR)) {
		u8 type;

		pci_read_config_byte(dev, pos + VPCI_FIELD(cfg_type), &type);
		if (type != cfg_type)
			continue;

		pci_read_config_byte(dev, pos + VPCI_FIELD(bar), &bar);

		/* Ignore structures with reserved BAR values */
		if (type != VIRTIO_PCI_CAP_PCI_CFG && bar > 0x5)
			continue;

		cap->bar = bar;
		pci_read_config_dword(dev, pos + VPCI_FIELD(length),
				      &cap->length);
		pci_read_config_dword(dev, pos + VPCI_FIELD(offset),
				      &cap->offset);

		return pos;
	}
	return 0;
}

static int viommu_pci_reset(struct virtio_pci_common_cfg __iomem *cfg)
{
	u8 status;
	ktime_t timeout = ktime_add_ms(ktime_get(), 100);

	iowrite8(0, &cfg->device_status);
	while ((status = ioread8(&cfg->device_status)) != 0 &&
	       ktime_before(ktime_get(), timeout))
		msleep(1);

	return status ? -ETIMEDOUT : 0;
}

static void viommu_pci_parse_topology(struct pci_dev *dev)
{
	int ret;
	u32 features;
	void __iomem *regs, *common_regs;
	struct viommu_cap_config cap = {0};
	struct virtio_pci_common_cfg __iomem *common_cfg;

	/*
	 * The virtio infrastructure might not be loaded at this point. We need
	 * to access the BARs ourselves.
	 */
	ret = viommu_pci_find_capability(dev, VIRTIO_PCI_CAP_COMMON_CFG, &cap);
	if (!ret) {
		pci_warn(dev, "virtio-pci common cfg capability not found\n");
		return;
	}

	if (pci_enable_device_mem(dev))
		return;

	common_regs = pci_iomap(dev, cap.bar, 0);
	if (!common_regs)
		return;

	common_cfg = common_regs + cap.offset;

	/* Perform the init sequence before we can read the config */
	ret = viommu_pci_reset(common_cfg);
	if (ret < 0) {
		pci_warn(dev, "unable to reset device\n");
		goto out_unmap_common;
	}

	iowrite8(VIRTIO_CONFIG_S_ACKNOWLEDGE, &common_cfg->device_status);
	iowrite8(VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER,
		 &common_cfg->device_status);

	/* Find out if the device supports topology description */
	iowrite32(0, &common_cfg->device_feature_select);
	features = ioread32(&common_cfg->device_feature);

	if (!(features & BIT(VIRTIO_IOMMU_F_TOPOLOGY))) {
		pci_dbg(dev, "device doesn't have topology description");
		goto out_reset;
	}

	ret = viommu_pci_find_capability(dev, VIRTIO_PCI_CAP_DEVICE_CFG, &cap);
	if (!ret) {
		pci_warn(dev, "device config capability not found\n");
		goto out_reset;
	}

	regs = pci_iomap(dev, cap.bar, 0);
	if (!regs)
		goto out_reset;

	pci_info(dev, "parsing virtio-iommu topology\n");
	ret = viommu_parse_topology(&dev->dev, regs + cap.offset,
				    pci_resource_len(dev, 0) - cap.offset);
	if (ret)
		pci_warn(dev, "failed to parse topology: %d\n", ret);

	pci_iounmap(dev, regs);
out_reset:
	ret = viommu_pci_reset(common_cfg);
	if (ret)
		pci_warn(dev, "unable to reset device\n");
out_unmap_common:
	pci_iounmap(dev, common_regs);
}

/*
 * Catch a PCI virtio-iommu implementation early to get the topology description
 * before we start probing other endpoints.
 */
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1040 + VIRTIO_ID_IOMMU,
			viommu_pci_parse_topology);
