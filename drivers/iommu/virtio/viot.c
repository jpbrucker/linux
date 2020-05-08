// SPDX-License-Identifier: GPL-2.0
/*
 * Virtual I/O topology
 */
#define pr_fmt(fmt) "ACPI: VIOT: " fmt

#include <linux/acpi_viot.h>
#include <linux/fwnode.h>
#include <linux/list.h>

#include "topology-helpers.h"

/* Keep track of IOMMU nodes already visited, while parsing. */
struct viot_iommu {
	struct virt_topo_iommu spec;
	struct list_head list;
	unsigned int offset;
};

static struct acpi_table_viot *viot;
static LIST_HEAD(iommus);

static int viot_check_bounds(const struct acpi_viot_node *node)
{
	struct acpi_viot_node *start, *end;

	start = ACPI_ADD_PTR(struct acpi_viot_node, viot, viot->node_offset);
	end = ACPI_ADD_PTR(struct acpi_viot_node, viot, viot->header.length);

	if (node < start || node >= end) {
		pr_err("Node pointer overflows, bad table\n");
		return -EOVERFLOW;
	}
	if (node->length < sizeof(*node)) {
		pr_err("Empty node, bad table\n");
		return -EINVAL;
	}
	return 0;
}

static struct virt_topo_iommu *viot_get_iommu(unsigned int offset)
{
	struct viot_iommu *viommu;
	struct acpi_viot_node *node = ACPI_ADD_PTR(struct acpi_viot_node, viot,
						   offset);
	union {
		struct acpi_viot_virtio_iommu_pci pci;
		struct acpi_viot_virtio_iommu_mmio mmio;
	} *cfg = (void *)node;

	list_for_each_entry(viommu, &iommus, list)
		if (viommu->offset == offset)
			return &viommu->spec;

	if (viot_check_bounds(node))
		return NULL;

	viommu = kzalloc(sizeof(*viommu), GFP_KERNEL);
	if (!viommu)
		return NULL;

	viommu->offset = offset;
	switch (node->type) {
	case ACPI_VIOT_NODE_VIRTIO_IOMMU_PCI:
		if (node->length < sizeof(cfg->pci))
			goto err_free;

		viommu->spec.dev_id.type = VIRT_TOPO_DEV_TYPE_PCI;
		viommu->spec.dev_id.segment = cfg->pci.segment;
		viommu->spec.dev_id.bdf_start = cfg->pci.bdf;
		viommu->spec.dev_id.bdf_end = cfg->pci.bdf;
		break;
	case ACPI_VIOT_NODE_VIRTIO_IOMMU_MMIO:
		if (node->length < sizeof(cfg->mmio))
			goto err_free;

		viommu->spec.dev_id.type = VIRT_TOPO_DEV_TYPE_MMIO;
		viommu->spec.dev_id.base = cfg->mmio.base_address;
		break;
	default:
		kfree(viommu);
		return NULL;
	}

	list_add(&viommu->list, &iommus);
	virt_topo_add_iommu(&viommu->spec);
	return &viommu->spec;

err_free:
	kfree(viommu);
	return NULL;
}

static int __init viot_parse_node(const struct acpi_viot_node *node)
{
	int ret = -EINVAL;
	struct virt_topo_endpoint *ep;
	union {
		struct acpi_viot_mmio mmio;
		struct acpi_viot_pci_range pci;
	} *cfg = (void *)node;

	if (viot_check_bounds(node))
		return -EINVAL;

	if (node->reserved)
		pr_warn("unexpected reserved data in node\n");

	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (!ep)
		return -ENOMEM;

	switch (node->type) {
	case ACPI_VIOT_NODE_PCI_RANGE:
		if (node->length < sizeof(cfg->pci))
			goto err_free;

		ep->dev_id.type = VIRT_TOPO_DEV_TYPE_PCI;
		ep->dev_id.segment = cfg->pci.segment;
		ep->dev_id.bdf_start = cfg->pci.bdf_start;
		ep->dev_id.bdf_end = cfg->pci.bdf_end;
		ep->endpoint_id = cfg->pci.endpoint_start;
		ep->viommu = viot_get_iommu(cfg->pci.output_node);
		break;
	case ACPI_VIOT_NODE_MMIO:
		if (node->length < sizeof(cfg->mmio))
			goto err_free;

		ep->dev_id.type = VIRT_TOPO_DEV_TYPE_MMIO;
		ep->dev_id.base = cfg->mmio.base_address;
		ep->endpoint_id = cfg->mmio.endpoint;
		ep->viommu = viot_get_iommu(cfg->mmio.output_node);
		break;
	default:
		ret = 0;
		goto err_free;
	}

	if (!ep->viommu) {
		ret = -ENODEV;
		goto err_free;
	}

	virt_topo_add_endpoint(ep);
	return 0;

err_free:
	kfree(ep);
	return ret;
}

static void __init viot_parse_nodes(void)
{
	int i;
	struct acpi_viot_node *node;

	if (viot->node_offset < sizeof(*viot)) {
		pr_err("Invalid node offset, bad table\n");
		return;
	}

	node = ACPI_ADD_PTR(struct acpi_viot_node, viot, viot->node_offset);

	for (i = 0; i < viot->node_count; i++) {
		if (viot_parse_node(node))
			return;

		node = ACPI_ADD_PTR(struct acpi_viot_node, node, node->length);
	}
}

void __init acpi_viot_init(void)
{
	acpi_status status;
	struct acpi_table_header *hdr;

	status = acpi_get_table(ACPI_SIG_VIOT, 0, &hdr);
	if (ACPI_FAILURE(status)) {
		if (status != AE_NOT_FOUND) {
			const char *msg = acpi_format_exception(status);

			pr_err("Failed to get table, %s\n", msg);
		}
		return;
	}

	viot = (void *)hdr;
	viot_parse_nodes();
}
