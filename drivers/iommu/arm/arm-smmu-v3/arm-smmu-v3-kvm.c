// SPDX-License-Identifier: GPL-2.0
/*
 * pKVM host driver for the Arm SMMUv3
 *
 * Copyright (C) 2022 Linaro Ltd.
 */
#include <asm/kvm_mmu.h>
#include <linux/local_lock.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>

#include <kvm/arm_smmu_v3.h>

#include "arm-smmu-v3.h"

struct host_arm_smmu_device {
	struct arm_smmu_device		smmu;
	pkvm_handle_t			id;
	u32				boot_gbpa;
	unsigned int			pgd_order;
};

#define smmu_to_host(_smmu) \
	container_of(_smmu, struct host_arm_smmu_device, smmu);

struct kvm_arm_smmu_master {
	struct arm_smmu_device		*smmu;
	struct device			*dev;
	struct kvm_arm_smmu_domain	*domain;
};

struct kvm_arm_smmu_domain {
	struct iommu_domain		domain;
	struct arm_smmu_device		*smmu;
	struct mutex			init_mutex;
	unsigned long			pgd;
	pkvm_handle_t			id;
};

#define to_kvm_smmu_domain(_domain) \
	container_of(_domain, struct kvm_arm_smmu_domain, domain)

static size_t				kvm_arm_smmu_cur;
static size_t				kvm_arm_smmu_count;
static struct hyp_arm_smmu_v3_device	*kvm_arm_smmu_array;
static struct kvm_hyp_iommu_memcache	*kvm_arm_smmu_memcache;
static DEFINE_IDA(kvm_arm_smmu_domain_ida);

static DEFINE_PER_CPU(local_lock_t, memcache_lock) =
				INIT_LOCAL_LOCK(memcache_lock);

static void *kvm_arm_smmu_alloc_page(void *opaque)
{
	struct arm_smmu_device *smmu = opaque;
	struct page *p;

	p = alloc_pages_node(dev_to_node(smmu->dev), GFP_ATOMIC, 0);
	if (!p)
		return NULL;

	return page_address(p);
}

static void kvm_arm_smmu_free_page(void *va, void *opaque)
{
	free_page((unsigned long)va);
}

static phys_addr_t kvm_arm_smmu_host_pa(void *va)
{
	return __pa(va);
}

static void *kvm_arm_smmu_host_va(phys_addr_t pa)
{
	return __va(pa);
}

static int kvm_arm_smmu_topup_memcache(struct arm_smmu_device *smmu)
{
	struct kvm_hyp_memcache *mc;
	int cpu = raw_smp_processor_id();

	lockdep_assert_held(this_cpu_ptr(&memcache_lock));
	mc = &kvm_arm_smmu_memcache[cpu].pages;

	if (!kvm_arm_smmu_memcache[cpu].needs_page)
		return -EBADE;

	kvm_arm_smmu_memcache[cpu].needs_page = false;
	return  __topup_hyp_memcache(mc, 1, kvm_arm_smmu_alloc_page,
				     kvm_arm_smmu_host_pa, smmu);
}

static void kvm_arm_smmu_reclaim_memcache(void)
{
	struct kvm_hyp_memcache *mc;
	int cpu = raw_smp_processor_id();

	lockdep_assert_held(this_cpu_ptr(&memcache_lock));
	mc = &kvm_arm_smmu_memcache[cpu].pages;

	__free_hyp_memcache(mc, kvm_arm_smmu_free_page,
			    kvm_arm_smmu_host_va, NULL);
}

/*
 * Issue hypercall, and retry after filling the memcache if necessary.
 * After the call, reclaim pages pushed in the memcache by the hypervisor.
 */
#define kvm_call_hyp_nvhe_mc(smmu, ...)				\
({								\
	int __ret;						\
	do {							\
		__ret = kvm_call_hyp_nvhe(__VA_ARGS__);		\
	} while (__ret && !kvm_arm_smmu_topup_memcache(smmu));	\
	kvm_arm_smmu_reclaim_memcache();			\
	__ret;							\
})

static struct platform_driver kvm_arm_smmu_driver;

static struct arm_smmu_device *
kvm_arm_smmu_get_by_fwnode(struct fwnode_handle *fwnode)
{
	struct device *dev;

	dev = driver_find_device_by_fwnode(&kvm_arm_smmu_driver.driver, fwnode);
	put_device(dev);
	return dev ? dev_get_drvdata(dev) : NULL;
}

static struct iommu_ops kvm_arm_smmu_ops;

static struct iommu_device *kvm_arm_smmu_probe_device(struct device *dev)
{
	struct arm_smmu_device *smmu;
	struct kvm_arm_smmu_master *master;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

	if (!fwspec || fwspec->ops != &kvm_arm_smmu_ops)
		return ERR_PTR(-ENODEV);

	if (WARN_ON_ONCE(dev_iommu_priv_get(dev)))
		return ERR_PTR(-EBUSY);

	smmu = kvm_arm_smmu_get_by_fwnode(fwspec->iommu_fwnode);
	if (!smmu)
		return ERR_PTR(-ENODEV);

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	master->dev = dev;
	master->smmu = smmu;
	dev_iommu_priv_set(dev, master);

	return &smmu->iommu;
}

static void kvm_arm_smmu_release_device(struct device *dev)
{
	struct kvm_arm_smmu_master *master = dev_iommu_priv_get(dev);

	kfree(master);
	iommu_fwspec_free(dev);
}

static struct iommu_domain *kvm_arm_smmu_domain_alloc(unsigned type)
{
	struct kvm_arm_smmu_domain *kvm_smmu_domain;

	/*
	 * We don't support
	 * - IOMMU_DOMAIN_IDENTITY because we rely on the host telling the
	 *   hypervisor which pages are used for DMA.
	 * - IOMMU_DOMAIN_DMA_FQ because lazy unmap would clash with memory
	 *   donation to guests.
	 */
	if (type != IOMMU_DOMAIN_DMA &&
	    type != IOMMU_DOMAIN_UNMANAGED)
		return NULL;

	kvm_smmu_domain = kzalloc(sizeof(*kvm_smmu_domain), GFP_KERNEL);
	if (!kvm_smmu_domain)
		return NULL;

	mutex_init(&kvm_smmu_domain->init_mutex);

	return &kvm_smmu_domain->domain;
}

static int kvm_arm_smmu_domain_finalize(struct kvm_arm_smmu_domain *kvm_smmu_domain,
					struct kvm_arm_smmu_master *master)
{
	int ret = 0;
	struct page *p;
	unsigned long pgd;
	struct arm_smmu_device *smmu = master->smmu;
	struct host_arm_smmu_device *host_smmu = smmu_to_host(smmu);

	if (kvm_smmu_domain->smmu) {
		if (kvm_smmu_domain->smmu != smmu)
			return -EINVAL;
		return 0;
	}

	ret = ida_alloc_range(&kvm_arm_smmu_domain_ida, 0, 1 << smmu->vmid_bits,
			      GFP_KERNEL);
	if (ret < 0)
		return ret;
	kvm_smmu_domain->id = ret;

	/*
	 * PGD allocation does not use the memcache because it may be of higher
	 * order when concatenated.
	 */
	p = alloc_pages_node(dev_to_node(smmu->dev), GFP_KERNEL | __GFP_ZERO,
			     host_smmu->pgd_order);
	if (!p)
		return -ENOMEM;

	pgd = (unsigned long)page_to_virt(p);

	local_lock_irq(&memcache_lock);
	ret = kvm_call_hyp_nvhe_mc(smmu, __pkvm_host_iommu_alloc_domain,
				   host_smmu->id, kvm_smmu_domain->id, pgd);
	local_unlock_irq(&memcache_lock);
	if (ret)
		goto err_free;

	kvm_smmu_domain->domain.pgsize_bitmap = smmu->pgsize_bitmap;
	kvm_smmu_domain->domain.geometry.aperture_end = (1UL << smmu->ias) - 1;
	kvm_smmu_domain->domain.geometry.force_aperture = true;
	kvm_smmu_domain->smmu = smmu;
	kvm_smmu_domain->pgd = pgd;

	return 0;

err_free:
	free_pages(pgd, host_smmu->pgd_order);
	ida_free(&kvm_arm_smmu_domain_ida, kvm_smmu_domain->id);
	return ret;
}

static void kvm_arm_smmu_domain_free(struct iommu_domain *domain)
{
	int ret;
	struct kvm_arm_smmu_domain *kvm_smmu_domain = to_kvm_smmu_domain(domain);
	struct arm_smmu_device *smmu = kvm_smmu_domain->smmu;

	if (smmu) {
		struct host_arm_smmu_device *host_smmu = smmu_to_host(smmu);

		ret = kvm_call_hyp_nvhe(__pkvm_host_iommu_free_domain,
					host_smmu->id, kvm_smmu_domain->id);
		/*
		 * On failure, leak the pgd because it probably hasn't been
		 * reclaimed by the host.
		 */
		if (!WARN_ON(ret))
			free_pages(kvm_smmu_domain->pgd, host_smmu->pgd_order);
		ida_free(&kvm_arm_smmu_domain_ida, kvm_smmu_domain->id);
	}
	kfree(kvm_smmu_domain);
}

static int kvm_arm_smmu_detach_dev(struct host_arm_smmu_device *host_smmu,
				   struct kvm_arm_smmu_master *master)
{
	int i, ret;
	struct arm_smmu_device *smmu = &host_smmu->smmu;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(master->dev);

	if (!master->domain)
		return 0;

	for (i = 0; i < fwspec->num_ids; i++) {
		int sid = fwspec->ids[i];

		ret = kvm_call_hyp_nvhe(__pkvm_host_iommu_detach_dev,
					host_smmu->id, master->domain->id, sid);
		if (ret) {
			dev_err(smmu->dev, "cannot detach device %s (0x%x): %d\n",
				dev_name(master->dev), sid, ret);
			break;
		}
	}

	master->domain = NULL;

	return ret;
}

static int kvm_arm_smmu_attach_dev(struct iommu_domain *domain,
				   struct device *dev)
{
	int i, ret;
	struct arm_smmu_device *smmu;
	struct host_arm_smmu_device *host_smmu;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct kvm_arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct kvm_arm_smmu_domain *kvm_smmu_domain = to_kvm_smmu_domain(domain);

	if (!master)
		return -ENODEV;

	smmu = master->smmu;
	host_smmu = smmu_to_host(smmu);

	ret = kvm_arm_smmu_detach_dev(host_smmu, master);
	if (ret)
		return ret;

	mutex_lock(&kvm_smmu_domain->init_mutex);
	ret = kvm_arm_smmu_domain_finalize(kvm_smmu_domain, master);
	mutex_unlock(&kvm_smmu_domain->init_mutex);
	if (ret)
		return ret;

	local_lock_irq(&memcache_lock);
	for (i = 0; i < fwspec->num_ids; i++) {
		int sid = fwspec->ids[i];

		ret = kvm_call_hyp_nvhe_mc(smmu, __pkvm_host_iommu_attach_dev,
					   host_smmu->id, kvm_smmu_domain->id,
					   sid);
		if (ret) {
			dev_err(smmu->dev, "cannot attach device %s (0x%x): %d\n",
				dev_name(dev), sid, ret);
			goto out_unlock;
		}
	}
	master->domain = kvm_smmu_domain;

out_unlock:
	if (ret)
		kvm_arm_smmu_detach_dev(host_smmu, master);
	local_unlock_irq(&memcache_lock);
	return ret;
}

static int kvm_arm_smmu_map_pages(struct iommu_domain *domain,
				  unsigned long iova, phys_addr_t paddr,
				  size_t pgsize, size_t pgcount, int prot,
				  gfp_t gfp, size_t *mapped)
{
	int ret;
	unsigned long irqflags;
	struct kvm_arm_smmu_domain *kvm_smmu_domain = to_kvm_smmu_domain(domain);
	struct arm_smmu_device *smmu = kvm_smmu_domain->smmu;
	struct host_arm_smmu_device *host_smmu = smmu_to_host(smmu);

	local_lock_irqsave(&memcache_lock, irqflags);
	ret = kvm_call_hyp_nvhe_mc(smmu, __pkvm_host_iommu_map_pages,
				   host_smmu->id, kvm_smmu_domain->id, iova,
				   paddr, pgsize, pgcount, prot);
	local_unlock_irqrestore(&memcache_lock, irqflags);
	if (ret)
		return ret;

	*mapped = pgsize * pgcount;
	return 0;
}

static size_t kvm_arm_smmu_unmap_pages(struct iommu_domain *domain,
				       unsigned long iova, size_t pgsize,
				       size_t pgcount,
				       struct iommu_iotlb_gather *iotlb_gather)
{
	size_t unmapped;
	unsigned long irqflags;
	struct kvm_arm_smmu_domain *kvm_smmu_domain = to_kvm_smmu_domain(domain);
	struct arm_smmu_device *smmu = kvm_smmu_domain->smmu;
	struct host_arm_smmu_device *host_smmu = smmu_to_host(smmu);

	local_lock_irqsave(&memcache_lock, irqflags);
	do {
		unmapped = kvm_call_hyp_nvhe(__pkvm_host_iommu_unmap_pages,
					     host_smmu->id, kvm_smmu_domain->id,
					     iova, pgsize, pgcount);
	} while (!unmapped && !kvm_arm_smmu_topup_memcache(smmu));
	kvm_arm_smmu_reclaim_memcache();
	local_unlock_irqrestore(&memcache_lock, irqflags);

	return unmapped;
}

static phys_addr_t kvm_arm_smmu_iova_to_phys(struct iommu_domain *domain,
					     dma_addr_t iova)
{
	struct kvm_arm_smmu_domain *kvm_smmu_domain = to_kvm_smmu_domain(domain);
	struct host_arm_smmu_device *host_smmu = smmu_to_host(kvm_smmu_domain->smmu);

	return kvm_call_hyp_nvhe(__pkvm_host_iommu_iova_to_phys, host_smmu->id,
				 kvm_smmu_domain->id, iova);
}

static struct iommu_ops kvm_arm_smmu_ops = {
	.capable		= arm_smmu_capable,
	.device_group		= arm_smmu_device_group,
	.of_xlate		= arm_smmu_of_xlate,
	.probe_device		= kvm_arm_smmu_probe_device,
	.release_device		= kvm_arm_smmu_release_device,
	.domain_alloc		= kvm_arm_smmu_domain_alloc,
	.owner			= THIS_MODULE,
	.default_domain_ops = &(const struct iommu_domain_ops) {
		.attach_dev	= kvm_arm_smmu_attach_dev,
		.free		= kvm_arm_smmu_domain_free,
		.map_pages	= kvm_arm_smmu_map_pages,
		.unmap_pages	= kvm_arm_smmu_unmap_pages,
		.iova_to_phys	= kvm_arm_smmu_iova_to_phys,
	}
};

static bool kvm_arm_smmu_validate_features(struct arm_smmu_device *smmu)
{
	unsigned long oas;
	unsigned int required_features =
		ARM_SMMU_FEAT_TRANS_S2 |
		ARM_SMMU_FEAT_TT_LE;
	unsigned int forbidden_features =
		ARM_SMMU_FEAT_STALL_FORCE;
	unsigned int keep_features =
		ARM_SMMU_FEAT_2_LVL_STRTAB	|
		ARM_SMMU_FEAT_2_LVL_CDTAB	|
		ARM_SMMU_FEAT_TT_LE		|
		ARM_SMMU_FEAT_SEV		|
		ARM_SMMU_FEAT_COHERENCY		|
		ARM_SMMU_FEAT_TRANS_S1		|
		ARM_SMMU_FEAT_TRANS_S2		|
		ARM_SMMU_FEAT_VAX		|
		ARM_SMMU_FEAT_RANGE_INV;

	if (smmu->options & ARM_SMMU_OPT_PAGE0_REGS_ONLY) {
		dev_err(smmu->dev, "unsupported layout\n");
		return false;
	}

	if ((smmu->features & required_features) != required_features) {
		dev_err(smmu->dev, "missing features 0x%x\n",
			required_features & ~smmu->features);
		return false;
	}

	if (smmu->features & forbidden_features) {
		dev_err(smmu->dev, "features 0x%x forbidden\n",
			smmu->features & forbidden_features);
		return false;
	}

	smmu->features &= keep_features;

	/*
	 * This can be relaxed (although the spec says that OAS "must match
	 * the system physical address size."), but requires some changes. All
	 * table and queue allocations must use GFP_DMA* to ensure the SMMU can
	 * access them.
	 */
	oas = get_kvm_ipa_limit();
	if (smmu->oas < oas) {
		dev_err(smmu->dev, "incompatible address size\n");
		return false;
	}

	return true;
}

static int kvm_arm_smmu_device_reset(struct host_arm_smmu_device *host_smmu)
{
	int ret;
	u32 reg;
	struct arm_smmu_device *smmu = &host_smmu->smmu;

	reg = readl_relaxed(smmu->base + ARM_SMMU_CR0);
	if (reg & CR0_SMMUEN)
		dev_warn(smmu->dev, "SMMU currently enabled! Resetting...\n");

	/* Disable bypass */
	host_smmu->boot_gbpa = readl_relaxed(smmu->base + ARM_SMMU_GBPA);
	ret = arm_smmu_update_gbpa(smmu, GBPA_ABORT, 0);
	if (ret)
		return ret;

	ret = arm_smmu_device_disable(smmu);
	if (ret)
		return ret;

	/* Stream table */
	writeq_relaxed(smmu->strtab_cfg.strtab_base,
		       smmu->base + ARM_SMMU_STRTAB_BASE);
	writel_relaxed(smmu->strtab_cfg.strtab_base_cfg,
		       smmu->base + ARM_SMMU_STRTAB_BASE_CFG);

	/* Command queue */
	writeq_relaxed(smmu->cmdq.q.q_base, smmu->base + ARM_SMMU_CMDQ_BASE);

	return 0;
}

static int kvm_arm_probe_scmi_pd(struct device_node *scmi_node,
				 struct kvm_power_domain *pd)
{
	int ret;
	struct resource res;
	struct of_phandle_args args;

	pd->type = KVM_POWER_DOMAIN_ARM_SCMI;

	ret = of_parse_phandle_with_args(scmi_node, "shmem", NULL, 0, &args);
	if (ret)
		return ret;

	ret = of_address_to_resource(args.np, 0, &res);
	if (ret)
		goto out_put_nodes;

	ret = of_property_read_u32(scmi_node, "arm,smc-id",
				   &pd->arm_scmi.smc_id);
	if (ret)
		goto out_put_nodes;

	/*
	 * The shared buffer is unmapped from the host while a request is in
	 * flight, so it has to be on its own page.
	 */
	if (!IS_ALIGNED(res.start, SZ_64K) || resource_size(&res) < SZ_64K) {
		ret = -EINVAL;
		goto out_put_nodes;
	}

	pd->arm_scmi.shmem_base = res.start;
	pd->arm_scmi.shmem_size = resource_size(&res);

out_put_nodes:
	of_node_put(args.np);
	return ret;
}

/* TODO: Move this. None of it is specific to SMMU */
static int kvm_arm_probe_power_domain(struct device *dev,
				      struct kvm_power_domain *pd)
{
	int ret;
	struct device_node *parent;
	struct of_phandle_args args;

	if (!of_get_property(dev->of_node, "power-domains", NULL))
		return 0;

	ret = of_parse_phandle_with_args(dev->of_node, "power-domains",
					 "#power-domain-cells", 0, &args);
	if (ret)
		return ret;

	parent = of_get_parent(args.np);
	if (parent && of_device_is_compatible(parent, "arm,scmi-smc") &&
	    args.args_count > 0) {
		pd->arm_scmi.domain_id = args.args[0];
		ret = kvm_arm_probe_scmi_pd(parent, pd);
	} else {
		dev_err(dev, "Unsupported PM method for %pOF\n", args.np);
		ret = -EINVAL;
	}
	of_node_put(parent);
	of_node_put(args.np);
	return ret;
}

static void *kvm_arm_smmu_alloc_domains(struct arm_smmu_device *smmu)
{
	return (void *)devm_get_free_pages(smmu->dev, GFP_KERNEL | __GFP_ZERO,
					   get_order(KVM_IOMMU_DOMAINS_ROOT_SIZE));
}

static int kvm_arm_smmu_probe(struct platform_device *pdev)
{
	int ret;
	bool bypass;
	struct resource *res;
	phys_addr_t mmio_addr;
	struct io_pgtable_cfg cfg;
	size_t mmio_size, pgd_size;
	struct arm_smmu_device *smmu;
	struct device *dev = &pdev->dev;
	struct host_arm_smmu_device *host_smmu;
	struct hyp_arm_smmu_v3_device *hyp_smmu;
	struct kvm_power_domain power_domain = {};

	if (kvm_arm_smmu_cur >= kvm_arm_smmu_count)
		return -ENOSPC;

	hyp_smmu = &kvm_arm_smmu_array[kvm_arm_smmu_cur];

	host_smmu = devm_kzalloc(dev, sizeof(*host_smmu), GFP_KERNEL);
	if (!host_smmu)
		return -ENOMEM;

	smmu = &host_smmu->smmu;
	smmu->dev = dev;

	ret = arm_smmu_fw_probe(pdev, smmu, &bypass);
	if (ret || bypass)
		return ret ?: -EINVAL;

	ret = kvm_arm_probe_power_domain(dev, &power_domain);
	if (ret)
		return ret;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	mmio_size = resource_size(res);
	if (mmio_size < SZ_128K) {
		dev_err(dev, "unsupported MMIO region size (%pr)\n", res);
		return -EINVAL;
	}
	mmio_addr = res->start;
	host_smmu->id = kvm_arm_smmu_cur;

	smmu->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(smmu->base))
		return PTR_ERR(smmu->base);

	ret = arm_smmu_device_hw_probe(smmu);
	if (ret)
		return ret;

	if (!kvm_arm_smmu_validate_features(smmu))
		return -ENODEV;

	/*
	 * Stage-1 should be easy to support, though we do need to allocate a
	 * context descriptor table.
	 */
	cfg = (struct io_pgtable_cfg) {
		.fmt = ARM_64_LPAE_S2,
		.pgsize_bitmap = smmu->pgsize_bitmap,
		.ias = smmu->ias,
		.oas = smmu->oas,
		.coherent_walk = smmu->features & ARM_SMMU_FEAT_COHERENCY,
	};

	/*
	 * Choose the page and address size. Compute the PGD size as well, so we
	 * know how much memory to pre-allocate.
	 */
	ret = io_pgtable_configure(&cfg, &pgd_size);
	if (ret)
		return ret;

	host_smmu->pgd_order = get_order(pgd_size);
	smmu->pgsize_bitmap = cfg.pgsize_bitmap;
	smmu->ias = cfg.ias;
	smmu->oas = cfg.oas;

	ret = arm_smmu_init_one_queue(smmu, &smmu->cmdq.q, smmu->base,
				      ARM_SMMU_CMDQ_PROD, ARM_SMMU_CMDQ_CONS,
				      CMDQ_ENT_DWORDS, "cmdq");
	if (ret)
		return ret;

	ret = arm_smmu_init_strtab(smmu);
	if (ret)
		return ret;

	ret = kvm_arm_smmu_device_reset(host_smmu);
	if (ret)
		return ret;

	hyp_smmu->iommu.domains = kvm_arm_smmu_alloc_domains(smmu);
	if (!hyp_smmu->iommu.domains)
		return -ENOMEM;

	hyp_smmu->iommu.nr_domains = 1 << smmu->vmid_bits;

	ret = arm_smmu_register_iommu(smmu, &kvm_arm_smmu_ops, mmio_addr);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, host_smmu);

	/* Hypervisor parameters */
	hyp_smmu->mmio_addr = mmio_addr;
	hyp_smmu->mmio_size = mmio_size;
	hyp_smmu->features = smmu->features;
	hyp_smmu->iommu.pgtable_cfg = cfg;
	hyp_smmu->iommu.power_domain = power_domain;

	kvm_arm_smmu_cur++;

	return 0;
}

static int kvm_arm_smmu_remove(struct platform_device *pdev)
{
	struct host_arm_smmu_device *host_smmu = platform_get_drvdata(pdev);
	struct arm_smmu_device *smmu = &host_smmu->smmu;

	/*
	 * There was an error during hypervisor setup. The hyp driver may
	 * have already enabled the device, so disable it.
	 */
	arm_smmu_unregister_iommu(smmu);
	arm_smmu_device_disable(smmu);
	arm_smmu_update_gbpa(smmu, host_smmu->boot_gbpa, GBPA_ABORT);
	return 0;
}

static const struct of_device_id arm_smmu_of_match[] = {
	{ .compatible = "arm,smmu-v3", },
	{ },
};

static struct platform_driver kvm_arm_smmu_driver = {
	.driver = {
		.name = "kvm-arm-smmu-v3",
		.of_match_table = arm_smmu_of_match,
	},
	.remove = kvm_arm_smmu_remove,
};

static int kvm_arm_smmu_array_alloc(void)
{
	int smmu_order, mc_order;
	struct device_node *np;

	kvm_arm_smmu_count = 0;
	for_each_compatible_node(np, NULL, "arm,smmu-v3")
		kvm_arm_smmu_count++;

	if (!kvm_arm_smmu_count)
		return 0;

	/* Allocate the parameter list shared with the hypervisor */
	smmu_order = get_order(kvm_arm_smmu_count * sizeof(*kvm_arm_smmu_array));
	kvm_arm_smmu_array = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						      smmu_order);
	if (!kvm_arm_smmu_array)
		return -ENOMEM;

	mc_order = get_order(NR_CPUS * sizeof(*kvm_arm_smmu_memcache));
	kvm_arm_smmu_memcache = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
							 mc_order);
	if (!kvm_arm_smmu_memcache)
		goto err_free_array;

	return 0;

err_free_array:
	free_pages((unsigned long)kvm_arm_smmu_array, smmu_order);
	return -ENOMEM;
}

static void kvm_arm_smmu_array_free(void)
{
	int order;

	order = get_order(kvm_arm_smmu_count * sizeof(*kvm_arm_smmu_array));
	free_pages((unsigned long)kvm_arm_smmu_array, order);
	order = get_order(NR_CPUS * sizeof(*kvm_arm_smmu_memcache));
	free_pages((unsigned long)kvm_arm_smmu_memcache, order);
}

/**
 * kvm_arm_smmu_v3_init() - Reserve the SMMUv3 for KVM
 * @count: on success, number of SMMUs successfully initialized
 *
 * Return 0 if all present SMMUv3 were probed successfully, or an error.
 *   If no SMMU was found, return 0, with a count of 0.
 */
int kvm_arm_smmu_v3_init(unsigned int *count)
{
	int ret;

	/*
	 * Check whether any device owned by the host is behind an SMMU.
	 */
	ret = kvm_arm_smmu_array_alloc();
	*count = kvm_arm_smmu_count;
	if (ret || !kvm_arm_smmu_count)
		return ret;

	ret = platform_driver_probe(&kvm_arm_smmu_driver, kvm_arm_smmu_probe);
	if (ret)
		goto err_free;

	if (kvm_arm_smmu_cur != kvm_arm_smmu_count) {
		/* A device exists but failed to probe */
		ret = -EUNATCH;
		goto err_free;
	}

	/*
	 * These variables are stored in the nVHE image, and won't be accessible
	 * after KVM initialization. Ownership of kvm_arm_smmu_array will be
	 * transferred to the hypervisor as well.
	 *
	 * kvm_arm_smmu_memcache is shared between hypervisor and host.
	 */
	kvm_hyp_arm_smmu_v3_smmus = kern_hyp_va(kvm_arm_smmu_array);
	kvm_hyp_arm_smmu_v3_count = kvm_arm_smmu_count;
	kvm_hyp_iommu_memcaches = kern_hyp_va(kvm_arm_smmu_memcache);
	return 0;

err_free:
	kvm_arm_smmu_array_free();
	return ret;
}

void kvm_arm_smmu_v3_remove(void)
{
	platform_driver_unregister(&kvm_arm_smmu_driver);
}
