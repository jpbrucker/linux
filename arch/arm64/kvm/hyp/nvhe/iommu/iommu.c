// SPDX-License-Identifier: GPL-2.0
/*
 * IOMMU operations for pKVM
 *
 * Copyright (C) 2022 Linaro Ltd.
 */

#include <asm/kvm_hyp.h>
#include <kvm/iommu.h>
#include <kvm/pl011.h>
#include <nvhe/iommu.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>

struct kvm_hyp_iommu_memcache __ro_after_init *kvm_hyp_iommu_memcaches;

#define domain_to_iopt(_iommu, _domain, _domain_id)		\
	(struct io_pgtable) {					\
		.ops = &(_iommu)->pgtable->ops,			\
		.pgd = (_domain)->pgd,				\
		.cookie = &(struct kvm_iommu_tlb_cookie) {	\
			.iommu		= (_iommu),		\
			.domain_id	= (_domain_id),		\
		},						\
	}

void *kvm_iommu_donate_page(void)
{
	void *p;
	int cpu = hyp_smp_processor_id();
	struct kvm_hyp_memcache tmp = kvm_hyp_iommu_memcaches[cpu].pages;

	if (!tmp.nr_pages) {
		kvm_hyp_iommu_memcaches[cpu].needs_page = true;
		return NULL;
	}

	p = pkvm_admit_host_page(&tmp);
	if (!p)
		return NULL;

	kvm_hyp_iommu_memcaches[cpu].pages = tmp;
	memset(p, 0, PAGE_SIZE);
	return p;
}

void kvm_iommu_reclaim_page(void *p)
{
	int cpu = hyp_smp_processor_id();

	pkvm_teardown_donated_memory(&kvm_hyp_iommu_memcaches[cpu].pages, p,
				     PAGE_SIZE);
}

static struct kvm_hyp_iommu_domain *
handle_to_domain(struct kvm_hyp_iommu *iommu, pkvm_handle_t domain_id)
{
	int idx;
	struct kvm_hyp_iommu_domain *domains;

	if (domain_id >= iommu->nr_domains)
		return NULL;
	domain_id = array_index_nospec(domain_id, iommu->nr_domains);

	idx = domain_id >> KVM_IOMMU_DOMAIN_ID_SPLIT;
	domains = iommu->domains[idx];
	if (!domains) {
		domains = kvm_iommu_donate_page();
		if (!domains)
			return NULL;
		iommu->domains[idx] = domains;
	}

	return &domains[domain_id & KVM_IOMMU_DOMAIN_ID_LEAF_MASK];
}

int kvm_iommu_alloc_domain(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			   unsigned long pgd_hva)
{
	int ret = -EINVAL;
	struct io_pgtable iopt;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return -EINVAL;

	hyp_spin_lock(&iommu->lock);
	domain = handle_to_domain(iommu, domain_id);
	if (!domain)
		goto out_unlock;

	if (domain->refs)
		goto out_unlock;

	iopt = domain_to_iopt(iommu, domain, domain_id);
	ret = kvm_iommu_ops.alloc_iopt(&iopt, pgd_hva);
	if (ret)
		goto out_unlock;

	domain->refs = 1;
	domain->pgd = iopt.pgd;
out_unlock:
	hyp_spin_unlock(&iommu->lock);
	return ret;
}

int kvm_iommu_free_domain(pkvm_handle_t iommu_id, pkvm_handle_t domain_id)
{
	int ret = -EINVAL;
	struct io_pgtable iopt;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return -EINVAL;

	hyp_spin_lock(&iommu->lock);
	domain = handle_to_domain(iommu, domain_id);
	if (!domain)
		goto out_unlock;

	if (domain->refs != 1)
		goto out_unlock;

	iopt = domain_to_iopt(iommu, domain, domain_id);
	ret = kvm_iommu_ops.free_iopt(&iopt);

	memset(domain, 0, sizeof(*domain));

out_unlock:
	hyp_spin_unlock(&iommu->lock);
	return ret;
}

int kvm_iommu_attach_dev(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			 u32 endpoint_id)
{
	int ret = -EINVAL;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return -EINVAL;

	hyp_spin_lock(&iommu->lock);
	domain = handle_to_domain(iommu, domain_id);
	if (!domain || !domain->refs || domain->refs == UINT_MAX)
		goto out_unlock;

	ret = kvm_iommu_ops.attach_dev(iommu, domain_id, domain, endpoint_id);
	if (ret)
		goto out_unlock;

	domain->refs++;
out_unlock:
	hyp_spin_unlock(&iommu->lock);
	return ret;
}

int kvm_iommu_detach_dev(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			 u32 endpoint_id)
{
	int ret = -EINVAL;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return -EINVAL;

	hyp_spin_lock(&iommu->lock);
	domain = handle_to_domain(iommu, domain_id);
	if (!domain || domain->refs <= 1)
		goto out_unlock;

	ret = kvm_iommu_ops.detach_dev(iommu, domain_id, domain, endpoint_id);
	if (ret)
		goto out_unlock;

	domain->refs--;
out_unlock:
	hyp_spin_unlock(&iommu->lock);
	return ret;
}

#define IOMMU_PROT_MASK (IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE |\
			 IOMMU_NOEXEC | IOMMU_MMIO | IOMMU_PRIV)

size_t kvm_iommu_map_pages(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			   unsigned long iova, phys_addr_t paddr, size_t pgsize,
			   size_t pgcount, int prot)
{
	size_t size;
	size_t mapped;
	size_t granule;
	int ret = -EINVAL;
	struct io_pgtable iopt;
	size_t total_mapped = 0;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	if (prot & ~IOMMU_PROT_MASK)
		return 0;

	if (__builtin_mul_overflow(pgsize, pgcount, &size) ||
	    iova + size < iova || paddr + size < paddr)
		return 0;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return 0;

	hyp_spin_lock(&iommu->lock);
	domain = handle_to_domain(iommu, domain_id);
	if (!domain)
		goto err_unlock;

	granule = 1 << __ffs(iommu->pgtable->cfg.pgsize_bitmap);
	if (!IS_ALIGNED(iova | paddr | pgsize, granule))
		goto err_unlock;

	ret = __pkvm_host_share_dma(paddr, size, !(prot & IOMMU_MMIO));
	if (ret)
		goto err_unlock;

	iopt = domain_to_iopt(iommu, domain, domain_id);
	while (pgcount && !ret) {
		mapped = 0;
		ret = iopt_map_pages(&iopt, iova, paddr, pgsize, pgcount, prot,
				     0, &mapped);
		WARN_ON(!IS_ALIGNED(mapped, pgsize));
		WARN_ON(mapped > pgcount * pgsize);

		pgcount -= mapped / pgsize;
		total_mapped += mapped;
		iova += mapped;
		paddr += mapped;
	}

	/*
	 * Unshare the bits that haven't been mapped yet. The host calls back
	 * either to continue mapping, or to unmap and unshare what's been done
	 * so far.
	 */
	if (pgcount)
		__pkvm_host_unshare_dma(paddr, pgcount * pgsize);
err_unlock:
	hyp_spin_unlock(&iommu->lock);
	return total_mapped;
}

size_t kvm_iommu_unmap_pages(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			     unsigned long iova, size_t pgsize, size_t pgcount)
{
	int ret;
	size_t size;
	size_t granule;
	size_t unmapped;
	phys_addr_t paddr = 0;
	struct io_pgtable iopt;
	size_t total_unmapped = 0;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	if (!pgsize || !pgcount)
		return 0;

	if (__builtin_mul_overflow(pgsize, pgcount, &size) ||
	    iova + size < iova)
		return 0;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return 0;

	hyp_spin_lock(&iommu->lock);
	domain = handle_to_domain(iommu, domain_id);
	if (!domain)
		goto out_unlock;

	granule = 1 << __ffs(iommu->pgtable->cfg.pgsize_bitmap);
	if (!IS_ALIGNED(iova | pgsize, granule))
		goto out_unlock;

	iopt = domain_to_iopt(iommu, domain, domain_id);

	while (total_unmapped < size) {
		/*
		 * One page/block at a time so that we can unshare each page.
		 * The IOVA range provided may not be physically contiguous, and
		 * @pgsize may be larger than the one used when mapping.
		 */
		unmapped = iopt_unmap_leaf(&iopt, iova, pgsize, &paddr);
		if (!unmapped || !paddr)
			goto out_unlock;

		ret = __pkvm_host_unshare_dma(paddr, unmapped);
		if (WARN_ON(ret))
			goto out_unlock;

		iova += unmapped;
		total_unmapped += unmapped;
	}

out_unlock:
	hyp_spin_unlock(&iommu->lock);
	return total_unmapped;
}

phys_addr_t kvm_iommu_iova_to_phys(pkvm_handle_t iommu_id,
				   pkvm_handle_t domain_id, unsigned long iova)
{
	phys_addr_t phys = 0;
	struct io_pgtable iopt;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return 0;

	hyp_spin_lock(&iommu->lock);
	domain = handle_to_domain(iommu, domain_id);
	if (domain) {
		iopt = domain_to_iopt(iommu, domain, domain_id);

		phys = iopt_iova_to_phys(&iopt, iova);
	}
	hyp_spin_unlock(&iommu->lock);
	return phys;
}

static int iommu_power_on(struct kvm_power_domain *pd)
{
	struct kvm_hyp_iommu *iommu = container_of(pd, struct kvm_hyp_iommu,
						   power_domain);

	pkvm_debug("%s\n", __func__);

	/*
	 * We currently assume that the device retains its architectural state
	 * across power off, hence no save/restore.
	 */
	hyp_spin_lock(&iommu->lock);
	iommu->power_is_off = false;
	hyp_spin_unlock(&iommu->lock);
	return 0;
}

static int iommu_power_off(struct kvm_power_domain *pd)
{
	struct kvm_hyp_iommu *iommu = container_of(pd, struct kvm_hyp_iommu,
						   power_domain);

	pkvm_debug("%s\n", __func__);

	hyp_spin_lock(&iommu->lock);
	iommu->power_is_off = true;
	hyp_spin_unlock(&iommu->lock);
	return 0;
}

static const struct kvm_power_domain_ops iommu_power_ops = {
	.power_on	= iommu_power_on,
	.power_off	= iommu_power_off,
};

int kvm_iommu_init_device(struct kvm_hyp_iommu *iommu)
{
	int ret;
	void *domains;

	ret = pkvm_init_power_domain(&iommu->power_domain, &iommu_power_ops);
	if (ret)
		return ret;

	domains = iommu->domains;
	iommu->domains = kern_hyp_va(domains);
	return pkvm_create_mappings(iommu->domains, iommu->domains +
				    KVM_IOMMU_DOMAINS_ROOT_ENTRIES, PAGE_HYP);
}

int kvm_iommu_init(void)
{
	enum kvm_pgtable_prot prot;

	if (WARN_ON(!kvm_iommu_ops.get_iommu_by_id ||
		    !kvm_iommu_ops.alloc_iopt ||
		    !kvm_iommu_ops.free_iopt ||
		    !kvm_iommu_ops.attach_dev ||
		    !kvm_iommu_ops.detach_dev))
		return -ENODEV;

	/* The memcache is shared with the host */
	prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_SHARED_OWNED);
	return pkvm_create_mappings(kvm_hyp_iommu_memcaches,
				    kvm_hyp_iommu_memcaches + NR_CPUS, prot);
}
