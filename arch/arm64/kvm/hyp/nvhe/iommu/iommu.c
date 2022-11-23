// SPDX-License-Identifier: GPL-2.0
/*
 * IOMMU operations for pKVM
 *
 * Copyright (C) 2022 Linaro Ltd.
 */

#include <asm/kvm_hyp.h>
#include <kvm/iommu.h>
#include <nvhe/iommu.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>

struct kvm_hyp_iommu_memcache __ro_after_init *kvm_hyp_iommu_memcaches;

/*
 * Serialize access to domains and IOMMU driver internal structures (command
 * queue, device tables)
 */
static hyp_spinlock_t iommu_lock;

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
handle_to_domain(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
		 struct kvm_hyp_iommu **out_iommu)
{
	int idx;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domains;

	iommu = kvm_iommu_ops.get_iommu_by_id(iommu_id);
	if (!iommu)
		return NULL;

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

	*out_iommu = iommu;
	return &domains[domain_id & KVM_IOMMU_DOMAIN_ID_LEAF_MASK];
}

int kvm_iommu_alloc_domain(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			   unsigned long pgd_hva)
{
	int ret = -EINVAL;
	struct io_pgtable iopt;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	hyp_spin_lock(&iommu_lock);
	domain = handle_to_domain(iommu_id, domain_id, &iommu);
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
	hyp_spin_unlock(&iommu_lock);
	return ret;
}

int kvm_iommu_free_domain(pkvm_handle_t iommu_id, pkvm_handle_t domain_id)
{
	int ret = -EINVAL;
	struct io_pgtable iopt;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	hyp_spin_lock(&iommu_lock);
	domain = handle_to_domain(iommu_id, domain_id, &iommu);
	if (!domain)
		goto out_unlock;

	if (domain->refs != 1)
		goto out_unlock;

	iopt = domain_to_iopt(iommu, domain, domain_id);
	ret = kvm_iommu_ops.free_iopt(&iopt);

	memset(domain, 0, sizeof(*domain));

out_unlock:
	hyp_spin_unlock(&iommu_lock);
	return ret;
}

int kvm_iommu_attach_dev(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			 u32 endpoint_id)
{
	int ret = -EINVAL;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	hyp_spin_lock(&iommu_lock);
	domain = handle_to_domain(iommu_id, domain_id, &iommu);
	if (!domain || !domain->refs || domain->refs == UINT_MAX)
		goto out_unlock;

	ret = kvm_iommu_ops.attach_dev(iommu, domain_id, domain, endpoint_id);
	if (ret)
		goto out_unlock;

	domain->refs++;
out_unlock:
	hyp_spin_unlock(&iommu_lock);
	return ret;
}

int kvm_iommu_detach_dev(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			 u32 endpoint_id)
{
	int ret = -EINVAL;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	hyp_spin_lock(&iommu_lock);
	domain = handle_to_domain(iommu_id, domain_id, &iommu);
	if (!domain || domain->refs <= 1)
		goto out_unlock;

	ret = kvm_iommu_ops.detach_dev(iommu, domain_id, domain, endpoint_id);
	if (ret)
		goto out_unlock;

	domain->refs--;
out_unlock:
	hyp_spin_unlock(&iommu_lock);
	return ret;
}

#define IOMMU_PROT_MASK (IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE |\
			 IOMMU_NOEXEC | IOMMU_MMIO)

int kvm_iommu_map_pages(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			unsigned long iova, phys_addr_t paddr, size_t pgsize,
			size_t pgcount, int prot)
{
	size_t size;
	size_t granule;
	int ret = -EINVAL;
	size_t mapped = 0;
	struct io_pgtable iopt;
	struct kvm_hyp_iommu *iommu;
	size_t pgcount_orig = pgcount;
	phys_addr_t paddr_orig = paddr;
	unsigned long iova_orig = iova;
	struct kvm_hyp_iommu_domain *domain;

	if (prot & ~IOMMU_PROT_MASK)
		return -EINVAL;

	if (__builtin_mul_overflow(pgsize, pgcount, &size) ||
	    iova + size < iova || paddr + size < paddr)
		return -EOVERFLOW;

	hyp_spin_lock(&iommu_lock);

	domain = handle_to_domain(iommu_id, domain_id, &iommu);
	if (!domain)
		goto err_unlock;

	granule = 1 << __ffs(iommu->pgtable->cfg.pgsize_bitmap);
	if (!IS_ALIGNED(iova | paddr | pgsize, granule))
		goto err_unlock;

	ret = __pkvm_host_share_dma(paddr, size, !(prot & IOMMU_MMIO));
	if (ret)
		goto err_unlock;

	iopt = domain_to_iopt(iommu, domain, domain_id);
	while (pgcount) {
		ret = iopt_map_pages(&iopt, iova, paddr, pgsize, pgcount, prot,
				     0, &mapped);
		WARN_ON(!IS_ALIGNED(mapped, pgsize));
		pgcount -= mapped / pgsize;
		if (ret)
			goto err_unmap;
		iova += mapped;
		paddr += mapped;
	}

	hyp_spin_unlock(&iommu_lock);
	return 0;

err_unmap:
	pgcount = pgcount_orig - pgcount;
	if (pgcount)
		iopt_unmap_pages(&iopt, iova_orig, pgsize, pgcount, NULL);
	__pkvm_host_unshare_dma(paddr_orig, size);
err_unlock:
	hyp_spin_unlock(&iommu_lock);
	return ret;
}

int kvm_iommu_unmap_pages(pkvm_handle_t iommu_id, pkvm_handle_t domain_id,
			  unsigned long iova, size_t pgsize, size_t pgcount)
{
	size_t size;
	size_t granule;
	size_t unmapped;
	phys_addr_t paddr;
	int ret = -EINVAL;
	struct io_pgtable iopt;
	size_t total_unmapped = 0;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	if (__builtin_mul_overflow(pgsize, pgcount, &size) ||
	    iova + size < iova)
		return -EOVERFLOW;

	hyp_spin_lock(&iommu_lock);
	domain = handle_to_domain(iommu_id, domain_id, &iommu);
	if (!domain)
		goto out_unlock;

	granule = 1 << __ffs(iommu->pgtable->cfg.pgsize_bitmap);
	if (!IS_ALIGNED(iova | pgsize, granule))
		goto out_unlock;

	iopt = domain_to_iopt(iommu, domain, domain_id);

	while (total_unmapped < size) {
		paddr = iopt_iova_to_phys(&iopt, iova);
		if (paddr == 0) {
			ret = -EINVAL;
			goto out_unlock;
		}

		/*
		 * One page/block at a time, because the range provided may not
		 * be physically contiguous, and we need to unshare all physical
		 * pages.
		 */
		unmapped = iopt_unmap_pages(&iopt, iova, pgsize, 1, NULL);
		if (!unmapped) {
			ret = -EINVAL;
			goto out_unlock;
		}

		ret = __pkvm_host_unshare_dma(paddr, pgsize);
		if (ret)
			goto out_unlock;

		iova += unmapped;
		pgcount -= unmapped / pgsize;
		total_unmapped += unmapped;
	}

out_unlock:
	hyp_spin_unlock(&iommu_lock);
	return ret;
}

phys_addr_t kvm_iommu_iova_to_phys(pkvm_handle_t iommu_id,
				   pkvm_handle_t domain_id, unsigned long iova)
{
	phys_addr_t phys = 0;
	struct io_pgtable iopt;
	struct kvm_hyp_iommu *iommu;
	struct kvm_hyp_iommu_domain *domain;

	hyp_spin_lock(&iommu_lock);
	domain = handle_to_domain(iommu_id, domain_id, &iommu);
	if (domain) {
		iopt = domain_to_iopt(iommu, domain, domain_id);

		phys = iopt_iova_to_phys(&iopt, iova);
	}
	hyp_spin_unlock(&iommu_lock);
	return phys;
}

int kvm_iommu_init_device(struct kvm_hyp_iommu *iommu)
{
	void *domains;

	domains = iommu->domains;
	iommu->domains = kern_hyp_va(domains);
	return pkvm_create_mappings(iommu->domains, iommu->domains +
				    KVM_IOMMU_DOMAINS_ROOT_ENTRIES, PAGE_HYP);
}

int kvm_iommu_init(void)
{
	enum kvm_pgtable_prot prot;

	hyp_spin_lock_init(&iommu_lock);

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
