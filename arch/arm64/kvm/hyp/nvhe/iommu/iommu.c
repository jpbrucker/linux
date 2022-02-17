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
