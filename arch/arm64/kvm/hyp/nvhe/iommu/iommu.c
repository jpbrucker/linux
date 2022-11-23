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

int kvm_iommu_init(void)
{
	enum kvm_pgtable_prot prot;

	/* The memcache is shared with the host */
	prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_SHARED_OWNED);
	return pkvm_create_mappings(kvm_hyp_iommu_memcaches,
				    kvm_hyp_iommu_memcaches + NR_CPUS, prot);
}
