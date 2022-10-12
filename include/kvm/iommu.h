/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_IOMMU_H
#define __KVM_IOMMU_H

#include <asm/kvm_host.h>
#include <kvm/power_domain.h>
#include <linux/io-pgtable.h>

/*
 * Parameters from the trusted host:
 * @pgtable_cfg:	page table configuration
 * @domains:		root domain table
 * @nr_domains:		max number of domains (exclusive)
 * @power_domain:	power domain information
 *
 * Other members are filled and used at runtime by the IOMMU driver.
 */
struct kvm_hyp_iommu {
	struct io_pgtable_cfg		pgtable_cfg;
	void				**domains;
	size_t				nr_domains;
	struct kvm_power_domain		power_domain;

	struct io_pgtable_params	*pgtable;
	bool				power_is_off;
};

struct kvm_hyp_iommu_memcache {
	struct kvm_hyp_memcache	pages;
	bool needs_page;
} ____cacheline_aligned_in_smp;

extern struct kvm_hyp_iommu_memcache *kvm_nvhe_sym(kvm_hyp_iommu_memcaches);
#define kvm_hyp_iommu_memcaches kvm_nvhe_sym(kvm_hyp_iommu_memcaches)

struct kvm_hyp_iommu_domain {
	void			*pgd;
	u32			refs;
};

/*
 * At the moment the number of domains is limited by the ASID and VMID size on
 * Arm. With single-stage translation, that size is 2^8 or 2^16. On a lot of
 * platforms the number of devices is actually the limiting factor and we'll
 * only need a handful of domains, but with PASID or SR-IOV support that limit
 * can be reached.
 *
 * In practice we're rarely going to need a lot of domains. To avoid allocating
 * a large domain table, we use a two-level table, indexed by domain ID. With
 * 4kB pages and 16-bytes domains, the leaf table contains 256 domains, and the
 * root table 256 pointers. With 64kB pages, the leaf table contains 4096
 * domains and the root table 16 pointers. In this case, or when using 8-bit
 * VMIDs, it may be more advantageous to use a single level. But using two
 * levels allows to easily extend the domain size.
 */
#define KVM_IOMMU_MAX_DOMAINS	(1 << 16)

/* Number of entries in the level-2 domain table */
#define KVM_IOMMU_DOMAINS_PER_PAGE \
	(PAGE_SIZE / sizeof(struct kvm_hyp_iommu_domain))

/* Number of entries in the root domain table */
#define KVM_IOMMU_DOMAINS_ROOT_ENTRIES \
	(KVM_IOMMU_MAX_DOMAINS / KVM_IOMMU_DOMAINS_PER_PAGE)

#define KVM_IOMMU_DOMAINS_ROOT_SIZE \
	(KVM_IOMMU_DOMAINS_ROOT_ENTRIES * sizeof(void *))

/* Bits [16:split] index the root table, bits [split-1:0] index the leaf table */
#define KVM_IOMMU_DOMAIN_ID_SPLIT	ilog2(KVM_IOMMU_DOMAINS_PER_PAGE)

#define KVM_IOMMU_DOMAIN_ID_LEAF_MASK	((1 << KVM_IOMMU_DOMAIN_ID_SPLIT) - 1)

#endif /* __KVM_IOMMU_H */
