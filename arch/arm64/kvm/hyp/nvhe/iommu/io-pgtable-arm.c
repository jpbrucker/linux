// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Arm Ltd.
 */
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <kvm/arm_smmu_v3.h>
#include <linux/types.h>
#include <linux/gfp_types.h>
#include <linux/io-pgtable-arm.h>

#include <nvhe/iommu.h>
#include <nvhe/mem_protect.h>

bool __ro_after_init selftest_running;

void *__arm_lpae_alloc_pages(size_t size, gfp_t gfp, struct io_pgtable_cfg *cfg)
{
	void *addr = kvm_iommu_donate_page();

	BUG_ON(size != PAGE_SIZE);

	if (addr && !cfg->coherent_walk)
		kvm_flush_dcache_to_poc(addr, size);

	return addr;
}

void __arm_lpae_free_pages(void *addr, size_t size, struct io_pgtable_cfg *cfg)
{
	BUG_ON(size != PAGE_SIZE);

	if (!cfg->coherent_walk)
		kvm_flush_dcache_to_poc(addr, size);

	kvm_iommu_reclaim_page(addr);
}

void __arm_lpae_sync_pte(arm_lpae_iopte *ptep, int num_entries,
			 struct io_pgtable_cfg *cfg)
{
	if (!cfg->coherent_walk)
		kvm_flush_dcache_to_poc(ptep, sizeof(*ptep) * num_entries);
}

int kvm_arm_io_pgtable_init(struct io_pgtable_cfg *cfg,
			    struct arm_lpae_io_pgtable *data)
{
	int ret = arm_lpae_init_pgtable_s2(cfg, data);

	if (ret)
		return ret;

	data->iop.cfg = *cfg;
	return 0;
}

int kvm_arm_io_pgtable_alloc(struct io_pgtable *iopt, unsigned long pgd_hva)
{
	size_t pgd_size, alignment;
	struct arm_lpae_io_pgtable *data = io_pgtable_ops_to_data(iopt->ops);

	pgd_size = ARM_LPAE_PGD_SIZE(data);
	/*
	 * If it has eight or more entries, the table must be aligned on
	 * its size. Otherwise 64 bytes.
	 */
	alignment = max(pgd_size, 8 * sizeof(arm_lpae_iopte));
	if (!IS_ALIGNED(pgd_hva, alignment))
		return -EINVAL;

	iopt->pgd = pkvm_map_donated_memory(pgd_hva, pgd_size);
	if (!iopt->pgd)
		return -ENOMEM;

	if (!data->iop.cfg.coherent_walk)
		kvm_flush_dcache_to_poc(iopt->pgd, pgd_size);

	/* Ensure the empty pgd is visible before any actual TTBR write */
	wmb();

	return 0;
}

int kvm_arm_io_pgtable_free(struct io_pgtable *iopt)
{
	struct arm_lpae_io_pgtable *data = io_pgtable_ops_to_data(iopt->ops);
	size_t pgd_size = ARM_LPAE_PGD_SIZE(data);

	if (!data->iop.cfg.coherent_walk)
		kvm_flush_dcache_to_poc(iopt->pgd, pgd_size);

	/* Free all tables but the pgd */
	__arm_lpae_free_pgtable(data, data->start_level, iopt->pgd, true);
	pkvm_unmap_donated_memory(iopt->pgd, pgd_size);
	return 0;
}
