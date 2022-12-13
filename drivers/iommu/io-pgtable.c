// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic page table allocator for IOMMUs.
 *
 * Copyright (C) 2014 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#include <linux/bug.h>
#include <linux/io-pgtable.h>
#include <linux/kernel.h>
#include <linux/types.h>

static const struct io_pgtable_init_fns *
io_pgtable_init_table[IO_PGTABLE_NUM_FMTS] = {
#ifdef CONFIG_IOMMU_IO_PGTABLE_LPAE
	[ARM_32_LPAE_S1] = &io_pgtable_arm_32_lpae_s1_init_fns,
	[ARM_32_LPAE_S2] = &io_pgtable_arm_32_lpae_s2_init_fns,
	[ARM_64_LPAE_S1] = &io_pgtable_arm_64_lpae_s1_init_fns,
	[ARM_64_LPAE_S2] = &io_pgtable_arm_64_lpae_s2_init_fns,
	[ARM_MALI_LPAE] = &io_pgtable_arm_mali_lpae_init_fns,
#endif
#ifdef CONFIG_IOMMU_IO_PGTABLE_DART
	[APPLE_DART] = &io_pgtable_apple_dart_init_fns,
	[APPLE_DART2] = &io_pgtable_apple_dart_init_fns,
#endif
#ifdef CONFIG_IOMMU_IO_PGTABLE_ARMV7S
	[ARM_V7S] = &io_pgtable_arm_v7s_init_fns,
#endif
#ifdef CONFIG_AMD_IOMMU
	[AMD_IOMMU_V1] = &io_pgtable_amd_iommu_v1_init_fns,
	[AMD_IOMMU_V2] = &io_pgtable_amd_iommu_v2_init_fns,
#endif
};

int alloc_io_pgtable_ops(struct io_pgtable *iop, struct io_pgtable_cfg *cfg,
			 void *cookie)
{
	int ret;
	struct io_pgtable_params *params;
	const struct io_pgtable_init_fns *fns;

	if (cfg->fmt >= IO_PGTABLE_NUM_FMTS)
		return -EINVAL;

	fns = io_pgtable_init_table[cfg->fmt];
	if (!fns)
		return -EINVAL;

	ret = fns->alloc(iop, cfg, cookie);
	if (ret)
		return ret;

	params = io_pgtable_ops_to_params(iop->ops);

	iop->cookie	= cookie;
	params->cfg	= *cfg;

	return 0;
}
EXPORT_SYMBOL_GPL(alloc_io_pgtable_ops);

/*
 * It is the IOMMU driver's responsibility to ensure that the page table
 * is no longer accessible to the walker by this point.
 */
void free_io_pgtable_ops(struct io_pgtable *iop)
{
	struct io_pgtable_params *params;

	if (!iop)
		return;

	params = io_pgtable_ops_to_params(iop->ops);
	io_pgtable_tlb_flush_all(&params->cfg, iop);
	io_pgtable_init_table[params->cfg.fmt]->free(iop);
	memset(iop, 0, sizeof(*iop));
}
EXPORT_SYMBOL_GPL(free_io_pgtable_ops);

int io_pgtable_configure(struct io_pgtable_cfg *cfg, size_t *pgd_size)
{
	const struct io_pgtable_init_fns *fns;

	if (cfg->fmt >= IO_PGTABLE_NUM_FMTS)
		return -EINVAL;

	fns = io_pgtable_init_table[cfg->fmt];
	if (!fns || !fns->configure)
		return -EOPNOTSUPP;

	return fns->configure(cfg, pgd_size);
}
EXPORT_SYMBOL_GPL(io_pgtable_configure);
