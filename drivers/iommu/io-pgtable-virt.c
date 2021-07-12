// SPDX-License-Identifier: GPL-2.0-only
/*
 * Virt I/O Page table format.
 * At the moment the format is loosly specified and mainly for experiments.
 *
 * A lot copied from io-pgtable-arm.c
 * Copyright (C) 2014 ARM Limited
 * Copyright (C) 2021 Linaro Limited
 */

#define pr_fmt(fmt) "virt io-pgtable: " fmt

#include <linux/bitops.h>
//#include <linux/bug.h> /* Probably can be removed */
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/io-pgtable.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "io-pgtable-virt.h"

/* Only for development */
#define IOPT_DEBUG(fmt, ...) pr_info("### %s: " fmt, __func__, ##__VA_ARGS__)
#define IOPT_BUG_ON BUG_ON

struct virt_iopt {
	struct io_pgtable iopt;
	void *pgd;
};

#define iopt_to_viopt(_iopt) container_of(_iopt, struct virt_iopt, iopt)
#define iopt_ops_to_viopt(ops) iopt_to_viopt(container_of(ops, struct io_pgtable, ops))

static void *virt_iopt_pte_to_va(viopte_t pte)
{
	return phys_to_virt(pte &
			    VIRT_PGTABLE_PTE_PFN_MASK(VIRT_PGTABLE_LAST_LEVEL));
}

/* Allocate a page table and install it at @ptep */
static viopte_t virt_iopt_install_table(struct virt_iopt *viopt, viopte_t *ptep,
					viopte_t old_pte, gfp_t gfp)
{
	phys_addr_t paddr;
	viopte_t *table;
	viopte_t pte;

	/*
	 * I suppose we could write all DMA addresses in the table, but we do
	 * need phys_to_virt() to free the table. We're not going to support
	 * non-coherent IOMMUs anyway, and all the other kids do it!
	 */
	table = (viopte_t *)get_zeroed_page(gfp);
	if (!table)
		return 0;

	paddr = virt_to_phys(table);
	if (WARN_ON(paddr & ~VIRT_PGTABLE_PTE_PFN_MASK(VIRT_PGTABLE_LAST_LEVEL)))
		goto err_free_table;

	/*
	 * Ensure the table is visible before the pte. Pairs with the address
	 * dependency on the page walker side.
	 *
	 * TODO: dma_wmb() if VIRTIO_F_ORDER_PLATFORM
	 */
	smp_wmb();

	pte = paddr | VIRT_PGTABLE_PTE_VALID | VIRT_PGTABLE_PTE_TABLE;
	old_pte = cmpxchg64_relaxed(ptep, old_pte, pte);
	if (old_pte) {
		/*
		 * We may race with another thread to install the table.
		 * No problem.
		 */
		IOPT_DEBUG("race while installing table 0x%llx -> 0x%llx (OK)\n",
			   old_pte, pte);
		free_page((unsigned long)table);
		return old_pte;
	}

	return pte;
err_free_table:
	free_page((unsigned long)table);
	return 0;
}

/* Recursively free all pages starting from the one at @ptep */
static void virt_iopt_free_table(struct virt_iopt *viopt, int lvl,
				 viopte_t *ptep)
{
	int idx;
	viopte_t pte;

	IOPT_BUG_ON(lvl < 0 || lvl > VIRT_PGTABLE_LAST_LEVEL);

	for (idx = 0; lvl != VIRT_PGTABLE_LAST_LEVEL &&
	     idx < VIRT_PGTABLE_NUM_PTES; idx++) {
		pte = READ_ONCE(ptep[idx]);

		if (!(pte & VIRT_PGTABLE_PTE_TABLE))
			continue;

		/*
		 * We sent an invalidation after clearing the parent table
		 * pointer, so it's now safe to free everything without
		 * synchronization.
		 */
		virt_iopt_free_table(viopt, lvl + 1, virt_iopt_pte_to_va(pte));
	}

	free_page((unsigned long)ptep);
}

static int virt_iopt_install_pte(struct virt_iopt *viopt, unsigned long iova,
				 phys_addr_t paddr, size_t size, int prot,
				 int lvl, viopte_t *ptep, size_t num_entries)
{
	size_t i;
	viopte_t pte, old, flags;

	if (WARN_ON(paddr & ~VIRT_PGTABLE_PTE_PFN_MASK(lvl)))
		return -EINVAL;

	flags = VIRT_PGTABLE_PTE_VALID;
	if (prot & IOMMU_READ)
		flags |= VIRT_PGTABLE_PTE_READ;
	if (prot & IOMMU_WRITE)
		flags |= VIRT_PGTABLE_PTE_WRITE;

	for (i = 0; i < num_entries; i++) {
		pte = (paddr + i * size) | flags;
		old = xchg_relaxed(ptep + i, pte);

		/*
		 * If we're replacing a table with a block, free the table. This
		 * happens because unmap() doesn't free the parent table when it
		 * removes a leaf.
		 */
		if (old & VIRT_PGTABLE_PTE_TABLE) {
			IOPT_DEBUG("removing old tables 0x%lx %zu (OK)\n", iova, size);
			io_pgtable_tlb_flush_walk(&viopt->iopt, iova + i * size,
						  size, VIRT_PGTABLE_GRANULE);
			virt_iopt_free_table(viopt, lvl,
					     virt_iopt_pte_to_va(old));
		} else if (WARN_ON(old)) {
			return -EEXIST;
		}
	}
	return 0;
}

static int __virt_iopt_map(struct virt_iopt *viopt, unsigned long iova,
			   phys_addr_t paddr, size_t pgsize, size_t pgcount,
			   int prot, gfp_t gfp, int lvl, viopte_t *ptep,
			   size_t *mapped)
{
	int ret;
	viopte_t pte;
	unsigned int idx;
	size_t num_entries, max_entries;
	size_t cur_size = VIRT_PGTABLE_PAGE_SIZE(lvl);

	IOPT_BUG_ON(lvl < 0 || lvl > VIRT_PGTABLE_LAST_LEVEL);

	idx = VIRT_PGTABLE_IDX(iova, lvl);
	IOPT_BUG_ON(idx >= VIRT_PGTABLE_NUM_PTES);

	ptep += idx;

	if (cur_size == pgsize) {
		max_entries = VIRT_PGTABLE_NUM_PTES - idx;
		num_entries = min(max_entries, pgcount);
		ret = virt_iopt_install_pte(viopt, iova, paddr, pgsize, prot,
					    lvl, ptep, num_entries);
		if (!ret)
			*mapped += num_entries * pgsize;

		return ret;
	}

	/* Next table */
	pte = READ_ONCE(*ptep);
	if (!(pte & VIRT_PGTABLE_PTE_VALID)) {
		pte = virt_iopt_install_table(viopt, ptep, pte, gfp);
		if (!pte)
			return -EFAULT;
	} else if (WARN_ON(!(pte & VIRT_PGTABLE_PTE_TABLE))) {
		return -EEXIST;
	}

	return __virt_iopt_map(viopt, iova, paddr, pgsize, pgcount, prot, gfp,
			       lvl + 1, virt_iopt_pte_to_va(pte), mapped);
}

static int virt_iopt_map(struct io_pgtable_ops *ops, unsigned long iova,
			 phys_addr_t paddr, size_t pgsize, size_t pgcount,
			 int prot, gfp_t gfp, size_t *mapped)
{
	int ret;
	struct virt_iopt *viopt = iopt_ops_to_viopt(ops);

	ret = __virt_iopt_map(viopt, iova, paddr, pgsize, pgcount, prot, gfp, 0,
			      viopt->pgd, mapped);

	/*
	 * The device driver can now publish the IOVA. Synchronize against the
	 * page walker. Pairs with a smp_rmb() on the walker side.
	 */
	smp_wmb();

	return ret;
}

static size_t viopt_remove_pte(struct virt_iopt *viopt, unsigned long iova,
			       size_t pgsize, size_t nr_entries,
			       struct iommu_iotlb_gather *gather, int lvl,
			       viopte_t *ptep)
{
	size_t i;
	viopte_t old_pte;

	for (i = 0; i < nr_entries; i++) {
		old_pte = xchg_relaxed(ptep + i, 0);
		WARN_ON(!(old_pte & VIRT_PGTABLE_PTE_VALID));
		if (old_pte & VIRT_PGTABLE_PTE_TABLE) {
			IOPT_BUG_ON(lvl == VIRT_PGTABLE_LAST_LEVEL);
			/* Wait for walks before freeing the table */
			io_pgtable_tlb_flush_walk(&viopt->iopt,
						  iova + i * pgsize, pgsize,
						  VIRT_PGTABLE_GRANULE);
			virt_iopt_free_table(viopt, lvl,
					     virt_iopt_pte_to_va(old_pte));
			IOPT_DEBUG("freed table (OK)\n");
		} else {
			io_pgtable_tlb_add_page(&viopt->iopt, gather,
						iova + i * pgsize, pgsize);
		}
	}
	return i * pgsize;
}

static size_t __virt_iopt_unmap(struct virt_iopt *viopt, unsigned long iova,
				size_t pgsize, size_t pgcount,
				struct iommu_iotlb_gather *gather, int lvl,
				viopte_t *ptep)
{
	viopte_t pte;
	unsigned int idx;
	size_t max_entries, nr_entries;
	size_t cur_size = VIRT_PGTABLE_PAGE_SIZE(lvl);

	IOPT_BUG_ON(lvl < 0 || lvl > VIRT_PGTABLE_LAST_LEVEL);

	idx = VIRT_PGTABLE_IDX(iova, lvl);
	IOPT_BUG_ON(idx >= VIRT_PGTABLE_NUM_PTES);

	ptep += idx;

	max_entries = VIRT_PGTABLE_NUM_PTES - idx;
	nr_entries = min(max_entries, pgcount);

	pte = READ_ONCE(*ptep);
	if (WARN_ON(!(pte & VIRT_PGTABLE_PTE_VALID)))
		return 0;

	if (cur_size == pgsize)
		return viopt_remove_pte(viopt, iova, pgsize, nr_entries, gather,
					lvl, ptep);

	if (WARN_ON(!(pte & VIRT_PGTABLE_PTE_TABLE))) {
	    /*
	     * FIXME: do we need to split the block? The mapping tree doesn't
	     * allow splitting and we've not received complaints yet.
	     * It will be easy to notice, there is a WARN() in dma-iommu.
	     */
	    return 0;
	}

	return __virt_iopt_unmap(viopt, iova, pgsize, pgcount, gather, lvl + 1,
				 virt_iopt_pte_to_va(pte));
}

static size_t virt_iopt_unmap(struct io_pgtable_ops *ops, unsigned long iova,
			      size_t pgsize, size_t pgcount,
			      struct iommu_iotlb_gather *gather)
{
	struct virt_iopt *viopt = iopt_ops_to_viopt(ops);

	return __virt_iopt_unmap(viopt, iova, pgsize, pgcount, gather, 0,
				 viopt->pgd);
}

static phys_addr_t __virt_iopt_iova_to_phys(struct virt_iopt *viopt,
					    unsigned long iova, int lvl,
					    viopte_t *ptep)
{
	viopte_t pte;
	unsigned int idx;
	unsigned long mask;

	idx = VIRT_PGTABLE_IDX(iova, lvl);
	IOPT_BUG_ON(idx >= VIRT_PGTABLE_NUM_PTES);

	pte = READ_ONCE(ptep[idx]);
	if (!(pte & VIRT_PGTABLE_PTE_VALID)) {
		return 0;
	} else if (pte & VIRT_PGTABLE_PTE_TABLE) {
		return __virt_iopt_iova_to_phys(viopt, iova, lvl + 1,
						virt_iopt_pte_to_va(pte));
	}

	mask = VIRT_PGTABLE_PAGE_SIZE(lvl) - 1;
	return (pte & VIRT_PGTABLE_PTE_PFN_MASK(lvl)) | (iova & mask);
}

static phys_addr_t virt_iopt_iova_to_phys(struct io_pgtable_ops *ops,
					  unsigned long iova)
{
	struct virt_iopt *viopt = iopt_ops_to_viopt(ops);

	return __virt_iopt_iova_to_phys(viopt, iova, 0, viopt->pgd);
}

static struct io_pgtable *virt_iopt_alloc(struct io_pgtable_cfg *cfg, void *cookie)
{
	struct virt_iopt *viopt;

	BUILD_BUG_ON(VIRT_PGTABLE_IDX_SHIFT(0) != 39);
	BUILD_BUG_ON(VIRT_PGTABLE_IDX_SHIFT(1) != 30);
	BUILD_BUG_ON(VIRT_PGTABLE_IDX_SHIFT(2) != 21);
	BUILD_BUG_ON(VIRT_PGTABLE_IDX_SHIFT(3) != 12);
	BUILD_BUG_ON(VIRT_PGTABLE_PTE_PFN_MASK(0) != 0xfff8000000000);
	BUILD_BUG_ON(VIRT_PGTABLE_PTE_PFN_MASK(1) != 0xfffffc0000000);
	BUILD_BUG_ON(VIRT_PGTABLE_PTE_PFN_MASK(2) != 0xfffffffe00000);
	BUILD_BUG_ON(VIRT_PGTABLE_PTE_PFN_MASK(3) != 0xffffffffff000);
	BUILD_BUG_ON(VIRT_PGTABLE_IDX(0x765276401000, 1) != 0x149);

	if (cfg->quirks)
		return NULL;

	/* Classic for now: 48-bit IOVA, 4kB pages, 4 levels */
	if (cfg->pgsize_bitmap != 0x40201000 ||
	    cfg->ias > VIRT_PGTABLE_VA_BITS || cfg->oas > VIRT_PGTABLE_PA_BITS)
		return NULL;

	viopt = kmalloc(sizeof(*viopt), GFP_KERNEL);
	if (!viopt)
		return NULL;

	viopt->pgd = (viopte_t *)get_zeroed_page(GFP_KERNEL);
	if (!viopt->pgd)
		goto err_free_viopt;
	cfg->virt.pgd = virt_to_phys(viopt->pgd);

	viopt->iopt.ops = (struct io_pgtable_ops) {
		.map_pages	= virt_iopt_map,
		.unmap_pages	= virt_iopt_unmap,
		.iova_to_phys	= virt_iopt_iova_to_phys,
	};

	return &viopt->iopt;
err_free_viopt:
	kfree(viopt);
	return NULL;
}

static void virt_iopt_free(struct io_pgtable *iopt)
{
	struct virt_iopt *viopt = iopt_to_viopt(iopt);

	/* TODO: double-check that it is detached? */
	virt_iopt_free_table(viopt, 0, viopt->pgd);
	kfree(viopt);
}

struct io_pgtable_init_fns io_pgtable_virt_init_fns = {
	.alloc = virt_iopt_alloc,
	.free = virt_iopt_free,
};
