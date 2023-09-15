// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/kmemleak.h>
#include <linux/kvm_host.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/sort.h>

#include <asm/kvm_host.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm.h>

#include "hyp_constants.h"

DEFINE_STATIC_KEY_FALSE(kvm_protected_mode_initialized);

static struct reserved_mem *pkvm_firmware_mem;
static phys_addr_t *pvmfw_base = &kvm_nvhe_sym(pvmfw_base);
static phys_addr_t *pvmfw_size = &kvm_nvhe_sym(pvmfw_size);

static struct memblock_region *hyp_memory = kvm_nvhe_sym(hyp_memory);
static unsigned int *hyp_memblock_nr_ptr = &kvm_nvhe_sym(hyp_memblock_nr);

phys_addr_t hyp_mem_base;
phys_addr_t hyp_mem_size;

static int cmp_hyp_memblock(const void *p1, const void *p2)
{
	const struct memblock_region *r1 = p1;
	const struct memblock_region *r2 = p2;

	return r1->base < r2->base ? -1 : (r1->base > r2->base);
}

static void __init sort_memblock_regions(void)
{
	sort(hyp_memory,
	     *hyp_memblock_nr_ptr,
	     sizeof(struct memblock_region),
	     cmp_hyp_memblock,
	     NULL);
}

static int __init register_memblock_regions(void)
{
	struct memblock_region *reg;

	for_each_mem_region(reg) {
		if (*hyp_memblock_nr_ptr >= HYP_MEMBLOCK_REGIONS)
			return -ENOMEM;

		hyp_memory[*hyp_memblock_nr_ptr] = *reg;
		(*hyp_memblock_nr_ptr)++;
	}
	sort_memblock_regions();

	return 0;
}

void __init kvm_hyp_reserve(void)
{
	u64 hyp_mem_pages = 0;
	int ret;

	if (!is_hyp_mode_available() || is_kernel_in_hyp_mode())
		return;

	if (kvm_get_mode() != KVM_MODE_PROTECTED)
		return;

	ret = register_memblock_regions();
	if (ret) {
		*hyp_memblock_nr_ptr = 0;
		kvm_err("Failed to register hyp memblocks: %d\n", ret);
		return;
	}

	hyp_mem_pages += hyp_s1_pgtable_pages();
	hyp_mem_pages += host_s2_pgtable_pages();
	hyp_mem_pages += hyp_vm_table_pages();
	hyp_mem_pages += hyp_vmemmap_pages(STRUCT_HYP_PAGE_SIZE);
	hyp_mem_pages += hyp_ffa_proxy_pages();
	hyp_mem_pages += hyp_host_fp_pages(num_possible_cpus());

	/*
	 * Try to allocate a PMD-aligned region to reduce TLB pressure once
	 * this is unmapped from the host stage-2, and fallback to PAGE_SIZE.
	 */
	hyp_mem_size = hyp_mem_pages << PAGE_SHIFT;
	hyp_mem_base = memblock_phys_alloc(ALIGN(hyp_mem_size, PMD_SIZE),
					   PMD_SIZE);
	if (!hyp_mem_base)
		hyp_mem_base = memblock_phys_alloc(hyp_mem_size, PAGE_SIZE);
	else
		hyp_mem_size = ALIGN(hyp_mem_size, PMD_SIZE);

	if (!hyp_mem_base) {
		kvm_err("Failed to reserve hyp memory\n");
		return;
	}

	kvm_info("Reserved %lld MiB at 0x%llx\n", hyp_mem_size >> 20,
		 hyp_mem_base);
}

static int __pkvm_create_hyp_vcpu(struct kvm *host_kvm, struct kvm_vcpu *host_vcpu, unsigned long idx)
{
	pkvm_handle_t handle = host_kvm->arch.pkvm.handle;
	struct kvm_hyp_req *hyp_reqs;
	int ret;

	/* Indexing of the vcpus to be sequential starting at 0. */
	if (WARN_ON(host_vcpu->vcpu_idx != idx))
		return -EINVAL;

	hyp_reqs = (struct kvm_hyp_req *)__get_free_page(GFP_KERNEL_ACCOUNT);
	if (!hyp_reqs)
		return -ENOMEM;

	ret = kvm_share_hyp(hyp_reqs, hyp_reqs + 1);
	if (ret)
		goto end;
	host_vcpu->arch.hyp_reqs = hyp_reqs;

	ret = refill_hyp_alloc(kvm_call_hyp_nvhe(__pkvm_init_vcpu,
						 handle, host_vcpu), 2);
end:
	if (ret) {
		free_page((unsigned long)hyp_reqs);
		host_vcpu->arch.hyp_reqs = NULL;
	}

	return ret;
}

/*
 * Allocates and donates memory for hypervisor VM structs at EL2.
 *
 * Allocates space for the VM state, which includes the hyp vm as well as
 * the hyp vcpus.
 *
 * Stores an opaque handler in the kvm struct for future reference.
 *
 * Return 0 on success, negative error code on failure.
 */
static int __pkvm_create_hyp_vm(struct kvm *host_kvm)
{
	struct kvm_vcpu *host_vcpu;
	pkvm_handle_t handle;
	unsigned long idx;
	size_t pgd_sz;
	void *pgd;
	int ret;

	if (host_kvm->created_vcpus < 1)
		return -EINVAL;

	pgd_sz = kvm_pgtable_stage2_pgd_size(host_kvm->arch.vtcr);

	/*
	 * The PGD pages will be reclaimed using a hyp_memcache which implies
	 * page granularity. So, use alloc_pages_exact() to get individual
	 * refcounts.
	 */
	pgd = alloc_pages_exact(pgd_sz, GFP_KERNEL_ACCOUNT);
	if (!pgd)
		return -ENOMEM;

	/* Donate the VM memory to hyp and let hyp initialize it. */
	ret = refill_hyp_alloc(kvm_call_hyp_nvhe(__pkvm_init_vm,
						 host_kvm, pgd), 4);
	if (ret < 0)
		goto free_pgd;

	handle = ret;

	host_kvm->arch.pkvm.handle = handle;

	/* Donate memory for the vcpus at hyp and initialize it. */
	kvm_for_each_vcpu(idx, host_vcpu, host_kvm) {
		ret = __pkvm_create_hyp_vcpu(host_kvm, host_vcpu, idx);
		if (ret)
			goto destroy_vm;
	}

	return 0;

destroy_vm:
	pkvm_destroy_hyp_vm(host_kvm);
	return ret;
free_pgd:
	free_pages_exact(pgd, pgd_sz);
	return ret;
}

int pkvm_create_hyp_vm(struct kvm *host_kvm)
{
	int ret = 0;

	mutex_lock(&host_kvm->lock);
	if (!host_kvm->arch.pkvm.handle)
		ret = __pkvm_create_hyp_vm(host_kvm);
	mutex_unlock(&host_kvm->lock);

	return ret;
}

void pkvm_destroy_hyp_vm(struct kvm *host_kvm)
{
	struct kvm_pinned_page *ppage;
	struct mm_struct *mm = current->mm;
	struct kvm_vcpu *host_vcpu;
	struct rb_node *node;
	unsigned long idx;

	if (!host_kvm->arch.pkvm.handle)
		goto out_free;

	WARN_ON(kvm_call_hyp_nvhe(__pkvm_start_teardown_vm, host_kvm->arch.pkvm.handle));
	node = rb_first(&host_kvm->arch.pkvm.pinned_pages);
	while (node) {
		ppage = rb_entry(node, struct kvm_pinned_page, node);
		WARN_ON(kvm_call_hyp_nvhe(__pkvm_reclaim_dying_guest_page,
					  host_kvm->arch.pkvm.handle,
					  page_to_pfn(ppage->page),
					  ppage->ipa));
		cond_resched();

		account_locked_vm(mm, 1, false);
		unpin_user_pages_dirty_lock(&ppage->page, 1, true);
		node = rb_next(node);
		rb_erase(&ppage->node, &host_kvm->arch.pkvm.pinned_pages);
		kfree(ppage);
	}

	WARN_ON(kvm_call_hyp_nvhe(__pkvm_finalize_teardown_vm, host_kvm->arch.pkvm.handle));

out_free:
	host_kvm->arch.pkvm.handle = 0;
	free_hyp_memcache(&host_kvm->arch.pkvm.teardown_mc, 0);

	kvm_for_each_vcpu(idx, host_vcpu, host_kvm) {
		struct kvm_hyp_req *hyp_reqs = host_vcpu->arch.hyp_reqs;

		if (!hyp_reqs)
			continue;

		kvm_unshare_hyp(hyp_reqs, hyp_reqs + 1);
		free_page((unsigned long)hyp_reqs);
	}
}

int pkvm_init_host_vm(struct kvm *host_kvm, unsigned long type)
{
	mutex_init(&host_kvm->lock);

	if (!(type & KVM_VM_TYPE_ARM_PROTECTED))
		return 0;

	if (!is_protected_kvm_enabled())
		return -EINVAL;

	host_kvm->arch.pkvm.pvmfw_load_addr = PVMFW_INVALID_LOAD_ADDR;
	host_kvm->arch.pkvm.enabled = true;
	return 0;
}

static void __init _kvm_host_prot_finalize(void *arg)
{
	int *err = arg;

	if (WARN_ON(kvm_call_hyp_nvhe(__pkvm_prot_finalize)))
		WRITE_ONCE(*err, -EINVAL);
}

static int __init pkvm_drop_host_privileges(void)
{
	int ret = 0;

	/*
	 * Flip the static key upfront as that may no longer be possible
	 * once the host stage 2 is installed.
	 */
	static_branch_enable(&kvm_protected_mode_initialized);
	on_each_cpu(_kvm_host_prot_finalize, &ret, 1);
	return ret;
}

static int __init finalize_pkvm(void)
{
	int ret;

	if (!is_protected_kvm_enabled() || !is_kvm_arm_initialised())
		return 0;

	/*
	 * Exclude HYP sections from kmemleak so that they don't get peeked
	 * at, which would end badly once inaccessible.
	 */
	kmemleak_free_part(__hyp_bss_start, __hyp_bss_end - __hyp_bss_start);
	kmemleak_free_part_phys(hyp_mem_base, hyp_mem_size);

	ret = pkvm_drop_host_privileges();
	if (ret)
		pr_err("Failed to finalize Hyp protection: %d\n", ret);

	return ret;
}
device_initcall_sync(finalize_pkvm);

static int rb_ppage_cmp(const void *key, const struct rb_node *node)
{
       struct kvm_pinned_page *p = container_of(node, struct kvm_pinned_page, node);
       phys_addr_t ipa = (phys_addr_t)key;

       return (ipa < p->ipa) ? -1 : (ipa > p->ipa);
}

void pkvm_host_reclaim_page(struct kvm *host_kvm, phys_addr_t ipa)
{
	struct kvm_pinned_page *ppage;
	struct mm_struct *mm = current->mm;
	struct rb_node *node;

	write_lock(&host_kvm->mmu_lock);
	node = rb_find((void *)ipa, &host_kvm->arch.pkvm.pinned_pages,
		       rb_ppage_cmp);
	if (node)
		rb_erase(node, &host_kvm->arch.pkvm.pinned_pages);
	write_unlock(&host_kvm->mmu_lock);

	WARN_ON(!node);
	if (!node)
		return;

	ppage = container_of(node, struct kvm_pinned_page, node);
	account_locked_vm(mm, 1, false);
	unpin_user_pages_dirty_lock(&ppage->page, 1, true);
	kfree(ppage);
}

static int __init pkvm_firmware_rmem_err(struct reserved_mem *rmem,
					 const char *reason)
{
	phys_addr_t end = rmem->base + rmem->size;

	kvm_err("Ignoring pkvm guest firmware memory reservation [%pa - %pa]: %s\n",
		&rmem->base, &end, reason);
	return -EINVAL;
}

static int __init pkvm_firmware_rmem_init(struct reserved_mem *rmem)
{
	unsigned long node = rmem->fdt_node;

	if (pkvm_firmware_mem)
		return pkvm_firmware_rmem_err(rmem, "duplicate reservation");

	if (!of_get_flat_dt_prop(node, "no-map", NULL))
		return pkvm_firmware_rmem_err(rmem, "missing \"no-map\" property");

	if (of_get_flat_dt_prop(node, "reusable", NULL))
		return pkvm_firmware_rmem_err(rmem, "\"reusable\" property unsupported");

	if (!PAGE_ALIGNED(rmem->base))
		return pkvm_firmware_rmem_err(rmem, "base is not page-aligned");

	if (!PAGE_ALIGNED(rmem->size))
		return pkvm_firmware_rmem_err(rmem, "size is not page-aligned");

	*pvmfw_size = rmem->size;
	*pvmfw_base = rmem->base;
	pkvm_firmware_mem = rmem;
	return 0;
}
RESERVEDMEM_OF_DECLARE(pkvm_firmware, "linux,pkvm-guest-firmware-memory",
		       pkvm_firmware_rmem_init);

static int __init pkvm_firmware_rmem_clear(void)
{
	void *addr;
	phys_addr_t size;

	if (likely(!pkvm_firmware_mem) || is_protected_kvm_enabled())
		return 0;

	kvm_info("Clearing unused pKVM firmware memory\n");
	size = pkvm_firmware_mem->size;
	addr = memremap(pkvm_firmware_mem->base, size, MEMREMAP_WB);
	if (!addr)
		return -EINVAL;

	memset(addr, 0, size);
	dcache_clean_poc((unsigned long)addr, (unsigned long)addr + size);
	memunmap(addr);
	return 0;
}
device_initcall_sync(pkvm_firmware_rmem_clear);

static int pkvm_vm_ioctl_set_fw_ipa(struct kvm *kvm, u64 ipa)
{
	int ret = 0;

	if (!pkvm_firmware_mem)
		return -EINVAL;

	mutex_lock(&kvm->lock);
	if (kvm->arch.pkvm.handle) {
		ret = -EBUSY;
		goto out_unlock;
	}

	kvm->arch.pkvm.pvmfw_load_addr = ipa;
out_unlock:
	mutex_unlock(&kvm->lock);
	return ret;
}

static int pkvm_vm_ioctl_info(struct kvm *kvm,
			      struct kvm_protected_vm_info __user *info)
{
	struct kvm_protected_vm_info kinfo = {
		.firmware_size = pkvm_firmware_mem ?
				 pkvm_firmware_mem->size :
				 0,
	};

	return copy_to_user(info, &kinfo, sizeof(kinfo)) ? -EFAULT : 0;
}

int pkvm_vm_ioctl_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	if (!kvm_vm_is_protected(kvm))
		return -EINVAL;

	if (cap->args[1] || cap->args[2] || cap->args[3])
		return -EINVAL;

	switch (cap->flags) {
	case KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA:
		return pkvm_vm_ioctl_set_fw_ipa(kvm, cap->args[0]);
	case KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO:
		return pkvm_vm_ioctl_info(kvm, (void __force __user *)cap->args[0]);
	default:
		return -EINVAL;
	}

	return 0;
}

int __pkvm_topup_hyp_alloc(unsigned long nr_pages)
{
	struct kvm_hyp_memcache mc = {
		.head		= 0,
		.nr_pages	= 0,
	};
	int ret;

	ret = topup_hyp_memcache(&mc, nr_pages, 0);
	if (ret)
		return ret;

	ret = kvm_call_hyp_nvhe(__pkvm_hyp_alloc_refill, mc.head, mc.nr_pages);
	if (ret)
		free_hyp_memcache(&mc, 0);

	return ret;
}
EXPORT_SYMBOL_GPL(__pkvm_topup_hyp_alloc);

unsigned long __pkvm_reclaim_hyp_alloc(unsigned long nr_pages)
{
	unsigned long ratelimit, last_reclaim, reclaimed = 0;
	struct kvm_hyp_memcache mc;
	struct arm_smccc_res res;

	do {
		/* Arbitrary upper bound to limit the time spent at EL2 */
		ratelimit = min(nr_pages, 256UL);

		arm_smccc_1_1_hvc(KVM_HOST_SMCCC_FUNC(__pkvm_hyp_alloc_reclaim),
				  ratelimit, &res);
		if (WARN_ON(res.a0 != SMCCC_RET_SUCCESS))
			break;

		mc.head = res.a2;
		last_reclaim = mc.nr_pages = res.a3;
		free_hyp_memcache(&mc, 0);

		reclaimed += last_reclaim;
		if (last_reclaim > nr_pages)
			break;
		nr_pages -= last_reclaim;

	} while (last_reclaim && nr_pages);

	return reclaimed;
}

#include <linux/debugfs.h>

static ssize_t hyp_reclaim_debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *off)
{
	struct kvm_hyp_memcache mc;
	struct arm_smccc_res res;
	int target;

	if (kstrtoint_from_user(buf, count, 10, &target))
		return -EINVAL;

	arm_smccc_1_1_hvc(KVM_HOST_SMCCC_FUNC(__pkvm_hyp_alloc_reclaim), target, &res);
	WARN_ON(res.a0 != SMCCC_RET_SUCCESS);

	mc.head = res.a2;
	mc.nr_pages = res.a3;

	printk("%lu page(s) reclaimed\n", mc.nr_pages);

	free_hyp_memcache(&mc, 0);

	return count;
}

static const struct file_operations hyp_reclaim_debugfs_fops = {
	.write = hyp_reclaim_debugfs_write,
};

static ssize_t hyp_alloc_debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *off)
{
	u64 value;
	int ret;

	ret = kstrtoull_from_user(buf, count, 10, &value);
	if (ret)
		return ret;
again:
	ret = kvm_call_hyp_nvhe(__pkvm_hyp_alloc, value);
	if (ret == -ENOMEM) {
		struct kvm_hyp_memcache mc = {
			.head		= 0,
			.nr_pages	= 0,
		};

		ret = topup_hyp_memcache(&mc, 1, 0);
		if (ret)
			return ret;

		ret = kvm_call_hyp_nvhe(__pkvm_hyp_alloc_refill, mc.head, mc.nr_pages);
		if (ret)
			return ret;
		goto again;
	} else if (ret) {
		return ret;
	}

	return count;
}

static const struct file_operations hyp_alloc_debugfs_fops = {
	.write = hyp_alloc_debugfs_write,
};

static ssize_t hyp_free_debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *off)
{
	u64 value;
	int ret;

	ret = kstrtoull_from_user(buf, count, 16, &value);
	if (ret)
		return ret;

	ret = kvm_call_hyp_nvhe(__pkvm_hyp_free, value);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations hyp_free_debugfs_fops = {
	.write = hyp_free_debugfs_write,
};

struct hyp_allocator_chunk_dump {
	unsigned long	addr;
	unsigned long	alloc_start;
	size_t		alloc_size;
	size_t		unmapped_size;
	size_t 		mapped_size;
	u32		hash;
};

#define BYTES_TO_LINES PAGE_SIZE
#define LINE_WIDTH 33
#if 0
static void __dump_region(struct seq_file *m, const char *name, size_t size, unsigned long va,
			  bool end_chunk)
{
	int i, j, nr_lines = size / BYTES_TO_LINES;

	/* TODO: Check for non decreasing va */

	if (!size)
		return;

	if (!nr_lines)
		nr_lines = 1;

	for (i = 0; i < nr_lines; i++) {
		if (i == nr_lines / 2) {
			int name_len = strlen(name);
			int start = (LINE_WIDTH - 2 - name_len) / 2;

			seq_putc(m, '|');
			for (j = 0; j < start; j++)
				seq_putc(m, ' ');

			seq_puts(m, name);
			for (j = 0; j < (name_len % 2 ? start - 1 : start); j++)
				seq_putc(m, ' ');
			seq_puts(m, "|\n");
		} else
			seq_puts(m, "|                              |\n");
	}

	if (end_chunk)
		seq_printf(m, "+==============================+ 0x%08lx\n", va);
	else
		seq_printf(m, "+------------------------------+ 0x%08lx\n", va);
}

static int dump_hyp_allocator_show(struct seq_file *m, void *v)
{
	struct hyp_allocator_chunk_dump *first_chunk, *chunk;
	void *page = m->private;

	seq_printf(m, "Reclaimable: %ld pages\n",
		   kvm_call_hyp_nvhe(__pkvm_hyp_alloc_reclaimable));

	/* Decode the page */
	first_chunk = chunk = (struct hyp_allocator_chunk_dump *)page;
	if (!chunk->addr)
		return 0;

	while ((chunk + 1)->addr)
		chunk++;

	seq_printf(m, "+==============================+ 0x%08lx\n", chunk->addr + chunk->mapped_size + chunk->unmapped_size);
	while ((unsigned long)chunk >= (unsigned long)first_chunk) {
		size_t header_size = chunk->alloc_start - chunk->addr;
		size_t mapped_display_size = chunk->mapped_size - header_size - chunk->alloc_size;

		__dump_region(m, "unmapped", chunk->unmapped_size,
			      chunk->addr + chunk->mapped_size, false);
		__dump_region(m, "mapped", mapped_display_size,
			      chunk->alloc_start + chunk->alloc_size, false);
		__dump_region(m, "alloc", chunk->alloc_size,
			      chunk->alloc_start, false);
		__dump_region(m, "chunk header", header_size, chunk->addr, true);
		chunk--;
	}

	return 0;
}
#else
static int dump_hyp_allocator_show(struct seq_file *m, void *v)
{
	struct hyp_allocator_chunk_dump *first_chunk, *chunk;
	void *page = m->private;

	first_chunk = chunk = (struct hyp_allocator_chunk_dump *)page;
	if (!chunk->addr)
		return 0;

	while (chunk->addr) {
		seq_printf(m, "0x%lx: alloc=%zu mapped=%zu unmapped=%zu hash=%x\n",
			   chunk->addr, chunk->alloc_size, chunk->mapped_size,
			   chunk->unmapped_size, chunk->hash);
		chunk++;
	}

	return 0;
}
#endif
static int dump_hyp_allocator_open(struct inode *inode, struct file *file)
{
	void *page;
	int ret;

	page = page_address(alloc_page(GFP_KERNEL));
	if (!page)
		return -ENOMEM;

	ret = kvm_call_hyp_nvhe(__pkvm_dump_hyp_allocator, page);
	if (ret) {
		free_page((unsigned long)page);
		return ret;
	}

	return single_open(file, dump_hyp_allocator_show, page);
}

static int dump_hyp_allocator_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	void *page = m->private;

	free_page((unsigned long)page);
	seq_release(inode, file);

	return 0;
}

static const struct file_operations dump_hyp_allocator_debugfs_fops = {
	.open = dump_hyp_allocator_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = dump_hyp_allocator_release,
};

static int __init hyp_allocator_debugfs_init(void)
{
	debugfs_create_file("hyp_alloc", S_IWUSR, NULL, NULL, &hyp_alloc_debugfs_fops);

	debugfs_create_file("hyp_free", S_IWUSR, NULL, NULL, &hyp_free_debugfs_fops);

	debugfs_create_file("hyp_reclaim", S_IWUSR, NULL, NULL, &hyp_reclaim_debugfs_fops);

	debugfs_create_file("dump_hyp_allocator", S_IRUSR, NULL, NULL, &dump_hyp_allocator_debugfs_fops);

	return 0;
}
late_initcall(hyp_allocator_debugfs_init);
