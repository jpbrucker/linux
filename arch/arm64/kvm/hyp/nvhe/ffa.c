// SPDX-License-Identifier: GPL-2.0-only
/*
 * FF-A v1.0 proxy to filter out invalid memory-sharing SMC calls issued by
 * the host. FF-A is a slightly more palatable abbreviation of "Arm Firmware
 * Framework for Arm A-profile", which is specified by Arm in document
 * number DEN0077.
 *
 * Copyright (C) 2022 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 *
 * This driver hooks into the SMC trapping logic for the host and intercepts
 * all calls falling within the FF-A range. Each call is either:
 *
 *	- Forwarded on unmodified to the SPMD at EL3
 *	- Rejected as "unsupported"
 *	- Accompanied by a host stage-2 page-table check/update and reissued
 *
 * Consequently, any attempts by the host to make guest memory pages
 * accessible to the secure world using FF-A will be detected either here
 * (in the case that the memory is already owned by the guest) or during
 * donation to the guest (in the case that the memory was previously shared
 * with the secure world).
 *
 * To allow the rolling-back of page-table updates and FF-A calls in the
 * event of failure, operations involving the RXTX buffers are locked for
 * the duration and are therefore serialised.
 */

#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <linux/list.h>
#include <asm/kvm_pkvm.h>

#include <kvm/arm_hypercalls.h>

#include <nvhe/alloc.h>
#include <nvhe/ffa.h>
#include <nvhe/mem_protect.h>
#include <nvhe/memory.h>
#include <nvhe/trap_handler.h>
#include <nvhe/spinlock.h>

#define	SMC_ENTITY_TRUSTED_OS		50	/* Trusted OS calls */
#define SMC_NR(entity, fn, fastcall, smc64) ((((fastcall) & 0x1U) << 31) | \
					     (((smc64) & 0x1U) << 30) | \
					     (((entity) & 0x3FU) << 24) | \
					     ((fn) & 0xFFFFU) \
					    )

#define SMC_STDCALL_NR(entity, fn)      SMC_NR((entity), (fn), 0, 0)
#define SMC_SC_VIRTIO_STOP      SMC_STDCALL_NR(SMC_ENTITY_TRUSTED_OS, 22)

/*
 * "ID value 0 must be returned at the Non-secure physical FF-A instance"
 * We share this ID with the host.
 */
#define HOST_FFA_ID	0

/*
 * A buffer to hold the maximum descriptor size we can see from the host,
 * which is required when the SPMD returns a fragmented FFA_MEM_RETRIEVE_RESP
 * when resolving the handle on the reclaim path.
 */
struct kvm_ffa_descriptor_buffer {
	void	*buf;
	size_t	len;
};

struct ffa_guest_repainted_addr {
	u64 ipa;
	u64 pa;
};

struct ffa_guest_share_ctxt {
	struct list_head node;
	u64 ffa_handle;
	size_t no_repainted;
	struct ffa_guest_repainted_addr repainted[0];
};

static struct kvm_ffa_descriptor_buffer ffa_desc_buf;

struct kvm_ffa_buffers {
	hyp_spinlock_t lock;
	void *tx;
	void *rx;
	struct list_head transfers;
};

/*
 * Note that we don't currently lock these buffers explicitly, instead
 * relying on the locking of the hyp FFA buffers.
 */
static struct kvm_ffa_buffers hyp_buffers;
static struct kvm_ffa_buffers non_secure_el1_buffers[KVM_MAX_PVMS];
static u8 hyp_buffer_refcnt;
static bool ffa_available;

static void ffa_to_smccc_error(struct arm_smccc_res *res, u64 ffa_errno)
{
	*res = (struct arm_smccc_res) {
		.a0	= FFA_ERROR,
		.a2	= ffa_errno,
	};
}

static void ffa_to_smccc_res_prop(struct arm_smccc_res *res, int ret, u64 prop)
{
	if (ret == FFA_RET_SUCCESS) {
		*res = (struct arm_smccc_res) { .a0 = FFA_SUCCESS,
						.a2 = prop };
	} else {
		ffa_to_smccc_error(res, ret);
	}
}

static void ffa_to_smccc_res(struct arm_smccc_res *res, int ret)
{
	ffa_to_smccc_res_prop(res, ret, 0);
}

static void ffa_set_retval(struct kvm_cpu_context *ctxt,
			   struct arm_smccc_res *res)
{
	cpu_reg(ctxt, 0) = res->a0;
	cpu_reg(ctxt, 1) = res->a1;
	cpu_reg(ctxt, 2) = res->a2;
	cpu_reg(ctxt, 3) = res->a3;
}

static int ffa_map_hyp_buffers(u64 ffa_page_count)
{
	struct arm_smccc_res res;

	if (hyp_buffer_refcnt > 0)
		return FFA_RET_SUCCESS;

	arm_smccc_1_1_smc(FFA_FN64_RXTX_MAP,
			  hyp_virt_to_phys(hyp_buffers.tx),
			  hyp_virt_to_phys(hyp_buffers.rx),
			  ffa_page_count,
			  0, 0, 0, 0,
			  &res);

	return res.a0 == FFA_SUCCESS ? FFA_RET_SUCCESS : res.a2;
}

static int ffa_unmap_hyp_buffers(void)
{
	struct arm_smccc_res res;

	/* We unmap the buffers from the spmd only when no one references
	 * them.
	 */
	if (hyp_buffer_refcnt != 0)
		return FFA_RET_SUCCESS;

	arm_smccc_1_1_smc(FFA_RXTX_UNMAP,
			  HOST_FFA_ID,
			  0, 0, 0, 0, 0, 0,
			  &res);

	return res.a0 == FFA_SUCCESS ? FFA_RET_SUCCESS : res.a2;
}

static void ffa_mem_frag_tx(struct arm_smccc_res *res, u32 handle_lo,
			     u32 handle_hi, u32 fraglen, u32 endpoint_id)
{
	arm_smccc_1_1_smc(FFA_MEM_FRAG_TX,
			  handle_lo, handle_hi, fraglen, endpoint_id,
			  0, 0, 0,
			  res);
}

static void ffa_mem_frag_rx(struct arm_smccc_res *res, u32 handle_lo,
			     u32 handle_hi, u32 fragoff)
{
	arm_smccc_1_1_smc(FFA_MEM_FRAG_RX,
			  handle_lo, handle_hi, fragoff, HOST_FFA_ID,
			  0, 0, 0,
			  res);
}

static void ffa_mem_xfer(struct arm_smccc_res *res, u64 func_id, u32 len,
			  u32 fraglen)
{
	arm_smccc_1_1_smc(func_id, len, fraglen,
			  0, 0, 0, 0, 0,
			  res);
}

static void ffa_mem_reclaim(struct arm_smccc_res *res, u32 handle_lo,
			     u32 handle_hi, u32 flags)
{
	arm_smccc_1_1_smc(FFA_MEM_RECLAIM,
			  handle_lo, handle_hi, flags,
			  0, 0, 0, 0,
			  res);
}

static void ffa_retrieve_req(struct arm_smccc_res *res, u32 len)
{
	arm_smccc_1_1_smc(FFA_FN64_MEM_RETRIEVE_REQ,
			  len, len,
			  0, 0, 0, 0, 0,
			  res);
}

static void trusty_stop_virtio(struct arm_smccc_res *res, u32 client_id)
{
	arm_smccc_1_1_smc(SMC_SC_VIRTIO_STOP,
			  0, 0, 0, 0, 0, 0, client_id,
			  res);
}

static int host_share_hyp_buffers(struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(phys_addr_t, tx, ctxt, 1);
	DECLARE_REG(phys_addr_t, rx, ctxt, 2);
	int ret;
	void *rx_virt, *tx_virt;

	ret = __pkvm_host_share_hyp(hyp_phys_to_pfn(tx));
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unmap;
	}

	ret = __pkvm_host_share_hyp(hyp_phys_to_pfn(rx));
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unshare_tx;
	}

	tx_virt = hyp_phys_to_virt(tx);
	ret = hyp_pin_shared_mem(tx_virt, tx_virt + 1);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unshare_rx;
	}

	rx_virt = hyp_phys_to_virt(rx);
	ret = hyp_pin_shared_mem(rx_virt, rx_virt + 1);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unpin_tx;
	}

	non_secure_el1_buffers[0].tx = tx_virt;
	non_secure_el1_buffers[0].rx = rx_virt;
	hyp_buffer_refcnt++;
	return ret;
err_unpin_tx:
	hyp_unpin_shared_mem(tx_virt, tx_virt + 1);
err_unshare_rx:
	__pkvm_host_unshare_hyp(hyp_phys_to_pfn(rx));
err_unshare_tx:
	__pkvm_host_unshare_hyp(hyp_phys_to_pfn(tx));
err_unmap:
	ffa_unmap_hyp_buffers();
	return ret;
}

static int guest_share_hyp_buffers(struct kvm_cpu_context *ctxt, u64 vmid)
{
	DECLARE_REG(phys_addr_t, tx, ctxt, 1);
	DECLARE_REG(phys_addr_t, rx, ctxt, 2);
	struct kvm_vcpu *vcpu = ctxt->__hyp_running_vcpu;
	struct pkvm_hyp_vcpu *pkvm_vcpu;
	struct pkvm_hyp_vm *vm;
	int ret;
	void *rx_virt, *tx_virt;
	phys_addr_t phys;
	kvm_pte_t pte;

	if (!vcpu)
		vcpu = container_of(ctxt, struct kvm_vcpu, arch.ctxt);

	pkvm_vcpu = container_of(vcpu, struct pkvm_hyp_vcpu, vcpu);
	ret = __pkvm_guest_share_hyp(pkvm_vcpu, tx);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unmap;
	}

	ret = __pkvm_guest_share_hyp(pkvm_vcpu, rx);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unshare_tx;
	}

	/* Convert the guest IPA address to hyp virtual address */
	vm = pkvm_hyp_vcpu_to_hyp_vm(pkvm_vcpu);
	ret = kvm_pgtable_get_leaf(&vm->pgt, tx, &pte, NULL);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unshare_rx;
	}

	phys = kvm_pte_to_phys(pte);
	tx_virt = __hyp_va(phys);
	ret = hyp_pin_shared_mem_from_guest(pkvm_vcpu, (void *)tx, tx_virt,
					    tx_virt + 1);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unshare_rx;
	}

	ret = kvm_pgtable_get_leaf(&vm->pgt, rx, &pte, NULL);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unpin_tx;
	}

	phys = kvm_pte_to_phys(pte);
	rx_virt = __hyp_va(phys);
	ret = hyp_pin_shared_mem_from_guest(pkvm_vcpu, (void *)rx, rx_virt,
					    rx_virt + 1);
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unpin_tx;
	}

	non_secure_el1_buffers[vmid].tx = tx_virt;
	non_secure_el1_buffers[vmid].rx = rx_virt;
	hyp_buffer_refcnt++;
	return ret;

err_unpin_tx:
	hyp_unpin_shared_mem_from_guest(pkvm_vcpu, tx_virt, tx_virt + 1);
err_unshare_rx:
	__pkvm_guest_unshare_hyp(pkvm_vcpu, rx);
err_unshare_tx:
	__pkvm_guest_unshare_hyp(pkvm_vcpu, tx);
err_unmap:
	ffa_unmap_hyp_buffers();
	return ret;
}

static void do_ffa_rxtx_map(struct arm_smccc_res *res,
			    struct kvm_cpu_context *ctxt,
			    u64 vmid)
{
	DECLARE_REG(phys_addr_t, tx, ctxt, 1);
	DECLARE_REG(phys_addr_t, rx, ctxt, 2);
	DECLARE_REG(u32, npages, ctxt, 3);
	int ret = 0;

	if (npages != (KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE) / FFA_PAGE_SIZE) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	if (!PAGE_ALIGNED(tx) || !PAGE_ALIGNED(rx)) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	if (vmid >= KVM_MAX_PVMS) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	hyp_spin_lock(&hyp_buffers.lock);
	if (non_secure_el1_buffers[vmid].tx) {
		ret = FFA_RET_DENIED;
		goto out_unlock;
	}
	ret = ffa_map_hyp_buffers(npages);
	if (ret)
		goto out_unlock;

	if (vmid == 0)
		ret = host_share_hyp_buffers(ctxt);
	else
		ret = guest_share_hyp_buffers(ctxt, vmid);

out_unlock:
	hyp_spin_unlock(&hyp_buffers.lock);
out:
	ffa_to_smccc_res(res, ret);
	return;
}

static void do_ffa_rxtx_unmap(struct arm_smccc_res *res,
			      struct kvm_cpu_context *ctxt,
			      u64 vmid)
{
	DECLARE_REG(u32, id, ctxt, 1);
	DECLARE_REG(phys_addr_t, tx, ctxt, 2);
	DECLARE_REG(phys_addr_t, rx, ctxt, 3);
	int ret = 0;
	u64 pfn;
	struct kvm_vcpu *vcpu = ctxt->__hyp_running_vcpu;
	struct pkvm_hyp_vcpu *pkvm_vcpu;
	struct pkvm_hyp_vm *vm;
	void *rx_virt, *tx_virt;
	phys_addr_t phys;
	kvm_pte_t pte;

	if (id != HOST_FFA_ID) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	hyp_spin_lock(&hyp_buffers.lock);
	if (!non_secure_el1_buffers[vmid].tx) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	if (vmid == 0) {
		hyp_unpin_shared_mem(non_secure_el1_buffers[vmid].tx,
				     non_secure_el1_buffers[vmid].tx + 1);
		hyp_unpin_shared_mem(non_secure_el1_buffers[vmid].rx,
				     non_secure_el1_buffers[vmid].rx + 1);
		pfn = hyp_virt_to_pfn(non_secure_el1_buffers[vmid].tx);
		WARN_ON(__pkvm_host_unshare_hyp(pfn));

		pfn = hyp_virt_to_pfn(non_secure_el1_buffers[vmid].rx);
		WARN_ON(__pkvm_host_unshare_hyp(pfn));
	} else {
		/* For guests we need to convert the HYP va to a guest IPA
		 *
		 * Note: this is tricky because we need a reverse mapping:
		 * guest stage2: PHYS -> IPA and can be avoided if we
		 * pass the IPA address of the buffers in the FFA_RXTX_UNMAP
		 * instead of passing the ID of the buffer.
		 */
		WARN_ON(tx == 0 ||  rx == 0);

		/* Note: we should not blindly unshare these buffers with
		 * the hyp. First check that the received buffer addresses
		 * are part of the guest.
		 */
		if (!vcpu)
			vcpu = container_of(ctxt, struct kvm_vcpu, arch.ctxt);

		pkvm_vcpu = container_of(vcpu, struct pkvm_hyp_vcpu, vcpu);
		vm = pkvm_hyp_vcpu_to_hyp_vm(pkvm_vcpu);
		WARN_ON(kvm_pgtable_get_leaf(&vm->pgt, tx, &pte, NULL));

		phys = kvm_pte_to_phys(pte);
		tx_virt = __hyp_va(phys);

		WARN_ON(non_secure_el1_buffers[vmid].tx != tx_virt);
		WARN_ON(kvm_pgtable_get_leaf(&vm->pgt, rx, &pte, NULL));

		phys = kvm_pte_to_phys(pte);
		rx_virt = __hyp_va(phys);

		WARN_ON(non_secure_el1_buffers[vmid].rx != rx_virt);

		/* Now it's safe to unshare the buffers from guest */
		hyp_unpin_shared_mem_from_guest(pkvm_vcpu,
						non_secure_el1_buffers[vmid].tx,
						non_secure_el1_buffers[vmid].tx + 1);
		hyp_unpin_shared_mem_from_guest(pkvm_vcpu,
						non_secure_el1_buffers[vmid].rx,
						non_secure_el1_buffers[vmid].rx + 1);

		WARN_ON(__pkvm_guest_unshare_hyp(pkvm_vcpu, tx));
		WARN_ON(__pkvm_guest_unshare_hyp(pkvm_vcpu, rx));
	}

	non_secure_el1_buffers[vmid].rx = NULL;
	non_secure_el1_buffers[vmid].tx = NULL;

	if (hyp_buffer_refcnt > 0)
		hyp_buffer_refcnt--;

	ffa_unmap_hyp_buffers();

out_unlock:
	hyp_spin_unlock(&hyp_buffers.lock);
out:
	ffa_to_smccc_res(res, ret);
}

static u32 __ffa_host_share_ranges(struct ffa_mem_region_addr_range *ranges,
				   u32 nranges)
{
	u32 i;

	for (i = 0; i < nranges; ++i) {
		struct ffa_mem_region_addr_range *range = &ranges[i];
		u64 sz = (u64)range->pg_cnt * FFA_PAGE_SIZE;
		u64 pfn = hyp_phys_to_pfn(range->address);

		if (!PAGE_ALIGNED(sz))
			break;

		if (__pkvm_host_share_ffa(pfn, sz / PAGE_SIZE))
			break;
	}

	return i;
}

static u32 __ffa_host_unshare_ranges(struct ffa_mem_region_addr_range *ranges,
				     u32 nranges)
{
	u32 i;

	for (i = 0; i < nranges; ++i) {
		struct ffa_mem_region_addr_range *range = &ranges[i];
		u64 sz = (u64)range->pg_cnt * FFA_PAGE_SIZE;
		u64 pfn = hyp_phys_to_pfn(range->address);

		if (!PAGE_ALIGNED(sz))
			break;

		if (__pkvm_host_unshare_ffa(pfn, sz / PAGE_SIZE))
			break;
	}

	return i;
}

static int ffa_host_share_ranges(struct ffa_mem_region_addr_range *ranges,
				 u32 nranges)
{
	u32 nshared = __ffa_host_share_ranges(ranges, nranges);
	int ret = 0;

	if (nshared != nranges) {
		WARN_ON(__ffa_host_unshare_ranges(ranges, nshared) != nshared);
		ret = FFA_RET_DENIED;
	}

	return ret;
}

static int ffa_host_unshare_ranges(struct ffa_mem_region_addr_range *ranges,
				   u32 nranges)
{
	u32 nunshared = __ffa_host_unshare_ranges(ranges, nranges);
	int ret = 0;

	if (nunshared != nranges) {
		WARN_ON(__ffa_host_share_ranges(ranges, nunshared) != nunshared);
		ret = FFA_RET_DENIED;
	}

	return ret;
}

/* Allocates memory that will hold the IPA <-> PA repainting and the FF-A
 * global handle which identifies the memory transfer.
 */
static struct ffa_guest_share_ctxt
*ffa_guest_allocate_share_context(u32 num_entries, struct kvm_cpu_context *ctxt,
				  u64 vmid, u64 *exit_code)
{
	struct ffa_guest_share_ctxt *transfer;
	struct kvm_vcpu *vcpu = ctxt->__hyp_running_vcpu;
	struct pkvm_hyp_vcpu *pkvm_vcpu;
	size_t alloc_sz;
	struct kvm_hyp_req *mem_topup_req;

	if (!vcpu)
		vcpu = container_of(ctxt, struct kvm_vcpu, arch.ctxt);
	pkvm_vcpu = container_of(vcpu, struct pkvm_hyp_vcpu, vcpu);

	alloc_sz = sizeof(struct ffa_guest_share_ctxt) + num_entries *
		sizeof(struct ffa_guest_repainted_addr);

	transfer = hyp_alloc(alloc_sz);
	if (!transfer) {
		mem_topup_req = pkvm_hyp_req_reserve(pkvm_vcpu,
						     KVM_HYP_REQ_MEM);
		if (!mem_topup_req)
			return NULL;

		mem_topup_req->mem.nr_pages = hyp_alloc_missing_donations();
		mem_topup_req->mem.dest = 1;
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		return NULL;
	}

	transfer->no_repainted = num_entries;
	return transfer;
}

static void ffa_guest_free_share_context(struct ffa_guest_share_ctxt *transfer)
{
	if (transfer == NULL)
		return;

	hyp_free(transfer);
}

static int ffa_guest_insert_repainted(struct ffa_guest_share_ctxt *share_ctxt,
				      struct ffa_guest_repainted_addr *node,
				      size_t pos)
{
	if (pos >= share_ctxt->no_repainted)
		return -EINVAL;

	share_ctxt->repainted[pos].ipa = node->ipa;
	share_ctxt->repainted[pos].pa  = node->pa;
	return 0;
}

/* Repaint the guest IPA addresses with PA addresses and break the contiguous
 * constituents. Return the number of painted constituents or a negative error code.
 */
static int ffa_guest_repaint_ipa_ranges(struct ffa_composite_mem_region *reg,
					struct kvm_cpu_context *ctxt, u64 vmid,
					struct ffa_guest_share_ctxt *share_ctxt)
{
	struct ffa_mem_region_addr_range *ipa_ranges = reg->constituents;
	struct kvm_vcpu *vcpu = ctxt->__hyp_running_vcpu;
	struct ffa_mem_region_addr_range *phys_ranges;
	struct pkvm_hyp_vcpu *pkvm_vcpu;
	struct ffa_guest_repainted_addr node;
	int i, pg_idx, ret, nr_entries = 0;
	u64 ipa_addr;
	size_t total_sz;
	struct pkvm_hyp_vm *vm;
	kvm_pte_t pte;

	if (!vcpu)
		vcpu = container_of(ctxt, struct kvm_vcpu, arch.ctxt);

	pkvm_vcpu = container_of(vcpu, struct pkvm_hyp_vcpu, vcpu);
	vm = pkvm_hyp_vcpu_to_hyp_vm(pkvm_vcpu);
	total_sz = reg->total_pg_cnt * sizeof(struct ffa_mem_region_addr_range);

	if (total_sz > ffa_desc_buf.len)
		return FFA_RET_NO_MEMORY;

	phys_ranges = (struct ffa_mem_region_addr_range *)ffa_desc_buf.buf;
	for (i = 0; i < reg->addr_range_cnt; ++i) {
		struct ffa_mem_region_addr_range *range =
			&phys_ranges[nr_entries];

		ret = kvm_pgtable_get_leaf(&vm->pgt, ipa_ranges[i].address,
					   &pte, NULL);
		if (ret) {
			return FFA_RET_INVALID_PARAMETERS;
		}

		range->address = kvm_pte_to_phys(pte);
		range->pg_cnt = 1;

		node.ipa = ipa_ranges[i].address;
		node.pa = range->address;
		ret = ffa_guest_insert_repainted(share_ctxt, &node, nr_entries);
		if (ret) {
			return ret;
		}

		nr_entries++;

		/* If we have multipple pages in the contiguous IPA space,
		 * break the address region into multipple constituents.
		 */
		for (pg_idx = 1; pg_idx < ipa_ranges[i].pg_cnt; pg_idx++) {
			range = &phys_ranges[nr_entries];
			ipa_addr = ipa_ranges[i].address + PAGE_SIZE * pg_idx;

			ret = kvm_pgtable_get_leaf(&vm->pgt, ipa_addr, &pte,
						   NULL);
			if (ret) {
				return FFA_RET_INVALID_PARAMETERS;
			}

			range->address = kvm_pte_to_phys(pte);
			range->pg_cnt = 1;

			node.ipa = ipa_addr;
			node.pa = range->address;
			ret = ffa_guest_insert_repainted(share_ctxt, &node,
							 nr_entries);
			if (ret) {
				return ret;
			}

			nr_entries++;
		}
	}

	return nr_entries;
}

static struct ffa_guest_share_ctxt
*ffa_guest_get_ipa_from_pa(struct kvm_ffa_buffers *guest_ctxt, u64 pa, u64 *ipa)
{
	struct ffa_guest_share_ctxt *transfer_ctxt;
	int i;

	/* TODO: optimise this search */
	list_for_each_entry(transfer_ctxt, &guest_ctxt->transfers, node) {
		for (i = 0; i < transfer_ctxt->no_repainted; i++) {
			if (transfer_ctxt->repainted[i].pa == pa) {
				*ipa = transfer_ctxt->repainted[i].ipa;
				return transfer_ctxt;
			}
		}
	}

	return NULL;
}

static void ffa_guest_repaint_pa_ranges(struct ffa_composite_mem_region *reg,
					struct kvm_ffa_buffers *guest_ctxt)
{
	int i, j;
	struct ffa_mem_region_addr_range *range;
	struct ffa_guest_share_ctxt *transfer_ctxt = NULL;
	u64 ipa;

	for (i = 0; i < reg->addr_range_cnt; i++) {
		range = &reg->constituents[i];
		for (j = 0; j < range->pg_cnt; j++) {
			transfer_ctxt = ffa_guest_get_ipa_from_pa(guest_ctxt,
								  range->address,
								  &ipa);
			WARN_ON(!transfer_ctxt);
			range->address = ipa;
		}
	}

	/* Cleanup the transfer context from this guest */
	list_del(&transfer_ctxt->node);
	ffa_guest_free_share_context(transfer_ctxt);
}


/* Annotate the pagetables of the guest as being shared with FF-A */
static int ffa_guest_share_ranges(struct ffa_mem_region_addr_range *ranges,
				  u32 nranges, struct kvm_cpu_context *ctxt,
				  u64 vmid, u64 *exit_code)
{
	struct kvm_vcpu *vcpu = ctxt->__hyp_running_vcpu;
	struct ffa_mem_region_addr_range *range;
	struct pkvm_hyp_vcpu *pkvm_vcpu;
	int i, j, ret;
	u64 ipa_addr;

	if (!vcpu)
		vcpu = container_of(ctxt, struct kvm_vcpu, arch.ctxt);

	pkvm_vcpu = container_of(vcpu, struct pkvm_hyp_vcpu, vcpu);
	for (i = 0; i < nranges; ++i) {
		range = &ranges[i];
		for (j = 0; j < range->pg_cnt; j++) {
			ipa_addr = range->address + j * FFA_PAGE_SIZE;

			if (!PAGE_ALIGNED(ipa_addr)) {
				ret = -EINVAL;
				goto unshare_inner_pages;
			}

			ret = __pkvm_guest_share_ffa(pkvm_vcpu, ipa_addr);
			if (!ret) {
				continue;
			} else if (ret == -EFAULT) {
				*exit_code = __pkvm_memshare_page_req(pkvm_vcpu,
								      ipa_addr);
				return ret;
			} else {
				goto unshare_inner_pages;
			}
		}
	}

	return 0;

unshare_inner_pages:
	for (j = j - 1; j >= 0; j--) {
		ipa_addr = range->address + j * FFA_PAGE_SIZE;
		WARN_ON(__pkvm_guest_unshare_ffa(pkvm_vcpu, ipa_addr));
	}

	for (i = i - 1; i >= 0; i--) {
		range = &ranges[i];
		for (j = 0; j < range->pg_cnt; j++) {
			ipa_addr = range->address + j * FFA_PAGE_SIZE;
			WARN_ON(__pkvm_guest_unshare_ffa(pkvm_vcpu, ipa_addr));
		}
	}

	return ret;
}

static int ffa_guest_unshare_ranges(struct ffa_mem_region_addr_range *ranges,
				    u32 nranges, struct kvm_cpu_context *ctxt,
				    u64 vmid)
{
	struct kvm_vcpu *vcpu = ctxt->__hyp_running_vcpu;
	struct ffa_mem_region_addr_range *range;
	struct pkvm_hyp_vcpu *pkvm_vcpu;
	int i, j, ret = 0;
	u64 ipa_addr;

	if (!vcpu)
		vcpu = container_of(ctxt, struct kvm_vcpu, arch.ctxt);

	pkvm_vcpu = container_of(vcpu, struct pkvm_hyp_vcpu, vcpu);
	for (i = 0; i < nranges; i++) {
		range = &ranges[i];
		for (j = 0; j < range->pg_cnt; j++) {
			ipa_addr = range->address + j * FFA_PAGE_SIZE;
			ret = __pkvm_guest_unshare_ffa(pkvm_vcpu, ipa_addr);
			if (ret != 0) {
				return ret;
			}
		}
	}

	return ret;
}

/* Verifies if the VM is allowed to do FF-A memory operations */
static bool is_ffa_id_valid(u16 sender_ffa_id, u64 vmid)
{
#if 1
	return true;
#else
	if (sender_ffa_id == HOST_FFA_ID)
		return true;

	return false;
#endif
}

static void do_ffa_mem_frag_tx(struct arm_smccc_res *res,
			       struct kvm_cpu_context *ctxt,
			       u64 vmid)
{
	DECLARE_REG(u32, handle_lo, ctxt, 1);
	DECLARE_REG(u32, handle_hi, ctxt, 2);
	DECLARE_REG(u32, fraglen, ctxt, 3);
	DECLARE_REG(u32, endpoint_id, ctxt, 4);
	struct ffa_mem_region_addr_range *buf;
	int ret = FFA_RET_INVALID_PARAMETERS;
	u32 nr_ranges;

	if (fraglen > KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE)
		goto out;

	if (fraglen % sizeof(*buf))
		goto out;

	hyp_spin_lock(&hyp_buffers.lock);
	if (!non_secure_el1_buffers[vmid].tx)
		goto out_unlock;

	buf = hyp_buffers.tx;
	memcpy(buf, non_secure_el1_buffers[vmid].tx, fraglen);
	nr_ranges = fraglen / sizeof(*buf);

	ret = ffa_host_share_ranges(buf, nr_ranges);
	if (ret) {
		/*
		 * We're effectively aborting the transaction, so we need
		 * to restore the global state back to what it was prior to
		 * transmission of the first fragment.
		 */
		ffa_mem_reclaim(res, handle_lo, handle_hi, 0);
		WARN_ON(res->a0 != FFA_SUCCESS);
		goto out_unlock;
	}

	ffa_mem_frag_tx(res, handle_lo, handle_hi, fraglen, endpoint_id);
	if (res->a0 != FFA_SUCCESS && res->a0 != FFA_MEM_FRAG_RX)
		WARN_ON(ffa_host_unshare_ranges(buf, nr_ranges));

out_unlock:
	hyp_spin_unlock(&hyp_buffers.lock);
out:
	if (ret)
		ffa_to_smccc_res(res, ret);

	/*
	 * If for any reason this did not succeed, we're in trouble as we have
	 * now lost the content of the previous fragments and we can't rollback
	 * the host stage-2 changes. The pages previously marked as shared will
	 * remain stuck in that state forever, hence preventing the host from
	 * sharing/donating them again and may possibly lead to subsequent
	 * failures, but this will not compromise confidentiality.
	 */
	return;
}

static __always_inline int do_ffa_mem_xfer(const u64 func_id,
					   struct arm_smccc_res *res,
					   struct kvm_cpu_context *ctxt,
					   u64 vmid, u64 *exit_code)
{
	DECLARE_REG(u32, len, ctxt, 1);
	DECLARE_REG(u32, fraglen, ctxt, 2);
	DECLARE_REG(u64, addr_mbz, ctxt, 3);
	DECLARE_REG(u32, npages_mbz, ctxt, 4);
	struct ffa_composite_mem_region *reg;
	struct ffa_mem_region *buf;
	struct ffa_guest_share_ctxt *transfer = NULL;
	u32 offset, nr_ranges, total_pg_cnt;
	int i, ret = 0, no_painted;
	size_t adjust_sz = 0, remaining_sz;

	BUILD_BUG_ON(func_id != FFA_FN64_MEM_SHARE &&
		     func_id != FFA_FN64_MEM_LEND);

	if (addr_mbz || npages_mbz || fraglen > len ||
	    fraglen > KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	if (fraglen < sizeof(struct ffa_mem_region) +
		      sizeof(struct ffa_mem_region_attributes)) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	hyp_spin_lock(&hyp_buffers.lock);
	if (!non_secure_el1_buffers[vmid].tx) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	buf = hyp_buffers.tx;
	memcpy(buf, non_secure_el1_buffers[vmid].tx, fraglen);

	offset = buf->ep_mem_access[0].composite_off;
	if (!offset || buf->ep_count != 1 ||
	    !is_ffa_id_valid(buf->sender_id, vmid)) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	if (fraglen < offset + sizeof(struct ffa_composite_mem_region)) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	reg = (void *)buf + offset;
	nr_ranges = ((void *)buf + fraglen) - (void *)reg->constituents;
	if (nr_ranges % sizeof(reg->constituents[0])) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	nr_ranges /= sizeof(reg->constituents[0]);
	if (nr_ranges != reg->addr_range_cnt) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	total_pg_cnt = 0;
	for (i = 0; i < nr_ranges; ++i) {
		total_pg_cnt += reg->constituents[i].pg_cnt;
	}
	if (total_pg_cnt != reg->total_pg_cnt) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	if (vmid == 0) {
		ret = ffa_host_share_ranges(reg->constituents, nr_ranges);
		if (ret)
			goto out_unlock;
	} else {
		transfer = ffa_guest_allocate_share_context(total_pg_cnt,
							    ctxt,
							    vmid,
							    exit_code);
		if (transfer == NULL) {
			ret = -ENOMEM;
			goto out_unlock;
		}

		ret = ffa_guest_share_ranges(reg->constituents, nr_ranges,
					     ctxt, vmid, exit_code);
		if (ret)
			goto out_release_transfer;

		no_painted = ffa_guest_repaint_ipa_ranges(reg, ctxt, vmid,
							  transfer);
		if (no_painted < 0 ||
		    no_painted < reg->addr_range_cnt) {
			ret = no_painted;
			goto err_unshare;
		}

		/* Verify if we need extra space for the broken down contiguous IPA
		 * range.
		 */
		adjust_sz = (no_painted - reg->addr_range_cnt) *
			sizeof(struct ffa_mem_region_addr_range);
		remaining_sz = KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE -
			fraglen;

		if (adjust_sz < remaining_sz) {
			memcpy(reg->constituents, ffa_desc_buf.buf,
			       no_painted *
			       sizeof(struct ffa_mem_region_addr_range));
		} else {
			/* There is not enough space inside the mailbox
			 * buffer after breaking down the contiguous
			 * constituents.
			 */
			ret = FFA_RET_NO_MEMORY;
			goto err_unshare;
		}

		fraglen += adjust_sz;
		len += adjust_sz;
		reg->addr_range_cnt = no_painted;
	}

	ffa_mem_xfer(res, func_id, len, fraglen);
	if (fraglen != len) {
		if (res->a0 != FFA_MEM_FRAG_RX)
			goto err_unshare;

		if (res->a3 != fraglen)
			goto err_unshare;
	} else if (res->a0 != FFA_SUCCESS) {
		fraglen -= adjust_sz;
		goto err_unshare;
	}

	if (transfer) {
		transfer->ffa_handle = PACK_HANDLE(res->a2, res->a3);
		list_add(&transfer->node,
			 &non_secure_el1_buffers[vmid].transfers);
	}

	goto out_unlock;

out_release_transfer:
	ffa_guest_free_share_context(transfer);
out_unlock:
	hyp_spin_unlock(&hyp_buffers.lock);
out:
	if (ret)
		ffa_to_smccc_res(res, ret);

	return ret;

err_unshare:
	if (vmid == 0) {
		WARN_ON(ffa_host_unshare_ranges(reg->constituents, nr_ranges));
	} else {
		/* This is tricky because we need to copy again the buffer
		 * from the guest driver and do the verifications one more
		 * time before removing the annotation from the guest stage-2.
		 */
		memcpy(buf, non_secure_el1_buffers[vmid].tx, fraglen);

		offset = buf->ep_mem_access[0].composite_off;
		WARN_ON(!offset || buf->ep_count != 1 ||
			!is_ffa_id_valid(buf->sender_id, vmid));

		WARN_ON(fraglen < offset + sizeof(struct ffa_composite_mem_region));
		reg = (void *)buf + offset;
		nr_ranges = ((void *)buf + fraglen) -
			(void *)reg->constituents;
		WARN_ON(nr_ranges % sizeof(reg->constituents[0]));
		nr_ranges /= sizeof(reg->constituents[0]);

		WARN_ON(nr_ranges != reg->addr_range_cnt);
		WARN_ON(ffa_guest_unshare_ranges(reg->constituents, nr_ranges,
						 ctxt, vmid));
	}

	goto out_release_transfer;
}

static void do_ffa_mem_reclaim(struct arm_smccc_res *res,
			       struct kvm_cpu_context *ctxt,
			       u64 vmid)
{
	DECLARE_REG(u32, handle_lo, ctxt, 1);
	DECLARE_REG(u32, handle_hi, ctxt, 2);
	DECLARE_REG(u32, flags, ctxt, 3);
	struct ffa_composite_mem_region *reg;
	u32 offset, len, fraglen, fragoff;
	struct ffa_mem_region *buf;
	int ret = 0;
	u64 handle;

	handle = PACK_HANDLE(handle_lo, handle_hi);

	hyp_spin_lock(&hyp_buffers.lock);

	buf = hyp_buffers.tx;

	/* TODO: Check if it is ok to pass the HOST_FFA_ID here in case
	 * we try to reclaim guest memory.
	 */
	*buf = (struct ffa_mem_region) {
		.sender_id	= HOST_FFA_ID,
		.handle		= handle,
	};

	ffa_retrieve_req(res, sizeof(*buf));
	buf = hyp_buffers.rx;
	if (res->a0 != FFA_MEM_RETRIEVE_RESP)
		goto out_unlock;

	len = res->a1;
	fraglen = res->a2;

	offset = buf->ep_mem_access[0].composite_off;
	/*
	 * We can trust the SPMD to get this right, but let's at least
	 * check that we end up with something that doesn't look _completely_
	 * bogus.
	 */
	if (WARN_ON(offset > len ||
		    fraglen > KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE)) {
		ret = FFA_RET_ABORTED;
		goto out_unlock;
	}

	if (len > ffa_desc_buf.len) {
		ret = FFA_RET_NO_MEMORY;
		goto out_unlock;
	}

	buf = ffa_desc_buf.buf;
	memcpy(buf, hyp_buffers.rx, fraglen);

	for (fragoff = fraglen; fragoff < len; fragoff += fraglen) {
		ffa_mem_frag_rx(res, handle_lo, handle_hi, fragoff);
		if (res->a0 != FFA_MEM_FRAG_TX) {
			ret = FFA_RET_INVALID_PARAMETERS;
			goto out_unlock;
		}

		fraglen = res->a3;
		memcpy((void *)buf + fragoff, hyp_buffers.rx, fraglen);
	}

	ffa_mem_reclaim(res, handle_lo, handle_hi, flags);
	if (res->a0 != FFA_SUCCESS)
		goto out_unlock;

	reg = (void *)buf + offset;

	if (vmid == 0) {
		/* If the SPMD was happy, then we should be too. */
		WARN_ON(ffa_host_unshare_ranges(reg->constituents,
						reg->addr_range_cnt));
	} else {
		ffa_guest_repaint_pa_ranges(reg, &non_secure_el1_buffers[vmid]);
		WARN_ON(ffa_guest_unshare_ranges(reg->constituents,
						 reg->addr_range_cnt,
						 ctxt, vmid));
	}
out_unlock:
	hyp_spin_unlock(&hyp_buffers.lock);

	if (ret)
		ffa_to_smccc_res(res, ret);
}

/*
 * Is a given FFA function supported, either by forwarding on directly
 * or by handling at EL2?
 */
static bool ffa_call_supported(u64 func_id)
{
	switch (func_id) {
	/* Unsupported memory management calls */
	case FFA_FN64_MEM_RETRIEVE_REQ:
	case FFA_MEM_RETRIEVE_RESP:
	case FFA_MEM_RELINQUISH:
	case FFA_MEM_OP_PAUSE:
	case FFA_MEM_OP_RESUME:
	case FFA_MEM_FRAG_RX:
	case FFA_FN64_MEM_DONATE:
	/* Indirect message passing via RX/TX buffers */
	case FFA_MSG_SEND:
	case FFA_MSG_POLL:
	case FFA_MSG_WAIT:
	/* 32-bit variants of 64-bit calls */
	case FFA_MSG_SEND_DIRECT_REQ:
	case FFA_MSG_SEND_DIRECT_RESP:
	case FFA_RXTX_MAP:
	case FFA_MEM_DONATE:
	case FFA_MEM_RETRIEVE_REQ:
		return false;
	}

	return true;
}

static bool do_ffa_features(struct arm_smccc_res *res,
			    struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(u32, id, ctxt, 1);
	u64 prop = 0;
	int ret = 0;

	if (!ffa_call_supported(id)) {
		ret = FFA_RET_NOT_SUPPORTED;
		goto out_handled;
	}

	switch (id) {
	case FFA_MEM_SHARE:
	case FFA_FN64_MEM_SHARE:
	case FFA_MEM_LEND:
	case FFA_FN64_MEM_LEND:
		ret = FFA_RET_SUCCESS;
		prop = 0; /* No support for dynamic buffers */
		goto out_handled;
	default:
		return false;
	}

out_handled:
	ffa_to_smccc_res_prop(res, ret, prop);
	return true;
}

bool kvm_host_ffa_handler(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, func_id, host_ctxt, 0);
	struct arm_smccc_res res;

	/*
	 * There's no way we can tell what a non-standard SMC call might
	 * be up to. Ideally, we would terminate these here and return
	 * an error to the host, but sadly devices make use of custom
	 * firmware calls for things like power management, debugging,
	 * RNG access and crash reporting.
	 *
	 * Given that the architecture requires us to trust EL3 anyway,
	 * we forward unrecognised calls on under the assumption that
	 * the firmware doesn't expose a mechanism to access arbitrary
	 * non-secure memory. Short of a per-device table of SMCs, this
	 * is the best we can do.
	 */
	if (!is_ffa_call(func_id))
		return false;

	switch (func_id) {
	case FFA_FEATURES:
		if (!do_ffa_features(&res, host_ctxt))
			return false;
		goto out_handled;
	case FFA_ID_GET:
		ffa_to_smccc_res_prop(&res, FFA_RET_SUCCESS, HOST_FFA_ID);
		goto out_handled;
	/* Memory management */
	case FFA_FN64_RXTX_MAP:
		do_ffa_rxtx_map(&res, host_ctxt, 0);
		goto out_handled;
	case FFA_RXTX_UNMAP:
		do_ffa_rxtx_unmap(&res, host_ctxt, 0);
		goto out_handled;
	case FFA_MEM_SHARE:
	case FFA_FN64_MEM_SHARE:
		do_ffa_mem_xfer(FFA_FN64_MEM_SHARE, &res, host_ctxt, 0, NULL);
		goto out_handled;
	case FFA_MEM_RECLAIM:
		do_ffa_mem_reclaim(&res, host_ctxt, 0);
		goto out_handled;
	case FFA_MEM_LEND:
	case FFA_FN64_MEM_LEND:
		do_ffa_mem_xfer(FFA_FN64_MEM_LEND, &res, host_ctxt, 0, NULL);
		goto out_handled;
	case FFA_MEM_FRAG_TX:
		do_ffa_mem_frag_tx(&res, host_ctxt, 0);
		goto out_handled;
	}

	if (ffa_call_supported(func_id))
		return false; /* Pass through */

	ffa_to_smccc_error(&res, FFA_RET_NOT_SUPPORTED);
out_handled:
	ffa_set_retval(host_ctxt, &res);
	return true;
}

int kvm_guest_ffa_handler(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 func_id = smccc_get_function(vcpu);
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	struct kvm_s2_mmu *mmu = vcpu->arch.hw_mmu;
	struct arm_smccc_res res;
	int ret = 0;
	struct kvm_vmid *kvm_vmid = &mmu->vmid;
	u64 vmid = atomic64_read(&kvm_vmid->id);

	switch (func_id) {
	case FFA_FEATURES:
		if (!do_ffa_features(&res, ctxt))
			return -EPERM;
		goto out_handled;
	case FFA_ID_GET:
		/* Return vmid as the partition id */
		ffa_to_smccc_res_prop(&res, FFA_RET_SUCCESS, vmid);
		goto out_handled;
	/* Memory management */
	case FFA_FN64_RXTX_MAP:
		do_ffa_rxtx_map(&res, ctxt, vmid);
		goto out_handled;
	case FFA_RXTX_UNMAP:
		do_ffa_rxtx_unmap(&res, ctxt, vmid);
		goto out_handled;
	case FFA_MEM_SHARE:
	case FFA_FN64_MEM_SHARE:
		ret = do_ffa_mem_xfer(FFA_FN64_MEM_SHARE, &res, ctxt, vmid,
				      exit_code);
		goto out_handled;
	case FFA_MEM_RECLAIM:
		do_ffa_mem_reclaim(&res, ctxt, vmid);
		goto out_handled;
	case FFA_MEM_LEND:
	case FFA_FN64_MEM_LEND:
	case FFA_MEM_FRAG_TX:
		break;
	}

	/* If this is not an FF-A call we should filter it before forwarding
	 * it to Trustzone.
	 */
	if (ffa_call_supported(func_id))
		return 1;

	ffa_to_smccc_error(&res, FFA_RET_NOT_SUPPORTED);
out_handled:
	/* If there is a fault during the guest sharing path because there
	 * is no guest stage-2 mapping, we will replay the last instruction
	 * so don't overwrite the registers with the FF-A retval.
	 */


	if (ret == -EFAULT || ret == -ENOMEM)
		return ret;

	ffa_set_retval(ctxt, &res);
	return ret;
}

bool hyp_ffa_release_buffers(struct pkvm_hyp_vcpu *vcpu, int vmid, void *addr)
{
	bool found = false;

	if (vmid < 0 || vmid >= KVM_MAX_PVMS || !addr)
		return false;

	hyp_spin_lock(&hyp_buffers.lock);

	if (non_secure_el1_buffers[vmid].tx == addr) {
		found = true;
		non_secure_el1_buffers[vmid].tx = NULL;
	}

	if (non_secure_el1_buffers[vmid].rx == addr) {
		found = true;
		non_secure_el1_buffers[vmid].rx = NULL;
	}

	if (!found)
		goto unlock_ffa_buffers;

	if (vmid == 0) {
		hyp_unpin_shared_mem(addr, addr + 1);
	} else {
		hyp_unpin_shared_mem_from_guest(vcpu, addr, addr + 1);
	}

	if (!non_secure_el1_buffers[vmid].rx &&
	    !non_secure_el1_buffers[vmid].tx &&
	    hyp_buffer_refcnt > 0)
		hyp_buffer_refcnt--;

	ffa_unmap_hyp_buffers();

unlock_ffa_buffers:
	hyp_spin_unlock(&hyp_buffers.lock);
	return !!found;
}

int guest_ffa_reclaim_memory(struct pkvm_hyp_vm *vm)
{
	struct pkvm_hyp_vcpu *hyp_vcpu = vm->vcpus[0];
	struct ffa_mem_region *req;
	struct kvm_ffa_buffers *guest_ctxt;
	struct ffa_guest_share_ctxt *transfer_ctxt, *tmp_ctxt;
	struct ffa_composite_mem_region *reg;
	struct arm_smccc_res res = {0};
	u32 offset, len, fraglen, fragoff;
	u32 handle_lo, handle_hi;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	int ret = 0, retry = 5;
	struct kvm_s2_mmu *mmu;
	struct kvm_vmid *kvm_vmid;
	u64 vmid;

	mmu = &vm->kvm.arch.mmu;
	kvm_vmid = &mmu->vmid;
	vmid = atomic64_read(&kvm_vmid->id);

	if (vmid >= KVM_MAX_PVMS)
		return -EINVAL;

	hyp_spin_lock(&hyp_buffers.lock);
	guest_ctxt = &non_secure_el1_buffers[vmid];
	req = hyp_buffers.tx;

	if (!ffa_available || list_empty(&guest_ctxt->transfers)) {
		ret= 0;
		goto unlock;
	}

	do {
		trusty_stop_virtio(&res, vmid & U32_MAX);
	} while (res.a0 == -5 && retry-- > 0);
	if (retry < 0) {
		ret = res.a0;
		goto unlock;
	}

	list_for_each_entry_safe(transfer_ctxt, tmp_ctxt,
				 &guest_ctxt->transfers, node) {
		*req =  (struct ffa_mem_region) {
			.sender_id      = HOST_FFA_ID,
			.handle         = transfer_ctxt->ffa_handle,
		};

		/* TODO: Remove the hack to relinquish the FF-A global memory
		 * handlers on the Secure OS side once FF-A destroy
		 * message is implemented.
		 */

		handle_lo = HANDLE_LOW(transfer_ctxt->ffa_handle);
		handle_hi = HANDLE_HIGH(transfer_ctxt->ffa_handle);

		ffa_retrieve_req(&res, sizeof(*req));
		if (res.a0 != FFA_MEM_RETRIEVE_RESP) {
			ret = res.a0;
			goto unlock;
		}

		req = hyp_buffers.rx;
		len = res.a1;
		fraglen = res.a2;
		offset  = req->ep_mem_access[0].composite_off;

		WARN_ON(offset > len ||
			fraglen > KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE);

		if (len > ffa_desc_buf.len) {
			ret = -ENOMEM;
			goto unlock;
		}

		req = ffa_desc_buf.buf;
		memcpy(req, hyp_buffers.rx, fraglen);

		for (fragoff = fraglen; fragoff < len; fragoff += fraglen) {
			ffa_mem_frag_rx(&res, handle_lo, handle_hi, fragoff);
			if (res.a0 != FFA_MEM_FRAG_TX) {
				ret = res.a0;
				goto unlock;
			}

			fraglen = res.a3;
			memcpy((void *)req + fragoff, hyp_buffers.rx, fraglen);
		}

		ffa_mem_reclaim(&res, handle_lo, handle_hi, 0);
		if (res.a0 != FFA_SUCCESS) {
			ret = res.a0;
			goto unlock;
		}

		reg = (void *)req + offset;
		ffa_guest_repaint_pa_ranges(reg, guest_ctxt);
		WARN_ON(ffa_guest_unshare_ranges(reg->constituents,
						 reg->addr_range_cnt,
						 ctxt, vmid));
	}

unlock:
	hyp_spin_unlock(&hyp_buffers.lock);
	return ret;
}

int hyp_ffa_init(void *pages)
{
	struct arm_smccc_res res;
	size_t min_rxtx_sz;
	void *tx, *rx;
	int i;

	if (kvm_host_psci_config.smccc_version < ARM_SMCCC_VERSION_1_1)
		return 0;

	arm_smccc_1_1_smc(FFA_VERSION, FFA_VERSION_1_0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == FFA_RET_NOT_SUPPORTED)
		return 0;

	/*
	 * Firmware returns the maximum supported version of the FF-A
	 * implementation. Check that the returned version is
	 * backwards-compatible with the hyp according to the rules in DEN0077A
	 * v1.1 REL0 13.2.1.
	 *
	 * Of course, things are never simple when dealing with firmware. v1.1
	 * broke ABI with v1.0 on several structures, which is itself
	 * incompatible with the aforementioned versioning scheme. The
	 * expectation is that v1.x implementations that do not support the v1.0
	 * ABI return NOT_SUPPORTED rather than a version number, according to
	 * DEN0077A v1.1 REL0 18.6.4.
	 */
	if (FFA_MAJOR_VERSION(res.a0) != 1)
		return -EOPNOTSUPP;

	arm_smccc_1_1_smc(FFA_ID_GET, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != FFA_SUCCESS)
		return -EOPNOTSUPP;

	if (res.a2 != HOST_FFA_ID)
		return -EINVAL;

	arm_smccc_1_1_smc(FFA_FEATURES, FFA_FN64_RXTX_MAP,
			  0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != FFA_SUCCESS)
		return -EOPNOTSUPP;

	switch (res.a2) {
	case FFA_FEAT_RXTX_MIN_SZ_4K:
		min_rxtx_sz = SZ_4K;
		break;
	case FFA_FEAT_RXTX_MIN_SZ_16K:
		min_rxtx_sz = SZ_16K;
		break;
	case FFA_FEAT_RXTX_MIN_SZ_64K:
		min_rxtx_sz = SZ_64K;
		break;
	default:
		return -EINVAL;
	}

	if (min_rxtx_sz > PAGE_SIZE)
		return -EOPNOTSUPP;

	tx = pages;
	pages += KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE;
	rx = pages;
	pages += KVM_FFA_MBOX_NR_PAGES * PAGE_SIZE;

	ffa_desc_buf = (struct kvm_ffa_descriptor_buffer) {
		.buf	= pages,
		.len	= PAGE_SIZE *
			  (hyp_ffa_proxy_pages() - (2 * KVM_FFA_MBOX_NR_PAGES)),
	};

	hyp_buffers = (struct kvm_ffa_buffers) {
		.lock	= __HYP_SPIN_LOCK_UNLOCKED,
		.tx	= tx,
		.rx	= rx,
	};

	for (i = 0; i < KVM_MAX_PVMS; i++) {
		non_secure_el1_buffers[i] = (struct kvm_ffa_buffers) {
			.lock	= __HYP_SPIN_LOCK_UNLOCKED,
			.tx	= NULL,
			.rx	= NULL,
		};

		INIT_LIST_HEAD(&non_secure_el1_buffers[i].transfers);
	}

	ffa_available = true;

	return 0;
}
