/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_NVHE_ALLOC__
#define __KVM_NVHE_ALLOC__
#include <linux/types.h>

#include <asm/kvm_host.h>

void *hyp_alloc(size_t size);
void *hyp_zalloc(size_t size);
int hyp_alloc_errno(void);
void hyp_free(void *addr);
int hyp_alloc_init(size_t size);
int hyp_alloc_refill(struct kvm_hyp_memcache *host_mc);
int hyp_alloc_reclaimable(void);
void hyp_alloc_reclaim(struct kvm_hyp_memcache *host_mc, int target);
#endif
