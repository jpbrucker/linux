/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */
#ifndef __KVM_HYP_FFA_H
#define __KVM_HYP_FFA_H

#include <asm/kvm_host.h>
#include <nvhe/pkvm.h>

#define FFA_MIN_FUNC_NUM 0x60
#define FFA_MAX_FUNC_NUM 0x7F

int hyp_ffa_init(void *pages);
bool kvm_host_ffa_handler(struct kvm_cpu_context *host_ctxt);
int kvm_guest_ffa_handler(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code);

static inline bool is_ffa_call(u64 func_id)
{
	return ARM_SMCCC_IS_FAST_CALL(func_id) &&
	       ARM_SMCCC_OWNER_NUM(func_id) == ARM_SMCCC_OWNER_STANDARD &&
	       ARM_SMCCC_FUNC_NUM(func_id) >= FFA_MIN_FUNC_NUM &&
	       ARM_SMCCC_FUNC_NUM(func_id) <= FFA_MAX_FUNC_NUM;
}

bool hyp_ffa_release_buffers(struct pkvm_hyp_vcpu *vcpu, int vmid, void *addr);

#endif /* __KVM_HYP_FFA_H */
