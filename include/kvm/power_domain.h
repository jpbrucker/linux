/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_POWER_DOMAIN_H
#define __KVM_POWER_DOMAIN_H

enum kvm_power_domain_type {
	KVM_POWER_DOMAIN_NONE,
	KVM_POWER_DOMAIN_ARM_SCMI,
};

struct kvm_power_domain {
	enum kvm_power_domain_type	type;
	union {
		struct {
			u32		smc_id;
			u32		domain_id;
			phys_addr_t	shmem_base;
			size_t		shmem_size;
		} arm_scmi;
	};
};

#endif /* __KVM_POWER_DOMAIN_H */
