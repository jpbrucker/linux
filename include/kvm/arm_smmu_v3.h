/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_ARM_SMMU_V3_H
#define __KVM_ARM_SMMU_V3_H

#include <asm/kvm_asm.h>
#include <linux/io-pgtable-arm.h>
#include <kvm/iommu.h>

#if IS_ENABLED(CONFIG_ARM_SMMU_V3_PKVM)

/*
 * Parameters from the trusted host:
 * @mmio_addr		base address of the SMMU registers
 * @mmio_size		size of the registers resource
 * @caches_clean_on_power_on
 *			is it safe to elide cache and TLB invalidation commands
 *			while the SMMU is OFF
 *
 * Other members are filled and used at runtime by the SMMU driver.
 */
struct hyp_arm_smmu_v3_device {
	struct kvm_hyp_iommu	iommu;
	phys_addr_t		mmio_addr;
	size_t			mmio_size;
	unsigned long		features;
	bool			caches_clean_on_power_on;

	void __iomem		*base;
	u32			cmdq_prod;
	u64			*cmdq_base;
	size_t			cmdq_log2size;
	u64			*strtab_base;
	size_t			strtab_num_entries;
	size_t			strtab_num_l1_entries;
	u8			strtab_split;
	struct arm_lpae_io_pgtable pgtable;
};

extern size_t kvm_nvhe_sym(kvm_hyp_arm_smmu_v3_count);
#define kvm_hyp_arm_smmu_v3_count kvm_nvhe_sym(kvm_hyp_arm_smmu_v3_count)

extern struct hyp_arm_smmu_v3_device *kvm_nvhe_sym(kvm_hyp_arm_smmu_v3_smmus);
#define kvm_hyp_arm_smmu_v3_smmus kvm_nvhe_sym(kvm_hyp_arm_smmu_v3_smmus)

#endif /* CONFIG_ARM_SMMU_V3_PKVM */

#ifndef __KVM_NVHE_HYPERVISOR__
# if IS_ENABLED(CONFIG_ARM_SMMU_V3_PKVM)
int kvm_arm_smmu_v3_init(unsigned int *count);
void kvm_arm_smmu_v3_remove(void);

# else /* CONFIG_ARM_SMMU_V3_PKVM */
static inline int kvm_arm_smmu_v3_init(unsigned int *count)
{
	return -ENODEV;
}
static void kvm_arm_smmu_v3_remove(void) {}
# endif /* CONFIG_ARM_SMMU_V3_PKVM */
#endif /* __KVM_NVHE_HYPERVISOR__ */

#endif /* __KVM_ARM_SMMU_V3_H */
