// SPDX-License-Identifier: GPL-2.0
/*
 * pKVM hyp driver for the Arm SMMUv3
 *
 * Copyright (C) 2022 Linaro Ltd.
 */
#include <asm/arm-smmu-v3-regs.h>
#include <asm/kvm_hyp.h>
#include <kvm/arm_smmu_v3.h>
#include <nvhe/iommu.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>

#define ARM_SMMU_POLL_TIMEOUT_US	1000000 /* 1s! */

size_t __ro_after_init kvm_hyp_arm_smmu_v3_count;
struct hyp_arm_smmu_v3_device __ro_after_init *kvm_hyp_arm_smmu_v3_smmus;

#define for_each_smmu(smmu) \
	for ((smmu) = kvm_hyp_arm_smmu_v3_smmus; \
	     (smmu) != &kvm_hyp_arm_smmu_v3_smmus[kvm_hyp_arm_smmu_v3_count]; \
	     (smmu)++)

/*
 * Wait until @cond is true.
 * Return 0 on success, or -ETIMEDOUT
 */
#define smmu_wait(_cond)					\
({								\
	int __i = 0;						\
	int __ret = 0;						\
								\
	while (!(_cond)) {					\
		if (++__i > ARM_SMMU_POLL_TIMEOUT_US) {		\
			__ret = -ETIMEDOUT;			\
			break;					\
		}						\
		pkvm_udelay(1);					\
	}							\
	__ret;							\
})

static int smmu_write_cr0(struct hyp_arm_smmu_v3_device *smmu, u32 val)
{
	writel_relaxed(val, smmu->base + ARM_SMMU_CR0);
	return smmu_wait(readl_relaxed(smmu->base + ARM_SMMU_CR0ACK) == val);
}

static int smmu_init_registers(struct hyp_arm_smmu_v3_device *smmu)
{
	u64 val, old;

	if (!(readl_relaxed(smmu->base + ARM_SMMU_GBPA) & GBPA_ABORT))
		return -EINVAL;

	/* Initialize all RW registers that will be read by the SMMU */
	smmu_write_cr0(smmu, 0);

	val = FIELD_PREP(CR1_TABLE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_TABLE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_TABLE_IC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_QUEUE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_IC, CR1_CACHE_WB);
	writel_relaxed(val, smmu->base + ARM_SMMU_CR1);
	writel_relaxed(CR2_PTM, smmu->base + ARM_SMMU_CR2);
	writel_relaxed(0, smmu->base + ARM_SMMU_IRQ_CTRL);

	val = readl_relaxed(smmu->base + ARM_SMMU_GERROR);
	old = readl_relaxed(smmu->base + ARM_SMMU_GERRORN);
	/* Service Failure Mode is fatal */
	if ((val ^ old) & GERROR_SFM_ERR)
		return -EIO;
	/* Clear pending errors */
	writel_relaxed(val, smmu->base + ARM_SMMU_GERRORN);

	return 0;
}

static int smmu_init_device(struct hyp_arm_smmu_v3_device *smmu)
{
	int ret;

	if (!PAGE_ALIGNED(smmu->mmio_addr | smmu->mmio_size))
		return -EINVAL;

	ret = pkvm_create_hyp_device_mapping(smmu->mmio_addr, smmu->mmio_size,
					     &smmu->base);
	if (IS_ERR(smmu->base))
		return PTR_ERR(smmu->base);

	ret = smmu_init_registers(smmu);
	if (ret)
		return ret;

	return 0;
}

static int smmu_init(void)
{
	int ret;
	struct hyp_arm_smmu_v3_device *smmu;

	ret = pkvm_create_mappings(kvm_hyp_arm_smmu_v3_smmus,
				   kvm_hyp_arm_smmu_v3_smmus +
				   kvm_hyp_arm_smmu_v3_count,
				   PAGE_HYP);
	if (ret)
		return ret;

	for_each_smmu(smmu) {
		ret = smmu_init_device(smmu);
		if (ret)
			return ret;
	}

	return 0;
}

static struct kvm_iommu_ops smmu_ops = {
	.init				= smmu_init,
};

int kvm_arm_smmu_v3_register(void)
{
	kvm_iommu_ops = smmu_ops;
	return 0;
}
