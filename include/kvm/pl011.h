/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_PL011_H
#define __KVM_PL011_H

#include <asm/kvm_asm.h>

#define PL011_DR		0x00
#define PL011_RSR		0x04
#define PL011_ECR		0x04
#define PL011_FR		0x18
#define PL011_IBRD		0x24
#define PL011_FBRD		0x28
#define PL011_LCR_H		0x2c
#define PL011_CR		0x30

#define PL011_FIFO_BUSY		(1 << 3)
#define PL011_FIFO_FULL		(1 << 5)


struct kvm_arm_pl011_device {
	phys_addr_t		mmio_addr;
	size_t			mmio_size;
	void __iomem		*base;
};

extern struct kvm_arm_pl011_device *kvm_nvhe_sym(kvm_hyp_arm_pl011_device);
#define kvm_hyp_arm_pl011_device kvm_nvhe_sym(kvm_hyp_arm_pl011_device)

#ifdef __KVM_NVHE_HYPERVISOR__
int pkvm_pl011_init(void);
__attribute__((format(printf, 1, 2)))
void pkvm_pl011_printf(const char *fmt, ...);

#define pkvm_debug(fmt, ...) pkvm_pl011_printf("pKVM: "fmt, ##__VA_ARGS__)

#else
#define pkvm_debug(...)

#endif

#endif /* __KVM_PL011_H */
