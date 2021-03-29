/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_IA64_CPU_H_
#define _ASM_IA64_CPU_H_

#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/topology.h>
#include <linux/percpu.h>

DECLARE_PER_CPU(int, cpu_state);

#ifdef CONFIG_HOTPLUG_CPU
extern void arch_unregister_cpu(int);
#endif

#endif /* _ASM_IA64_CPU_H_ */
