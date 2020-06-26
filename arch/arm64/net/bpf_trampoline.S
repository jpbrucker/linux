/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Linaro Limited
 */

#include <linux/linkage.h>
#include <asm/memory.h>

#include "bpf_jit.h"

/* We currently build the BPF_JIT_REGION_START address using two 16-bit mov */
#if (BPF_JIT_REGION_START & 0xffffffff) != 0
#error BPF_JIT_REGION_START is not aligned on 4G
#endif

#define BPF_JIT_REGION_START_LO	(BPF_JIT_REGION_START & 0xffffffffffff)
#define BPF_JIT_REGION_START_HI	(BPF_JIT_REGION_START >> 48)

/*
 * The caller has been patched with two instructions:
 *	mov x16, #idx
 *	b bpf_tramp_call
 *
 * Now jump to the BPF trampoline.
 */
SYM_FUNC_START(bpf_tramp_call)
	mov x17, #BPF_JIT_REGION_START_LO
	movk x17, #BPF_JIT_REGION_START_HI, lsl #48
	add x16, x17, x16, lsl #BPF_TRAMPOLINE_SHIFT
	br x16
SYM_FUNC_END(bpf_tramp_call)
