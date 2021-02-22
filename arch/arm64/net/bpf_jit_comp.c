// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF JIT compiler for ARM64
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 */

#define pr_fmt(fmt) "bpf_jit: " fmt

#include <linux/bitfield.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/printk.h>
#include <linux/slab.h>

#include <asm/asm-extable.h>
#include <asm/byteorder.h>
#include <asm/cacheflush.h>
#include <asm/debug-monitors.h>
#include <asm/insn.h>
#include <asm/patching.h>
#include <asm/set_memory.h>

#include "bpf_jit.h"

#define TMP_REG_1 (MAX_BPF_JIT_REG + 0)
#define TMP_REG_2 (MAX_BPF_JIT_REG + 1)
#define TCALL_CNT (MAX_BPF_JIT_REG + 2)
#define TMP_REG_3 (MAX_BPF_JIT_REG + 3)

/* Map BPF registers to A64 registers */
static const int bpf2a64[] = {
	/* return value from in-kernel function, and exit value from eBPF */
	[BPF_REG_0] = A64_R(7),
	/* arguments from eBPF program to in-kernel function */
	[BPF_REG_1] = A64_R(0),
	[BPF_REG_2] = A64_R(1),
	[BPF_REG_3] = A64_R(2),
	[BPF_REG_4] = A64_R(3),
	[BPF_REG_5] = A64_R(4),
	/* callee saved registers that in-kernel function will preserve */
	[BPF_REG_6] = A64_R(19),
	[BPF_REG_7] = A64_R(20),
	[BPF_REG_8] = A64_R(21),
	[BPF_REG_9] = A64_R(22),
	/* read-only frame pointer to access stack */
	[BPF_REG_FP] = A64_R(25),
	/* temporary registers for BPF JIT */
	[TMP_REG_1] = A64_R(10),
	[TMP_REG_2] = A64_R(11),
	[TMP_REG_3] = A64_R(12),
	/* tail_call_cnt */
	[TCALL_CNT] = A64_R(26),
	/* temporary register for blinding constants */
	[BPF_REG_AX] = A64_R(9),
};

struct jit_ctx {
	const struct bpf_prog *prog;
	int idx;
	int epilogue_offset;
	int *offset;
	int exentry_idx;
	__le32 *image;
	u32 stack_size;
};

static inline void emit(const u32 insn, struct jit_ctx *ctx)
{
	WARN_ON(insn == AARCH64_BREAK_FAULT);
	if (ctx->image != NULL)
		ctx->image[ctx->idx] = cpu_to_le32(insn);

	ctx->idx++;
}

static inline void emit_a64_mov_i(const int is64, const int reg,
				  const s32 val, struct jit_ctx *ctx)
{
	u16 hi = val >> 16;
	u16 lo = val & 0xffff;

	if (hi & 0x8000) {
		if (hi == 0xffff) {
			emit(A64_MOVN(is64, reg, (u16)~lo, 0), ctx);
		} else {
			emit(A64_MOVN(is64, reg, (u16)~hi, 16), ctx);
			if (lo != 0xffff)
				emit(A64_MOVK(is64, reg, lo, 0), ctx);
		}
	} else {
		emit(A64_MOVZ(is64, reg, lo, 0), ctx);
		if (hi)
			emit(A64_MOVK(is64, reg, hi, 16), ctx);
	}
}

static inline int emit_bl(void *target, struct jit_ctx *ctx)
{
	long pc;
	u32 insn;
	long offset;
	long addr = (long)target;

	/* First pass only computes the image size */
	if (!ctx->image) {
		ctx->idx++;
		return 0;
	}

	pc = (long)&ctx->image[ctx->idx];

	/* Preliminary checks here to avoid printing errors. */
	if ((pc & 0x3) || (addr & 0x3))
		return -EINVAL;

	offset = ((long)addr - (long)pc);
	if (offset < -SZ_128M || offset >= SZ_128M)
		return -ERANGE;

	insn = aarch64_insn_gen_branch_imm(pc, addr, AARCH64_INSN_BRANCH_LINK);
	if (insn == AARCH64_BREAK_FAULT)
		return -EINVAL;
	emit(insn, ctx);
	return 0;
}

static int i64_i16_blocks(const u64 val, bool inverse)
{
	return (((val >>  0) & 0xffff) != (inverse ? 0xffff : 0x0000)) +
	       (((val >> 16) & 0xffff) != (inverse ? 0xffff : 0x0000)) +
	       (((val >> 32) & 0xffff) != (inverse ? 0xffff : 0x0000)) +
	       (((val >> 48) & 0xffff) != (inverse ? 0xffff : 0x0000));
}

static inline void emit_a64_mov_i64(const int reg, const u64 val,
				    struct jit_ctx *ctx)
{
	u64 nrm_tmp = val, rev_tmp = ~val;
	bool inverse;
	int shift;

	if (!(nrm_tmp >> 32))
		return emit_a64_mov_i(0, reg, (u32)val, ctx);

	inverse = i64_i16_blocks(nrm_tmp, true) < i64_i16_blocks(nrm_tmp, false);
	shift = max(round_down((inverse ? (fls64(rev_tmp) - 1) :
					  (fls64(nrm_tmp) - 1)), 16), 0);
	if (inverse)
		emit(A64_MOVN(1, reg, (rev_tmp >> shift) & 0xffff, shift), ctx);
	else
		emit(A64_MOVZ(1, reg, (nrm_tmp >> shift) & 0xffff, shift), ctx);
	shift -= 16;
	while (shift >= 0) {
		if (((nrm_tmp >> shift) & 0xffff) != (inverse ? 0xffff : 0x0000))
			emit(A64_MOVK(1, reg, (nrm_tmp >> shift) & 0xffff, shift), ctx);
		shift -= 16;
	}
}

/*
 * Kernel addresses in the vmalloc space use at most 48 bits, and the
 * remaining bits are guaranteed to be 0x1. So we can compose the address
 * with a fixed length movn/movk/movk sequence.
 */
static inline void emit_addr_mov_i64(const int reg, const u64 val,
				     struct jit_ctx *ctx)
{
	u64 tmp = val;
	int shift = 0;

	emit(A64_MOVN(1, reg, ~tmp & 0xffff, shift), ctx);
	while (shift < 32) {
		tmp >>= 16;
		shift += 16;
		emit(A64_MOVK(1, reg, tmp & 0xffff, shift), ctx);
	}
}

static inline int bpf2a64_offset(int bpf_insn, int off,
				 const struct jit_ctx *ctx)
{
	/* BPF JMP offset is relative to the next instruction */
	bpf_insn++;
	/*
	 * Whereas arm64 branch instructions encode the offset
	 * from the branch itself, so we must subtract 1 from the
	 * instruction offset.
	 */
	return ctx->offset[bpf_insn + off] - (ctx->offset[bpf_insn] - 1);
}

static void jit_fill_hole(void *area, unsigned int size)
{
	__le32 *ptr;
	/* We are guaranteed to have aligned memory. */
	for (ptr = area; size >= sizeof(u32); size -= sizeof(u32))
		*ptr++ = cpu_to_le32(AARCH64_BREAK_FAULT);
}

static inline int epilogue_offset(const struct jit_ctx *ctx)
{
	int to = ctx->epilogue_offset;
	int from = ctx->idx;

	return to - from;
}

static bool is_addsub_imm(u32 imm)
{
	/* Either imm12 or shifted imm12. */
	return !(imm & ~0xfff) || !(imm & ~0xfff000);
}

#define BTI_PROLOGUE_OFFSET IS_ENABLED(CONFIG_ARM64_BTI_KERNEL)
#define TRAMP_PROLOGUE_OFFSET IS_ENABLED(CONFIG_ARM64_BPF_TRAMPOLINE)

/* Tail call offset to jump into */
#define PROLOGUE_OFFSET (7 + BTI_PROLOGUE_OFFSET + TRAMP_PROLOGUE_OFFSET)

static int build_prologue(struct jit_ctx *ctx, bool ebpf_from_cbpf)
{
	const struct bpf_prog *prog = ctx->prog;
	const u8 r6 = bpf2a64[BPF_REG_6];
	const u8 r7 = bpf2a64[BPF_REG_7];
	const u8 r8 = bpf2a64[BPF_REG_8];
	const u8 r9 = bpf2a64[BPF_REG_9];
	const u8 fp = bpf2a64[BPF_REG_FP];
	const u8 tcc = bpf2a64[TCALL_CNT];
	const int idx0 = ctx->idx;
	int cur_offset;

	/*
	 * BPF prog stack layout
	 *
	 *                         high
	 * original A64_SP =>   0:+-----+ BPF prologue
	 *                        |FP/LR|
	 * current A64_FP =>  -16:+-----+
	 *                        | ... | callee saved registers
	 * BPF fp register => -64:+-----+ <= (BPF_FP)
	 *                        |     |
	 *                        | ... | BPF prog stack
	 *                        |     |
	 *                        +-----+ <= (BPF_FP - prog->aux->stack_depth)
	 *                        |RSVD | padding
	 * current A64_SP =>      +-----+ <= (BPF_FP - ctx->stack_size)
	 *                        |     |
	 *                        | ... | Function call stack
	 *                        |     |
	 *                        +-----+
	 *                          low
	 *
	 */

	/* BTI landing pad */
	if (IS_ENABLED(CONFIG_ARM64_BTI_KERNEL))
		emit(A64_BTI_C, ctx);

	/* Add patchable instruction */
	if (IS_ENABLED(CONFIG_ARM64_BPF_TRAMPOLINE))
		emit(aarch64_insn_gen_nop(), ctx);

	/* Save FP and LR registers to stay align with ARM64 AAPCS */
	emit(A64_PUSH(A64_FP, A64_LR, A64_SP), ctx);
	emit(A64_MOV(1, A64_FP, A64_SP), ctx);

	/* Save callee-saved registers */
	emit(A64_PUSH(r6, r7, A64_SP), ctx);
	emit(A64_PUSH(r8, r9, A64_SP), ctx);
	emit(A64_PUSH(fp, tcc, A64_SP), ctx);

	/* Set up BPF prog stack base register */
	emit(A64_MOV(1, fp, A64_SP), ctx);

	if (!ebpf_from_cbpf) {
		/* Initialize tail_call_cnt */
		emit(A64_MOVZ(1, tcc, 0, 0), ctx);

		cur_offset = ctx->idx - idx0;
		if (cur_offset != PROLOGUE_OFFSET) {
			pr_err_once("PROLOGUE_OFFSET = %d, expected %d!\n",
				    cur_offset, PROLOGUE_OFFSET);
			return -1;
		}

		/* BTI landing pad for the tail call, done with a BR */
		if (IS_ENABLED(CONFIG_ARM64_BTI_KERNEL))
			emit(A64_BTI_J, ctx);
	}

	/* Stack must be multiples of 16B */
	ctx->stack_size = round_up(prog->aux->stack_depth, 16);

	/* Set up function call stack */
	emit(A64_SUB_I(1, A64_SP, A64_SP, ctx->stack_size), ctx);
	return 0;
}

static int out_offset = -1; /* initialized on the first pass of build_body() */
static int emit_bpf_tail_call(struct jit_ctx *ctx)
{
	/* bpf_tail_call(void *prog_ctx, struct bpf_array *array, u64 index) */
	const u8 r2 = bpf2a64[BPF_REG_2];
	const u8 r3 = bpf2a64[BPF_REG_3];

	const u8 tmp = bpf2a64[TMP_REG_1];
	const u8 prg = bpf2a64[TMP_REG_2];
	const u8 tcc = bpf2a64[TCALL_CNT];
	const int idx0 = ctx->idx;
#define cur_offset (ctx->idx - idx0)
#define jmp_offset (out_offset - (cur_offset))
	size_t off;

	/* if (index >= array->map.max_entries)
	 *     goto out;
	 */
	off = offsetof(struct bpf_array, map.max_entries);
	emit_a64_mov_i64(tmp, off, ctx);
	emit(A64_LDR32(tmp, r2, tmp), ctx);
	emit(A64_MOV(0, r3, r3), ctx);
	emit(A64_CMP(0, r3, tmp), ctx);
	emit(A64_B_(A64_COND_CS, jmp_offset), ctx);

	/*
	 * if (tail_call_cnt >= MAX_TAIL_CALL_CNT)
	 *     goto out;
	 * tail_call_cnt++;
	 */
	emit_a64_mov_i64(tmp, MAX_TAIL_CALL_CNT, ctx);
	emit(A64_CMP(1, tcc, tmp), ctx);
	emit(A64_B_(A64_COND_CS, jmp_offset), ctx);
	emit(A64_ADD_I(1, tcc, tcc, 1), ctx);

	/* prog = array->ptrs[index];
	 * if (prog == NULL)
	 *     goto out;
	 */
	off = offsetof(struct bpf_array, ptrs);
	emit_a64_mov_i64(tmp, off, ctx);
	emit(A64_ADD(1, tmp, r2, tmp), ctx);
	emit(A64_LSL(1, prg, r3, 3), ctx);
	emit(A64_LDR64(prg, tmp, prg), ctx);
	emit(A64_CBZ(1, prg, jmp_offset), ctx);

	/* goto *(prog->bpf_func + prologue_offset); */
	off = offsetof(struct bpf_prog, bpf_func);
	emit_a64_mov_i64(tmp, off, ctx);
	emit(A64_LDR64(tmp, prg, tmp), ctx);
	emit(A64_ADD_I(1, tmp, tmp, sizeof(u32) * PROLOGUE_OFFSET), ctx);
	emit(A64_ADD_I(1, A64_SP, A64_SP, ctx->stack_size), ctx);
	emit(A64_BR(tmp), ctx);

	/* out: */
	if (out_offset == -1)
		out_offset = cur_offset;
	if (cur_offset != out_offset) {
		pr_err_once("tail_call out_offset = %d, expected %d!\n",
			    cur_offset, out_offset);
		return -1;
	}
	return 0;
#undef cur_offset
#undef jmp_offset
}

static void build_epilogue(struct jit_ctx *ctx)
{
	const u8 r0 = bpf2a64[BPF_REG_0];
	const u8 r6 = bpf2a64[BPF_REG_6];
	const u8 r7 = bpf2a64[BPF_REG_7];
	const u8 r8 = bpf2a64[BPF_REG_8];
	const u8 r9 = bpf2a64[BPF_REG_9];
	const u8 fp = bpf2a64[BPF_REG_FP];

	/* We're done with BPF stack */
	emit(A64_ADD_I(1, A64_SP, A64_SP, ctx->stack_size), ctx);

	/* Restore fs (x25) and x26 */
	emit(A64_POP(fp, A64_R(26), A64_SP), ctx);

	/* Restore callee-saved register */
	emit(A64_POP(r8, r9, A64_SP), ctx);
	emit(A64_POP(r6, r7, A64_SP), ctx);

	/* Restore FP/LR registers */
	emit(A64_POP(A64_FP, A64_LR, A64_SP), ctx);

	/* Set return value */
	emit(A64_MOV(1, A64_R(0), r0), ctx);

	emit(A64_RET(A64_LR), ctx);
}

#define BPF_FIXUP_OFFSET_MASK	GENMASK(26, 0)
#define BPF_FIXUP_REG_MASK	GENMASK(31, 27)

bool ex_handler_bpf(const struct exception_table_entry *ex,
		    struct pt_regs *regs)
{
	off_t offset = FIELD_GET(BPF_FIXUP_OFFSET_MASK, ex->fixup);
	int dst_reg = FIELD_GET(BPF_FIXUP_REG_MASK, ex->fixup);

	regs->regs[dst_reg] = 0;
	regs->pc = (unsigned long)&ex->fixup - offset;
	return true;
}

/* For accesses to BTF pointers, add an entry to the exception table */
static int add_exception_handler(const struct bpf_insn *insn,
				 struct jit_ctx *ctx,
				 int dst_reg)
{
	off_t offset;
	unsigned long pc;
	struct exception_table_entry *ex;

	if (!ctx->image)
		/* First pass */
		return 0;

	if (BPF_MODE(insn->code) != BPF_PROBE_MEM)
		return 0;

	if (!ctx->prog->aux->extable ||
	    WARN_ON_ONCE(ctx->exentry_idx >= ctx->prog->aux->num_exentries))
		return -EINVAL;

	ex = &ctx->prog->aux->extable[ctx->exentry_idx];
	pc = (unsigned long)&ctx->image[ctx->idx - 1];

	offset = pc - (long)&ex->insn;
	if (WARN_ON_ONCE(offset >= 0 || offset < INT_MIN))
		return -ERANGE;
	ex->insn = offset;

	/*
	 * Since the extable follows the program, the fixup offset is always
	 * negative and limited to BPF_JIT_REGION_SIZE. Store a positive value
	 * to keep things simple, and put the destination register in the upper
	 * bits. We don't need to worry about buildtime or runtime sort
	 * modifying the upper bits because the table is already sorted, and
	 * isn't part of the main exception table.
	 */
	offset = (long)&ex->fixup - (pc + AARCH64_INSN_SIZE);
	if (!FIELD_FIT(BPF_FIXUP_OFFSET_MASK, offset))
		return -ERANGE;

	ex->fixup = FIELD_PREP(BPF_FIXUP_OFFSET_MASK, offset) |
		    FIELD_PREP(BPF_FIXUP_REG_MASK, dst_reg);

	ex->type = EX_TYPE_BPF;

	ctx->exentry_idx++;
	return 0;
}

/* JITs an eBPF instruction.
 * Returns:
 * 0  - successfully JITed an 8-byte eBPF instruction.
 * >0 - successfully JITed a 16-byte eBPF instruction.
 * <0 - failed to JIT.
 */
static int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx,
		      bool extra_pass)
{
	const u8 code = insn->code;
	const u8 dst = bpf2a64[insn->dst_reg];
	const u8 src = bpf2a64[insn->src_reg];
	const u8 tmp = bpf2a64[TMP_REG_1];
	const u8 tmp2 = bpf2a64[TMP_REG_2];
	const u8 tmp3 = bpf2a64[TMP_REG_3];
	const s16 off = insn->off;
	const s32 imm = insn->imm;
	const int i = insn - ctx->prog->insnsi;
	const bool is64 = BPF_CLASS(code) == BPF_ALU64 ||
			  BPF_CLASS(code) == BPF_JMP;
	const bool isdw = BPF_SIZE(code) == BPF_DW;
	u8 jmp_cond, reg;
	s32 jmp_offset;
	u32 a64_insn;
	int ret;

#define check_imm(bits, imm) do {				\
	if ((((imm) > 0) && ((imm) >> (bits))) ||		\
	    (((imm) < 0) && (~(imm) >> (bits)))) {		\
		pr_info("[%2d] imm=%d(0x%x) out of range\n",	\
			i, imm, imm);				\
		return -EINVAL;					\
	}							\
} while (0)
#define check_imm19(imm) check_imm(19, imm)
#define check_imm26(imm) check_imm(26, imm)

	switch (code) {
	/* dst = src */
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		emit(A64_MOV(is64, dst, src), ctx);
		break;
	/* dst = dst OP src */
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_X:
		emit(A64_ADD(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_X:
		emit(A64_SUB(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
		emit(A64_AND(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_X:
		emit(A64_ORR(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		emit(A64_EOR(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_X:
		emit(A64_MUL(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_X:
		emit(A64_UDIV(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_X:
		emit(A64_UDIV(is64, tmp, dst, src), ctx);
		emit(A64_MSUB(is64, dst, dst, tmp, src), ctx);
		break;
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_X:
		emit(A64_LSLV(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_X:
		emit(A64_LSRV(is64, dst, dst, src), ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit(A64_ASRV(is64, dst, dst, src), ctx);
		break;
	/* dst = -dst */
	case BPF_ALU | BPF_NEG:
	case BPF_ALU64 | BPF_NEG:
		emit(A64_NEG(is64, dst, dst), ctx);
		break;
	/* dst = BSWAP##imm(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE:
	case BPF_ALU | BPF_END | BPF_FROM_BE:
#ifdef CONFIG_CPU_BIG_ENDIAN
		if (BPF_SRC(code) == BPF_FROM_BE)
			goto emit_bswap_uxt;
#else /* !CONFIG_CPU_BIG_ENDIAN */
		if (BPF_SRC(code) == BPF_FROM_LE)
			goto emit_bswap_uxt;
#endif
		switch (imm) {
		case 16:
			emit(A64_REV16(is64, dst, dst), ctx);
			/* zero-extend 16 bits into 64 bits */
			emit(A64_UXTH(is64, dst, dst), ctx);
			break;
		case 32:
			emit(A64_REV32(is64, dst, dst), ctx);
			/* upper 32 bits already cleared */
			break;
		case 64:
			emit(A64_REV64(dst, dst), ctx);
			break;
		}
		break;
emit_bswap_uxt:
		switch (imm) {
		case 16:
			/* zero-extend 16 bits into 64 bits */
			emit(A64_UXTH(is64, dst, dst), ctx);
			break;
		case 32:
			/* zero-extend 32 bits into 64 bits */
			emit(A64_UXTW(is64, dst, dst), ctx);
			break;
		case 64:
			/* nop */
			break;
		}
		break;
	/* dst = imm */
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
		emit_a64_mov_i(is64, dst, imm, ctx);
		break;
	/* dst = dst OP imm */
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_K:
		if (is_addsub_imm(imm)) {
			emit(A64_ADD_I(is64, dst, dst, imm), ctx);
		} else if (is_addsub_imm(-imm)) {
			emit(A64_SUB_I(is64, dst, dst, -imm), ctx);
		} else {
			emit_a64_mov_i(is64, tmp, imm, ctx);
			emit(A64_ADD(is64, dst, dst, tmp), ctx);
		}
		break;
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
		if (is_addsub_imm(imm)) {
			emit(A64_SUB_I(is64, dst, dst, imm), ctx);
		} else if (is_addsub_imm(-imm)) {
			emit(A64_ADD_I(is64, dst, dst, -imm), ctx);
		} else {
			emit_a64_mov_i(is64, tmp, imm, ctx);
			emit(A64_SUB(is64, dst, dst, tmp), ctx);
		}
		break;
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
		a64_insn = A64_AND_I(is64, dst, dst, imm);
		if (a64_insn != AARCH64_BREAK_FAULT) {
			emit(a64_insn, ctx);
		} else {
			emit_a64_mov_i(is64, tmp, imm, ctx);
			emit(A64_AND(is64, dst, dst, tmp), ctx);
		}
		break;
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_K:
		a64_insn = A64_ORR_I(is64, dst, dst, imm);
		if (a64_insn != AARCH64_BREAK_FAULT) {
			emit(a64_insn, ctx);
		} else {
			emit_a64_mov_i(is64, tmp, imm, ctx);
			emit(A64_ORR(is64, dst, dst, tmp), ctx);
		}
		break;
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
		a64_insn = A64_EOR_I(is64, dst, dst, imm);
		if (a64_insn != AARCH64_BREAK_FAULT) {
			emit(a64_insn, ctx);
		} else {
			emit_a64_mov_i(is64, tmp, imm, ctx);
			emit(A64_EOR(is64, dst, dst, tmp), ctx);
		}
		break;
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_MUL(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
		emit_a64_mov_i(is64, tmp, imm, ctx);
		emit(A64_UDIV(is64, dst, dst, tmp), ctx);
		break;
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		emit_a64_mov_i(is64, tmp2, imm, ctx);
		emit(A64_UDIV(is64, tmp, dst, tmp2), ctx);
		emit(A64_MSUB(is64, dst, dst, tmp, tmp2), ctx);
		break;
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_LSH | BPF_K:
		emit(A64_LSL(is64, dst, dst, imm), ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_RSH | BPF_K:
		emit(A64_LSR(is64, dst, dst, imm), ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		emit(A64_ASR(is64, dst, dst, imm), ctx);
		break;

	/* JUMP off */
	case BPF_JMP | BPF_JA:
		jmp_offset = bpf2a64_offset(i, off, ctx);
		check_imm26(jmp_offset);
		emit(A64_B(jmp_offset), ctx);
		break;
	/* IF (dst COND src) JUMP off */
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
		emit(A64_CMP(is64, dst, src), ctx);
emit_cond_jmp:
		jmp_offset = bpf2a64_offset(i, off, ctx);
		check_imm19(jmp_offset);
		switch (BPF_OP(code)) {
		case BPF_JEQ:
			jmp_cond = A64_COND_EQ;
			break;
		case BPF_JGT:
			jmp_cond = A64_COND_HI;
			break;
		case BPF_JLT:
			jmp_cond = A64_COND_CC;
			break;
		case BPF_JGE:
			jmp_cond = A64_COND_CS;
			break;
		case BPF_JLE:
			jmp_cond = A64_COND_LS;
			break;
		case BPF_JSET:
		case BPF_JNE:
			jmp_cond = A64_COND_NE;
			break;
		case BPF_JSGT:
			jmp_cond = A64_COND_GT;
			break;
		case BPF_JSLT:
			jmp_cond = A64_COND_LT;
			break;
		case BPF_JSGE:
			jmp_cond = A64_COND_GE;
			break;
		case BPF_JSLE:
			jmp_cond = A64_COND_LE;
			break;
		default:
			return -EFAULT;
		}
		emit(A64_B_(jmp_cond, jmp_offset), ctx);
		break;
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_X:
		emit(A64_TST(is64, dst, src), ctx);
		goto emit_cond_jmp;
	/* IF (dst COND imm) JUMP off */
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JEQ | BPF_K:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_K:
	case BPF_JMP32 | BPF_JNE | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		if (is_addsub_imm(imm)) {
			emit(A64_CMP_I(is64, dst, imm), ctx);
		} else if (is_addsub_imm(-imm)) {
			emit(A64_CMN_I(is64, dst, -imm), ctx);
		} else {
			emit_a64_mov_i(is64, tmp, imm, ctx);
			emit(A64_CMP(is64, dst, tmp), ctx);
		}
		goto emit_cond_jmp;
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
		a64_insn = A64_TST_I(is64, dst, imm);
		if (a64_insn != AARCH64_BREAK_FAULT) {
			emit(a64_insn, ctx);
		} else {
			emit_a64_mov_i(is64, tmp, imm, ctx);
			emit(A64_TST(is64, dst, tmp), ctx);
		}
		goto emit_cond_jmp;
	/* function call */
	case BPF_JMP | BPF_CALL:
	{
		const u8 r0 = bpf2a64[BPF_REG_0];
		bool func_addr_fixed;
		u64 func_addr;

		ret = bpf_jit_get_func_addr(ctx->prog, insn, extra_pass,
					    &func_addr, &func_addr_fixed);
		if (ret < 0)
			return ret;
		emit_addr_mov_i64(tmp, func_addr, ctx);
		emit(A64_BLR(tmp), ctx);
		emit(A64_MOV(1, r0, A64_R(0)), ctx);
		break;
	}
	/* tail call */
	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_bpf_tail_call(ctx))
			return -EFAULT;
		break;
	/* function return */
	case BPF_JMP | BPF_EXIT:
		/* Optimization: when last instruction is EXIT,
		   simply fallthrough to epilogue. */
		if (i == ctx->prog->len - 1)
			break;
		jmp_offset = epilogue_offset(ctx);
		check_imm26(jmp_offset);
		emit(A64_B(jmp_offset), ctx);
		break;

	/* dst = imm64 */
	case BPF_LD | BPF_IMM | BPF_DW:
	{
		const struct bpf_insn insn1 = insn[1];
		u64 imm64;

		imm64 = (u64)insn1.imm << 32 | (u32)imm;
		emit_a64_mov_i64(dst, imm64, ctx);

		return 1;
	}

	/* LDX: dst = *(size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_DW:
	case BPF_LDX | BPF_PROBE_MEM | BPF_DW:
	case BPF_LDX | BPF_PROBE_MEM | BPF_W:
	case BPF_LDX | BPF_PROBE_MEM | BPF_H:
	case BPF_LDX | BPF_PROBE_MEM | BPF_B:
		emit_a64_mov_i(1, tmp, off, ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(A64_LDR32(dst, src, tmp), ctx);
			break;
		case BPF_H:
			emit(A64_LDRH(dst, src, tmp), ctx);
			break;
		case BPF_B:
			emit(A64_LDRB(dst, src, tmp), ctx);
			break;
		case BPF_DW:
			emit(A64_LDR64(dst, src, tmp), ctx);
			break;
		}

		ret = add_exception_handler(insn, ctx, dst);
		if (ret)
			return ret;
		break;

	/* speculation barrier */
	case BPF_ST | BPF_NOSPEC:
		/*
		 * Nothing required here.
		 *
		 * In case of arm64, we rely on the firmware mitigation of
		 * Speculative Store Bypass as controlled via the ssbd kernel
		 * parameter. Whenever the mitigation is enabled, it works
		 * for all of the kernel code with no need to provide any
		 * additional instructions.
		 */
		break;

	/* ST: *(size *)(dst + off) = imm */
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_DW:
		/* Load imm to a register then store it */
		emit_a64_mov_i(1, tmp2, off, ctx);
		emit_a64_mov_i(1, tmp, imm, ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(A64_STR32(tmp, dst, tmp2), ctx);
			break;
		case BPF_H:
			emit(A64_STRH(tmp, dst, tmp2), ctx);
			break;
		case BPF_B:
			emit(A64_STRB(tmp, dst, tmp2), ctx);
			break;
		case BPF_DW:
			emit(A64_STR64(tmp, dst, tmp2), ctx);
			break;
		}
		break;

	/* STX: *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_B:
	case BPF_STX | BPF_MEM | BPF_DW:
		emit_a64_mov_i(1, tmp, off, ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(A64_STR32(src, dst, tmp), ctx);
			break;
		case BPF_H:
			emit(A64_STRH(src, dst, tmp), ctx);
			break;
		case BPF_B:
			emit(A64_STRB(src, dst, tmp), ctx);
			break;
		case BPF_DW:
			emit(A64_STR64(src, dst, tmp), ctx);
			break;
		}
		break;

	case BPF_STX | BPF_ATOMIC | BPF_W:
	case BPF_STX | BPF_ATOMIC | BPF_DW:
		if (insn->imm != BPF_ADD) {
			pr_err_once("unknown atomic op code %02x\n", insn->imm);
			return -EINVAL;
		}

		/* STX XADD: lock *(u32 *)(dst + off) += src
		 * and
		 * STX XADD: lock *(u64 *)(dst + off) += src
		 */

		if (!off) {
			reg = dst;
		} else {
			emit_a64_mov_i(1, tmp, off, ctx);
			emit(A64_ADD(1, tmp, tmp, dst), ctx);
			reg = tmp;
		}
		if (cpus_have_cap(ARM64_HAS_LSE_ATOMICS)) {
			emit(A64_STADD(isdw, reg, src), ctx);
		} else {
			emit(A64_LDXR(isdw, tmp2, reg), ctx);
			emit(A64_ADD(isdw, tmp2, tmp2, src), ctx);
			emit(A64_STXR(isdw, tmp2, reg, tmp3), ctx);
			jmp_offset = -3;
			check_imm19(jmp_offset);
			emit(A64_CBNZ(0, tmp3, jmp_offset), ctx);
		}
		break;

	default:
		pr_err_ratelimited("[%2d] unknown opcode %02x\n", i, code);
		return -EINVAL;
	}

	return 0;
}

static int build_body(struct jit_ctx *ctx, bool extra_pass)
{
	const struct bpf_prog *prog = ctx->prog;
	int i;

	/*
	 * - offset[0] offset of the end of prologue,
	 *   start of the 1st instruction.
	 * - offset[1] - offset of the end of 1st instruction,
	 *   start of the 2nd instruction
	 * [....]
	 * - offset[3] - offset of the end of 3rd instruction,
	 *   start of 4th instruction
	 */
	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		int ret;

		if (ctx->image == NULL)
			ctx->offset[i] = ctx->idx;
		ret = build_insn(insn, ctx, extra_pass);
		if (ret > 0) {
			i++;
			if (ctx->image == NULL)
				ctx->offset[i] = ctx->idx;
			continue;
		}
		if (ret)
			return ret;
	}
	/*
	 * offset is allocated with prog->len + 1 so fill in
	 * the last element with the offset after the last
	 * instruction (end of program)
	 */
	if (ctx->image == NULL)
		ctx->offset[i] = ctx->idx;

	return 0;
}

static int validate_code(struct jit_ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->idx; i++) {
		u32 a64_insn = le32_to_cpu(ctx->image[i]);

		if (a64_insn == AARCH64_BREAK_FAULT)
			return -1;
	}

	if (WARN_ON_ONCE(ctx->exentry_idx != ctx->prog->aux->num_exentries))
		return -1;

	return 0;
}

static inline void bpf_flush_icache(void *start, void *end)
{
	flush_icache_range((unsigned long)start, (unsigned long)end);
}

struct arm64_jit_data {
	struct bpf_binary_header *header;
	u8 *image;
	struct jit_ctx ctx;
};

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	int image_size, prog_size, extable_size;
	struct bpf_prog *tmp, *orig_prog = prog;
	struct bpf_binary_header *header;
	struct arm64_jit_data *jit_data;
	bool was_classic = bpf_prog_was_classic(prog);
	bool tmp_blinded = false;
	bool extra_pass = false;
	struct jit_ctx ctx;
	u8 *image_ptr;

	if (!prog->jit_requested)
		return orig_prog;

	tmp = bpf_jit_blind_constants(prog);
	/* If blinding was requested and we failed during blinding,
	 * we must fall back to the interpreter.
	 */
	if (IS_ERR(tmp))
		return orig_prog;
	if (tmp != prog) {
		tmp_blinded = true;
		prog = tmp;
	}

	jit_data = prog->aux->jit_data;
	if (!jit_data) {
		jit_data = kzalloc(sizeof(*jit_data), GFP_KERNEL);
		if (!jit_data) {
			prog = orig_prog;
			goto out;
		}
		prog->aux->jit_data = jit_data;
	}
	if (jit_data->ctx.offset) {
		ctx = jit_data->ctx;
		image_ptr = jit_data->image;
		header = jit_data->header;
		extra_pass = true;
		prog_size = sizeof(u32) * ctx.idx;
		goto skip_init_ctx;
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.prog = prog;

	ctx.offset = kcalloc(prog->len + 1, sizeof(int), GFP_KERNEL);
	if (ctx.offset == NULL) {
		prog = orig_prog;
		goto out_off;
	}

	/* 1. Initial fake pass to compute ctx->idx. */

	/* Fake pass to fill in ctx->offset. */
	if (build_body(&ctx, extra_pass)) {
		prog = orig_prog;
		goto out_off;
	}

	if (build_prologue(&ctx, was_classic)) {
		prog = orig_prog;
		goto out_off;
	}

	ctx.epilogue_offset = ctx.idx;
	build_epilogue(&ctx);

	extable_size = prog->aux->num_exentries *
		sizeof(struct exception_table_entry);

	/* Now we know the actual image size. */
	prog_size = sizeof(u32) * ctx.idx;
	image_size = prog_size + extable_size;
	header = bpf_jit_binary_alloc(image_size, &image_ptr,
				      sizeof(u32), jit_fill_hole);
	if (header == NULL) {
		prog = orig_prog;
		goto out_off;
	}

	/* 2. Now, the actual pass. */

	ctx.image = (__le32 *)image_ptr;
	if (extable_size)
		prog->aux->extable = (void *)image_ptr + prog_size;
skip_init_ctx:
	ctx.idx = 0;
	ctx.exentry_idx = 0;

	build_prologue(&ctx, was_classic);

	if (build_body(&ctx, extra_pass)) {
		bpf_jit_binary_free(header);
		prog = orig_prog;
		goto out_off;
	}

	build_epilogue(&ctx);

	/* 3. Extra pass to validate JITed code. */
	if (validate_code(&ctx)) {
		bpf_jit_binary_free(header);
		prog = orig_prog;
		goto out_off;
	}

	/* And we're done. */
	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, prog_size, 2, ctx.image);

	bpf_flush_icache(header, ctx.image + ctx.idx);

	if (!prog->is_func || extra_pass) {
		if (extra_pass && ctx.idx != jit_data->ctx.idx) {
			pr_err_once("multi-func JIT bug %d != %d\n",
				    ctx.idx, jit_data->ctx.idx);
			bpf_jit_binary_free(header);
			prog->bpf_func = NULL;
			prog->jited = 0;
			goto out_off;
		}
		bpf_jit_binary_lock_ro(header);
	} else {
		jit_data->ctx = ctx;
		jit_data->image = image_ptr;
		jit_data->header = header;
	}
	prog->bpf_func = (void *)ctx.image;
	prog->jited = 1;
	prog->jited_len = prog_size;

	if (!prog->is_func || extra_pass) {
		bpf_prog_fill_jited_linfo(prog, ctx.offset + 1);
out_off:
		kfree(ctx.offset);
		kfree(jit_data);
		prog->aux->jit_data = NULL;
	}
out:
	if (tmp_blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   tmp : orig_prog);
	return prog;
}

#ifdef CONFIG_ARM64_BPF_TRAMPOLINE
static unsigned long bpf_arch_find_branch(unsigned long pc)
{
	int i, ret;
	u32 insn, expected;

	/*
	 * ftrace should have generated the right prologue (mov x9, lr) at boot
	 * time (see ftrace_init_nop()). Find it.
	 */
	expected = aarch64_insn_gen_move_reg(AARCH64_INSN_REG_9,
					     AARCH64_INSN_REG_LR,
					     AARCH64_INSN_VARIANT_64BIT);


	for (i = 0; i < 3; i++, pc += AARCH64_INSN_SIZE) {
		ret = aarch64_insn_read((void *)pc, &insn);
		if (ret) {
			pr_err("#### %s: could not read 0x%lx\n", __func__, pc);
			return 0;
		}
		pr_debug("#### %s: %x %x\n", __func__, insn, expected);

		if (insn == expected) {
			/* The branch/nop is the next instruction */
			return pc;
		}

		/*
		 * HACK: is it one of ours? x16 is a giveaway.
		 */
		if (aarch64_insn_is_movz(insn) && (insn & 0x1f) == 16)
			return pc;

		/*
		 * Otherwise it may be a BTI landing pad or PAC. Keep looking.
		 * I'm being excessively lazy here. There is a correct way to do
		 * this, by inspecting the mcount records.
		 */
	}

	pr_debug("#### %s: cannot patch at 0x%lx\n", __func__, pc);
	return 0;
}

#define IS_BPF_TEXT(addr) ((unsigned long)(addr) >= BPF_JIT_REGION_START && \
			   (unsigned long)(addr) < BPF_JIT_REGION_END)

static int bpf_prog_poke(unsigned long pc, enum bpf_text_poke_location l,
			 void *old_addr, void *new_addr)
{
	int ret;
	u32 old_insn, new_insn;

	if (IS_ENABLED(CONFIG_ARM64_BTI_KERNEL))
		pc += AARCH64_INSN_SIZE;

	if (old_addr)
		old_insn = aarch64_insn_gen_branch_imm(pc,
						       (unsigned long)old_addr,
						       AARCH64_INSN_BRANCH_NOLINK);
	else
		old_insn = aarch64_insn_gen_nop();

	if (new_addr)
		new_insn = aarch64_insn_gen_branch_imm(pc,
						       (unsigned long)new_addr,
						       AARCH64_INSN_BRANCH_NOLINK);
	else
		new_insn = aarch64_insn_gen_nop();

	if (WARN_ON(old_insn == AARCH64_BREAK_FAULT ||
		    new_insn == AARCH64_BREAK_FAULT))
		return -EINVAL;

	ret = aarch64_insn_update(pc, old_insn, new_insn, true);
	if (ret)
		pr_err("#### %s: insn update %d\n", __func__, ret);
	return ret;
}

static u32 bpf_tramp_to_insn(void *trampoline_addr)
{
	int idx;
	unsigned long addr = (unsigned long)trampoline_addr;

	if (WARN_ON(addr < BPF_JIT_REGION_START || addr >= BPF_JIT_REGION_END)) {
		pr_err("#### %s: Address 0x%lx outside JIT region\n", __func__,
		       addr);
		return AARCH64_BREAK_FAULT;
	}

	if (WARN_ON(!IS_ALIGNED(addr, 1UL << BPF_TRAMPOLINE_SHIFT))) {
		pr_err("#### %s: address 0x%lx is not aligned\n", __func__,
		       addr);
		return AARCH64_BREAK_FAULT;
	}

	idx = (addr - BPF_JIT_REGION_START) >> BPF_TRAMPOLINE_SHIFT;
	return A64_MOVZ(1, A64_R(16), idx, 0);
}

struct insn_update {
	void *addr;
	unsigned int old, new;
};

#define MAX_UPDATE_INSNS 2
static int bpf_update_instructions(struct insn_update *updates, int nr)
{
	int i, ret;
	void *addr;
	int nr_updates = 0;
	u32 insn, old, new;
	void *addrs[MAX_UPDATE_INSNS];
	u32 insns[MAX_UPDATE_INSNS];

	if (nr > MAX_UPDATE_INSNS)
		return -EINVAL;

	/*
	 * First check that all existing instructions are expected. Don't want
	 * to start patching right away only to realize later that we created an
	 * invalid path.
	 */
	for (i = 0; i < nr; i++) {
		old = updates[i].old;
		new = updates[i].new;
		addr = updates[i].addr;

		if (old == AARCH64_BREAK_FAULT || new == AARCH64_BREAK_FAULT)
			return -EINVAL;

		ret = aarch64_insn_read(addr, &insn);
		if (ret) {
			pr_err("#### %s: insn read fault at %px\n", __func__,
			       addr);
			return ret;
		}
		if (insn != old) {
			pr_err("#### %s: unexpected insn 0x%x != 0x%x at %px\n",
			       __func__, insn, old, addr);
			return -EINVAL;
		}

		if (!new)
			continue;
		addrs[nr_updates] = addr;
		insns[nr_updates] = new;
		nr_updates++;
	}

	/* Stop the world and perform these updates. */
	return aarch64_insn_patch_text(addrs, insns, nr_updates);
}

/*
 * The trampoline code is somewhere within the 128M JIT region, aligned on
 * PAGE_SIZE / 2, so we have a set of 64k possible entry points. The trampoline
 * is constructed specially for this function, so we don't need a BLR, and so we
 * don't have to save LR. The first patch instruction specifies the trampoline
 * frame number, and the second one jumps to an intermediate trampoline, like
 * so:
 *	mov x16, #idx
 *	b bpf_tramp_call
 *
 * bpf_tramp_call (conceptually):
 *	mov x17, BFP_JIT_REGION_START
 *	add x16, x16, x17, lsl #BPF_TRAMPOLINE_SHIFT
 *	br x16
 */
int bpf_arch_text_poke(void *ptr, enum bpf_text_poke_type t,
		       enum bpf_text_poke_location l, void *old_addr,
		       void *new_addr)
{
	unsigned long pc = (unsigned long)ptr;
	struct insn_update updates[2] = {};
	u32 br_tramp, mov_x9_lr, nop;

	pr_debug("#### %s(%px %d %px %px)\n", __func__, ptr, t, old_addr,
		 new_addr);

	if (WARN_ON((new_addr && !IS_BPF_TEXT(new_addr)) ||
		    (old_addr && !IS_BPF_TEXT(old_addr))))
		return -EINVAL;

	if (is_bpf_text_address(pc))
		return bpf_prog_poke(pc, l, old_addr, new_addr);

	if (!core_kernel_text(pc))
		return -EINVAL;

	pc = bpf_arch_find_branch(pc);
	if (!pc)
		return -EINVAL;
	ptr = (void *)pc;

	nop = aarch64_insn_gen_nop();
	br_tramp = aarch64_insn_gen_branch_imm(pc + AARCH64_INSN_SIZE,
					       (unsigned long)&bpf_tramp_call,
					       AARCH64_INSN_BRANCH_NOLINK);
	mov_x9_lr = aarch64_insn_gen_move_reg(AARCH64_INSN_REG_9,
					      AARCH64_INSN_REG_LR,
					      AARCH64_INSN_VARIANT_64BIT);

	if (new_addr && old_addr) {
		updates[0].addr = ptr;
		updates[0].old = bpf_tramp_to_insn(old_addr);
		updates[0].new = bpf_tramp_to_insn(new_addr);

		/* No change, but check that it is what we expect. */
		updates[1].addr = ptr + AARCH64_INSN_SIZE;
		updates[1].old = br_tramp;
	} else if (new_addr) {
		updates[0].addr = ptr;
		updates[0].old = mov_x9_lr;
		updates[0].new = bpf_tramp_to_insn(new_addr);

		updates[1].addr = ptr + AARCH64_INSN_SIZE;
		updates[1].old = nop;
		updates[1].new = br_tramp;
	} else if (old_addr) {
		/* Remove the branch first */
		updates[0].addr = ptr + AARCH64_INSN_SIZE;
		updates[0].old = br_tramp;
		updates[0].new = nop;

		updates[1].addr = ptr;
		updates[1].old = bpf_tramp_to_insn(old_addr);
		updates[1].new = mov_x9_lr;
	} else {
		WARN_ON(1);
		return -EINVAL;
	}

	return bpf_update_instructions(updates, 2);
}

/* Up to 8 arguments in x0-x7 */
#define BPF_TRAMP_MAX_ARGS 8

/* Emit branches to one BPF program, wrapped with __bpf_prog_enter/exit() */
static int invoke_one_bpf(const struct btf_func_model *m, struct jit_ctx *ctx,
			  struct bpf_prog *prog, int *ret_branch, u32 flags,
			  u8 tstamp_reg, u8 retval_reg, u8 prog_enter_reg,
			  u8 prog_exit_reg)
{
	int ret;
	off_t offset;
	const u8 x0 = A64_R(0);
	const u8 x1 = A64_R(1);

	u64 (*enter_fun)(struct bpf_prog *prog);
	void (*exit_fun)(struct bpf_prog *prog, u64 start);

	/*
	 * Calls to BPF programs are wrapped between calls to __bpf_prog_enter
	 * and __bpf_prog_exit. Unfortunately the kernel text is at least 128MB
	 * away from pc, so we can't use a direct jump.
	 */
	if (prog->aux->sleepable) {
		enter_fun = __bpf_prog_enter_sleepable;
		exit_fun = __bpf_prog_exit_sleepable;
	} else {
		enter_fun = __bpf_prog_enter;
		exit_fun = __bpf_prog_exit;
	}

	emit_a64_mov_i64(prog_enter_reg, (u64)enter_fun, ctx);
	emit_a64_mov_i64(prog_exit_reg, (u64)exit_fun, ctx);

	/* Call __bpf_prog_enter(prog) */
	emit_a64_mov_i64(x0, (long)prog, ctx);
	emit(A64_BLR(prog_enter_reg), ctx);
	/* Save the timestamp returned by __bpf_prog_enter */
	emit(A64_MOV(1, tstamp_reg, x0), ctx);

	/*
	 * The BPF program takes a context pointer in x0. The context
	 * contains all fun() arguments, and for fmod_ret programs, the
	 * return value of the previous BPF program. If the program is
	 * interpreted, it also needs a pointer to the instructions in r2.
	 */
	emit(A64_MOV(1, x0, A64_SP), ctx);
	if (!prog->jited) {
		WARN_ONCE(1, "### REMOVE ME %s ### this path is now tested\n",
			  __func__);
		emit_a64_mov_i64(x1, (long)prog->insnsi, ctx);
	}

	/* The BPF JIT region is 128M, so at least this should succeed. */
	ret = emit_bl(prog->bpf_func, ctx);
	if (ret) {
		pr_err_once("invalid branch outside BPF region\n");
		return ret;
	}

	/*
	 * When we don't call or return to a patched function (flags == 0), the
	 * return value of the last program is the one from the trampoline.
	 */
	if (ret_branch || !flags)
		emit(A64_MOV(1, retval_reg, x0), ctx);

	/* Call __bpf_prog_exit(bpf_prog, tstamp) */
	emit_a64_mov_i64(x0, (long)prog, ctx);
	emit(A64_MOV(1, x1, tstamp_reg), ctx);
	emit(A64_BLR(prog_exit_reg), ctx);

	if (ret_branch) {
		/* If ret == 0, skip the next two instructions. */
		emit(A64_CMP(1, retval_reg, A64_ZR), ctx);
		emit(A64_B_(A64_COND_EQ, (3 * AARCH64_INSN_SIZE) >> 2), ctx);

		/*
		 * Otherwise store the return value and jump past the function
		 * invocation. We don't yet have the target address, so emit a
		 * placeholder.
		 */
		offset = 8 * m->nr_args;
		emit(A64_STR64_IMM(retval_reg, A64_SP, offset), ctx);
		*ret_branch = ctx->idx;
		emit(aarch64_insn_gen_nop(), ctx);
	}

	return 0;
}

static int invoke_bpf(const struct btf_func_model *m, struct jit_ctx *ctx,
		      struct bpf_tramp_progs *tp, int *ret_branches,
		      u32 flags, u8 tstamp_reg, u8 retval_reg, u8
		      prog_enter_reg, u8 prog_exit_reg)
{
	int i, ret;

	for (i = 0; i < tp->nr_progs; i++) {
		int *ret_branch = ret_branches ? &ret_branches[i] : NULL;

		ret = invoke_one_bpf(m, ctx, tp->progs[i], ret_branch,
				     flags, tstamp_reg, retval_reg,
				     prog_enter_reg, prog_exit_reg);
		if (ret)
			return ret;
	}
	return 0;
}

static int gen_trampoline(struct jit_ctx *ctx, const struct btf_func_model *m,
			  u32 flags, struct bpf_tramp_progs *tprogs,
			  void *orig_call)
{
	int i, ret;
	off_t offset;
	size_t nr_stack_regs;
	int *ret_branches = NULL;
	size_t nr_args = m->nr_args;
	u8 stack[BPF_TRAMP_MAX_ARGS + 2 + 6];
	const u8 tstamp_reg = bpf2a64[BPF_REG_6];
	const u8 retval_reg = bpf2a64[BPF_REG_7];
	const u8 prog_enter_reg = bpf2a64[BPF_REG_8];
	const u8 prog_exit_reg = bpf2a64[BPF_REG_9];
	/* Not callee saved */
	const u8 tmp1_reg = bpf2a64[TMP_REG_1];
	const u8 tmp2_reg = bpf2a64[TMP_REG_2];

	unsigned long ret_address = (unsigned long)orig_call;

	bool return_to_orig = false;
	bool call_orig = (flags & BPF_TRAMP_F_CALL_ORIG);
	bool restore_regs = (flags & BPF_TRAMP_F_RESTORE_REGS);
	bool restore_ret = false;

	struct bpf_tramp_progs *fentry = &tprogs[BPF_TRAMP_FENTRY];
	struct bpf_tramp_progs *fexit = &tprogs[BPF_TRAMP_FEXIT];
	struct bpf_tramp_progs *fmod_ret = &tprogs[BPF_TRAMP_MODIFY_RETURN];

	/* Only support register parameters for now */
	if (nr_args > BPF_TRAMP_MAX_ARGS)
		return -ENOTSUPP;

	/*
	 * Support three modes:
	 * - No flags
	 *   A simple call to the trampoline (for bpf_struct_ops), there is no
	 *   patched function and LR is the callsite.
	 * - BPF_TRAMP_F_RESTORE_REGS
	 *   Call fentry only and return to fun() with its original arguments.
	 * - BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_SKIP_FRAME
	 *   Call fentry and fmod_ret, return to fun(), call fexit, return to
	 *   the parent.
	 */
	switch (flags) {
	case 0:
		if (WARN_ON_ONCE(orig_call))
			return -EINVAL;
		restore_ret = true;
		break;
	case BPF_TRAMP_F_RESTORE_REGS:
		if (WARN_ON_ONCE(fmod_ret->nr_progs || fexit->nr_progs ||
				 !orig_call))
			return -EINVAL;
		return_to_orig = true;
		break;
	case BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_SKIP_FRAME:
		if (WARN_ON_ONCE(!orig_call))
			return -EINVAL;
		restore_ret = true;
		break;
	default:
		WARN_ON_ONCE(1);
		return -ENOTSUPP;
	}

	/* BTI landing pad */
	if (IS_ENABLED(CONFIG_ARM64_BTI_KERNEL)) {
		/* FIXME: This is too fragile. Find it in the mcount records. */
		ret_address += AARCH64_INSN_SIZE;
		emit(A64_BTI_C, ctx);
	}

	/*
	 * The BPF patch is just a branch, the kernel text patch is a mov + a
	 * branch
	 */
	if (IS_BPF_TEXT(orig_call))
		ret_address += AARCH64_INSN_SIZE;
	else
		ret_address += AARCH64_INSN_SIZE * 2;

	/*
	 * Initialize the trampoline frame:
	 *
	 *       0 +--------------------+ <- SP on trampoline entry
	 *         |   LR, FP           |
	 *     -16 +--------------------+ <- trampoline FP
	 *         | - callee saved     |
	 *     -48 +--------------------+
	 *         | - saved ret value  |
	 *         | - fun() args       |
	 *   -48-X +--------------------+ <- ctx of BPF programs
	 *
	 * Where X = ALIGN(8 * (nr_args + 1), 16)
	 */

	for (i = 0; i < nr_args; i++)
		stack[i] = i;
	/* Reserve one slot (initialized to zero) for the return value */
	stack[i++] = A64_ZR;

	/* Align the stack to 16 bytes */
	if (i % 2)
		stack[i++] = A64_ZR;

	stack[i++] = tstamp_reg;
	stack[i++] = retval_reg;
	stack[i++] = prog_enter_reg;
	stack[i++] = prog_exit_reg;
	nr_stack_regs = i;

	/* Save FP and LR registers */
	emit(A64_PUSH(A64_FP, A64_LR, A64_SP), ctx);
	emit(A64_MOV(1, A64_FP, A64_SP), ctx);
	ctx->stack_size += 16;

	for (i = nr_stack_regs - 2; i >= 0; i -= 2)
		emit(A64_PUSH(stack[i], stack[i + 1], A64_SP), ctx);
	ctx->stack_size += nr_stack_regs * 8;
	if (WARN_ON_ONCE(!IS_ALIGNED(ctx->stack_size, 16)))
		return -EFAULT;

	/* (1) Call all the fentry programs */
	ret = invoke_bpf(m, ctx, fentry, NULL, flags, tstamp_reg,
			 retval_reg, prog_enter_reg, prog_exit_reg);
	if (ret)
		return ret;

	/* (2) Call all the fmod_ret programs */
	if (fmod_ret->nr_progs) {
		ret_branches = kcalloc(fmod_ret->nr_progs,
				       sizeof(ret_branches[0]), GFP_KERNEL);
		if (!ret_branches)
			return -ENOMEM;

		ret = invoke_bpf(m, ctx, fmod_ret, ret_branches, flags,
				 tstamp_reg, retval_reg, prog_enter_reg,
				 prog_exit_reg);
		if (ret)
			goto out_free;
	}

	if (call_orig) {
		/*
		 * (3a) Return to fun().
		 *
		 * One does not simply walk into fun(). There is no BTI landing
		 * pad after the patched function entry. We have to return there
		 * after modifying the stack and return address to bring us back
		 * here once the function terminates.
		 *
		 * See also the FUNCTION_GRAPH_TRACER implementation, it does
		 * the same thing.
		 */

		/*
		 * Restore the original fun() arguments without popping the
		 * frame.
		 */
		emit(A64_MOV(1, tmp1_reg, A64_SP), ctx);
		for (i = 0; i < nr_args; i += 2)
			/* May pop the return value into xzr. Harmless. */
			emit(A64_POP(stack[i], stack[i + 1], tmp1_reg), ctx);

		emit_a64_mov_i64(tmp2_reg, ret_address, ctx);

		/*
		 * Set fun()'s LR to return on the insn following ret. This
		 * one's funny: emit_a64_mov_i64() generates one to four mov
		 * instructions, depending on the target address. And the target
		 * address depends on the number of movs :) Lazy solution: use a
		 * fixed offset of 4 and fill with nops.
		 */
		offset = ctx->idx + 4;
		if (ctx->image)
			emit_a64_mov_i64(A64_LR,
					 (long)(ctx->image + offset + 1), ctx);
		for (i = ctx->idx; i < offset; i++)
			emit(aarch64_insn_gen_nop(), ctx);
		emit(A64_RET(tmp2_reg), ctx);

		/* fun() returns here. Store its return value. */
		offset = nr_args * 8;
		emit(A64_MOV(1, retval_reg, A64_R(0)), ctx);
		emit(A64_STR64_IMM(retval_reg, A64_SP, offset), ctx);
	}

	/*
	 * Patch the fmod_ret branches to jump here if their return
	 * value was != 0
	 */
	for (i = 0; i < fmod_ret->nr_progs && ctx->image; i++) {
		int branch_idx = ret_branches[i];
		u32 insn = le32_to_cpu(ctx->image[branch_idx]);

		if (WARN_ON(insn != aarch64_insn_gen_nop())) {
			ret = -EINVAL;
			goto out_free;
		}

		offset = AARCH64_INSN_SIZE * (ctx->idx - branch_idx);
		if (WARN_ON(offset > SZ_1M)) {
			ret = -ERANGE;
			goto out_free;
		}
		insn = A64_B(offset >> 2);
		ctx->image[branch_idx] = cpu_to_le32(insn);
	}

	/* (4) Call all the fexit programs */
	ret = invoke_bpf(m, ctx, fexit, NULL, flags, tstamp_reg, retval_reg,
			 prog_enter_reg, prog_exit_reg);
	if (ret)
		goto out_free;

	/*
	 * Restore fun() args if required, or discard them.
	 * Stack pointer must be multiple of 16B.
	 */
	offset = round_up(8 * (nr_args + 1), 16);
	for (i = 0; restore_regs && i < nr_args; i += 2) {
		emit(A64_POP(stack[i], stack[i + 1], A64_SP), ctx);
		offset -= 16;
	}
	if (offset)
		emit(A64_ADD_I(1, A64_SP, A64_SP, offset), ctx);

	if (restore_ret)
		emit(A64_MOV(1, A64_R(0), retval_reg), ctx);

	/* Restore callee-saved */
	for (i = ALIGN(nr_args + 1, 2); i < nr_stack_regs; i += 2)
		emit(A64_POP(stack[i], stack[i + 1], A64_SP), ctx);

	/* Restore FP/LR registers */
	emit(A64_POP(A64_FP, A64_LR, A64_SP), ctx);

	if (return_to_orig) {
		emit_a64_mov_i64(tmp1_reg, ret_address, ctx);
		emit(A64_RET(tmp1_reg), ctx);
	} else {
		emit(A64_RET(A64_LR), ctx);
	}

out_free:
	kfree(ret_branches);
	return ret;
}

/*
 * Generate a trampoline function. A patched function fun(...) branches into the
 * trampoline.
 *
 * Then:
 * (1) Call all the fentry BPF programs.
 * (2) Call all the fmod_ret programs. If any of them returns non-null, fun() is
 *     not called, we go directly to (4).
 * (3a) Return to fun().
 * (4) Call all the fexit BPF programs.
 * (5) Return to fun()'s parent.
 *
 * If there aren't any fexit or fmod_ret programs:
 * (3b) Return to fun(), done.
 *
 * There is also the possibility to use the trampoline as a simple function,
 * called from bpf_struct_ops. In this case we have:
 * (3c) Return to LR.
 *
 * Returns the number of bytes emitted, or a negative error.
 */
int arch_prepare_bpf_trampoline(void *image, void *image_end,
				const struct btf_func_model *m, u32 flags,
				struct bpf_tramp_progs *tprogs,
				void *orig_call)
{
	int ret;
	size_t tramp_size;

	struct jit_ctx ctx = {};

	/* First pass to check that we have enough space */
	ret = gen_trampoline(&ctx, m, flags, tprogs, orig_call);
	if (ret < 0)
		return ret;

	tramp_size = ctx.idx * AARCH64_INSN_SIZE;
	if (WARN_ON_ONCE(tramp_size > (image_end - image)))
		return -ENOSPC;

	/* Second pass */
	ctx.idx = 0;
	ctx.image = image;
	ret = gen_trampoline(&ctx, m, flags, tprogs, orig_call);
	if (ret < 0)
		return ret;

	if (WARN_ON_ONCE(ctx.idx * AARCH64_INSN_SIZE != tramp_size))
		return -EFAULT;

	bpf_flush_icache(ctx.image, ctx.image + ctx.idx);
	pr_debug("%s: Trampoline is %zu bytes\n", __func__, tramp_size);
	print_hex_dump_debug("", DUMP_PREFIX_ADDRESS, 16, 4, ctx.image, ctx.idx
			     * AARCH64_INSN_SIZE, false);
	return tramp_size;
}
#endif

u64 bpf_jit_alloc_exec_limit(void)
{
	return BPF_JIT_REGION_SIZE;
}

void *bpf_jit_alloc_exec(unsigned long size)
{
	return __vmalloc_node_range(size, PAGE_SIZE, BPF_JIT_REGION_START,
				    BPF_JIT_REGION_END, GFP_KERNEL,
				    PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}

void bpf_jit_free_exec(void *addr)
{
	return vfree(addr);
}
