/* From the test_align.c selftest */
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <bpf/bpf.h>
#include "bpf_insn.h"

static char bpf_log_buf[BPF_LOG_BUF_SIZE];

#define PREP_PKT_POINTERS \
        BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, \
                    offsetof(struct __sk_buff, data)), \
        BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, \
                    offsetof(struct __sk_buff, data_end))

#define LOAD_UNKNOWN(DST_REG) \
        PREP_PKT_POINTERS, \
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_2), \
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8), \
        BPF_JMP_REG(BPF_JGE, BPF_REG_3, BPF_REG_0, 1), \
        BPF_EXIT_INSN(), \
        BPF_LDX_MEM(BPF_B, DST_REG, BPF_REG_2, 0)


int main(int argc, char **argv)
{
	int prog_fd;
	struct bpf_insn prog[] = {
		LOAD_UNKNOWN(BPF_REG_6),
		/* Test overflow
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 14),
		BPF_JMP_REG(BPF_JGE, BPF_REG_2, BPF_REG_3, 2),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -2),
		BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_2, 0),
		 */


		BPF_MOV64_REG(BPF_REG_5, BPF_REG_2),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, 14),
		BPF_ALU64_REG(BPF_ADD, BPF_REG_5, BPF_REG_6),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, 14),
		BPF_ALU64_REG(BPF_ADD, BPF_REG_5, BPF_REG_6),
		BPF_EXIT_INSN(),
	};
	size_t prog_size = sizeof(prog) / sizeof(struct bpf_insn);

	prog_fd = bpf_verify_program(BPF_PROG_TYPE_SCHED_CLS,
				     prog, prog_size, BPF_F_STRICT_ALIGNMENT,
				     "GPL", 0, bpf_log_buf, BPF_LOG_BUF_SIZE,
				     /* log level */ 3);
	if (prog_fd < 0)
		printf("failed to load prog '%s'\n", strerror(errno));

	printf("---- START_LOG_BUF -----\n");
	printf("%s\n", bpf_log_buf);
	printf("---- END_LOG_BUF -----\n");

	/* Wait a bit so we can use bpftool to dump the jitted code */
	//printf("Press return...");
	//fflush(stdout);
	//fgetc(stdin);

	return 0;
}
