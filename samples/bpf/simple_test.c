#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <bpf/bpf.h>
#include "bpf_insn.h"

static char bpf_log_buf[BPF_LOG_BUF_SIZE];

struct test_val {
	unsigned int index;
	int foo[11];
};

int main(int argc, char **argv)
{
	int ret;
	int map_fd;
	int prog_fd;
	uint32_t retval;
	__u8 in_data[64];
	__u8 out_data[64 << 2];
	__u32 size_in_data = sizeof(in_data);
	__u32 size_out_data = sizeof(out_data);
	struct bpf_insn prog[] = {
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 6),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),   // from
		BPF_MOV64_IMM(BPF_REG_2, 4),           // from size
		BPF_MOV64_IMM(BPF_REG_3, 0),           // to
		BPF_MOV64_IMM(BPF_REG_4, 0),           // to_size
		BPF_MOV64_IMM(BPF_REG_5, 0),           // seed
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_csum_diff),
		BPF_EXIT_INSN(),
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);
	struct bpf_load_program_attr attr = {
		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
		.expected_attach_type = 0,
		.insns = prog,
		.insns_cnt = insns_cnt,
		.license = "GPL",
		.log_level = 1,
		.prog_flags = 0,
	};

	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int),
				sizeof(struct test_val), 1,
				BPF_F_RDONLY_PROG);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		return map_fd;
	}

	{
		/* Setup map */
		int index = 0;
		struct test_val value = {
			.index = (6 + 1) * sizeof(int), // Dunno why
			.foo[6] = 0xabdef12,
		};

		assert(!bpf_map_update_elem(map_fd, &index, &value, 0));
		prog[3].imm = map_fd;
	}

	prog_fd = bpf_load_program_xattr(&attr, bpf_log_buf, BPF_LOG_BUF_SIZE);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		printf("%s\n", bpf_log_buf);
		return prog_fd;
	}

	/* Wait a bit so we can use bpftool to dump the jitted code */
	printf("Press return...");
	fflush(stdout);
	fgetc(stdin);

	ret = bpf_prog_test_run(prog_fd, 1, &in_data, size_in_data, out_data,
				&size_out_data, &retval, NULL);
	printf("%d, 0x%x %hd\n", size_out_data, retval, retval);
	if (ret) {
		printf("test_run failed with %d '%s'\n", ret, strerror(errno));
	}
	return ret;
}
