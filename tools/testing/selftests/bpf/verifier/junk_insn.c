{
	"junk insn",
	.insns = {
	BPF_RAW_INSN(0, 0, 0, 0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "unknown opcode 00",
	.result = REJECT,
},
{
	"junk insn2",
	.insns = {
	BPF_RAW_INSN(1, 0, 0, 0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "BPF_LDX uses reserved fields",
	.result = REJECT,
},
{
	"junk insn3",
	.insns = {
	BPF_RAW_INSN(-1, 0, 0, 0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "unknown opcode ff",
	.result = REJECT,
},
{
	"junk insn4",
	.insns = {
	BPF_RAW_INSN(-1, -1, -1, -1, -1),
	BPF_EXIT_INSN(),
	},
	.errstr = "unknown opcode ff",
	.result = REJECT,
},
{
	"junk insn5",
	.insns = {
	BPF_RAW_INSN(0x7f, -1, -1, -1, -1),
	BPF_EXIT_INSN(),
	},
	.errstr = "BPF_ALU uses reserved fields",
	.result = REJECT,
},
{
	/* BPF_PROBE_MEM is used internally by the verifier */
#define BPF_PROBE_MEM 0x20
	"ldx probe mem",
	.insns = {
	BPF_RAW_INSN(BPF_LDX | BPF_SIZE(BPF_DW) | BPF_PROBE_MEM,
		     BPF_REG_0, BPF_REG_1, 0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "BPF_LDX uses reserved fields",
	.result = REJECT,
},
