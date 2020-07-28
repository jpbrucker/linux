// SPDX-License-Identifier: GPL-2.0
#include "bpf_iter.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("iter/ipv6_route")
int dump_ipv6_route(struct bpf_iter__ipv6_route *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct fib6_info *rt = ctx->rt;

	if (rt)
		/* Follow pointers as recklessly as possible. */
		BPF_SEQ_PRINTF(seq, "%s\n",
			       &rt->nh->nh_info->fib6_nh.fib_nh_dev->name);
	return 0;
}

SEC("iter/task")
int dump_kthread_vm(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	int i, garbage = 0;

	if (task == (void *)0)
		return 0;

	/* Only inspect kthreadd */
	if (task->pid != 2)
		return 0;

	/* task->mm is NULL */
	BPF_SEQ_PRINTF(seq, "pid=%d vm=%d", task->pid, task->mm->total_vm);

	/* Generate a few more fault sites for good measure */
	for (i = 0; i < 0x1000; i++) {
		task = task->parent;
		garbage += task->mm->mmap->vm_mm->total_vm;
	}
	BPF_SEQ_PRINTF(seq, " garbage=%d\n", garbage);
	return 0;
}
