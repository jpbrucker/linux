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
