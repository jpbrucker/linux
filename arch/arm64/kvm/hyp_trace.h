/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ARM64_KVM_HYP_TRACE_H__
#define __ARM64_KVM_HYP_TRACE_H__

#ifdef CONFIG_TRACING
int hyp_trace_init_tracefs(void);
int hyp_trace_init_events(void);
struct hyp_event *hyp_trace_find_event(int id);
void hyp_trace_init_event_tracefs(struct dentry *parent);
#else
static inline int hyp_trace_init_tracefs(void) { return 0; }
static inline int hyp_trace_init_events(void) { return 0; }
#endif
#endif
