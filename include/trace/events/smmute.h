#if !defined(SMMU_TEST_ENGINE_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define SMMU_TEST_ENGINE_TRACE_H

#include <linux/tracepoint.h>

#undef  TRACE_SYSTEM
#define TRACE_SYSTEM smmute

TRACE_EVENT(smmute_transaction_ready,
	TP_PROTO(struct smmute_transaction *transaction),
	TP_ARGS(transaction),
	TP_STRUCT__entry(
		__field(u64,				id)
		__field(char,				command)
		__field(u64,				dma_in_iova)
		__field(size_t,				dma_in_size)
		__field(u64,				dma_out_iova)
		__field(size_t,				dma_out_size)
	),

	TP_fast_assign(
		__entry->id = transaction->id;
		__entry->command = transaction->command == ENGINE_MEMCPY ? 'm' :
				  (transaction->command == ENGINE_RAND48 ? 'r' : 's');
		__entry->dma_in_iova = transaction->dma_in ?
				       transaction->dma_in->iova : 0;
		__entry->dma_in_size = transaction->dma_in ?
				       transaction->dma_in->size : 0;
		__entry->dma_out_iova = transaction->dma_out ?
					transaction->dma_out->iova : 0;
		__entry->dma_out_size = transaction->dma_out ?
					transaction->dma_out->size : 0;
	),

	TP_printk("    %04llu %c (%#llx %zu) (%#llx %zu)",
		  __entry->id, __entry->command,
		  __entry->dma_in_iova, __entry->dma_in_size,
		  __entry->dma_out_iova, __entry->dma_out_size)
);

TRACE_EVENT(smmute_transaction_launch,
	TP_PROTO(struct smmute_transaction *transaction),
	TP_ARGS(transaction),
	TP_STRUCT__entry(__field(u64, id)),
	TP_fast_assign(__entry->id = transaction->id),
	TP_printk("-> %04llu", __entry->id)
);

TRACE_EVENT(smmute_transaction_notify,
	TP_PROTO(struct smmute_transaction *transaction),
	TP_ARGS(transaction),
	TP_STRUCT__entry(__field(u64, id)),
	TP_fast_assign(__entry->id = transaction->id),
	TP_printk("*  %04llu", __entry->id)
);

TRACE_EVENT(smmute_transaction_finish,
	TP_PROTO(struct smmute_transaction *transaction),
	TP_ARGS(transaction),
	TP_STRUCT__entry(__field(u64, id)),
	TP_fast_assign(__entry->id = transaction->id),
	TP_printk("<- %04llu", __entry->id)
);

TRACE_EVENT(smmute_transaction_retire,
	TP_PROTO(struct smmute_transaction *transaction),
	TP_ARGS(transaction),
	TP_STRUCT__entry(__field(u64, id)),
	TP_fast_assign(__entry->id = transaction->id),
	TP_printk(" . %04llu", __entry->id)
);

TRACE_EVENT(smmute_alloc_task,
	TP_PROTO(struct smmute_task *smmute_task),
	TP_ARGS(smmute_task),
	TP_STRUCT__entry(__field(u32, ssid)),
	TP_fast_assign(__entry->ssid = smmute_task->ssid),
	TP_printk("ssid=%u", __entry->ssid)
);

TRACE_EVENT(smmute_put_task,
	TP_PROTO(struct smmute_task *smmute_task, const char *src),
	TP_ARGS(smmute_task, src),
	TP_STRUCT__entry(
		__field(u32, ssid)
		__field(unsigned long, refs)
		__string(src, src)
	),
	TP_fast_assign(
		__entry->ssid = smmute_task->ssid;
		__entry->refs = kref_read(&smmute_task->kobj.kref);
		__assign_str(src, src);
	),
	TP_printk("ssid=%u %lu %s", __entry->ssid, __entry->refs,
		  __get_str(src))
);

TRACE_EVENT(smmute_get_task,
	TP_PROTO(struct smmute_task *smmute_task, const char *src),
	TP_ARGS(smmute_task, src),
	TP_STRUCT__entry(
		__field(u32, ssid)
		__field(unsigned long, refs)
		__string(src, src)
	),
	TP_fast_assign(
		__entry->ssid = smmute_task->ssid;
		__entry->refs = kref_read(&smmute_task->kobj.kref);
		__assign_str(src, src);
	),
	TP_printk("ssid=%u %lu %s", __entry->ssid, __entry->refs,
		  __get_str(src))
);

TRACE_EVENT(smmute_free_task,
	TP_PROTO(struct smmute_task *smmute_task),
	TP_ARGS(smmute_task),
	TP_STRUCT__entry(__field(u32, ssid)),
	TP_fast_assign(__entry->ssid = smmute_task->ssid),
	TP_printk("ssid=%u", __entry->ssid)
);

#endif /* SMMU_TEST_ENGINE_TRACE_H */

#include <trace/define_trace.h>
