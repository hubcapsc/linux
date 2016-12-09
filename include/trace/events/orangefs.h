#undef TRACE_SYSTEM
#define TRACE_SYSTEM orangefs

#if !defined(_TRACE_ORANGEFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ORANGEFS_H

#include <linux/tracepoint.h>

TRACE_EVENT(orangefs_op_put,

	TP_PROTO(struct orangefs_kernel_op_s *op),

	TP_ARGS(op),

	TP_STRUCT__entry(
		__field(__u64, tag)
		__field(__u32, type)
	),

	TP_fast_assign(
		__entry->tag = op->tag;
		__entry->type = op->upcall.type;
	),

	TP_printk("put tag:%llu: type:%u:",  __entry->tag, __entry->type)
);

TRACE_EVENT(orangefs_op_get,

	TP_PROTO(struct orangefs_kernel_op_s *op),

	TP_ARGS(op),

	TP_STRUCT__entry(
		__field(__u64, tag)
		__field(__u32, type)
	),

	TP_fast_assign(
		__entry->tag = op->tag;
		__entry->type = op->upcall.type;
	),

	TP_printk("get tag:%llu: type:%u:",  __entry->tag, __entry->type)
);

TRACE_EVENT(orangefs_igothere,

	TP_PROTO(char *msg),

	TP_ARGS(msg),

	TP_STRUCT__entry(
		__string(msg, msg)
	),

	TP_fast_assign(
		__assign_str(msg, msg);
	),

	TP_printk("%s", __get_str(msg))
);

#endif

#include <trace/define_trace.h>
