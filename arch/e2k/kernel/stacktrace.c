/*
 * Stack trace management functions
 *
 *  Copyright (C) 2006-2009 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 */
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/e2k_debug.h>
#include <asm/stacktrace.h>


static int save_stack_address_kernel(struct task_struct *task,
		e2k_mem_crs_t *frame, unsigned long frame_address,
		void *data, void *unused1, void *unused2)
{
	struct stack_trace *trace = data;
	u64 ip;

	if (AS(frame->cr1_lo).pm == 0)
		return 1;

	if (trace->skip > 0) {
		trace->skip--;
		return 0;
	}

	ip = AS_STRUCT(frame->cr0_hi).ip << 3;

	if (likely(trace->nr_entries < trace->max_entries))
		trace->entries[trace->nr_entries++] = ip;
	else
		return 1;

	return 0;
}

static int save_stack_address_user(struct task_struct *task,
		e2k_mem_crs_t *frame, unsigned long frame_address,
		void *data, void *unused1, void *unused2)
{
	struct stack_trace *trace = data;
	u64 ip;

	if (AS(frame->cr1_lo).pm)
		return 0;

	if (trace->skip > 0) {
		trace->skip--;
		return 0;
	}

	ip = AS_STRUCT(frame->cr0_hi).ip << 3;

	if (likely(trace->nr_entries < trace->max_entries))
		trace->entries[trace->nr_entries++] = ip;
	else
		return 1;

	return 0;
}


/*
 * Save stack-backtrace addresses into a stack_trace buffer.
 */
void save_stack_trace(struct stack_trace *trace)
{
	parse_chain_stack(NULL, save_stack_address_kernel, trace, 0, 0);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace);

void save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
{
	parse_chain_stack(NULL, save_stack_address_kernel, trace, 0, 0);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	parse_chain_stack(tsk, save_stack_address_kernel, trace, 0, 0);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace_tsk);

void save_stack_trace_user(struct stack_trace *trace)
{
	parse_chain_stack(NULL, save_stack_address_user, trace, 0, 0);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

