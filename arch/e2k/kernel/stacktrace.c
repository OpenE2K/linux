/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Stack trace management functions
 */

#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <asm/e2k_debug.h>
#include <asm/stacktrace.h>


struct save_stack_address_kernel_args {
	struct stack_trace *trace;
	struct pt_regs *regs;
};

static int save_stack_address_kernel(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct save_stack_address_kernel_args *args = arg;
	struct stack_trace *trace = args->trace;
	struct pt_regs *regs = args->regs;
	u64 ip;

	if (regs && corrected_frame_addr > (AS(regs->stacks.pcsp_lo).base +
					    AS(regs->stacks.pcsp_hi).ind))
		return 0;

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

static int save_stack_address_user(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct stack_trace *trace = arg;
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
	struct save_stack_address_kernel_args args;

	args.trace = trace;
	args.regs = NULL;
	parse_chain_stack(false, NULL, save_stack_address_kernel, &args);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace);

void save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
{
	struct save_stack_address_kernel_args args;

	args.trace = trace;
	args.regs = regs;
	parse_chain_stack(false, NULL, save_stack_address_kernel, &args);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	struct save_stack_address_kernel_args args;

	args.trace = trace;
	args.regs = NULL;
	parse_chain_stack(false, tsk, save_stack_address_kernel, &args);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace_tsk);

void save_stack_trace_user(struct stack_trace *trace)
{
	parse_chain_stack(true, NULL, save_stack_address_user, trace);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

