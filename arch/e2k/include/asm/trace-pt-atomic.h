/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k_pt_atomic

#if !defined(_TRACE_PT_ATOMIC_E2K_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PT_ATOMIC_E2K_H

#include <linux/tracepoint.h>
#include <asm/pgatomic.h>

TRACE_EVENT(
	pt_atomic_update,
	TP_PROTO(void *mm, unsigned long addr,
		 pgprot_t *pgprot, pgprotval_t oldval,
		 pt_atomic_op_t atomic_op),
	TP_ARGS(mm, addr, pgprot, oldval, atomic_op),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(void *, mm)
		__field(pgprot_t *, pgprot)
		__field(pgprotval_t, oldval)
		__field(pgprotval_t, newval)
		__field(unsigned long, addr)
		__field(pt_atomic_op_t, atomic_op)
		),

	TP_fast_assign(
		__entry->cpu = smp_processor_id();
		__entry->mm = mm;
		__entry->pgprot = pgprot;
		__entry->oldval = oldval;
		__entry->newval = pgprot_val(*pgprot),
		__entry->addr = addr,
		__entry->atomic_op = atomic_op;
		),

	TP_printk("cpu #%d mm %px addr %px\n"
		"         atomic %s pte at %px %016lx : %016lx",
		__entry->cpu, __entry->mm, (void *)__entry->addr,
		__print_symbolic(__entry->atomic_op, PTE_ATOMIC_OP_NAME),
		__entry->pgprot, __entry->oldval, __entry->newval)
);


#endif /* _TRACE_PT_ATOMIC_E2K_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace-pt-atomic
#include <trace/define_trace.h>
