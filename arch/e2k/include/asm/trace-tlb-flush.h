#if !defined(_ASM_E2K_TRACE_TLB_FLUSH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _ASM_E2K_TRACE_TLB_FLUSH_H

#include <linux/types.h>
#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM tlb

TRACE_EVENT(
	mmu_pid_flush_tlb_all,

	TP_PROTO(int cpu_id),

	TP_ARGS(cpu_id),

	TP_STRUCT__entry(
		__field(int, cpu_id)
	),

	TP_fast_assign(
		__entry->cpu_id = cpu_id;
	),

	TP_printk("cpu #%d flush TLB all", __entry->cpu_id)
);

TRACE_EVENT(
	mmu_pid_flush_tlb_mm,

	TP_PROTO(int cpu_id, mm_context_t *context, bool is_active,
		 unsigned long old_pid, unsigned long new_pid
	),

	TP_ARGS(cpu_id, context, is_active, old_pid, new_pid),

	TP_STRUCT__entry(
		__field(int, cpu_id)
		__field(mm_context_t *, context)
		__field(bool, is_active)
		__field(unsigned long, old_pid)
		__field(unsigned long, new_pid)
	),

	TP_fast_assign(
		__entry->cpu_id = cpu_id;
		__entry->context = context;
		__entry->is_active = is_active;
		__entry->old_pid = old_pid;
		__entry->new_pid = new_pid;
	),

	TP_printk("cpu #%d mm flushed pid 0x%lx %s 0x%lx",
		__entry->cpu_id,
		__entry->old_pid, (__entry->is_active) ? "updated to" : "zeroed",
		__entry->new_pid
	)
);

TRACE_EVENT(
	mmu_pid_flush_tlb_page,

	TP_PROTO(int cpu_id, mm_context_t *context, e2k_addr_t addr,
		 unsigned long old_pid, unsigned long new_pid
	),

	TP_ARGS(cpu_id, context, addr, old_pid, new_pid),

	TP_STRUCT__entry(
		__field(int, cpu_id)
		__field(mm_context_t *, context)
		__field(e2k_addr_t, addr)
		__field(unsigned long, old_pid)
		__field(unsigned long, new_pid)
	),

	TP_fast_assign(
		__entry->cpu_id = cpu_id;
		__entry->context = context;
		__entry->addr = addr;
		__entry->old_pid = old_pid;
		__entry->new_pid = new_pid;
	),

	TP_printk("cpu #%d flushed addr %px and %s 0x%lx",
		__entry->cpu_id, (void *)__entry->addr,
		(__entry->old_pid == 0) ? "created new pid" : "pid former",
		__entry->new_pid
	)
);

TRACE_EVENT(
	mmu_pid_flush_tlb_range,

	TP_PROTO(int cpu_id, mm_context_t *context,
		 e2k_addr_t start, e2k_addr_t end,
		 unsigned long old_pid, unsigned long new_pid
	),

	TP_ARGS(cpu_id, context, start, end, old_pid, new_pid),

	TP_STRUCT__entry(
		__field(int, cpu_id)
		__field(mm_context_t *, context)
		__field(e2k_addr_t, start)
		__field(e2k_addr_t, end)
		__field(unsigned long, old_pid)
		__field(unsigned long, new_pid)
	),

	TP_fast_assign(
		__entry->cpu_id = cpu_id;
		__entry->context = context;
		__entry->start = start;
		__entry->end = end;
		__entry->old_pid = old_pid;
		__entry->new_pid = new_pid;
	),

	TP_printk("cpu #%d flushed %s from %px to %px and %s 0x%lx",
		__entry->cpu_id,
		(__entry->old_pid != __entry->new_pid) ?
			"all mm instead of range " : "only range",
		(void *)__entry->start, (void *)__entry->end,
		(__entry->old_pid != __entry->new_pid) ?
			"created new pid" : "pid former",
		__entry->new_pid
	)
);

TRACE_EVENT(
	va_tlb_state,

	TP_PROTO(e2k_addr_t address),

	TP_ARGS(address),

	TP_STRUCT__entry(
		__field(	e2k_addr_t,		address		)
		__field_struct(	tlb_line_state_t,	line		)
		__field_struct(	tlb_line_state_t,	huge_line	)
		__field(	u64,			dtlb_entry	)
		__field(	unsigned long,		mmu_pptb	)
		__field(	unsigned long,		mmu_pid		)
	),

	TP_fast_assign(
		__entry->address = address;
		get_va_tlb_state(&__entry->line, address, false);
		get_va_tlb_state(&__entry->huge_line, address, true);
		__entry->dtlb_entry = get_MMU_DTLB_ENTRY(address);
		__entry->mmu_pptb = NATIVE_READ_MMU_U_PPTB_REG();
		__entry->mmu_pid = NATIVE_READ_MMU_PID_REG();
	),

	TP_printk("   0x%016lx : dtlb 0x%016llx U_PPTB 0x%lx PID 0x%lx\n"
		"                        TLB set #0 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #1 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #2 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #3 tag 0x%016lx entry 0x%016lx\n"
		"                huge    TLB set #2 tag 0x%016lx entry 0x%016lx\n"
		"                huge    TLB set #3 tag 0x%016lx entry 0x%016lx",
		__entry->address, __entry->dtlb_entry,
		__entry->mmu_pptb, __entry->mmu_pid,
		__entry->line.sets[0].tlb_tag,
		pte_val(__entry->line.sets[0].tlb_entry),
		__entry->line.sets[1].tlb_tag,
		pte_val(__entry->line.sets[1].tlb_entry),
		__entry->line.sets[2].tlb_tag,
		pte_val(__entry->line.sets[2].tlb_entry),
		__entry->line.sets[3].tlb_tag,
		pte_val(__entry->line.sets[3].tlb_entry),
		__entry->huge_line.sets[2].tlb_tag,
		pte_val(__entry->huge_line.sets[2].tlb_entry),
		__entry->huge_line.sets[3].tlb_tag,
		pte_val(__entry->huge_line.sets[3].tlb_entry)
	)
);

#endif /* _ASM_E2K_TRACE_TLB_FLUSH_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../arch/e2k/include/asm
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-tlb-flush

/* This part must be outside protection */
#include <trace/define_trace.h>
