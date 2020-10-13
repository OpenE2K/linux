/* linux/arch/e2k/lib/boot_profiling.c.
 *
 * Copyright (C) 2011 MCST
 */

#include <linux/init.h>
#include <linux/smp.h>

#include <asm/boot_profiling.h>
#include <asm/atomic.h>
#include <asm/timex.h>
#include <asm/sections.h>

/* This assignment makes sure that this array is not put
 * into BSS segment and cleared by kernel while being in use.
 * This is also the reason to use '-1' for the 'top_event'
 * and '1' for 'boot_trace_enabled' initial values. */
struct boot_tracepoint boot_trace_events[BOOT_TRACE_ARRAY_SIZE] = {
	[0].cpu = 1,
	[BOOT_TRACE_ARRAY_SIZE - 1].cpu = 1
};
atomic_t boot_trace_top_event = ATOMIC_INIT(-1);

int boot_trace_enabled = 1;


#if NR_CPUS > 64
# error please initialize boot_trace_cpu_events_list[] for other cpus...
#endif

#if NR_CPUS > 48
# define BOOT_TRACE_LIST_SIZE NR_CPUS
#elif NR_CPUS > 32
# define BOOT_TRACE_LIST_SIZE 48
#elif NR_CPUS > 16
# define BOOT_TRACE_LIST_SIZE 32
#elif NR_CPUS > 4
# define BOOT_TRACE_LIST_SIZE 16
#elif NR_CPUS > 1
# define BOOT_TRACE_LIST_SIZE 4
#else
# define BOOT_TRACE_LIST_SIZE 1
#endif
struct list_head boot_trace_cpu_events_list[BOOT_TRACE_LIST_SIZE] = {
	[0]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[0]),
#if NR_CPUS > 1
	[1]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[1]),
	[2]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[2]),
	[3]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[3]),
#if NR_CPUS > 4
	[4]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[4]),
	[5]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[5]),
	[6]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[6]),
	[7]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[7]),
	[8]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[8]),
	[9]  = LIST_HEAD_INIT(boot_trace_cpu_events_list[9]),
	[10] = LIST_HEAD_INIT(boot_trace_cpu_events_list[10]),
	[11] = LIST_HEAD_INIT(boot_trace_cpu_events_list[11]),
	[12] = LIST_HEAD_INIT(boot_trace_cpu_events_list[12]),
	[13] = LIST_HEAD_INIT(boot_trace_cpu_events_list[13]),
	[14] = LIST_HEAD_INIT(boot_trace_cpu_events_list[14]),
	[15] = LIST_HEAD_INIT(boot_trace_cpu_events_list[15]),
#if NR_CPUS > 16
	[16] = LIST_HEAD_INIT(boot_trace_cpu_events_list[16]),
	[17] = LIST_HEAD_INIT(boot_trace_cpu_events_list[17]),
	[18] = LIST_HEAD_INIT(boot_trace_cpu_events_list[18]),
	[19] = LIST_HEAD_INIT(boot_trace_cpu_events_list[19]),
	[20] = LIST_HEAD_INIT(boot_trace_cpu_events_list[20]),
	[21] = LIST_HEAD_INIT(boot_trace_cpu_events_list[21]),
	[22] = LIST_HEAD_INIT(boot_trace_cpu_events_list[22]),
	[23] = LIST_HEAD_INIT(boot_trace_cpu_events_list[23]),
	[24] = LIST_HEAD_INIT(boot_trace_cpu_events_list[24]),
	[25] = LIST_HEAD_INIT(boot_trace_cpu_events_list[25]),
	[26] = LIST_HEAD_INIT(boot_trace_cpu_events_list[26]),
	[27] = LIST_HEAD_INIT(boot_trace_cpu_events_list[27]),
	[28] = LIST_HEAD_INIT(boot_trace_cpu_events_list[28]),
	[29] = LIST_HEAD_INIT(boot_trace_cpu_events_list[29]),
	[30] = LIST_HEAD_INIT(boot_trace_cpu_events_list[30]),
	[31] = LIST_HEAD_INIT(boot_trace_cpu_events_list[31]),
#if NR_CPUS > 32
	[32] = LIST_HEAD_INIT(boot_trace_cpu_events_list[32]),
	[33] = LIST_HEAD_INIT(boot_trace_cpu_events_list[33]),
	[34] = LIST_HEAD_INIT(boot_trace_cpu_events_list[34]),
	[35] = LIST_HEAD_INIT(boot_trace_cpu_events_list[35]),
	[36] = LIST_HEAD_INIT(boot_trace_cpu_events_list[36]),
	[37] = LIST_HEAD_INIT(boot_trace_cpu_events_list[37]),
	[38] = LIST_HEAD_INIT(boot_trace_cpu_events_list[38]),
	[39] = LIST_HEAD_INIT(boot_trace_cpu_events_list[39]),
	[40] = LIST_HEAD_INIT(boot_trace_cpu_events_list[40]),
	[41] = LIST_HEAD_INIT(boot_trace_cpu_events_list[41]),
	[42] = LIST_HEAD_INIT(boot_trace_cpu_events_list[42]),
	[43] = LIST_HEAD_INIT(boot_trace_cpu_events_list[43]),
	[44] = LIST_HEAD_INIT(boot_trace_cpu_events_list[44]),
	[45] = LIST_HEAD_INIT(boot_trace_cpu_events_list[45]),
	[46] = LIST_HEAD_INIT(boot_trace_cpu_events_list[46]),
	[47] = LIST_HEAD_INIT(boot_trace_cpu_events_list[47]),
#if NR_CPUS > 48
	[48] = LIST_HEAD_INIT(boot_trace_cpu_events_list[48]),
	[49] = LIST_HEAD_INIT(boot_trace_cpu_events_list[49]),
	[50] = LIST_HEAD_INIT(boot_trace_cpu_events_list[50]),
	[51] = LIST_HEAD_INIT(boot_trace_cpu_events_list[51]),
	[52] = LIST_HEAD_INIT(boot_trace_cpu_events_list[52]),
	[53] = LIST_HEAD_INIT(boot_trace_cpu_events_list[53]),
	[54] = LIST_HEAD_INIT(boot_trace_cpu_events_list[54]),
	[55] = LIST_HEAD_INIT(boot_trace_cpu_events_list[55]),
	[56] = LIST_HEAD_INIT(boot_trace_cpu_events_list[56]),
	[57] = LIST_HEAD_INIT(boot_trace_cpu_events_list[57]),
	[58] = LIST_HEAD_INIT(boot_trace_cpu_events_list[58]),
	[59] = LIST_HEAD_INIT(boot_trace_cpu_events_list[59]),
	[60] = LIST_HEAD_INIT(boot_trace_cpu_events_list[60]),
	[61] = LIST_HEAD_INIT(boot_trace_cpu_events_list[61]),
	[62] = LIST_HEAD_INIT(boot_trace_cpu_events_list[62]),
	[63] = LIST_HEAD_INIT(boot_trace_cpu_events_list[63]),
#endif	/* NR_CPUS > 48 */
#endif	/* NR_CPUS > 32 */
#endif	/* NR_CPUS > 16 */
#endif	/* NR_CPUS > 4 */
#endif	/* NR_CPUS > 1 */
};


__init_recv
void notrace add_boot_trace_event(const char *fmt, ...)
{
	va_list ap;
	struct boot_tracepoint *event;
	unsigned long flags;
	long index;
	unsigned int cpu;

	if (!boot_trace_enabled)
		return;

	index = atomic_inc_return(&boot_trace_top_event);
	if (unlikely(index >= BOOT_TRACE_ARRAY_SIZE)) {
		WARN_ONCE(1, "WARNING Overflow of boot tracepoints array! "
				"Disabling it...\n");
		atomic_set(&boot_trace_top_event, BOOT_TRACE_ARRAY_SIZE - 1);
		return;
	}

	event = &boot_trace_events[index];
	va_start(ap, fmt);
	vscnprintf(event->name, 81, fmt, ap);
	va_end(ap);

	raw_local_irq_save(flags);
	cpu = raw_smp_processor_id();

	event->cpu = cpu;
	list_add_tail(&event->list, &boot_trace_cpu_events_list[cpu]);

	event->cycles = boot_trace_get_cycles();
	raw_local_irq_restore(flags);
}

struct boot_tracepoint *boot_trace_prev_event(int cpu,
		struct boot_tracepoint *event)
{
	struct boot_tracepoint *prev;
	
	prev = list_entry(event->list.prev, struct boot_tracepoint, list);

	if (&prev->list == &boot_trace_cpu_events_list[cpu])
		return NULL;
	else
		return prev;
}

struct boot_tracepoint *boot_trace_next_event(int cpu,
		struct boot_tracepoint *event)
{
	struct boot_tracepoint *next;

	if (cpu >= NR_CPUS) {
		WARN_ON(1);
		return NULL;
	}

	next = list_entry(event->list.next, struct boot_tracepoint, list);

	if (&next->list == &boot_trace_cpu_events_list[cpu])
		return NULL;
	else
		return next;
}

void stop_boot_trace()
{
	boot_trace_enabled = 0;
}

