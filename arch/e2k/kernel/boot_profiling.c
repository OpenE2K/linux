/* linux/arch/e2k/lib/boot_profiling.c.
 *
 * Copyright (C) 2011 MCST
 */

#include <linux/init.h>

#include <asm/atomic.h>
#include <asm/boot_head.h>
#include <asm/boot_smp.h>
#include <asm/timex.h>
#include <asm/boot_profiling.h>


#define BL(list) ((struct list_head *) boot_vp_to_pp(list))

#ifdef CONFIG_RECOVERY
/* Makes sure events lists are cleared before saving a control point. */
void reinitialize_boot_trace_data(void)
{
	int i;

	for (i = 0; i < NR_CPUS; i++) {
		BL(&boot_trace_cpu_events_list[i])->next =
				&boot_trace_cpu_events_list[i];
		BL(&boot_trace_cpu_events_list[i])->prev =
				&boot_trace_cpu_events_list[i];
	}
	atomic_set((atomic_t *) boot_vp_to_pp(&boot_trace_top_event), -1);
	boot_get_vo_value(boot_trace_enabled) = 1;
}
#endif


__init_recv
void notrace boot_add_boot_trace_event(char *name)
{
	struct boot_tracepoint *event;
	static int overflow = 0;
	unsigned int cpu;
	long index;

	if (*(int *) boot_vp_to_pp(&boot_trace_enabled) == 0)
		return;

	index = atomic_inc_return(
			(atomic_t *) boot_vp_to_pp(&boot_trace_top_event));
	if (unlikely(index >= BOOT_TRACE_ARRAY_SIZE)) {
		if (*(int *) boot_vp_to_pp(&overflow) == 0) {
			*(int *) boot_vp_to_pp(&overflow) = 1;
			pr_warning("WARNING Overflow of boot tracepoints array!"
					" Disabling it...\n");
		}
		atomic_set((atomic_t *) boot_vp_to_pp(&boot_trace_top_event),
				BOOT_TRACE_ARRAY_SIZE - 1);
		return;
	}

	event = (struct boot_tracepoint *)
			boot_vp_to_pp(&boot_trace_events[index]);
	strcpy(event->name, (char *) boot_vp_to_pp(name));

#ifdef CONFIG_SMP
	cpu = READ_APIC_ID();
	if ((unsigned) cpu >= NR_CPUS)
		cpu = 0;
#else
	cpu = 0;
#endif

	event->cpu = cpu;

	BL(BL(&boot_trace_cpu_events_list[cpu])->prev)->next =
			&boot_trace_events[index].list;
	event->list.next = &boot_trace_cpu_events_list[cpu];
	event->list.prev = BL(&boot_trace_cpu_events_list[cpu])->prev;
	BL(&boot_trace_cpu_events_list[cpu])->prev =
			&boot_trace_events[index].list;

	event->cycles = get_cycles();
}
