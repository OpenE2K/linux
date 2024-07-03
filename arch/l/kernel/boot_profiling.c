/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/init.h>
#include <linux/smp.h>

#include <asm/boot_profiling.h>
#include <asm/atomic.h>
#include <asm/timex.h>
#include <asm/sections.h>
#include <asm/smp.h>

/* This assignment makes sure that this array is not put
 * into BSS segment and cleared by kernel while being in use.
 * This is also the reason to use '-1' for the 'top_event'
 * and '1' for 'boot_trace_enabled' initial values. */
struct boot_tracepoint boot_trace_events[BOOT_TRACE_ARRAY_SIZE] = {
	[0].cpuid = 1,
	[BOOT_TRACE_ARRAY_SIZE - 1].cpuid = 1
};
atomic_t boot_trace_top_event = ATOMIC_INIT(-1);

int boot_trace_enabled = 1;

__init_recv void notrace add_boot_trace_event(const char *fmt, ...)
{
	va_list ap;
	struct boot_tracepoint *event;
	long index;

	if (!boot_trace_enabled)
		return;

	index = atomic_inc_return(&boot_trace_top_event);
	if (unlikely(index >= BOOT_TRACE_ARRAY_SIZE)) {
		WARN_ONCE(1, "WARNING Overflow of boot tracepoints array! Disabling it...\n");
		atomic_set(&boot_trace_top_event, BOOT_TRACE_ARRAY_SIZE - 1);
		return;
	}

	event = &boot_trace_events[index];
	event->cpuid = hard_smp_processor_id();
	event->cycles = boot_trace_get_cycles();

	va_start(ap, fmt);
	vscnprintf(event->name, 81, fmt, ap);
	va_end(ap);
}

void stop_boot_trace()
{
	boot_trace_enabled = 0;
}

