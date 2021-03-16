/*
 * KVM guest processor and processes support
 *
 * Copyright (C) 2014 MCST
 */

#ifndef _E2K_PARAVIRT_PROCESSOR_H_
#define _E2K_PARAVIRT_PROCESSOR_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline int
pv_prepare_start_thread_frames(unsigned long entry, unsigned long sp)
{
	return pv_cpu_ops.prepare_start_thread_frames(entry, sp);
}

#define	pv_default_idle			(pv_cpu_ops.cpu_default_idle)
#define	pv_cpu_relax()			(pv_cpu_ops.cpu_relax())
#define	pv_cpu_relax_no_resched()	(pv_cpu_ops.cpu_relax_no_resched())

static inline void
pv_print_machine_type_info(void)
{
	pv_init_ops.print_machine_type_info();
}

static inline void
pv_paravirt_banner(void)
{
	if (pv_init_ops.banner)
		pv_init_ops.banner();
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* pure guest kernel (not paravirtualized based on pv_ops) */

static inline int
prepare_start_thread_frames(unsigned long entry, unsigned long sp)
{
	return pv_prepare_start_thread_frames(entry, sp);
}

#define	default_idle	pv_default_idle

static inline void cpu_relax(void)
{
	pv_cpu_relax();
}
static inline void cpu_relax_no_resched(void)
{
	pv_cpu_relax_no_resched();
}

static inline void print_machine_type_info(void)
{
	pv_print_machine_type_info();
}

static inline void paravirt_banner(void)
{
	pv_paravirt_banner();
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* ! __ASSEMBLY__ */
#endif /* _E2K_PARAVIRT_PROCESSOR_H_ */


