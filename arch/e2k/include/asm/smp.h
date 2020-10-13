#ifndef __ASM_SMP_H
#define __ASM_SMP_H

/*
 * We need the APIC definitions automatically as part of 'smp.h'
 */
#ifndef ASSEMBLY
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/nodemask.h>
#endif

#ifdef CONFIG_L_LOCAL_APIC
#ifndef ASSEMBLY
#include <asm/apicdef.h>
#include <asm/bitops.h>
#include <asm/mpspec.h>
#include <asm/e3m.h>
#include <asm/e3s.h>
#include <asm/es2.h>
#include <asm/e2s.h>
#ifdef CONFIG_L_IO_APIC
#include <asm/io_apic.h>
#endif
#include <asm/apic.h>
#endif /* !ASSEMBLY */
#endif /* CONFIG_L_LOCAL_APIC */

#ifdef CONFIG_SMP
#ifndef ASSEMBLY

typedef struct tlb_page {
	struct vm_area_struct	*vma;
	e2k_addr_t		addr;
} tlb_page_t;

typedef struct tlb_range {
	struct mm_struct	*mm;
	e2k_addr_t		start;
	e2k_addr_t		end;
} tlb_range_t;

typedef struct icache_page {
	struct vm_area_struct	*vma;
	struct page		*page;
} icache_page_t;

struct call_data_struct {
	void (*func) (void *info);
	void *info;
	atomic_t started;
	atomic_t finished;
	int wait;
};

/*
 * Private routines/data
 */
 
extern void smp_alloc_memory(void);
extern atomic_t	cpu_present_num;

#ifdef	CONFIG_RECOVERY
extern unsigned int	max_cpus_to_recover;
#endif	/* CONFIG_RECOVERY */

extern struct task_struct *copy_process(unsigned long clone_flags,
					unsigned long stack_start,
					unsigned long stack_size,
					int __user *child_tidptr,
					struct pid *pid,
					int trace);

extern volatile unsigned long smp_invalidate_needed;
extern int pic_mode;
extern int __init e2k_start_secondary(int cpuid);
extern int e2k_up_secondary(int cpuid);
extern void smp_flush_tlb(void);
extern void smp_message_irq(int cpl, void *dev_id, struct pt_regs *regs);
extern void smp_send_reschedule(int cpu);
extern void smp_invalidate_rcv(void);		/* Process an NMI */
extern void (*mtrr_hook) (void);
extern void zap_low_mappings (void);
extern void arch_send_call_function_single_ipi(int cpu);
extern void arch_send_call_function_ipi_mask(const struct cpumask *mask);
extern void smp_flush_icache_kernel_line(e2k_addr_t addr);
extern void smp_flush_tlb_all(void);

#ifdef	CONFIG_RECOVERY
extern int cpu_recover(unsigned int cpu);
extern void smp_prepare_boot_cpu_to_recover(void);
extern void smp_prepare_cpus_to_recover(unsigned int max_cpus);
extern void smp_cpus_recovery_done(unsigned int max_cpus);
#endif	/* CONFIG_RECOVERY */

extern void smp_send_refresh(void);

/*
 * General functions that each host system must provide.
 */
 
extern void smp_store_cpu_info(int id);	/* Store per CPU info */
					/* like the initial udelay numbers */

#ifndef CONFIG_E2S_CPU_RF_BUG
/*
 * This function is needed by all SMP systems. It must _always_ be valid
 * from the initial startup.
 */
register unsigned long long __cpu_reg __asm__ ("%g19");
# define raw_smp_processor_id() ((unsigned int) __cpu_reg)
#else
# define raw_smp_processor_id() (current_thread_info()->cpu)
#endif

#endif /* !ASSEMBLY */

#define NO_PROC_ID	0xFF		/* No processor magic marker */

/*
 *	This magic constant controls our willingness to transfer
 *	a process across CPUs. Such a transfer incurs misses on the L1
 *	cache, and on a P6 or P5 with multiple L2 caches L2 hits. My
 *	gut feeling is this will vary by board in value. For a board
 *	with separate L2 cache it probably depends also on the RSS, and
 *	for a board with shared L2 cache it ought to decay fast as other
 *	processes are run.
 */
 
#define PROC_CHANGE_PENALTY	15		/* Schedule penalty */

#endif	/* CONFIG_SMP */

#ifndef	ASSEMBLY

extern int hard_smp_processor_id();

static __inline int logical_smp_processor_id(void)
{
	return GET_APIC_LOGICAL_ID(arch_apic_read(APIC_LDR));
}

#define cpu_physical_id(cpu)			boot_cpu_physical_apicid
#endif /* ! ASSEMBLY */

#ifdef	CONFIG_HOTPLUG_CPU
/* Upping and downing of CPUs */
extern int __cpu_disable (void);
extern void __cpu_die (unsigned int cpu);
#endif  /* CONFIG_HOTPLUG_CPU */

#endif	/* __ASM_SMP_H */
