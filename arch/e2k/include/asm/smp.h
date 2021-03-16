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
#include <asm/epicdef.h>
#include <asm/bitops.h>
#include <asm/mpspec.h>
#include <asm/glob_regs.h>
#include <asm/es2.h>
#include <asm/e2s.h>
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

extern atomic_t	cpu_present_num;
extern unsigned long smp_invalidate_needed;
extern int pic_mode;
extern cpumask_t callin_go;

extern void smp_alloc_memory(void);
extern void e2k_start_secondary(int cpuid);
extern void start_secondary_resume(int cpuid, int cpu);
extern void wait_for_startup(int cpuid, int hotplug);
extern void smp_flush_tlb(void);
extern void smp_message_irq(int cpl, void *dev_id, struct pt_regs *regs);
extern void smp_send_reschedule(int cpu);
extern void smp_invalidate_rcv(void);		/* Process an NMI */
extern void (*mtrr_hook) (void);
extern void zap_low_mappings (void);
extern void arch_send_call_function_single_ipi(int cpu);
extern void arch_send_call_function_ipi_mask(const struct cpumask *mask);
extern void smp_send_refresh(void);

#ifdef	CONFIG_DATA_BREAKPOINT
typedef struct hw_data_bp {
	void	*address;
	int	size;
	bool	write;
	bool	read;
	bool	stop;
	int	cp_num;
} hw_data_bp_t;
extern atomic_t hw_data_breakpoint_num;
#define	DATA_BREAKPOINT_ON	(atomic_read(&hw_data_breakpoint_num) >= 0)

extern void smp_set_data_breakpoint(void *address, u64 size,
			bool write, bool read, bool stop, const int cp_num);
extern int smp_reset_data_breakpoint(void *address);
#else	/* ! CONFIG_DATA_BREAKPOINT */
#define	DATA_BREAKPOINT_ON	false
#endif	/* CONFIG_DATA_BREAKPOINT */

extern void native_wait_for_cpu_booting(void);
extern void native_wait_for_cpu_wake_up(void);
extern int native_activate_cpu(int vcpu_id);
extern int native_activate_all_cpus(void);

#ifdef CONFIG_RECOVERY
extern int cpu_recover(unsigned int cpu);
extern void smp_prepare_boot_cpu_to_recover(void);
extern void smp_prepare_cpus_to_recover(unsigned int max_cpus);
extern void smp_cpus_recovery_done(unsigned int max_cpus);
#endif  /* CONFIG_RECOVERY */

/*
 * General functions that each host system must provide.
 */
 
/*
 * This function is needed by all SMP systems. It must _always_ be valid
 * from the initial startup.
 */
register unsigned long long __cpu_reg DO_ASM_GET_GREG_MEMONIC(
							SMP_CPU_ID_GREG);
#define raw_smp_processor_id() ((unsigned int) __cpu_reg)

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

#else	/* ! CONFIG_SMP */
static inline void e2k_start_secondary(int cpuid) { }

#define	native_wait_for_cpu_booting()
#define	native_wait_for_cpu_wake_up()
#define	native_activate_cpu(vcpu_id)	0
#define	native_activate_all_cpus(void)	0

#define	DATA_BREAKPOINT_ON	false

#endif	/* CONFIG_SMP */

#ifndef	ASSEMBLY

extern int hard_smp_processor_id(void);

#endif /* ! ASSEMBLY */

#ifdef	CONFIG_HOTPLUG_CPU
/* Upping and downing of CPUs */
extern int __cpu_disable (void);
extern void __cpu_die (unsigned int cpu);
#endif	/* CONFIG_HOTPLUG_CPU */

/* this description from include/linux/smp.h */
/* do not forgot update here, if will be updated there */
enum {
	CSD_FLAG_LOCK		= 0x01,
	CSD_FLAG_SYNCHRONOUS	= 0x02,
	CSD_FLAG_LOCK_ASYNC	= 0x10,
};

#if defined(CONFIG_VIRTUALIZATION)
#include <linux/smp.h>

extern void native_csd_lock_wait(call_single_data_t *csd);
extern void native_csd_lock(call_single_data_t *csd);
extern void native_arch_csd_lock_async(call_single_data_t *csd);
extern void native_csd_unlock(call_single_data_t *csd);
#endif	/* CONFIG_VIRTUALIZATION */

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/smp.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/smp.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or native kernel with virtualization support */
static inline void
wait_for_cpu_booting(void)
{
	native_wait_for_cpu_booting();
}
static inline void
wait_for_cpu_wake_up(void)
{
	native_wait_for_cpu_wake_up();
}
static inline int
activate_cpu(int cpu_id)
{
	return native_activate_cpu(cpu_id);
}
static inline int
activate_all_cpus(void)
{
	return native_activate_all_cpus();
}

#if defined(CONFIG_VIRTUALIZATION)
static inline void csd_lock_wait(call_single_data_t *data)
{
	native_csd_lock_wait(data);
}
static inline void csd_lock(call_single_data_t *data)
{
	native_csd_lock(data);
}
static inline void arch_csd_lock_async(call_single_data_t *csd)
{
	native_arch_csd_lock_async(csd);
}
static inline void csd_unlock(call_single_data_t *data)
{
	native_csd_unlock(data);
}
#endif	/* CONFIG_VIRTUALIZATION */

static inline void
setup_local_pic_virq(unsigned int cpu)
{
	/* native and host kernel does not use virtual IRQs */
	/* and its handlers */
}
static inline void
startup_local_pic_virq(unsigned int cpuid)
{
	/* native and host kernel does not use virtual IRQs */
	/* and its handlers */
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __ASM_SMP_H */
