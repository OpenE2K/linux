/*
 * KVM guest processor and processes support
 *
 * Copyright (C) 2014 MCST
 */

#ifndef _E2K_KVM_GUEST_PROCESSOR_H_
#define _E2K_KVM_GUEST_PROCESSOR_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/ptrace.h>

extern int kvm_prepare_start_thread_frames(unsigned long entry,
						unsigned long sp);

extern void kvm_default_idle(void);
extern void kvm_cpu_relax(void);
extern void kvm_cpu_relax_no_resched(void);

/* defined at kernel/sched.c */
extern void wake_up_idle_vcpu(int cpu);

extern void kvm_print_machine_type_info(void);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* pure guest kernel (not paravirtualized based on pv_ops) */

#define paravirt_enabled()	true
#define	boot_paravirt_enabled()	paravirt_enabled()

static inline int
prepare_start_thread_frames(unsigned long entry, unsigned long sp)
{
	if (likely(IS_HV_GM())) {
		return native_do_prepare_start_thread_frames(entry, sp);
	} else {
		return kvm_prepare_start_thread_frames(entry, sp);
	}
}

#define default_idle()		kvm_default_idle()
#define	cpu_relax()		kvm_cpu_relax()
#define	cpu_relax_no_resched()	kvm_cpu_relax_no_resched()

static inline void
print_machine_type_info(void)
{
	kvm_print_machine_type_info();
}
static inline void
paravirt_banner(void)
{
	printk(KERN_INFO "Booting pure guest kernel (not paravirtualized "
		"based on pv_ops)\n");
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* ! __ASSEMBLY__ */
#endif /* _E2K_KVM_GUEST_PROCESSOR_H_ */


