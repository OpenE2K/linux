/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM host <-> guest Linux-specific hypervisor handling.
 */

#pragma once

#include <linux/types.h>
#include <linux/errno.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/trap_def.h>
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/guest/cpu.h>
#include <asm/kvm/paravirt_sw/hypercall.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
#include <asm/kvm/proc_context_types.h>

#ifdef	CONFIG_KVM_GUEST_HW_HCALL
extern unsigned long light_hw_hypercall(unsigned long nr,
					unsigned long arg1, unsigned long arg2,
					unsigned long arg3, unsigned long arg4,
					unsigned long arg5, unsigned long arg6);
extern u64 generic_hw_hypercall(u64 nr, u64 arg1, u64 arg2, u64 arg3,
				u64 arg4, u64 arg5, u64 arg6, u64 arg7);
#endif /* CONFIG_KVM_GUEST_HW_HCALL */

static inline unsigned long light_hypercall(unsigned long nr,
					    unsigned long arg1,
					    unsigned long arg2,
					    unsigned long arg3,
					    unsigned long arg4,
					    unsigned long arg5,
					    unsigned long arg6)
{
	unsigned long ret;

#ifdef CONFIG_KVM_GUEST_HW_HCALL
# ifdef CONFIG_KVM_GUEST_KERNEL
	if (kvm_vcpu_host_support_hw_hc())
# endif /* CONFIG_KVM_GUEST_KERNEL */
		return light_hw_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6);
#endif /* CONFIG_KVM_GUEST_HW_HCALL */

	ret = E2K_SYSCALL(LIGHT_HYPERCALL_TRAPNUM, nr, 6,
			  arg1, arg2, arg3, arg4, arg5, arg6);

	return ret;
}

static inline unsigned long light_hypercall0(unsigned long nr)
{
	return light_hypercall(nr, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long light_hypercall1(unsigned long nr,
					     unsigned long arg1)
{
	return light_hypercall(nr, arg1, 0, 0, 0, 0, 0);
}

static inline unsigned long light_hypercall2(unsigned long nr,
					     unsigned long arg1,
					     unsigned long arg2)
{
	return light_hypercall(nr, arg1, arg2, 0, 0, 0, 0);
}

static inline unsigned long light_hypercall3(unsigned long nr,
					     unsigned long arg1,
					     unsigned long arg2,
					     unsigned long arg3)
{
	return light_hypercall(nr, arg1, arg2, arg3, 0, 0, 0);
}

static inline unsigned long light_hypercall4(unsigned long nr,
					     unsigned long arg1,
					     unsigned long arg2,
					     unsigned long arg3,
					     unsigned long arg4)
{
	return light_hypercall(nr, arg1, arg2, arg3, arg4, 0, 0);
}

static inline unsigned long light_hypercall5(unsigned long nr,
					     unsigned long arg1,
					     unsigned long arg2,
					     unsigned long arg3,
					     unsigned long arg4,
					     unsigned long arg5)
{
	return light_hypercall(nr, arg1, arg2, arg3, arg4, arg5, 0);
}

static inline unsigned long light_hypercall6(unsigned long nr,
					     unsigned long arg1,
					     unsigned long arg2,
					     unsigned long arg3,
					     unsigned long arg4,
					     unsigned long arg5,
					     unsigned long arg6)
{
	return light_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6);
}

static inline u64 generic_hypercall(u64 nr, u64 arg1, u64 arg2, u64 arg3,
				    u64 arg4, u64 arg5, u64 arg6, u64 arg7)
{
	unsigned long ret;

#ifdef CONFIG_KVM_GUEST_HW_HCALL
# ifdef CONFIG_KVM_GUEST_KERNEL
	if (kvm_vcpu_host_support_hw_hc())
# endif /* CONFIG_KVM_GUEST_KERNEL */
		return generic_hw_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
#endif /* CONFIG_KVM_GUEST_HW_HCALL */

	ret = E2K_SYSCALL(GENERIC_HYPERCALL_TRAPNUM, nr, 7,
			  arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	return ret;
}

static inline unsigned long generic_hypercall0(unsigned long nr)
{
	return generic_hypercall(nr, 0, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall1(unsigned long nr,
					       unsigned long arg1)
{
	return generic_hypercall(nr, arg1, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall2(unsigned long nr,
					       unsigned long arg1,
					       unsigned long arg2)
{
	return generic_hypercall(nr, arg1, arg2, 0, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall3(unsigned long nr,
					       unsigned long arg1,
					       unsigned long arg2,
					       unsigned long arg3)
{
	return generic_hypercall(nr, arg1, arg2, arg3, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall4(unsigned long nr,
					       unsigned long arg1,
					       unsigned long arg2,
					       unsigned long arg3,
					       unsigned long arg4)
{
	return generic_hypercall(nr, arg1, arg2, arg3, arg4, 0, 0, 0);
}

static inline unsigned long generic_hypercall5(unsigned long nr,
					       unsigned long arg1,
					       unsigned long arg2,
					       unsigned long arg3,
					       unsigned long arg4,
					       unsigned long arg5)
{
	return generic_hypercall(nr, arg1, arg2, arg3, arg4, arg5, 0, 0);
}

static inline unsigned long generic_hypercall6(unsigned long nr,
					       unsigned long arg1,
					       unsigned long arg2,
					       unsigned long arg3,
					       unsigned long arg4,
					       unsigned long arg5,
					       unsigned long arg6)
{
	return generic_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6, 0);
}

#ifndef CONFIG_KVM_PARAVIRTUALIZATION
enum {
	KVM_LIGHT_HCALLS_NUM
};
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

/*
 * KVM hypervisor (host) <-> guest generic hypercalls list
 */

#ifndef CONFIG_KVM_PARAVIRTUALIZATION
enum {
	/* Suspend current vcpu until it will be woken up by call to KVM_HCALL_PV_KICK */
	KVM_HCALL_PV_WAIT = 1,

	/* Wake up vcpu suspended by call to KVM_HCALL_PV_WAIT */
	KVM_HCALL_PV_KICK,

	/* Enable/disable L2 prefetcher on current vcpu */
	KVM_HCALL_L2_PREFETCHER_SAVE,
	KVM_HCALL_L2_PREFETCHER_RESTORE,

	KVM_HCALL_FTRACE_STOP = 122,

#ifdef CONFIG_KVM_ASYNC_PF
	/* Enable async pf on current vcpu */
	KVM_HCALL_PV_ENABLE_ASYNC_PF = 133,
#endif /* CONFIG_KVM_ASYNC_PF */

	KVM_GENERIC_HCALLS_NUM
};
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline void HYPERVISOR_pv_wait(void)
{
	generic_hypercall0(KVM_HCALL_PV_WAIT);
}

static inline int HYPERVISOR_pv_kick(int cpu)
{
	return generic_hypercall1(KVM_HCALL_PV_KICK, cpu);
}

/**
 * HYPERVISOR_l2_prefetcher_save - disable L2 prefetcher on current vcpu
 *
 * Returns previous status: 1=enabled, 0=disabled, <0 on error.
 */
static inline s64 HYPERVISOR_l2_prefetcher_save(void)
{
	return generic_hypercall1(KVM_HCALL_L2_PREFETCHER_SAVE, 0ull);
}

/**
 * HYPERVISOR_l2_prefetcher_restore - restore L2 prefetcher state on current vcpu
 */
static inline s64 HYPERVISOR_l2_prefetcher_restore(s64 state)
{
	if (!state)
		return 0;

	return generic_hypercall2(KVM_HCALL_L2_PREFETCHER_RESTORE, 0ull, state);
}

static inline void HYPERVISOR_ftrace_stop(void)
{
	generic_hypercall0(KVM_HCALL_FTRACE_STOP);
}

#ifdef CONFIG_KVM_ASYNC_PF
static inline int HYPERVISOR_pv_enable_async_pf(u64 apf_reason_gpa, u64 apf_id_gpa,
						u32 apf_ready_vector, u32 irq_controller)
{
	return generic_hypercall4(KVM_HCALL_PV_ENABLE_ASYNC_PF,
				  apf_reason_gpa, apf_id_gpa,
				  apf_ready_vector, irq_controller);
}
#endif /* CONFIG_KVM_ASYNC_PF */