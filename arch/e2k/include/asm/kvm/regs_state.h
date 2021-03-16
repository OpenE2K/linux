#ifndef _E2K_KVM_REGS_STATE_H
#define _E2K_KVM_REGS_STATE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/irqflags.h>
#include <linux/kvm_host.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs_access.h>
#include <asm/mmu.h>
#include <asm/mmu_regs.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm/tags.h>
#endif /* __ASSEMBLY__ */

#ifdef	CONFIG_VIRTUALIZATION

#undef	DEBUG_GREGS_MODE
#undef	DebugGREGS
#define	DEBUG_GREGS_MODE	0	/* global registers save/restore */
#define	DebugGREGS(fmt, args...)					\
({									\
	if (DEBUG_GREGS_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define	DO_SAVE_GUEST_GREGS_EXCEPT_KERNEL_V2(gregs)			\
		DO_SAVE_GREGS_ON_MASK(gregs, E2K_ISET_V2, GUEST_GREGS_MASK)
#define	DO_SAVE_GUEST_GREGS_EXCEPT_KERNEL_V5(gregs)			\
		DO_SAVE_GREGS_ON_MASK(gregs, E2K_ISET_V5, GUEST_GREGS_MASK)

#define	DO_SAVE_GREGS_EXCEPT_HOST_V2(gregs)			\
		DO_SAVE_GREGS_ON_MASK(gregs, E2K_ISET_V2, GUEST_GREGS_MASK)
#define	DO_SAVE_GREGS_EXCEPT_HOST_V5(gregs)			\
		DO_SAVE_GREGS_ON_MASK(gregs, E2K_ISET_V5, GUEST_GREGS_MASK)

#define	DO_SAVE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V2(gregs)		\
		DO_SAVE_GREGS_ON_MASK(gregs, E2K_ISET_V2,		\
			GLOBAL_GREGS_USER_MASK | GUEST_GREGS_MASK)
#define	DO_SAVE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V5(gregs)		\
		DO_SAVE_GREGS_ON_MASK(gregs, E2K_ISET_V5,		\
			GLOBAL_GREGS_USER_MASK | GUEST_GREGS_MASK)

#define	DO_RESTORE_GUEST_GREGS_EXCEPT_KERNEL_V2(gregs)			\
		DO_RESTORE_GREGS_ON_MASK(gregs, E2K_ISET_V2, GUEST_GREGS_MASK)
#define	DO_RESTORE_GUEST_GREGS_EXCEPT_KERNEL_V5(gregs)			\
		DO_RESTORE_GREGS_ON_MASK(gregs, E2K_ISET_V5, GUEST_GREGS_MASK)

#define	DO_RESTORE_GREGS_EXCEPT_HOST_V2(gregs)				\
		DO_RESTORE_GREGS_ON_MASK(gregs, E2K_ISET_V2, GUEST_GREGS_MASK)
#define	DO_RESTORE_GREGS_EXCEPT_HOST_V5(gregs)				\
		DO_RESTORE_GREGS_ON_MASK(gregs, E2K_ISET_V5, GUEST_GREGS_MASK)

#define	DO_RESTORE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V2(gregs)		\
		DO_RESTORE_GREGS_ON_MASK(gregs, E2K_ISET_V2,		\
			GLOBAL_GREGS_USER_MASK | GUEST_GREGS_MASK)
#define	DO_RESTORE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V5(gregs)		\
		DO_RESTORE_GREGS_ON_MASK(gregs, E2K_ISET_V5,		\
			GLOBAL_GREGS_USER_MASK | GUEST_GREGS_MASK)

#ifndef	CONFIG_E2K_ISET_VER
#define	SAVE_GUEST_GREGS_EXCEPT_KERNEL(gregs)				\
		(machine.host.save_guest_gregs(gregs))
#define	RESTORE_GUEST_GREGS_EXCEPT_KERNEL(gregs)			\
		(machine.host.restore_guest_gregs(gregs))
#elif	CONFIG_E2K_ISET_VER < 5
#define	SAVE_GUEST_GREGS_EXCEPT_KERNEL(gregs)				\
		DO_SAVE_GUEST_GREGS_EXCEPT_KERNEL_V2((gregs)->g)
#define	RESTORE_GUEST_GREGS_EXCEPT_KERNEL(gregs)			\
		DO_RESTORE_GUEST_GREGS_EXCEPT_KERNEL_V2((gregs)->g)
#else	/* CONFIG_E2K_ISET_VER >= 5 */
#define	SAVE_GUEST_GREGS_EXCEPT_KERNEL(gregs)				\
		DO_SAVE_GUEST_GREGS_EXCEPT_KERNEL_V5((gregs)->g)
#define	RESTORE_GUEST_GREGS_EXCEPT_KERNEL(gregs)			\
		DO_RESTORE_GUEST_GREGS_EXCEPT_KERNEL_V5((gregs)->g)
#endif	/* CONFIG_E2K_ISET_VER */

#define	SET_GUEST_USER_GREG(gregs, gr_no, gr_main, gr_ext)		\
({									\
	global_regs_t *greg_to = (gregs);				\
									\
	greg_to->g[(gr_no)].base = (gr_main);				\
	greg_to->g[(gr_no)].ext = (gr_ext);				\
})
#define	COPY_GUEST_USER_GREG_ON_MASK(gr_from, gr_to, gr_mask)		\
({									\
	global_regs_t *greg_from = (gr_from);				\
	global_regs_t *greg_to = (gr_to);				\
	unsigned long cur_mask = (gr_mask);				\
	int gr_no = 0;							\
									\
	while (cur_mask) {						\
		if (cur_mask & 0x3UL) {					\
			SAVE_GUEST_USER_GREG_PAIR(			\
				greg_from->g, gr_no, greg_to->g, gr_no); \
		}							\
		gr_no += 2;						\
		cur_mask >>= 2;						\
	}								\
})
#define	SAVE_GUEST_USER_GREG_PAIR(__ti_gregs, ti_gr_no,			\
					__gti_gregs, gti_gr_no)		\
({									\
	NATIVE_MOVE_TAGGED_QWORD(					\
		(e2k_addr_t)&((__ti_gregs)[ti_gr_no + 0].base),		\
		(e2k_addr_t)&((__ti_gregs)[ti_gr_no + 1].base),		\
		(e2k_addr_t)&((__gti_gregs)[gti_gr_no + 0].base),	\
		(e2k_addr_t)&((__gti_gregs)[gti_gr_no + 1].base));	\
	(__gti_gregs)[(gti_gr_no) + 0].ext =				\
			(__ti_gregs)[(ti_gr_no) + 0].ext;		\
	(__gti_gregs)[(gti_gr_no) + 1].ext =				\
			(__ti_gregs)[(ti_gr_no) + 1].ext;		\
})
#define	RESTORE_GUEST_USER_GREG_PAIR(__ti_gregs, ti_gr_no,		\
					__gti_gregs, gti_gr_no)		\
({									\
	NATIVE_MOVE_TAGGED_QWORD(					\
		(e2k_addr_t)&((__gti_gregs)[gti_gr_no + 0].base),	\
		(e2k_addr_t)&((__gti_gregs)[gti_gr_no + 1].base),	\
		(e2k_addr_t)&((__ti_gregs)[ti_gr_no + 0].base),		\
		(e2k_addr_t)&((__ti_gregs)[ti_gr_no + 1].base));	\
	(__ti_gregs)[(ti_gr_no) + 0].ext =				\
			(__gti_gregs)[(gti_gr_no) + 0].ext;		\
	(__ti_gregs)[(ti_gr_no) + 1].ext =				\
			(__gti_gregs)[(gti_gr_no) + 1].ext;		\
})
#define	COPY_GUEST_KERNEL_GREGS_FROM_TI(__ti_gregs, __gti_regs)		\
({									\
	SAVE_GUEST_USER_GREG_PAIR(					\
		__ti_gregs, CURRENT_GREGS_PAIRS_INDEX_LO,		\
		__gti_regs, CURRENT_GREGS_PAIRS_INDEX_LO);		\
	SAVE_GUEST_USER_GREG_PAIR(					\
		__ti_gregs, CPU_GREGS_PAIRS_INDEX_LO,			\
		__gti_regs, CPU_GREGS_PAIRS_INDEX_LO);			\
})
#define	COPY_GUEST_KERNEL_GREGS_TO_TI(__ti_gregs, __gti_regs)		\
({									\
	RESTORE_GUEST_USER_GREG_PAIR(					\
		__ti_gregs, CURRENT_GREGS_PAIRS_INDEX_LO,		\
		__gti_regs, CURRENT_GREGS_PAIRS_INDEX_LO);		\
	RESTORE_GUEST_USER_GREG_PAIR(					\
		__ti_gregs, CPU_GREGS_PAIRS_INDEX_LO,			\
		__gti_regs, CPU_GREGS_PAIRS_INDEX_LO);			\
})

#define	SAVE_GUEST_KERNEL_GREGS_AT_GTI(__ti, __gti, __gregs)		\
({									\
	DebugGREGS("now: gregs_active %d gregs_valid %d "		\
		"gregs_for_currents_valid %d\n",			\
		__gti->gregs_active, __gti->gregs_valid,		\
		__gti->gregs_for_currents_valid);			\
	WARN_ON(__gti->gregs_active && __gti->gregs_for_currents_valid);\
	SAVE_GUEST_USER_GREG_PAIR(					\
		(__ti)->k_gregs.g, CURRENT_GREGS_PAIRS_INDEX_LO,	\
		(__gregs)->g, CURRENT_GREGS_PAIR_LO);			\
	SAVE_GUEST_USER_GREG_PAIR(					\
		(__ti)->k_gregs.g, CPU_GREGS_PAIRS_INDEX_LO,		\
		(__gregs)->g, CPU_GREGS_PAIR_LO);			\
	__gti->gregs_for_currents_valid = 1;				\
	DebugGREGS("set gregs_for_currents_valid %d\n",			\
		__gti->gregs_for_currents_valid);			\
})
#define	RESTORE_GUEST_KERNEL_GREGS_AT_TI(__ti, __gti, __gregs)		\
({									\
	DebugGREGS("now: gregs_active %d gregs_valid %d "		\
		"gregs_for_currents_valid %d\n",			\
		__gti->gregs_active, __gti->gregs_valid,		\
		__gti->gregs_for_currents_valid);			\
	WARN_ON(__gti->gregs_active && !__gti->gregs_for_currents_valid); \
	RESTORE_GUEST_USER_GREG_PAIR(					\
		(__ti)->k_gregs.g, CURRENT_GREGS_PAIRS_INDEX_LO,	\
		(__gregs)->g, CURRENT_GREGS_PAIR_LO);			\
	RESTORE_GUEST_USER_GREG_PAIR(					\
		(__ti)->k_gregs.g, CPU_GREGS_PAIRS_INDEX_LO,		\
		(__gregs)->g, CPU_GREGS_PAIR_LO);			\
	__gti->gregs_for_currents_valid = 0;				\
	DebugGREGS("clear gregs_for_currents_valid %d\n",		\
		__gti->gregs_for_currents_valid);			\
})

#define	DO_INIT_GUEST_USER_UPSR(__gti, __upsr)				\
({									\
	(__gti)->u_upsr = __upsr;					\
	(__gti)->u_upsr_valid = true;					\
})
#define	DO_INIT_GUEST_KERNEL_UPSR(__gti, __upsr)			\
({									\
	(__gti)->k_upsr = __upsr;					\
	(__gti)->k_upsr_valid = true;					\
})
#define	DO_SAVE_GUEST_USER_UPSR(__gti, __upsr)			\
({									\
	GTI_BUG_ON((__gti)->u_upsr_valid);				\
	DO_INIT_GUEST_USER_UPSR(__gti, __upsr);				\
})
#define	DO_SAVE_GUEST_KERNEL_UPSR(__gti, __upsr)			\
({									\
	GTI_BUG_ON((__gti)->k_upsr_valid);				\
	DO_INIT_GUEST_KERNEL_UPSR(__gti, __upsr);			\
})
#define	SAVE_GUEST_USER_UPSR_AT_GTI(__ti, __gti)	\
		DO_SAVE_GUEST_USER_UPSR(__gti, (__ti)->upsr)
#define	SAVE_GUEST_KERNEL_UPSR_AT_GTI(__ti, __gti)	\
		DO_SAVE_GUEST_KERNEL_UPSR(__gti, (__ti)->upsr)
#define	DO_RESTORE_GUEST_USER_UPSR(__gti, upsr_value)			\
({									\
	GTI_BUG_ON(!(__gti)->u_upsr_valid);				\
	(upsr_value) = (__gti)->u_upsr;					\
	(__gti)->u_upsr_valid = false;					\
})
#define	DO_RESTORE_GUEST_KERNEL_UPSR(__gti, upsr_value)			\
({									\
	GTI_BUG_ON(!(__gti)->k_upsr_valid);				\
	(upsr_value) = (__gti)->k_upsr;					\
	(__gti)->k_upsr_valid = false;					\
})
#define	RESTORE_GUEST_USER_UPSR_AT_TI(__ti, __gti)	\
		DO_RESTORE_GUEST_USER_UPSR(__gti, (__ti)->upsr)
#define	RESTORE_GUEST_KERNEL_UPSR_AT_TI(__ti, __gti)	\
		DO_RESTORE_GUEST_KERNEL_UPSR(__gti, (__ti)->upsr)

/* It is native host/guest kernel with virtualization support */
/* or paravirtualized host and guest kernel */
/* Save/restore global registers used by host to support guest */
#define	SAVE_GUEST_HOST_GREGS_AT_TI(__greg_pair, __gl_regs)		\
({									\
	SAVE_GUEST_USER_GREG_PAIR(					\
		__greg_pair, HOST_VCPU_STATE_GREGS_PAIRS_INDEX_LO,	\
		__gl_regs, VCPU_STATE_GREGS_PAIR_LO);			\
})
#define	RESTORE_GUEST_HOST_GREGS_AT_TI(__greg_pair, __gl_regs)		\
({									\
	RESTORE_GUEST_USER_GREG_PAIR(					\
		__greg_pair, HOST_VCPU_STATE_GREGS_PAIRS_INDEX_LO,	\
		__gl_regs, VCPU_STATE_GREGS_PAIR_LO);			\
})

#define	SAVE_GUEST_USER_REGS_AT_GTI(thread_info, gthread_info, save_upsr) \
({									\
	thread_info_t *__ti = (thread_info);				\
	gthread_info_t *__gti = (gthread_info);				\
	global_regs_t *__gregs = &__gti->gregs;				\
									\
	if (test_ti_thread_flag(__ti, TIF_VIRTUALIZED_GUEST)) {		\
		SAVE_GUEST_KERNEL_GREGS_AT_GTI(__ti, __gti, __gregs);	\
		SAVE_GUEST_HOST_GREGS_AT_TI(__ti->h_gregs.g,		\
							__gregs->g);	\
		if (save_upsr) {					\
			SAVE_GUEST_USER_UPSR_AT_GTI(__ti, __gti);	\
		}							\
	}								\
})
#define	RESTORE_GUEST_USER_REGS_AT_TI(thread_info, gthread_info, restore_upsr) \
({									\
	thread_info_t *__ti = (thread_info);				\
	gthread_info_t *__gti = (gthread_info);				\
	host_gregs_t *__greg_pair = &__ti->h_gregs;			\
	global_regs_t *__gregs = &__gti->gregs;				\
									\
	if (test_ti_thread_flag(__ti, TIF_VIRTUALIZED_GUEST)) {		\
		RESTORE_GUEST_KERNEL_GREGS_AT_TI(__ti, __gti, __gregs);	\
		RESTORE_GUEST_HOST_GREGS_AT_TI(__greg_pair->g,		\
							__gregs->g);	\
		if (restore_upsr) {					\
			RESTORE_GUEST_USER_UPSR_AT_TI(__ti, __gti);	\
		}							\
	}								\
})
#define	KVM_INIT_GUEST_USER_UPSR(thread_info, __upsr)			\
({									\
	thread_info_t *__ti = (thread_info);				\
	gthread_info_t *__gti = __ti->gthread_info;			\
									\
	DO_INIT_GUEST_USER_UPSR(__gti, __upsr);				\
})
#define	KVM_SAVE_GUEST_KERNEL_UPSR(thread_info, __upsr)			\
({									\
	thread_info_t *__ti = (thread_info);				\
	gthread_info_t *__gti = __ti->gthread_info;			\
									\
	DO_SAVE_GUEST_KERNEL_UPSR(__gti, __upsr);			\
})
#define	KVM_SAVE_GUEST_USER_UPSR(thread_info, __upsr)			\
({									\
	thread_info_t *__ti = (thread_info);				\
	gthread_info_t *__gti = __ti->gthread_info;			\
									\
	DO_SAVE_GUEST_USER_UPSR(__gti, __upsr);				\
})
#define	KVM_RESTORE_GUEST_KERNEL_UPSR(thread_info)			\
({									\
	thread_info_t *__ti = (thread_info);				\
	gthread_info_t *__gti = __ti->gthread_info;			\
	e2k_upsr_t __upsr;						\
									\
	DO_RESTORE_GUEST_KERNEL_UPSR(__gti, __upsr);			\
	NATIVE_WRITE_UPSR_REG(__upsr);					\
})
#define	KVM_RESTORE_GUEST_USER_UPSR(thread_info)			\
({									\
	thread_info_t *__ti = (thread_info);				\
	gthread_info_t *__gti = __ti->gthread_info;			\
	e2k_upsr_t __upsr;						\
									\
	DO_RESTORE_GUEST_USER_UPSR(__gti, __upsr);			\
	NATIVE_WRITE_UPSR_REG(__upsr);					\
})
#define	KVM_SET_GUEST_USER_INITIAL_UPSR(thread_info)			\
({									\
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));	\
	KVM_RESTORE_GUEST_USER_UPSR(thread_info);			\
})

#define	SAVE_GUEST_USER_GLOBAL_REGISTERS(gthread_info)			\
({									\
	gthread_info_t *gti = (gthread_info);				\
	global_regs_t *gregs = &gti->gregs;				\
									\
	DebugGREGS("now: gregs_active %d gregs_valid %d "		\
		"gregs_for_currents_valid %d\n",			\
		gti->gregs_active, gti->gregs_valid,			\
		gti->gregs_for_currents_valid);				\
	/* user state of gregs which now are under current pointers */	\
	/* should be saved into current guest thread info structure */	\
	WARN_ON(gti->gregs_active && !gti->gregs_for_currents_valid);	\
									\
	/* save current state of global registers excluding gregs */	\
	/* used by kernel */						\
	gregs->bgr = NATIVE_READ_BGR_REG();				\
	init_BGR_reg(); /* enable whole GRF */				\
	SAVE_GUEST_GREGS_EXCEPT_KERNEL(gregs);				\
	NATIVE_WRITE_BGR_REG(gregs->bgr);				\
	gti->gregs_valid = 1;						\
	DebugGREGS("set gregs_valid %d\n",				\
		gti->gregs_valid);					\
})
#define	SAVE_GUEST_USER_ALL_GLOBAL_REGISTERS(gthread_info, gti_base)	\
({									\
	gthread_info_t *__gti = (gthread_info);				\
	gthread_info_t *src_gti = (gti_base);				\
	global_regs_t *__gregs = &__gti->gregs;				\
	global_regs_t *src_gregs = &src_gti->gregs;			\
									\
	SAVE_GUEST_USER_GLOBAL_REGISTERS(__gti);			\
	WARN_ON(__gti->gregs_for_currents_valid);			\
	WARN_ON(!src_gti->gregs_for_currents_valid);			\
	/* global register which now used by kernel */			\
	/* saved from parent global registers state */			\
	COPY_GUEST_USER_GREG_ON_MASK(src_gregs, __gregs,		\
					GUEST_GREGS_MASK);		\
	__gti->gregs_for_currents_valid = 1;				\
	DebugGREGS("set gregs_for_currents_valid %d\n",			\
		__gti->gregs_for_currents_valid);			\
})

#define	RESTORE_GUEST_USER_GLOBAL_REGISTERS(gthread_info)		\
({									\
	gthread_info_t *gti = (gthread_info);				\
	global_regs_t *gregs = &gti->gregs;				\
									\
	DebugGREGS("now: gregs_active %d gregs_valid %d "		\
		"gregs_for_currents_valid %d\n",			\
		gti->gregs_active, gti->gregs_valid,			\
		gti->gregs_for_currents_valid);				\
	WARN_ON(gti->gregs_active && !gti->gregs_valid);		\
	WARN_ON(gti->gregs_active && !gti->gregs_for_currents_valid);	\
									\
	/* restore current state of global registers excluding gregs */	\
	/* used by kernel */						\
	init_BGR_reg(); /* enable whole GRF */				\
	RESTORE_GUEST_GREGS_EXCEPT_KERNEL(gregs);			\
	NATIVE_WRITE_BGR_REG(gregs->bgr);				\
	gti->gregs_valid = 0;						\
	DebugGREGS("clear gregs_valid %d\n",				\
		gti->gregs_valid);					\
})
#define	SAVE_PV_VCPU_GLOBAL_REGISTERS(gthread_info)			\
do {									\
	gthread_info_t *gti = (gthread_info);				\
	global_regs_t *gregs = &gti->sw_regs.gregs;			\
									\
	machine.save_gregs_dirty_bgr(gregs);				\
} while (false)

#define	RESTORE_PV_VCPU_GLOBAL_REGISTERS(gthread_info)			\
do {									\
	gthread_info_t *gti = (gthread_info);				\
	global_regs_t *gregs = &gti->sw_regs.gregs;			\
									\
	machine.restore_gregs(gregs);					\
} while (false)

#endif	/* CONFIG_VIRTUALIZATION */

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */
#define	NATIVE_RESTORE_USER_CUT_REGS(ti, regs)	/* CUTD is already set */
#define	RESTORE_USER_CUT_REGS(ti, regs, in_syscall) \
		NATIVE_RESTORE_USER_CUT_REGS(ti, regs)
#elif	defined(CONFIG_KVM_HOST_MODE)
/* it is native host kernel with virtualization support */
#define	HOST_RESTORE_USER_CUT_REGS(ti, regs, in_syscall)	\
do { \
	e2k_cutd_t cutd; \
	struct kvm_vcpu *vcpu; \
\
	if (likely(!test_ti_thread_flag((ti), TIF_HOST_AT_VCPU_MODE))) { \
		/* host at native or hypervisor mode */ \
		/* so CUT context is alredy set */ \
		break; \
	} \
	vcpu = (ti)->vcpu; \
	if (pv_vcpu_trap_on_guest_kernel(regs)) { \
		/* guest kernel return to kernel, need not switch context */ \
		break; \
	} else if ((in_syscall) ? \
			host_return_to_injected_guest_syscall((ti), (regs)) \
			: \
			host_return_to_injected_guest_trap(ti, (regs))) { \
		/* it need switch to guest kernel context */ \
		cutd = vcpu->arch.hw_ctxt.sh_oscutd; \
	} else { \
		/* it need switch to guest user context */ \
		cutd = pv_vcpu_get_gti(vcpu)->stack_regs.cutd; \
	} \
	NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(cutd.CUTD_reg); \
} while (false)
#define	RESTORE_USER_CUT_REGS(ti, regs, in_syscall)	\
		HOST_RESTORE_USER_CUT_REGS(ti, regs, in_syscall)
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravrtualized) */
#include <asm/kvm/guest/regs_state.h>
#else
 #error	"Undefined virtualization mode"
#endif	/* !CONFIG_VIRTUALIZATION */

#define	RESTORE_USER_TRAP_CUT_REGS(ti, regs)	\
		RESTORE_USER_CUT_REGS(ti, regs, false)
#define	RESTORE_USER_SYSCALL_CUT_REGS(ti, regs)	\
		RESTORE_USER_CUT_REGS(ti, regs, true)

#if defined(CONFIG_KVM) || defined(CONFIG_KVM_GUEST_KERNEL)
#define	SAVE_GUEST_VCPU_STATE_GREGS(regs)				\
({									\
	DO_SAVE_DGREG(GUEST_VCPU_STATE_GREG,				\
				regs->guest_vcpu_state_greg);		\
})
#define	RESTORE_GUEST_VCPU_STATE_GREGS(regs)				\
({									\
	DO_RESTORE_DGREG(GUEST_VCPU_STATE_GREG,				\
				regs->guest_vcpu_state_greg);		\
})
#else	/* ! CONFIG_KVM && ! CONFIG_KVM_GUEST_KERNEL */
#define	SAVE_GUEST_VCPU_STATE_GREGS(regs)
#define	RESTORE_GUEST_VCPU_STATE_GREGS(regs)
#endif	/* CONFIG_KVM || CONFIG_KVM_GUEST_KERNEL */

#endif /* _E2K_KVM_REGS_STATE_H */

