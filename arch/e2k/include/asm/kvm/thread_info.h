/*
 * kvm_thread_info.h: In-kernel KVM guest thread info related definitions
 * Copyright (c) 2011, MCST.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __E2K_KVM_THREAD_INFO_H
#define __E2K_KVM_THREAD_INFO_H

#include <linux/types.h>
#include <linux/kvm.h>
#include <linux/bitops.h>

#include <asm/trap_def.h>
#include <asm/cpu_regs_types.h>
#include <asm/stacks.h>
#include <asm/kvm/gpid.h>

#ifdef	CONFIG_VIRTUALIZATION

struct kvm;
struct kvm_vcpu;
struct gmm_struct;

/* TODO a security hole, undef it - bad guest can cause host to panic() */
#define	GTI_DEBUG_MODE

#ifdef	GTI_DEBUG_MODE
#define	GTI_BUG_ON(cond)	BUG_ON(cond)
#else	/* ! GTI_DEBUG_MODE */
#define	GTI_BUG_ON(cond)	do { } while (0)
#endif	/* GTI_DEBUG_MODE */

/*
 * Hardware & local data stacks registers state to save/restore guest stacks
 * while hypercalls under paravirtualization without hardware support.
 * It allows to emulate switch (on HCALL) and restore (on HRET) hardware
 * supported extensions.
 */
typedef struct guest_hw_stack {
	bool		valid;		/* stacks are valid */
	e2k_stacks_t	stacks;		/* pointers to local data & hardware */
					/* stacks */
	e2k_mem_crs_t	crs;		/* to startup & launch VCPU */
	e2k_cutd_t	cutd;		/* Compilation Unit table pointer */
} guest_hw_stack_t;

/*
 * Guest kernel pt_regs structure to keep some info about guest state on host
 * It needs to enable recursive traps, system calls, signal handlers
 * (same as on host kernel)
 */
typedef enum gpt_regs_type {
	undefined_regs_type,		/* unknown or any type */
	start_regs_type,		/* start activation of guest */
	trap_regs_type,			/* beacause of trap */
	syscall_regs_type,		/*	system call */
	hypercall_regs_type,		/*	hypercall */
	sig_handler_regs_type,		/* to run signal handler */
} gpt_regs_type_t;

typedef struct gpt_regs {
	gpt_regs_type_t	type;		/* the reason to have been created */
					/* this instance of structure */

	/* follow fields to save last guest and host activation state */
	/* to enable recursive kernel activations */
	int		g_stk_frame_no;	/* number of saved guest kernel */
					/* data stack activation (see below) */
	e2k_addr_t	g_usd_size;	/* guest kernel data stack size */
	int		k_stk_frame_no;	/* number of saved host kernel */
					/* data stack activation */
	e2k_addr_t	k_usd_size;	/* host kernel data stack size */
	e2k_size_t	pcsp_ind;	/* chain procedure stack index */
	struct pt_regs	*pt_regs;	/* head of pt_regs structure queue: */
					/* pointer to current pt_regs */

	/* all structures type of this gpt_regs (same as pt_regs structures) */
	/* allocated into host kernel data stack because of recursive events */
	/* (traps, system calls, hypercalls, signale handler) handled by */
	/* kernel on one stack using stack discipline */
	/* So it can use index into this stack as reference to previous or */
	/* next same structure instead of real pointer (address) to avoid */
	/* complex addresses translation while copy/clone stacks (fork()) */
	e2k_addr_t	next_index;	/* index of next same structure, */
					/* into host kernel data stack */
					/* which keeps state of previous */
					/* guest kernel activation */
} gpt_regs_t;

typedef struct vcpu_l_gregs {
	local_gregs_t	gregs;		/* guest user "local" global */
					/* registers to save updated on page */
					/* fault values */
	u64		updated;	/* mask of updated registers "local" */
					/* global registers (see above) */
	bool		valid;		/* gregs is valid */
	int		gener;		/* generation of valid gregs */
} vcpu_l_gregs_t;

typedef struct kvm_signal_context {
	/* signal stack area is used to store interrupted context */
	/* one for host thread and one for each guest threads */
	struct signal_stack stack;
	atomic_t traps_num;	/* counter of recursive traps at the */
				/* signal stack, actual only for guest */
	atomic_t in_work;	/* counter of recursive traps in the */
				/* work, actual only for guest */
	atomic_t syscall_num;	/* counter of recursive system calls at the */
				/* signal stack, actual only for guest */
	atomic_t in_syscall;	/* counter of recursive system calls in the */
				/* work, actual only for guest */
} kvm_signal_context_t;

/*
 * Guest kernel thread info structure
 */
typedef struct gthread_info {
	gpid_t		*gpid;

	/* guest kernel stacks pointers */
	e2k_usd_lo_t	g_usd_lo;
	e2k_usd_hi_t	g_usd_hi;
	e2k_sbr_t	g_sbr;
	e2k_psp_lo_t	g_psp_lo;
	e2k_psp_hi_t	g_psp_hi;
	e2k_pcsp_lo_t	g_pcsp_lo;
	e2k_pcsp_hi_t	g_pcsp_hi;

	e2k_size_t	us_size;	/* guest local data size: */
					/* kernel stack for kernel thread, */
					/* user stack for user */
	guest_hw_stack_t stack_regs;	/* state of pointers to local & */
					/* hardware stacks of guest */

	data_stack_t	data_stack;
	void		*stack;
	hw_stack_t	hw_stacks;
	vcpu_l_gregs_t	l_gregs;	/* guest user "local" global */
					/* registers to save updated on page */
					/* fault values */
	kernel_gregs_t	g_gregs;	/* guest kernel global resiters state */
					/* after migration to other VCPU */

	/* the following flags to mark event: */
	/* hardware stacks bounds trap occured, but 'sge' on guest */
	/* is disabled and the trap is not yet passed to guest kernel */
	bool		proc_bounds_waiting;	/* procedure stack bounds */
	bool		chain_bounds_waiting;	/* chain stack bounds */

	int		g_stk_frame_no;	/* current number of guest kernel */
					/* data stack activation */
					/* each kernel activation from user */
					/* (trap, system call, signal */
					/* handler) runs on kernel data stack */
					/* Activations can be nested, */
					/* so for each new nested activation */
					/* need new free frame of data stack */
					/* above (for data stack below) */
					/* previous activation */
	int		k_stk_frame_no;	/* current number of host kernel */
					/* data stack activation */

	unsigned long	flags;		/* flags (see below) */
	struct gmm_struct *gmm;		/* pointer to current guest mm agent */
					/* on host */
					/* NULL for guest kernel threads */
	hpa_t nonp_root_hpa;		/* physical base of nonpaging root PT */
	bool gmm_in_release;		/* guest mm is releasing (exit_mm()) */

	/* following fields should be updated for each multi-stack process */
	/* (task, thread) while switching */
	struct kvm_vcpu	*vcpu;		/* pointer to VCPU where the thread */
					/* is running now or was run last */
					/* time */
	struct pt_regs	fork_regs;	/* pt_regs structure of last host */
					/* sys_fork() system call */
	u32		intr_counter;	/* number of traps are handling */
	atomic_t	signal_counter;	/* number of signals are handling */
	struct sw_regs	sw_regs;	/* user special registers state */
					/* to save/restore while guest */
					/* process switch */
	kvm_signal_context_t signal;	/* the host kernel's signal/trap */
					/* stack of contexts */

	/* follow pointer should be updated by each recursive traps, */
	/* system calls, signal handler running */
	gpt_regs_t	*gpt_regs;	/* pointer to current state of */
					/* guest kernel */

	e2k_upsr_t	u_upsr;		/* guest user is different from */
	e2k_upsr_t	k_upsr;		/* guest kernel UPSR */

	/* FIXME: follow fields is added only to debug correct save/restore */
	/* guest UPSR state, delete after debugging completion with some */
	/* debug statements into other source files of kvm */
	bool		u_upsr_valid;	/* guest user upsr value is valid */
	bool		k_upsr_valid;	/* guest kernel upsr value is valid */

	global_regs_t	gregs;		/* structure to keep guest user */
					/* global registers state */
					/* FIXME: this structure duplicates */
					/* similar structure into sw_regs, */
					/* should use structure into sw_regs */
					/* only */
	bool gregs_active;		/* gregs structure above is active */
					/* for user global registers */
	bool gregs_valid;		/* gregs structure above contains */
					/* actual global registers state */
	bool gregs_for_currents_valid;	/* gregs used for currents pointers */
					/* contain actual global registers */
					/* state, when real global registers */
					/* is set to currents pointers */
	bool task_is_binco;		/* the guest task is binary */
					/* application compiler */
	bool task_is_protect;		/* the guest task is running at */
					/* protected mode */
} gthread_info_t;

/* guest stacks flag (field at structure above) */

/*
 * Guest thread flags
 */
#define	GTIF_VCPU_START_THREAD	0	/* this thread is booting (start) */
					/* guest kernel thread */
#define	GTIF_KERNEL_THREAD	1	/* this thread is guest kernel */
					/* thread */
#define	GTIF_THREAD_MIGRATED	2	/* the thread was migrated from one */
					/* VCPU to other */
#define	GTIF_HW_PS_LOCKED	16	/* hardware procedure stack */
					/* was locked by host */
#define	GTIF_HW_PCS_LOCKED	17	/* hardware chain stack */
					/* was locked by host */
#define	GTIF_HW_PS_PRESENTED	18	/* hardware procedure stack */
					/* was populated by host */
#define	GTIF_HW_PCS_PRESENTED	19	/* hardware chain stack */
					/* was populated by host */
#define	GTIF_DATA_STACK_HOSTED	20	/* local data stack of guest */
					/* was registered on host */
#define	GTIF_HW_PS_HOSTED	21	/* hardware procedure stack of guest */
					/* was registered on host */
#define	GTIF_HW_PCS_HOSTED	22	/* hardware chain stack of guest */
					/* was registered on host */
#define	GTIF_HW_PS_HAS_GUARD_PAGE 28	/* hardware procedure stack of guest */
					/* has extra guard page */
#define	GTIF_HW_PCS_HAS_GUARD_PAGE 29	/* hardware chain stack of guest */
					/* has extra guard page */

#define _GTIF_VCPU_START_THREAD		(1UL << GTIF_VCPU_START_THREAD)
#define	_GTIF_KERNEL_THREAD		(1UL << GTIF_KERNEL_THREAD)
#define	_GTIF_THREAD_MIGRATED		(1UL << GTIF_THREAD_MIGRATED)
#define	_GTIF_HW_PS_LOCKED		(1UL << GTIF_HW_PS_LOCKED)
#define	_GTIF_HW_PCS_LOCKED		(1UL << GTIF_HW_PCS_LOCKED)
#define	_GTIF_HW_PS_PRESENTED		(1UL << GTIF_HW_PS_PRESENTED)
#define	_GTIF_HW_PCS_PRESENTED		(1UL << GTIF_HW_PCS_PRESENTED)
#define	_GTIF_DATA_STACK_HOSTED		(1UL << GTIF_DATA_STACK_HOSTED)
#define	_GTIF_HW_PS_HOSTED		(1UL << GTIF_HW_PS_HOSTED)
#define	_GTIF_HW_PCS_HOSTED		(1UL << GTIF_HW_PCS_HOSTED)
#define _GTIF_HW_PS_HAS_GUARD_PAGE	(1UL << GTIF_HW_PS_HAS_GUARD_PAGE)
#define _GTIF_HW_PCS_HAS_GUARD_PAGE	(1UL << GTIF_HW_PCS_HAS_GUARD_PAGE)

#define	GTIF_ALL_STACKS_MASK		\
		(_GTIF_HW_PS_LOCKED | _GTIF_HW_PCS_LOCKED | \
		_GTIF_HW_PS_PRESENTED | _GTIF_HW_PCS_PRESENTED | \
		_GTIF_DATA_STACK_HOSTED | _GTIF_HW_PS_HOSTED | \
		_GTIF_HW_PCS_HOSTED)

static inline void set_the_flag(unsigned long *flags, int the_flag)
{
	set_bit(the_flag, flags);
}

static inline void clear_the_flag(unsigned long *flags, int the_flag)
{
	clear_bit(the_flag, flags);
}

static inline int test_and_set_the_flag(unsigned long *flags, int the_flag)
{
	return test_and_set_bit(the_flag, flags);
}

static inline int test_and_clear_the_flag(unsigned long *flags, int the_flag)
{
	return test_and_clear_bit(the_flag, flags);
}

static inline int test_the_flag(unsigned long *flags, int the_flag)
{
	return test_bit(the_flag, flags);
}

static inline void set_gti_thread_flag(gthread_info_t *gti, int flag)
{
	set_the_flag(&gti->flags, flag);
}

static inline void clear_gti_thread_flag(gthread_info_t *gti, int flag)
{
	clear_the_flag(&gti->flags, flag);
}

static inline int test_and_set_gti_thread_flag(gthread_info_t *gti, int flag)
{
	return test_and_set_the_flag(&gti->flags, flag);
}

static inline int test_and_clear_gti_thread_flag(gthread_info_t *gti, int flag)
{
	return test_and_clear_the_flag(&gti->flags, flag);
}

static inline int test_gti_thread_flag(gthread_info_t *gti, int flag)
{
	return test_the_flag(&gti->flags, flag);
}

/*
 * Hardware stacks bounds control
 */
static inline bool test_guest_hw_stack_bounds_waiting(thread_info_t *ti,
				unsigned long trap_mask)
{
	gthread_info_t *gti = ti->gthread_info;
	bool is_waiting = false;

	if (gti == NULL)
		return false;
	if (trap_mask & exc_proc_stack_bounds_mask)
		is_waiting |= gti->proc_bounds_waiting;
	if (trap_mask & exc_chain_stack_bounds_mask)
		is_waiting |= gti->chain_bounds_waiting;
	return is_waiting;
}
static inline bool test_guest_proc_bounds_waiting(thread_info_t *ti)
{
	return test_guest_hw_stack_bounds_waiting(ti,
				exc_proc_stack_bounds_mask);
}
static inline bool test_guest_chain_bounds_waiting(thread_info_t *ti)
{
	return test_guest_hw_stack_bounds_waiting(ti,
				exc_chain_stack_bounds_mask);
}
static inline void set_guest_hw_stack_bounds_waiting(thread_info_t *ti,
				unsigned long trap_mask)
{
	gthread_info_t *gti = ti->gthread_info;

	if (gti == NULL)
		return;
	if (trap_mask & exc_proc_stack_bounds_mask) {
		gti->proc_bounds_waiting = true;
	} else if (trap_mask & exc_chain_stack_bounds_mask) {
		gti->chain_bounds_waiting = true;
	} else {
		BUG_ON(true);
	}
}
static inline void set_guest_proc_bounds_waiting(thread_info_t *ti)
{
	set_guest_hw_stack_bounds_waiting(ti, exc_proc_stack_bounds_mask);
}
static inline void set_guest_chain_bounds_waiting(thread_info_t *ti)
{
	set_guest_hw_stack_bounds_waiting(ti, exc_chain_stack_bounds_mask);
}
static inline bool
test_and_set_guest_hw_stack_bounds_waiting(thread_info_t *ti,
						unsigned long trap_mask)
{
	bool waiting;

	waiting = test_guest_hw_stack_bounds_waiting(ti, trap_mask);
	if (!waiting)
		set_guest_hw_stack_bounds_waiting(ti, trap_mask);
	return waiting;
}
static inline bool test_and_set_guest_proc_bounds_waiting(thread_info_t *ti)
{
	return test_and_set_guest_hw_stack_bounds_waiting(ti,
					exc_proc_stack_bounds_mask);
}
static inline bool test_and_set_guest_chain_bounds_waiting(thread_info_t *ti)
{
	return test_and_set_guest_hw_stack_bounds_waiting(ti,
					exc_chain_stack_bounds_mask);
}
static inline void clear_guest_hw_stack_bounds_waiting(thread_info_t *ti,
				unsigned long trap_mask)
{
	gthread_info_t *gti = ti->gthread_info;

	if (gti == NULL)
		return;
	if (trap_mask & exc_proc_stack_bounds_mask) {
		gti->proc_bounds_waiting = false;
	} else if (trap_mask & exc_chain_stack_bounds_mask) {
		gti->chain_bounds_waiting = false;
	} else {
		BUG_ON(true);
	}
}
static inline void clear_guest_proc_bounds_waiting(thread_info_t *ti)
{
	clear_guest_hw_stack_bounds_waiting(ti, exc_proc_stack_bounds_mask);
}
static inline void clear_guest_chain_bounds_waiting(thread_info_t *ti)
{
	clear_guest_hw_stack_bounds_waiting(ti, exc_chain_stack_bounds_mask);
}
static inline bool
test_and_clear_guest_hw_stack_bounds_waiting(thread_info_t *ti,
						unsigned long trap_mask)
{
	bool waiting;

	waiting = test_guest_hw_stack_bounds_waiting(ti, trap_mask);
	if (waiting)
		clear_guest_hw_stack_bounds_waiting(ti, trap_mask);
	return waiting;
}
static inline bool test_and_clear_guest_proc_bounds_waiting(thread_info_t *ti)
{
	return test_and_clear_guest_hw_stack_bounds_waiting(ti,
					exc_proc_stack_bounds_mask);
}
static inline bool test_and_clear_guest_chain_bounds_waiting(thread_info_t *ti)
{
	return test_and_clear_guest_hw_stack_bounds_waiting(ti,
					exc_chain_stack_bounds_mask);
}

/*
 * Set of functions to manipulate with gpt_regs structures
 */

#define	ATOMIC_GET_HW_PCS_INDEX()					\
({									\
	unsigned long	pcsp_hi_val;					\
	unsigned int	pcshtp_val;					\
	e2k_pcsp_hi_t	pcsp_hi;					\
									\
	ATOMIC_READ_HW_PCS_SIZES(pcsp_hi_val, pcshtp_val);		\
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pcsp_hi.PCSP_hi_ind + pcshtp_val;				\
})

static inline e2k_size_t
gpt_regs_addr_to_index(thread_info_t *ti, gpt_regs_t *gregs)
{
	e2k_addr_t bottom;
	e2k_addr_t addr;

	if (gregs == NULL)
		return -1UL;
	bottom = (e2k_addr_t)thread_info_task(ti)->stack;
	addr = (e2k_addr_t)gregs;
	GTI_BUG_ON(addr < bottom ||
			addr + sizeof(*gregs) > bottom + KERNEL_C_STACK_SIZE);
	return addr - bottom;
}
static inline gpt_regs_t *
gpt_regs_index_to_addr(thread_info_t *ti, e2k_size_t gregs_index)
{
	e2k_addr_t bottom;

	if (gregs_index == -1UL)
		return NULL;
	bottom = (e2k_addr_t)thread_info_task(ti)->stack;
	GTI_BUG_ON(gregs_index < 0 ||
		gregs_index + sizeof(gpt_regs_t) > KERNEL_C_STACK_SIZE);
	return (gpt_regs_t *)(bottom + gregs_index);
}
static inline gpt_regs_t *
get_gpt_regs(thread_info_t *ti)
{
	gthread_info_t *gti = ti->gthread_info;

	GTI_BUG_ON(gti == NULL);
	return gti->gpt_regs;
}
static inline void
set_gpt_regs(thread_info_t *ti, gpt_regs_t *gregs)
{
	gthread_info_t *gti = ti->gthread_info;

	GTI_BUG_ON(gti == NULL);
	gti->gpt_regs = gregs;
}
static inline void
add_gpt_regs(thread_info_t *ti, gpt_regs_t *new_gregs, gpt_regs_type_t type)
{
	gpt_regs_t *cur_gregs;

	cur_gregs = get_gpt_regs(ti);
	new_gregs->type = type;
	new_gregs->next_index = gpt_regs_addr_to_index(ti, cur_gregs);
	new_gregs->pcsp_ind = ATOMIC_GET_HW_PCS_INDEX();
	set_gpt_regs(ti, new_gregs);
}
static inline gpt_regs_t *
delete_gpt_regs(thread_info_t *ti)
{
	gpt_regs_t *cur_gregs;

	cur_gregs = get_gpt_regs(ti);
	GTI_BUG_ON(cur_gregs == NULL);
	set_gpt_regs(ti, gpt_regs_index_to_addr(ti, cur_gregs->next_index));
	return cur_gregs;
}
static inline gpt_regs_t *
get_next_gpt_regs(thread_info_t *ti, gpt_regs_t *gregs)
{
	BUG_ON(gregs == NULL);
	return gpt_regs_index_to_addr(ti, gregs->next_index);
}

extern int kvm_pv_guest_thread_info_init(struct kvm *kvm);
extern void kvm_pv_guest_thread_info_destroy(struct kvm *kvm);
extern void kvm_pv_clear_guest_thread_info(gthread_info_t *gthread_info);

#else	/* !CONFIG_VIRTUALIZATION */

typedef struct guest_hw_stack {
	/* empty structure */
} guest_hw_stack_t;

typedef struct kvm_signal_context {
	/* empty structure */
} kvm_signal_context_t;
typedef struct gthread_info {
	/* empty structure */
} gthread_info_t;

#endif	/* CONFIG_VIRTUALIZATION */

#endif	/* __E2K_KVM_THREAD_INFO_H */
