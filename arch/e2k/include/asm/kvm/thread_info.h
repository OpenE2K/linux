/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * kvm_thread_info.h: In-kernel KVM guest thread info related definitions
 */

#pragma once

#include <linux/types.h>
#include <linux/kvm.h>
#include <linux/bitops.h>

#include <asm/trap_def.h>
#include <asm/cpu_regs_types.h>
#include <asm/stacks.h>

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/gpid.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */


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

#ifdef	CONFIG_VIRTUALIZATION

#define	GTI_DEBUG_MODE

#ifdef	GTI_DEBUG_MODE
#define	GTI_BUG_ON(cond)	BUG_ON(cond)
#else /* ! GTI_DEBUG_MODE */
#define	GTI_BUG_ON(cond)	do { } while (0)
#endif /* GTI_DEBUG_MODE */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/thread_info.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#endif /* CONFIG_VIRTUALIZATION */
