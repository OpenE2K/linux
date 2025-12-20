/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Guest kernel KVM process related definitions
 */

#ifndef __GUEST_PROCESS_H
#define __GUEST_PROCESS_H

#include <linux/types.h>
#include <linux/kvm.h>

#include <asm/kvm/cpu_regs_access.h>
#include <asm/regs_state.h>
#include <asm/process.h>

#include <asm/kvm/hypercall.h>

#include "traps.h"

/* timeout to wake up guest idle to check on need reschedule */
#define	GUEST_CPU_IDLE_TIMEOUT		HZ	/* every 1 sec. */
#define	GUEST_CPU_WAKE_UP_TIMEOUT	1	/* each jiffies to handle */
						/* timer interrupt */

extern int kvm_do_map_user_hard_stack_to_kernel(int nid,
		e2k_addr_t kernel_stack_base, e2k_addr_t user_stack_base,
		e2k_size_t kernel_size);

#endif	/* __GUEST_PROCESS_H */
