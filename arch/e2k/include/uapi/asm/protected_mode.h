/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * arch/e2k/include/asm/protected_mode.h, v 1.0 07/04/2020.
 *
 * Copyright (C) 2020 MCST
 */

/****************** E2K PROTECTED MODE SPECIFIC STUFF *******************/

#ifndef _E2K_PROTECTED_MODE_H_
#define _E2K_PROTECTED_MODE_H_

/*
 * PROTECTED MODE DEBUG CONTROLS:
 * When control below is set, kernel reports extra info and issues
 * identified to journal. Use command 'dmesg' to display these messages.
 * Set up corresponding env vars to 0/1 to control particular checks
 *                   or use arch_prctl() syscall to setup debug mode.
 */
/* Protected syscall debug mode initialized: */
#define PM_SC_DBG_MODE_INIT		0x0001
/* Output debug info on system calls to system journal: */
#define PM_SC_DBG_MODE_DEBUG		0x0002
/* Output debug info on protected complex syscall wrappers to system journal: */
#define PM_SC_DBG_MODE_COMPLEX_WRAPPERS	0x0004
/* Report issue to journal if syscall arg doesn't match expected format: */
#define PM_SC_DBG_MODE_CHECK		0x0008
/* If error in arg format detected, don't block syscall and proceed with execution: */
#define PROTECTED_MODE_SOFT		0x0010
/* Output to journal debug info on converting structures in syscall args: */
#define PM_SC_DBG_MODE_CONV_STRUCT	0x0020
/* Output to journal debug info related to signal manipulation: */
#define PM_SC_DBG_MODE_SIGNALS		0x0040
/* Don't output to journal warnings/alerts/errors (for better performance): */
#define PM_SC_DBG_MODE_NO_ERR_MESSAGES	0x0080

/* libc specific mmu control stuff: */

/* Enable check for dangling descriptors: */
#define PM_MM_CHECK_4_DANGLING_POINTERS 0x1000
/* Zeroing freed descriptor contents: */
#define PM_MM_ZEROING_FREED_POINTERS    0x2000
/* Emptying freed descriptor contents / light check for dangling descriptors: */
#define PM_MM_EMPTYING_FREED_POINTERS   0x4000

/* Enable all debug/diagnostic output to system journal: */
#define PM_SC_DBG_MODE_ALL		0xffff406f
/* Disable debug/diagnostic output to system journal: */
#define PM_SC_DBG_MODE_DISABLED		PM_SC_DBG_MODE_INIT

#define IF_PM_DBG_MODE(mask)	\
	(current->mm->context.pm_sc_debug_mode & (mask))

#define PM_SC_DBG_MODE_DEFAULT		(PM_SC_DBG_MODE_CHECK \
					| PM_MM_EMPTYING_FREED_POINTERS)

/* For backward compatibility: */
#define PM_SC_DBG_MODE_WARN_ONLY	PROTECTED_MODE_SOFT

/*
 * Arch-specific options for arch_prctl() syscall:
 */

/* PM debug mode controls */
# define PR_PM_DBG_MODE_SET		8192
# define PR_PM_DBG_MODE_GET		8193
# define PR_PM_DBG_MODE_RESET		8194
# define PR_PM_DBG_MODE_ADD		8195 /* adds to existing debug mode */
# define PR_PM_DBG_MODE_DEL		8196 /* removes from existing mode */


/*
 * Flags for the protected_sys_clean_descriptors() function:
 */
/* 0 - clean freed descriptor list */
#define CLEAN_DESCRIPTORS_SINGLE	1 /* clean single descriptor 'addr' */
#define CLEAN_DESCRIPTORS_NO_GARB_COLL	2 /* No garbidge collection */

#endif /* _E2K_PROTECTED_MODE_H_ */
