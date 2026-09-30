/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

/****************** E2K PROTECTED MODE SPECIFIC STUFF *******************/

#ifndef _E2K_PROTECTED_MODE_H_
#define _E2K_PROTECTED_MODE_H_

/*
 * PROTECTED MODE DEBUG CONTROLS:
 * When control below is set, kernel reports extra info and issues
 * identified to stderr/journal.
 * Use command 'dmesg' to display messages reported to journal.
 * Set up corresponding env vars to 0/1 to control particular checks
 *                   or use arch_prctl() syscall to setup debug mode.
 *
 * NB> IMPORTANT: Glibc mmu control stuff depends on these settings.
 * NB> IMPORTANT: never change these without approval from GLIBC owner.
 */

/* Output debug info on system calls: */
#define PM_SC_DBG_MODE_DEBUG		0x000002
/* Output debug info on protected complex syscall wrappers: */
#define PM_SC_DBG_MODE_COMPLEX_WRAPPERS	0x000004
/* Report issue to journal if syscall arg doesn't match expected format: */
#define PM_SC_DBG_MODE_CHECK		0x000008
/* If error in arg format detected, don't block syscall but run it anyway: */
#define PROTECTED_MODE_SOFT		0x000010
/* Output to journal debug info on converting structures in syscall args: */
#define PM_SC_DBG_MODE_CONV_STRUCT	0x000020
/* Output to journal debug info related to signal manipulation: */
#define PM_SC_DBG_MODE_SIGNALS		0x000040
/* Warn on buffers to write that contain tagged data: */
#define PM_SC_CHECK4TAGS_IN_BUFF	0x000080
/* Default max size of buffer to check for tagged data: */
#define PM_SC_CHECK4TAGS_DEFAULT_MAX_SIZE	(2 * DESCRIPTOR_SIZE)
/* Report extra warnings that protected execution mode provides: */
#define PM_SC_DBG_WARNINGS		0x000100
/* Treat warnings as errors: */
#define PM_SC_DBG_WARNINGS_AS_ERRORS	0x000200
/* Don't output to journal warnings/alerts/errors (for better performance): */
#define PM_SC_DBG_MODE_NO_ERR_MESSAGES	0x000400
/* Compatible 'clone' syscall behaviour: max stack size used; size-limited otherwise: */
#define PM_SC_COMPATIBLE_CLONE		0x000800 /* details see in the syscall wrapper */

/* libc specific mmu control stuff: */

/* Enable check for dangling descriptors: */
#define PM_MM_CHECK_4_DANGLING_POINTERS 0x001000
/* Zeroing freed descriptor contents: */
#define PM_MM_ZEROING_FREED_POINTERS    0x002000
/* Emptying freed descriptor contents / light check for dangling descriptors: */
#define PM_MM_EMPTYING_FREED_POINTERS   0x004000

#define PM_MM_FREE_PTR_MODE_MASK	0x007000
/* Default mmu control mode: */
#define PM_MM_DEFAULT_FREE_PTR_MODE	PM_MM_ZEROING_FREED_POINTERS

/* Malloc ops mode in PM: no initialization of memory allocated (64-bit compatible) */
#define PM_MM_MALLOC_MODE_MASK		0x030000UL
#define PM_MM_MALLOC_MODE_MASK_SHIFT	16 /* 0x030000 */
enum {
	PM_MALLOC_MODE_COMPATIBLE =	0, /* 64-bit compatible mode */
	PM_MALLOC_MODE_ZEROING =	1, /* zeroing of memory allocated */
	PM_MALLOC_MODE_EMPTYING =	2  /* emptying of memory allocated */
};
#define MAX_PM_MALLOC_MODE		2
#define PM_MM_MALLOC_MODE_DEFAULT	PM_MALLOC_MODE_ZEROING

/* Don't run clean_descriptors syscall (f.e. in the 'unsafe' protected mode: */
#define PM_SC_NO_CLEAN_DESCRIPTORS	0x040000

/* Error Messaging Interface:
 * NB> Calculated from the env vars at thread start up time
 * Message Language type: 0 - C / 1 - KOI8-R/RU.UTF-8
 */
#define PM_SC_ERR_MESSAGES_RU_UTF	0x0100000
#define PM_SC_ERR_MESSAGES_KOI8_R	0x0200000
/* Deliver diagnostic messages to journal: */
#define PM_DIAG_MESSAGES_IN_JOURNAL	0x0400000
/* Deliver diagnostic messages to stderr: */
#define PM_DIAG_MESSAGES_IN_STDERR	0x0800000

/* Print out contents of string syscall arguments: */
#define PM_SC_DBG_STRING_ARGS			0x1000000

/* Enable 'ptrace' syscall in PM: */
#define PM_SC_PTRACE_ENABLED			0x2000000
/* Enable 'unsafe_uint64_to_ptr' syscall in PM: */
#define PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED	0x4000000
/* The 'unsafe_uint64_to_ptr' syscall options:	*/
/* The syscall to return whole-size stack descriptor: */
#define PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE	0x0001
/* 3rd argument of the syscall to return descriptor (i.e. this is pointer-to-descriptor) */
#define PM_SC_UNSAFE_UINT64_TO_PTR_RETURN_MODE	0x1000

/* Sometimes it's important to know a repaired descriptor points at the stack memory: */
#define PM_SC_DBG_WARN_ON_REPAIRED_SAP		0x10000000
/* Enable 'extended' boundaries in repaired descriptor: */
#define PM_SC_UNSAFE_EXT_REPAIRED_BOUNDARIES	0x20000000

/* Enable all debug/diagnostic output: */
#define PM_SC_DBG_MODE_ALL		(PM_SC_DBG_MODE_DEBUG \
					| PM_SC_DBG_MODE_COMPLEX_WRAPPERS \
					| PM_SC_DBG_MODE_CHECK \
					| PM_SC_DBG_MODE_CONV_STRUCT \
					| PM_SC_DBG_MODE_SIGNALS \
					| PM_SC_DBG_STRING_ARGS \
					| PM_SC_CHECK4TAGS_IN_BUFF \
					| PM_SC_DBG_WARNINGS \
					| PM_MM_EMPTYING_FREED_POINTERS)

/* All debug/diagnostic print mask: */
#define PM_SC_DBG_DIAG_MASK_ALL		(PM_SC_DBG_MODE_DEBUG			\
					| PM_SC_DBG_MODE_COMPLEX_WRAPPERS	\
					| PM_SC_DBG_MODE_CHECK			\
					| PM_SC_DBG_MODE_CONV_STRUCT		\
					| PM_SC_DBG_MODE_SIGNALS		\
					| PM_SC_CHECK4TAGS_IN_BUFF		\
					| PM_SC_DBG_WARNINGS)

#define IF_PM_DBG_MODE(mask)	\
	(current->mm->context.pm_sc_debug_mode & (mask))

#define PM_SC_DBG_MODE_DEFAULT		(PM_SC_DBG_MODE_CHECK \
					| PM_MM_DEFAULT_FREE_PTR_MODE \
					| PROTECTED_MODE_SOFT \
					| PM_DIAG_MESSAGES_IN_STDERR)

#define PM_SC_DBG_ISSUE_WARNINGS (PM_SC_DBG_WARNINGS | PM_SC_DBG_WARNINGS_AS_ERRORS)

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
