/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/****************** E2K PROTECTED MODE SPECIFIC STUFF *******************/

#ifndef _E2K_ASM_PROTECTED_MODE_H_
#define _E2K_ASM_PROTECTED_MODE_H_

#include <uapi/asm/protected_mode.h>
#include <linux/kconfig.h>

/*
 * This structure specifies attributes of protected syscall arguments:
 */
struct prot_syscall_arg_attrs {
	u64  mask; /* for coding specs see prot_sys_call_synopsis.c */
	/* The next 6 fields specify minimum allowed argument size
	 *                          in case of argument-descriptor.
	 * If negative value, this means size is defined by corresponding arg.
	 *             F.e. value (-3) means size is specified by argument #3.
	 */
	short size1; /* min allowed size of arg1 of particular system call */
	short size2; /* minimum allowed size of arg2  */
	short size3; /* minimum allowed size of arg3  */
	short size4; /* minimum allowed size of arg4  */
	short size5; /* minimum allowed size of arg5  */
	short size6; /* minimum allowed size of arg6  */
} __aligned(sizeof(void *)) /* For faster address calculation */;
extern const struct prot_syscall_arg_attrs prot_syscall_arg_masks[];

#if IS_ENABLED(CONFIG_SOFT_PM)
extern void init_arch_init_soft_pm_mode(void (*initer)(void *context_ptr));
extern void remove_arch_init_soft_pm_mode(void);
#endif /* CONFIG_SOFT_PM */

extern unsigned long protected_mode_check_env_debug_mask(const char *env_var_name,
							 const size_t max_len,
							 const unsigned long mask);

extern void arch_init_secure_computing_mode(void *context_ptr);

/*
 * The structure 'scm_controls_struct' specifies secure computing (protected) mode controls,
 *				defined in a .conf file in /etc/sysctl.d:
 *
 * The contents of the /etc/sysctl.d/e2k_scm.conf file may look like this:
 *
 * ##############################################################################
 * # Controls of the E2K Secure Computing (Protected) execution Mode (SCM)
 * # 0=disable, 1=enable, >1 option value/bitmask
 * ##############################################################################
 * # Uncomment the line below to enable detailded protected syscall debug output:
 * # kernel.e2k.SCM.syscall_debug_mode_enabled = 1
 *
 * # Default protected syscall execution mode (equivalent to the following env var set):
 * #        MODE_CHECK | EMPTYING_FREED_POINTERS | MESSAGES_IN_STDERR
 * # kernel.e2k.SCM.default_syscall_debug_mode = 0x084008
 *
 * # Uncomment the line below to block dynamic control of the protected execution thru env vars:
 * # kernel.e2k.SCM.dynamic_syscall_debug_control_disabled=1
 *
 * # Freeing descriptors mode:
 * # 1 - zeroing; 2 - emptying freed contents; 3 - check for dangling pointers
 * kernel.e2k.SCM.dangling_pointers_control = 2
 *
 * # Malloc operation mode in PM:
 * # 0 - 64-bit compatible; 1 - zeroing of memory allocated; 2 - emptying of memory allocated.
 * kernel.e2k.SCM.prot_malloc_mode_control = 2
 *
 * # Enabling/disabling risky protected syscalls that reduce security protection level:
 *
 * # kernel.e2k.SCM.protected_syscall_ptrace_enabled = 1
 * # kernel.e2k.SCM.syscall_unsafe_uint64_to_ptr_enabled = 1
 * # The syscall to return whole-size stack pointer (=1) or minimized pointer (=0):
 * # kernel.e2k.SCM.unsafe_uint64_to_ptr_mode_whole_stack_mode = 1
 * ##############################################################################
 */
struct scm_controls_struct {
	int syscall_debug_mode_enabled;
	int default_syscall_debug_mode;
	int dynamic_syscall_debug_control_disabled;
	int dangling_pointers_control;
	int prot_malloc_mode_control;

	int protected_syscall_ptrace_enabled;

	int syscall_unsafe_uint64_to_ptr_enabled;
	int unsafe_uint64_to_ptr_whole_stack_mode;
};
extern struct scm_controls_struct scm_controls;

/*
 * SCM controls setup from /proc/sys/kernel/e2k/SCM :
 */

static inline int get_sysctld_syscall_debug_mode_enabled(void)
{
	return scm_controls.syscall_debug_mode_enabled;
}

static inline int get_sysctld_default_syscall_debug_mode(void)
{
	return scm_controls.default_syscall_debug_mode ? scm_controls.default_syscall_debug_mode
							: PM_SC_DBG_MODE_DEFAULT;
}

static inline int get_sysctld_dangling_pointers_control(void)
{
	return scm_controls.dangling_pointers_control;
}

static inline int get_sysctld_prot_malloc_mode_control(void)
{
	return scm_controls.prot_malloc_mode_control;
}

static inline int get_sysctld_dynamic_syscall_debug_control_disabled(void)
{
	return scm_controls.dynamic_syscall_debug_control_disabled;
}

static inline int get_sysctld_protected_syscall_ptrace_enabled(void)
{
	return scm_controls.protected_syscall_ptrace_enabled;
}

static inline int get_sysctld_syscall_unsafe_uint64_to_ptr_enabled(void)
{
	return scm_controls.syscall_unsafe_uint64_to_ptr_enabled;
}

static inline int get_unsafe_uint64_to_ptr_whole_stack_mode(void)
{
	return scm_controls.unsafe_uint64_to_ptr_whole_stack_mode;
}

static inline int e2k_scm_sysctld_controls_enabled(void)
{
	return scm_controls.syscall_debug_mode_enabled != 0 ||
		scm_controls.default_syscall_debug_mode != 0 ||
		scm_controls.dynamic_syscall_debug_control_disabled != 0 ||
		scm_controls.dangling_pointers_control != 0 ||
		scm_controls.protected_syscall_ptrace_enabled != 0 ||
		scm_controls.syscall_unsafe_uint64_to_ptr_enabled != 0;
}

void print_sysctld_SCM_controls(void);

#endif /* _E2K_ASM_PROTECTED_MODE_H_ */
