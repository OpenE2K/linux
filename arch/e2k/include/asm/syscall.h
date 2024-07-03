/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_SYSCALLS_H
#define _E2K_SYSCALLS_H

#include <uapi/linux/audit.h>

#include <asm/trap_table.h> /* for sys_call_table */

#ifdef CONFIG_PROTECTED_MODE
#include <asm/protected_syscalls.h>
#endif

/* The system call number is given by the user in 1 */
static inline int syscall_get_nr(struct task_struct *task,
				  struct pt_regs *regs)
{

	return (regs && from_syscall(regs)) ? regs->sys_num : -1;
}

static inline long syscall_get_return_value(struct task_struct *task,
					    struct pt_regs *regs)
{
	return regs->sys_rval;
}

static inline void syscall_set_return_value(struct task_struct *task,
					    struct pt_regs *regs,
					    int error, long val)
{
	regs->sys_rval = (long) error ?: val;
}

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned long *args)
{
	unsigned int n = 6, j;
	unsigned long *p = &regs->args[1];

	for (j = 0; j < n; j++) {
		if (!TASK_IS_PROTECTED(task))
			args[j] = p[j];
		else /* 'arg64_from_regs' uses natural arg numbering */
			args[j] = arg64_from_regs(regs, j + 1);
	}
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 const unsigned long *args)
{
	if (!TASK_IS_PROTECTED(task)) {
		unsigned int n = 6, j;
		unsigned long *p = &regs->args[1];

		for (j = 0; j < n; j++) {
			p[j] = args[j];
		}
	} else {
		PROTECTED_MODE_WARNING(PMSCERRMSG_FUNC_NOT_AVAILABLE_IN_PM,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], __func__);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
	}
}

static inline int syscall_get_arch(struct task_struct *task)
{
        return AUDIT_ARCH_E2K;
}

static inline void syscall_rollback(struct task_struct *task,
				    struct pt_regs *regs)
{
	/* Do nothing */
}

#endif /* _E2K_SYSCALLS_H */
