#ifndef _E2K_SYSCALLS_H
#define _E2K_SYSCALLS_H

#include <uapi/linux/audit.h>

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
	regs->sys_rval = val;
}

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned long *args)
{
	unsigned int n = 6, j;
	unsigned long *p = &regs->args[1];

	for (j = 0; j < n; j++) {
		args[j] = p[j];
	}
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 const unsigned long *args)
{
	unsigned int n = 6, j;
	unsigned long *p = &regs->args[1];

	for (j = 0; j < n; j++) {
		p[j] = args[j];
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
