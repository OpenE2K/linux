#ifndef _E2K_SYSCALLS_H
#define _E2K_SYSCALLS_H

/* The system call number is given by the user in 1 */
static inline long syscall_get_nr(struct task_struct *task,
				  struct pt_regs *regs)
{

	return (regs && from_syscall(regs)) ? regs->sys_num : -1L;
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
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
	unsigned int j;
	unsigned long *p = &regs->arg1;

	for (j = 0; j < n; j++) {
		args[j] = p[j];
	}
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 const unsigned long *args)
{
	unsigned int j;
	unsigned long *p = &regs->arg1;

	for (j = 0; j < n; j++) {
		p[j] = args[j];
	}
}


#endif /* _E2K_SYSCALLS_H */
