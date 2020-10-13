#ifndef _ASM_E2K_FTRACE_H
#define _ASM_E2K_FTRACE_H

extern struct ftrace_ops *function_trace_op;

#ifdef CONFIG_DYNAMIC_FTRACE
/* On e2k _mcount() is used for both dynamic and static cases. */
# define FTRACE_ADDR ((unsigned long) _mcount)
# define MCOUNT_ADDR ((unsigned long) _mcount)
# define MCOUNT_INSN_SIZE 8

# define ARCH_SUPPORTS_FTRACE_OPS 1

extern void _mcount(e2k_cr0_hi_t frompc);

struct dyn_arch_ftrace {
	/* No extra data needed for e2k */
};

static inline unsigned long ftrace_call_adjust(unsigned long addr)
{
	return addr;
}
#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
extern unsigned long ftrace_return_to_handler(unsigned long frame_pointer);
#endif

#define HAVE_ARCH_CALLER_ADDR
#define CALLER_ADDR0 ((unsigned long)__builtin_return_address(0))
#define CALLER_ADDR1 ((unsigned long)__builtin_return_address(1))
#define CALLER_ADDR2 ((unsigned long)__builtin_return_address(2))
#define CALLER_ADDR3 ((unsigned long)__builtin_return_address(3))
#define CALLER_ADDR4 ((unsigned long)__builtin_return_address(4))
#define CALLER_ADDR5 ((unsigned long)__builtin_return_address(5))
#define CALLER_ADDR6 ((unsigned long)__builtin_return_address(6))

#ifdef CONFIG_E2K_STACKS_TRACER
extern int stack_tracer_enabled;
extern int stack_tracer_kernel_only;
int
stack_trace_sysctl(struct ctl_table *table, int write,
		   void __user *buffer, size_t *lenp,
		   loff_t *ppos);
#endif

#endif /* _ASM_E2K_FTRACE_H */

