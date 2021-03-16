#ifndef _ASM_E2K_FTRACE_H
#define _ASM_E2K_FTRACE_H

static inline void return_to_handler(void){}

extern struct ftrace_ops *function_trace_op;

#ifdef CONFIG_HAVE_FUNCTION_GRAPH_FP_TEST
# define HAVE_FUNCTION_GRAPH_FP_TEST
#endif

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

#define ftrace_return_address(n) __e2k_kernel_return_address(n)

#ifdef CONFIG_E2K_STACKS_TRACER
extern int stack_tracer_enabled;
extern int stack_tracer_kernel_only;
int
stack_trace_sysctl(struct ctl_table *table, int write,
		   void __user *buffer, size_t *lenp,
		   loff_t *ppos);
#endif

#endif /* _ASM_E2K_FTRACE_H */

