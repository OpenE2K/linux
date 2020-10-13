/*
 * Code for replacing ftrace calls with jumps.
 *
 * Copyright (C) 2007-2008 Steven Rostedt <srostedt@redhat.com>
 *
 * Thanks goes to Ingo Molnar, for suggesting the idea.
 * Mathieu Desnoyers, for suggesting postponing the modifications.
 * Arjan van de Ven, for keeping me straight, and explaining to me
 * the dangers of modifying code on the run.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/stacktrace.h>
#include <trace/syscall.h>
#include <asm/cacheflush.h>
#include <asm/ftrace.h>
#include <asm/e2k_debug.h> 
#ifdef CONFIG_STACKTRACE
 #include <linux/stacktrace.h>
#endif /* CONFIG_STACKTRACE */

#undef DEBUG_FTRACE_MODE
#undef DebugFTRACE
#define DEBUG_FTRACE_MODE 0
#if DEBUG_FTRACE_MODE
#define DebugFTRACE(...) printk(__VA_ARGS__)
#else
#define DebugFTRACE(...)
#endif

#define NO_ANY_USER    0
#define ONLY_THIS_USER 1
#define ALL_CLONE_USER 2
#define ONLY_THIS_USER_WO_FP_REG 3
#define ALL_CLONE_WO_FP_REG      4

#undef DBG
#undef DEBUG_STACK_TRACE
//#define DEBUG_STACK_TRACE    

#ifdef DEBUG_STACK_TRACE
# define DBG(fmt, args...) printk(fmt, ##args)
# define CHECK_STACK(x, reg)   check_last_wish(x, reg)
# define CHECK_FLAGS(x)        check_flags(x) 
#else /* !DEBUG_STACK_TRACE */
# define DBG(fmt, args...) 
# define CHECK_STACK(x, reg)  
# define CHECK_FLAGS(x)     
#endif /* DEBUG_STACK_TRACE */
#undef DEBUG_TRACE
#define DEBUG_TRACE     0 
#define Dbg_trace(fmt,args...) if (DEBUG_TRACE) {trace_printk(fmt,args);}

/* for debugging */
#define MAX_ONCE 10
#define MAX_1   0
#define MAX_2   0
#define MAX_3   0
#define MAX_4   0

int     ONCE[MAX_ONCE];

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
extern void (*ftrace_graph_return)(struct ftrace_graph_ret *);
extern int (*ftrace_graph_entry)(struct ftrace_graph_ent *);
extern int ftrace_graph_entry_stub(struct ftrace_graph_ent *);
#endif

void __interrupt ftrace_stub(unsigned long selfpc, unsigned long frompc,
		struct ftrace_ops *op, struct pt_regs *regs)
{
	return;
}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
# if E2K_MAXSR > 112
#  error Bad configuration
# endif
extern void return_to_handler_0(void);
extern void return_to_handler_1(void);
extern void return_to_handler_2(void);
extern void return_to_handler_3(void);
extern void return_to_handler_4(void);
extern void return_to_handler_5(void);
extern void return_to_handler_6(void);
extern void return_to_handler_7(void);
extern void return_to_handler_8(void);
extern void return_to_handler_9(void);
extern void return_to_handler_10(void);
extern void return_to_handler_11(void);
extern void return_to_handler_12(void);
extern void return_to_handler_13(void);
extern void return_to_handler_14(void);
extern void return_to_handler_15(void);
extern void return_to_handler_16(void);
extern void return_to_handler_17(void);
extern void return_to_handler_18(void);
extern void return_to_handler_19(void);
extern void return_to_handler_20(void);
extern void return_to_handler_21(void);
extern void return_to_handler_22(void);
extern void return_to_handler_23(void);
extern void return_to_handler_24(void);
extern void return_to_handler_25(void);
extern void return_to_handler_26(void);
extern void return_to_handler_27(void);
extern void return_to_handler_28(void);
extern void return_to_handler_29(void);
extern void return_to_handler_30(void);
extern void return_to_handler_31(void);
extern void return_to_handler_32(void);
extern void return_to_handler_33(void);
extern void return_to_handler_34(void);
extern void return_to_handler_35(void);
extern void return_to_handler_36(void);
extern void return_to_handler_37(void);
extern void return_to_handler_38(void);
extern void return_to_handler_39(void);
extern void return_to_handler_40(void);
extern void return_to_handler_41(void);
extern void return_to_handler_42(void);
extern void return_to_handler_43(void);
extern void return_to_handler_44(void);
extern void return_to_handler_45(void);
extern void return_to_handler_46(void);
extern void return_to_handler_47(void);
extern void return_to_handler_48(void);
extern void return_to_handler_49(void);
extern void return_to_handler_50(void);
extern void return_to_handler_51(void);
extern void return_to_handler_52(void);
extern void return_to_handler_53(void);
extern void return_to_handler_54(void);
extern void return_to_handler_55(void);
extern void return_to_handler_56(void);
extern void return_to_handler_57(void);
extern void return_to_handler_58(void);
extern void return_to_handler_59(void);
extern void return_to_handler_60(void);
extern void return_to_handler_61(void);
extern void return_to_handler_62(void);
extern void return_to_handler_63(void);
extern void return_to_handler_64(void);
extern void return_to_handler_65(void);
extern void return_to_handler_66(void);
extern void return_to_handler_67(void);
extern void return_to_handler_68(void);
extern void return_to_handler_69(void);
extern void return_to_handler_70(void);
extern void return_to_handler_71(void);
extern void return_to_handler_72(void);
extern void return_to_handler_73(void);
extern void return_to_handler_74(void);
extern void return_to_handler_75(void);
extern void return_to_handler_76(void);
extern void return_to_handler_77(void);
extern void return_to_handler_78(void);
extern void return_to_handler_79(void);
extern void return_to_handler_80(void);
extern void return_to_handler_81(void);
extern void return_to_handler_82(void);
extern void return_to_handler_83(void);
extern void return_to_handler_84(void);
extern void return_to_handler_85(void);
extern void return_to_handler_86(void);
extern void return_to_handler_87(void);
extern void return_to_handler_88(void);
extern void return_to_handler_89(void);
extern void return_to_handler_90(void);
extern void return_to_handler_91(void);
extern void return_to_handler_92(void);
extern void return_to_handler_93(void);
extern void return_to_handler_94(void);
extern void return_to_handler_95(void);
extern void return_to_handler_96(void);
extern void return_to_handler_97(void);
extern void return_to_handler_98(void);
extern void return_to_handler_99(void);
extern void return_to_handler_100(void);
extern void return_to_handler_101(void);
extern void return_to_handler_102(void);
extern void return_to_handler_103(void);
extern void return_to_handler_104(void);
extern void return_to_handler_105(void);
extern void return_to_handler_106(void);
extern void return_to_handler_107(void);
extern void return_to_handler_108(void);
extern void return_to_handler_109(void);
extern void return_to_handler_110(void);
extern void return_to_handler_111(void);

typedef void (*ftrace_return_handler_t)(void);

static const ftrace_return_handler_t return_to_handlers_table[E2K_MAXSR] = {
	&return_to_handler_0, &return_to_handler_1, &return_to_handler_2,
	&return_to_handler_3, &return_to_handler_4, &return_to_handler_5,
	&return_to_handler_6, &return_to_handler_7, &return_to_handler_8,
	&return_to_handler_9, &return_to_handler_10, &return_to_handler_11,
	&return_to_handler_12, &return_to_handler_13, &return_to_handler_14,
	&return_to_handler_15, &return_to_handler_16, &return_to_handler_17,
	&return_to_handler_18, &return_to_handler_19, &return_to_handler_20,
	&return_to_handler_21, &return_to_handler_22, &return_to_handler_23,
	&return_to_handler_24, &return_to_handler_25, &return_to_handler_26,
	&return_to_handler_27, &return_to_handler_28, &return_to_handler_29,
	&return_to_handler_30, &return_to_handler_31, &return_to_handler_32,
	&return_to_handler_33, &return_to_handler_34, &return_to_handler_35,
	&return_to_handler_36, &return_to_handler_37, &return_to_handler_38,
	&return_to_handler_39, &return_to_handler_40, &return_to_handler_41,
	&return_to_handler_42, &return_to_handler_43, &return_to_handler_44,
	&return_to_handler_45, &return_to_handler_46, &return_to_handler_47,
	&return_to_handler_48, &return_to_handler_49, &return_to_handler_50,
	&return_to_handler_51, &return_to_handler_52, &return_to_handler_53,
	&return_to_handler_54, &return_to_handler_55, &return_to_handler_56,
	&return_to_handler_57, &return_to_handler_58, &return_to_handler_59,
	&return_to_handler_60, &return_to_handler_61, &return_to_handler_62,
	&return_to_handler_63, &return_to_handler_64, &return_to_handler_65,
	&return_to_handler_66, &return_to_handler_67, &return_to_handler_68,
	&return_to_handler_69, &return_to_handler_70, &return_to_handler_71,
	&return_to_handler_72, &return_to_handler_73, &return_to_handler_74,
	&return_to_handler_75, &return_to_handler_76, &return_to_handler_77,
	&return_to_handler_78, &return_to_handler_79, &return_to_handler_80,
	&return_to_handler_81, &return_to_handler_82, &return_to_handler_83,
	&return_to_handler_84, &return_to_handler_85, &return_to_handler_86,
	&return_to_handler_87, &return_to_handler_88, &return_to_handler_89,
	&return_to_handler_90, &return_to_handler_91, &return_to_handler_92,
	&return_to_handler_93, &return_to_handler_94, &return_to_handler_95,
	&return_to_handler_96, &return_to_handler_97, &return_to_handler_98,
	&return_to_handler_99, &return_to_handler_100, &return_to_handler_101,
	&return_to_handler_102, &return_to_handler_103, &return_to_handler_104,
	&return_to_handler_105, &return_to_handler_106, &return_to_handler_107,
	&return_to_handler_108, &return_to_handler_109, &return_to_handler_110,
	&return_to_handler_111
};


__noreturn void panic_ftrace_graph_cr()
{
	int i;

	if (current->ret_stack) {
		for (i = 0; i <= current->curr_ret_stack; i++)
			pr_emerg("%d: %pS -> %pS\n", i,
				(void *) current->ret_stack[i].ret,
				(void *) current->ret_stack[i].func);
	} else {
		pr_emerg("no ret_stack in return_to_handler\n");
	}

	panic("BUG in ftrace - returned to return_to_handler!\n");
}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */


#ifdef CONFIG_DYNAMIC_FTRACE
int __init ftrace_dyn_arch_init(void *data)
{
	/* return value is done indirectly via data */
	*(unsigned long *)data = 0;

	return 0;
}

static int saved_function_trace_stop;
int ftrace_arch_code_modify_prepare(void)
{
	saved_function_trace_stop = function_trace_stop;
	function_trace_stop = 1;

	return 0;
}

/* Update instruction cache on all processors. */
int ftrace_arch_code_modify_post_process(void)
{
	flush_icache_all();
	function_trace_stop = saved_function_trace_stop;

	return 0;
}

# define SS_CT_SHIFT 5
# define SS_CT_MASK (0xf << SS_CT_SHIFT)

#ifdef CONFIG_STACKTRACE
static unsigned long init_trace_data_enabled[100];

static struct stack_trace saved_trace_enabled = {
	.nr_entries = 0,
	.max_entries = ARRAY_SIZE(init_trace_data_enabled),
	.entries = init_trace_data_enabled,
	.skip = 0,
};

static unsigned long init_trace_data_disabled[100];

static struct stack_trace saved_trace_disabled = {
	.nr_entries = 0,
	.max_entries = ARRAY_SIZE(init_trace_data_disabled),
	.entries = init_trace_data_disabled,
	.skip = 0,
};
#endif /* CONFIG_STACKTRACE */

static inline int e2k_modify_call(const unsigned long addr,
		const unsigned long ip,
		const unsigned long phys_ip,
		const int enable)
{
	struct {
		instr_hs_t HS;
		instr_ss_t SS;
	} instruction;

# if DEBUG_FTRACE_MODE
	if (enable)
		DebugFTRACE("Enabling _mcount at %lx (phys %lx)\n",
				ip, phys_ip);
	else
		DebugFTRACE("Disabling _mcount at %lx (phys %lx)\n",
				ip, phys_ip);
# endif

	if (addr != FTRACE_ADDR) {
		pr_info("Passed addr is %lx instead of %lx\n",
				addr, FTRACE_ADDR);
		return -EINVAL;
	}

	/* Read the header and stubs syllables. */
	*((u64 *) &instruction) = E2K_READ_MAS_D(phys_ip, MAS_LOAD_PA);

	/* Check that the stubs syllable is present. */
	if (!AS(instruction.HS).s) {
		pr_info("Instruction at %lx does not have stubs syllable!\n"
				"Code: %llx\n", ip, *((u64 *) &instruction));
		return -EINVAL;
	}

	/* Sanity check: test that the CS1 syllable
	 * (which contains actual call) is present. */
	if (!(AS(instruction.HS).c & 2)) {
		pr_info("Instruction at %lx does not have CS1 syllable!\n"
				"Code: %llx\n", ip, *((u64 *) &instruction));
		return -EINVAL;
	}

	if (enable) {
		/* Check that the condition is not 1 already. */
		if (((AS(instruction.SS).ctcond & SS_CT_MASK) >> SS_CT_SHIFT)
				== 1) {
#ifdef CONFIG_STACKTRACE
			/* FIXME */
			extern struct stack_trace saved_trace_enabled;
			printk(" print_stack_trace saved_trace_enabled\n");
			print_stack_trace(&saved_trace_enabled, 0);
#endif /* CONFIG_STACKTRACE */
			printk("Enabling _mcount at %lx (phys %lx)\n",
				ip, phys_ip);
			WARN_ON(1);
			return -EINVAL;
		}

		/* Set the condition to 1. */
		AS(instruction.SS).ctcond &= ~SS_CT_MASK;
		AS(instruction.SS).ctcond |= 1 << SS_CT_SHIFT;
	} else {
		/* Check that the condition is not 0 already. */
		if ((AS(instruction.SS).ctcond & SS_CT_MASK) == 0) {
#ifdef CONFIG_STACKTRACE
			/* FIXME */
			extern struct stack_trace saved_trace_enabled;
			extern struct stack_trace saved_trace_disabled;
			printk(" print_stack_trace saved_trace_disabled\n");
			print_stack_trace(&saved_trace_disabled, 0);
			printk(" print_stack_trace saved_trace_enabled\n");
			print_stack_trace(&saved_trace_enabled, 0);
#endif /* CONFIG_STACKTRACE */
			printk("Disabling _mcount at %lx (phys %lx)\n",
				ip, phys_ip);
			WARN_ON(1);
			return -EINVAL;
		}

		/* Set the condition to 0. */
		AS(instruction.SS).ctcond &= ~SS_CT_MASK;
	}

	/* Write the modified syllable. */
	E2K_WRITE_MAS_D(phys_ip, *((u64 *) &instruction), MAS_STORE_PA);

	return 0;
}

int ftrace_make_nop(struct module *mod,
		struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long ip = rec->ip, phys_ip;
	int node, ret = 0;

	for_each_node_has_dup_kernel(node) {
		phys_ip = node_kernel_address_to_phys(node, ip);
		if (phys_ip == -EINVAL) {
			ret = -EFAULT;
			WARN_ON_ONCE(1);
			break;
		}

		ret = e2k_modify_call(addr, ip, phys_ip, 0);
		if (ret)
			return ret;

		if (!THERE_IS_DUP_KERNEL)
			break;

		/* Modules are not duplicated */
		if (!is_duplicated_code(ip))
			break;
	}

	return ret;
}

int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long ip = rec->ip, phys_ip;
	int node, ret = 0;

	for_each_node_has_dup_kernel(node) {
		phys_ip = node_kernel_address_to_phys(node, ip);
		if (phys_ip == -EINVAL) {
			ret = -EFAULT;
			WARN_ON_ONCE(1);
			break;
		}

		ret = e2k_modify_call(addr, ip, phys_ip, 1);
		if (ret)
			return ret;

		if (!THERE_IS_DUP_KERNEL)
			break;

		/* Modules are not duplicated */
		if (!is_duplicated_code(ip))
			break;
	}

	return ret;
}

static ftrace_func_t current_tracer_function = &ftrace_stub;

int ftrace_update_ftrace_func(ftrace_func_t func)
{
	current_tracer_function = func;

	return 0;
}

# ifdef CONFIG_FUNCTION_GRAPH_TRACER
static int ftrace_graph_caller_enabled = 0;

int ftrace_enable_ftrace_graph_caller(void)
{
	ftrace_graph_caller_enabled = 1;

	return 0;
}

int ftrace_disable_ftrace_graph_caller(void)
{
	ftrace_graph_caller_enabled = 0;

	return 0;
}
# endif /* CONFIG_FUNCTION_GRAPH_TRACER */

void _mcount(const e2k_cr0_hi_t frompc)
{
	unsigned long selfpc;

	selfpc = E2K_GET_DSREG_NV(cr0.hi);

	if (function_trace_stop) {
		return;
        }        

	if (current_tracer_function != ftrace_stub)
		current_tracer_function(selfpc, AW(frompc),
					function_trace_op, NULL);

# ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (ftrace_graph_caller_enabled) {
		struct ftrace_graph_ent	trace;
		unsigned long		flags;
		u64			wbs;
		e2k_mem_crs_t		*frame;
		e2k_pcsp_lo_t		pcsp_lo;
		e2k_pcsp_hi_t		pcsp_hi;
		u64			cr_ind;
		u64			base;
		u64			*parent;

		if (unlikely(atomic_read(&current->tracing_graph_pause)))
			return;

		raw_all_irq_save(flags);
		E2K_FLUSHC;

		/* Find frame of the function being traced. */
		pcsp_hi = READ_PCSP_HI_REG();
		pcsp_lo = READ_PCSP_LO_REG();

		cr_ind = AS_STRUCT(pcsp_hi).ind;
		base = AS_STRUCT(pcsp_lo).base;

		frame = ((e2k_mem_crs_t *) (base + cr_ind)) - 1;

		E2K_FLUSH_WAIT;

		wbs = frame->cr1_lo.fields.wbs;

		parent = &frame->cr0_hi.word;

		if (unlikely(frame->cr1_lo.fields.wpsz > 4
				|| wbs >= E2K_MAXSR)) {
			static int once = 1;
			/* return_to_hook() currently assumes that the
			 * parameters area is 8 registers long. This is
			 * in accordance with existing conventions. */
			if (once) {
				once = 0;
				pr_err("Bug in ftrace - psize(%d) is not 4 or wbs(%lld) is too big!\n",
						frame->cr1_lo.fields.wpsz, wbs);
				WARN_ON(1);
				goto out;
			}
		}

		*parent = (u64) return_to_handlers_table[wbs];

		if (unlikely(ftrace_push_return_trace(AW(frompc), selfpc,
				&trace.depth, (u64) frame) == -EBUSY))
			goto undo;

		trace.func = selfpc;

		/* Only trace if the calling function expects to */
		if (unlikely(!ftrace_graph_entry(&trace))) {
			current->curr_ret_stack--;
undo:
			E2K_FLUSHC;
			E2K_FLUSH_WAIT;
			*parent = AW(frompc);
		}

out:
		raw_all_irq_restore(flags);
	}
# endif /* CONFIG_FUNCTION_GRAPH_TRACER */
}
#else	/* CONFIG_DYNAMIC_FTRACE */
void _mcount(const e2k_cr0_hi_t frompc)
{
	unsigned long		selfpc;
# ifdef CONFIG_FUNCTION_GRAPH_TRACER
	struct ftrace_graph_ent	trace;
	unsigned long		flags;
	u64			wbs;
	e2k_mem_crs_t		*frame;
	e2k_pcsp_lo_t		pcsp_lo;
	e2k_pcsp_hi_t		pcsp_hi;
	u64			cr_ind;
	u64			base;
	u64			*parent;
# endif

# ifdef CONFIG_FUNCTION_TRACER
	if (function_trace_stop)
		return;

	if (unlikely(ftrace_trace_function != ftrace_stub))
		goto do_trace;
# endif

# ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (unlikely(ftrace_graph_return != ftrace_stub ||
			ftrace_graph_entry != ftrace_graph_entry_stub))
		goto do_graph_trace;
# endif /* CONFIG_FUNCTION_GRAPH_TRACER*/

	return;

# ifdef CONFIG_FUNCTION_TRACER
do_trace:
# endif
	selfpc = E2K_GET_DSREG_NV(cr0.hi);
	ftrace_trace_function(selfpc, AS_WORD(frompc), function_trace_op, NULL);

	return;

# ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/*
	 * Design of the function graph tracer is documented
	 * in Documentation/e2k/ftrace-function-graph-design.txt
	 */
do_graph_trace:
	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	raw_all_irq_save(flags);
	E2K_FLUSHC;

	/* Find frame of the function being traced. */
	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();

	selfpc = E2K_GET_DSREG_NV(cr0.hi);

	cr_ind = AS_STRUCT(pcsp_hi).ind;
	base = AS_STRUCT(pcsp_lo).base;

	frame = ((e2k_mem_crs_t *) (base + cr_ind)) - 1;

	E2K_FLUSH_WAIT;

	wbs = frame->cr1_lo.fields.wbs;

	parent = &frame->cr0_hi.word;

	if (unlikely(frame->cr1_lo.fields.wpsz > 4)) {
		static int once = 1;
		/* return_to_hook() currently assumes that the
		 * parameters area is 8 registers long. This is
		 * in accordance with existing conventions. */
		if (once) {
			once = 0;
			printk("Bug in ftrace - psize is not 4!\n");
			WARN_ON(1);
			goto out;
		}
	}

	*parent = return_to_handlers_table[wbs];

	if (unlikely(ftrace_push_return_trace(AW(frompc), selfpc,
			&trace.depth, (u64) frame) == -EBUSY))
		goto undo;

	trace.func = selfpc;

	/* Only trace if the calling function expects to */
	if (unlikely(!ftrace_graph_entry(&trace))) {
		current->curr_ret_stack--;
undo:
		E2K_FLUSHC;
		E2K_FLUSH_WAIT;
		*parent = AW(frompc);
	}

out:
	raw_all_irq_restore(flags);

	return;
# endif /* CONFIG_FUNCTION_GRAPH_TRACER */
}
#endif	/* CONFIG_DYNAMIC_FTRACE */
EXPORT_SYMBOL(_mcount);

#ifdef CONFIG_FTRACE_SYSCALLS
extern unsigned long *sys_call_table;

unsigned long __init arch_syscall_addr(int nr)
{
	return (unsigned long)(&sys_call_table)[nr];
}
#endif

