#ifndef _E2K_HW_BREAKPOINT_H
#define _E2K_HW_BREAKPOINT_H

#include <linux/types.h>

struct arch_hw_breakpoint {
	unsigned long address;
	u8 len;
	u8 type;
	u8 ss;
};

#define HBP_NUM 4
static inline int hw_breakpoint_slots(int type)
{
	return HBP_NUM;
}

struct perf_event;
struct perf_event_attr;
struct task_struct;

extern int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw);
extern int hw_breakpoint_arch_parse(struct perf_event *bp,
				    const struct perf_event_attr *attr,
				    struct arch_hw_breakpoint *hw);

extern int arch_install_hw_breakpoint(struct perf_event *bp);
extern void arch_uninstall_hw_breakpoint(struct perf_event *bp);

struct notifier_block;
extern int hw_breakpoint_exceptions_notify(
		struct notifier_block *unused, unsigned long val, void *data);

extern void hw_breakpoint_pmu_read(struct perf_event *bp);

#ifdef	CONFIG_HAVE_HW_BREAKPOINT
extern void bp_data_overflow_handle(struct pt_regs *regs);
extern void bp_instr_overflow_handle(struct pt_regs *regs);
extern void clear_ptrace_hw_breakpoint(struct task_struct *tsk);
#else	/* ! CONFIG_HAVE_HW_BREAKPOINT */
static inline void bp_data_overflow_handle(struct pt_regs *regs) { }
static inline void bp_instr_overflow_handle(struct pt_regs *regs) { }
static inline void clear_ptrace_hw_breakpoint(struct task_struct *tsk) {}
#endif	/* CONFIG_HAVE_HW_BREAKPOINT */

#endif /* _E2K_HW_BREAKPOINT_H */
