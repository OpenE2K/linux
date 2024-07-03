/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/hw_breakpoint.h>
#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>

#include <asm/e2k_debug.h>
#include <asm/process.h>
#include <asm/traps.h>
#include <linux/uaccess.h>


int hw_breakpoint_arch_parse(struct perf_event *bp,
			     const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw)
{
	if (cpu_has(CPU_HWBUG_SPURIOUS_EXC_DATA_DEBUG) &&
			attr->bp_type != HW_BREAKPOINT_X) {
		if (attr->bp_addr >= 0 && attr->bp_addr <= 30)
			return -EINVAL;
	}

	/* Type */
	switch (attr->bp_type) {
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W | HW_BREAKPOINT_R:
		break;
	case HW_BREAKPOINT_X:
		/*
		 * We don't allow kernel breakpoints in places that are not
		 * acceptable for kprobes.  On non-kprobes kernels, we don't
		 * allow kernel breakpoints at all.
		 */
		if (attr->bp_addr >= TASK_SIZE) {
#ifdef CONFIG_KPROBES
			if (within_kprobe_blacklist(attr->bp_addr))
				return -EINVAL;
#else
			return -EINVAL;
#endif
		}
		break;
	default:
		return -EINVAL;
	}

	switch (attr->bp_len) {
	case HW_BREAKPOINT_LEN_1:
	case HW_BREAKPOINT_LEN_2:
	case HW_BREAKPOINT_LEN_4:
	case HW_BREAKPOINT_LEN_8:
	case HW_BREAKPOINT_LEN_16:
		break;
	default:
		return -EINVAL;
	}

	if (attr->bp_addr & (attr->bp_len - 1))
		return -EINVAL;

	if (attr->bp_addr > E2K_VA_MASK)
		return -EINVAL;

	hw->address = attr->bp_addr;
	hw->type = attr->bp_type;
	hw->len = attr->bp_len;
	hw->ss = 0;

	return 0;
}

/*
 * Check for virtual address in kernel space.
 */
int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw)
{
	unsigned long max_addr = user_addr_max();

	/*
	 * We don't need to worry about (addr + len - 1) overflowing:
	 * we already require that va is aligned to a multiple of len.
	 */
	return hw->address >= max_addr || hw->address + hw->len - 1 >= max_addr;
}


/*
 * Stores the breakpoints currently in use on each breakpoint address
 * register for each cpus
 */
static DEFINE_PER_CPU(struct perf_event *, bp_instr_slot[HBP_NUM]);
static DEFINE_PER_CPU(struct perf_event *, bp_data_slot[HBP_NUM]);

DEFINE_PER_CPU(u8, perf_bps_used);

static inline struct perf_event **get_bp_slot_ptr(int bp_num, int is_data_bp)
{
	struct perf_event **slot;

	if (is_data_bp)
		slot = this_cpu_ptr(&bp_data_slot[bp_num]);
	else
		slot = this_cpu_ptr(&bp_instr_slot[bp_num]);

	return slot;
}

static inline u32 get_bp_mask(int is_data_bp, int bp_num)
{
	return 1 << (4 * !!is_data_bp + bp_num);
}

static inline int __arch_install_hw_breakpoint(int bp_num, int is_data_bp,
		struct arch_hw_breakpoint *info)
{
	unsigned long flags;
	int ret;

	raw_all_irq_save(flags);
	if (is_data_bp)
		ret = set_hardware_data_breakpoint(info->address, info->len,
				!!(info->type & HW_BREAKPOINT_W),
				!!(info->type & HW_BREAKPOINT_R),
				0, bp_num, 1);
	else
		ret = set_hardware_instr_breakpoint(info->address,
						    0, bp_num, 1);

	if (!ret)
		__this_cpu_or(perf_bps_used, get_bp_mask(is_data_bp, bp_num));
	raw_all_irq_restore(flags);

	return ret;
}

/*
 * Install a perf counter breakpoint.
 *
 * We seek a free debug address register and use it for this
 * breakpoint. Eventually we enable it in the debug control register.
 *
 * Atomic: we hold the counter->ctx->lock and we only handle variables
 * and registers local to this cpu.
 */
int arch_install_hw_breakpoint(struct perf_event *bp)
{
	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
	int i, is_data_bp;

	is_data_bp = info->type & (HW_BREAKPOINT_R|HW_BREAKPOINT_W);

	for (i = 0; i < HBP_NUM; i++) {
		struct perf_event **slot = get_bp_slot_ptr(i, is_data_bp);

		if (!*slot) {
			*slot = bp;
			break;
		}
	}

	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
		return -EBUSY;

	return __arch_install_hw_breakpoint(i, is_data_bp, info);
}


static inline void __arch_uninstall_hw_breakpoint(int bp_num, int is_data_bp)
{
	unsigned long flags;
	int ret;

	raw_all_irq_save(flags);
	if (is_data_bp)
		ret = set_hardware_data_breakpoint(0, 1, 0, 0, 0, bp_num, 0);
	else
		ret = set_hardware_instr_breakpoint(0, 0, bp_num, 0);

	if (!ret)
		__this_cpu_and(perf_bps_used, ~get_bp_mask(is_data_bp, bp_num));
	raw_all_irq_restore(flags);
}

/*
 * Uninstall the breakpoint contained in the given counter.
 *
 * First we search the debug address register it uses and then we disable
 * it.
 */
void arch_uninstall_hw_breakpoint(struct perf_event *bp)
{
	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
	int i, is_data_bp;

	is_data_bp = info->type & (HW_BREAKPOINT_R|HW_BREAKPOINT_W);

	for (i = 0; i < HBP_NUM; i++) {
		struct perf_event **slot = get_bp_slot_ptr(i, is_data_bp);

		if (*slot == bp) {
			*slot = NULL;
			break;
		}
	}

	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
		return;

	__arch_uninstall_hw_breakpoint(i, is_data_bp);
}


void bp_data_overflow_handle(struct pt_regs *regs)
{
	e2k_ddbsr_t ddbsr;
	int bp_num, handled = 0;

	ddbsr = READ_DDBSR_REG();

	for (bp_num = 0; bp_num < HBP_NUM; bp_num++) {
		struct perf_event *bp;

		if ((AW(ddbsr) & E2K_DDBSR_MASK(bp_num)) == 0)
			continue;

		/*
		 * The counter may be concurrently released but that can only
		 * occur from a call_rcu() path. We can then safely fetch
		 * the breakpoint, use its callback, touch its counter
		 * while we are in an rcu_read_lock() path.
		 */
		rcu_read_lock();

		bp = *get_bp_slot_ptr(bp_num, 1);
		if (!bp) {
			rcu_read_unlock();
			continue;
		}

		++handled;

		perf_bp_event(bp, regs);

		AW(ddbsr) &= ~E2K_DDBSR_MASK(bp_num);

		rcu_read_unlock();
	}

	if (handled)
		WRITE_DDBSR_REG(ddbsr);
}

static int __set_single_step_breakpoint(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	u64 target_frame = (u64) arg;

	if (target_frame != corrected_frame_addr)
		return 0;

	frame->cr1_lo.ss = 1;

	/* Set exc_instr_debug exception to fire on return */
	int ret = write_frame(real_frame_addr, frame);
	if (ret)
		return ret;

	return 1;
}

static void set_single_step_breakpoint(struct pt_regs *regs)
{
	u64 target_frame;
	long ret;

	target_frame = AS(regs->stacks.pcsp_lo).base +
		       AS(regs->stacks.pcsp_hi).ind;
	ret = parse_chain_stack(user_mode(regs), NULL,
			__set_single_step_breakpoint, (void *) target_frame);
	if (ret == 0)
		ret = -ESRCH;

	if (IS_ERR_VALUE(ret)) {
		pr_info("Could not set single step breakpoint in current chain stack, PCSP: 0x%llx 0x%llx\n",
			AW(regs->stacks.pcsp_lo), AW(regs->stacks.pcsp_hi));
		force_sig(SIGKILL);
	}
}

void bp_instr_overflow_handle(struct pt_regs *regs)
{
	e2k_dibsr_t dibsr;
	int bp_num, handled = 0, set_singlestep = 0;

	dibsr = READ_DIBSR_REG();

	/*
	 * Re-arm handled breakpoints if needed
	 */
	if (dibsr.ss) {
		if (test_ts_flag(TS_SINGLESTEP_USER)) {
			/* User set this singlestep, rearm it since on
			 * e2k 'ss' bit is cleared by hardware after
			 * delivering interrupt. */
			set_singlestep = 1;
			dibsr.ss = 0;
			++handled;
			/* If user does a system call then exc_instr_debug will
			 * arrive on the first instruction of kernel entry,
			 * do not send signal in this case since gdb is not
			 * expecting a kernel IP */
			if (call_from_user(regs))
				S_SIG(regs, SIGTRAP, exc_instr_debug_num,
						TRAP_HWBKPT);
		}

		for (bp_num = 0; bp_num < HBP_NUM; bp_num++) {
			struct arch_hw_breakpoint *info;
			struct perf_event *bp;

			/*
			 * The counter may be concurrently released but
			 * that can only occur from a call_rcu() path.
			 */
			rcu_read_lock();
			bp = *get_bp_slot_ptr(bp_num, 0);
			if (!bp) {
				rcu_read_unlock();
				continue;
			}

			info = counter_arch_bp(bp);
			if (info->ss) {
				__arch_install_hw_breakpoint(bp_num, 1, info);
				info->ss = 0;

				++handled;
				dibsr.ss = 0;
			}
			rcu_read_unlock();
		}
	}

	for (bp_num = 0; bp_num < HBP_NUM; bp_num++) {
		struct arch_hw_breakpoint *info;
		struct perf_event *bp;

		if ((AW(dibsr) & E2K_DIBSR_MASK(bp_num)) == 0)
			continue;

		/*
		 * The counter may be concurrently released but that can only
		 * occur from a call_rcu() path. We can then safely fetch
		 * the breakpoint, use its callback, touch its counter
		 * while we are in an rcu_read_lock() path.
		 */
		rcu_read_lock();

		bp = *get_bp_slot_ptr(bp_num, 0);
		if (!bp) {
			rcu_read_unlock();
			continue;
		}

		++handled;

		perf_bp_event(bp, regs);

		info = counter_arch_bp(bp);
		__arch_uninstall_hw_breakpoint(bp_num, 0);
		info->ss = 1;
		set_singlestep = 1;

		AW(dibsr) &= ~E2K_DIBSR_MASK(bp_num);

		rcu_read_unlock();
	}

	if (handled)
		WRITE_DIBSR_REG(dibsr);

	/*
	 * Set "single step" breakpoint - we cannot just return because
	 * instruction breakpoint generates a _synchronous_ exception.
	 */
	if (set_singlestep)
		set_single_step_breakpoint(regs);
}

int hw_breakpoint_exceptions_notify(
		struct notifier_block *unused, unsigned long val, void *data)
{
	return NOTIFY_DONE; 
}

void hw_breakpoint_pmu_read(struct perf_event *bp)
{
}

/*
 * Unregister breakpoints from this task and reset the pointers in
 * the thread_struct.
 */
void flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	struct thread_struct *thread = &tsk->thread;
	int i;

	for (i = 0; i < HBP_NUM; i++) {
		if (thread->debug.hbp_data[i]) {
			unregister_hw_breakpoint(thread->debug.hbp_data[i]);
			thread->debug.hbp_data[i] = NULL;
		}
		if (thread->debug.hbp_instr[i]) {
			unregister_hw_breakpoint(thread->debug.hbp_instr[i]);
			thread->debug.hbp_instr[i] = NULL;
		}
	}
}

/*
 * Set ptrace breakpoint pointers to zero for this task.
 * This is required in order to prevent child processes from unregistering
 * breakpoints held by their parent.
 */
void clear_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	struct thread_struct *thread = &tsk->thread;

	memset(thread->debug.hbp_data, 0, sizeof(thread->debug.hbp_data));
	memset(thread->debug.hbp_instr, 0, sizeof(thread->debug.hbp_instr));
}
