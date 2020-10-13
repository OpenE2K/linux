/*
 * Generic entry point for the idle threads
 */
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/tick.h>
#include <linux/mm.h>
#include <linux/stackprotector.h>

#include <asm/tlb.h>

#include <trace/events/power.h>

static int __read_mostly cpu_idle_force_poll;

void cpu_idle_poll_ctrl(bool enable)
{
	if (enable) {
		cpu_idle_force_poll++;
	} else {
		cpu_idle_force_poll--;
		WARN_ON_ONCE(cpu_idle_force_poll < 0);
	}
}

#ifdef CONFIG_GENERIC_IDLE_POLL_SETUP
static int __init cpu_idle_poll_setup(char *__unused)
{
	cpu_idle_force_poll = 1;
	return 1;
}
__setup("nohlt", cpu_idle_poll_setup);

static int __init cpu_idle_nopoll_setup(char *__unused)
{
	cpu_idle_force_poll = 0;
	return 1;
}
__setup("hlt", cpu_idle_nopoll_setup);
#endif

static inline int cpu_idle_poll(void)
{
	rcu_idle_enter();
	trace_cpu_idle_rcuidle(0, smp_processor_id());
	local_irq_enable();
	while (!tif_need_resched()) {
#ifdef CONFIG_MCST_RT
		idle_check_delayed_works(smp_processor_id());
#endif
		cpu_relax();
	}
	trace_cpu_idle_rcuidle(PWR_EVENT_EXIT, smp_processor_id());
	rcu_idle_exit();
	return 1;
}

/* Weak implementations for optional arch specific functions */
void __weak arch_cpu_idle_prepare(void) { }
void __weak arch_cpu_idle_enter(void) { }
void __weak arch_cpu_idle_exit(void) { }
void __weak arch_cpu_idle_dead(void) { }
void __weak arch_cpu_idle(void)
{
	cpu_idle_force_poll = 1;
	local_irq_enable();
}

#ifdef CONFIG_PREEMPT_RT_FULL
/*
 * RT can not call schedule_delayed_work from real interrupt context.
 * Need to make a thread to do the real work.
 */
static int run_check_pgt_cache(void *unused)
{
	while (!kthread_should_stop()) {
		check_pgt_cache();
		msleep_interruptible(60000);
	}

	return 0;
}

static __init int create_check_pgt_cache_thread(void)
{
	static struct task_struct *t;
	int cpu;

	for_each_possible_cpu(cpu) {
		t = kthread_create_on_cpu(run_check_pgt_cache, NULL,
					  cpu, "pgt_cached/%u");
		if (!IS_ERR(t))
			kthread_unpark(t);
	}

	return 0;
}
early_initcall(create_check_pgt_cache_thread);
#endif

/*
 * Generic idle loop implementation
 */
static void cpu_idle_loop(void)
{
	while (1) {
#ifdef CONFIG_WATCH_PREEMPT
		__get_cpu_var(nowatch_set) |= NEVER_PWATCH;
#endif
		tick_nohz_idle_enter();

		while (!need_resched()) {
#ifndef CONFIG_PREEMPT_RT_FULL
			check_pgt_cache();
#endif
			rmb();

			if (cpu_is_offline(smp_processor_id())) {
				arch_cpu_idle_dead();
			} else {
				local_irq_disable();
				arch_cpu_idle_enter();

				/*
			 	* In poll mode we reenable interrupts and spin.
			 	*
			 	* Also if we detected in the wakeup from idle
			 	* path that the tick broadcast device expired
			 	* for us, we don't want to go deep idle as we
			 	* know that the IPI is going to arrive right
			 	* away
			 	*/
#ifdef CONFIG_MCST_RT
				if (cpu_idle_force_poll ||
					tick_check_broadcast_expired() ||
						(rts_act_mask & RTS_HZ_RT)) {
#else
				if (cpu_idle_force_poll || tick_check_broadcast_expired()) {
#endif
					cpu_idle_poll();
				} else {
					if (!current_clr_polling_and_test()) {
						stop_critical_timings();
						rcu_idle_enter();
						arch_cpu_idle();
						WARN_ON_ONCE(irqs_disabled());
						rcu_idle_exit();
						start_critical_timings();
					} else {
						local_irq_enable();
					}
					__current_set_polling();
				}
				arch_cpu_idle_exit();
			}	
		}

		/*
		 * Since we fell out of the loop above, we know
		 * TIF_NEED_RESCHED must be set, propagate it into
		 * PREEMPT_NEED_RESCHED.
		 *
		 * This is required because for polling idle loops we will
		 * not have had an IPI to fold the state for us.
		 */
		preempt_set_need_resched();
		tick_nohz_idle_exit();
		schedule_preempt_disabled();
	}
}

void cpu_startup_entry(enum cpuhp_state state)
{
	/*
	 * This #ifdef needs to die, but it's too late in the cycle to
	 * make this generic (arm and sh have never invoked the canary
	 * init for the non boot cpus!). Will be fixed in 3.11
	 */
#ifdef CONFIG_X86
	/*
	 * If we're the non-boot CPU, nothing set the stack canary up
	 * for us. The boot CPU already has it initialized but no harm
	 * in doing it again. This is a good place for updating it, as
	 * we wont ever return from this function (so the invalid
	 * canaries already on the stack wont ever trigger).
	 */
	boot_init_stack_canary();
#endif
	__current_set_polling();
	arch_cpu_idle_prepare();
	cpu_idle_loop();
}
