/*
 * linux/kernel/irq/handle.c
 *
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the core interrupt handling code.
 *
 * Detailed information is available in Documentation/DocBook/genericirq
 *
 */

#include <linux/irq.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#include <trace/events/irq.h>

#include "internals.h"

/**
 * handle_bad_irq - handle spurious and unhandled irqs
 * @irq:       the interrupt number
 * @desc:      description of the interrupt
 *
 * Handles spurious and unhandled IRQ's. It also prints a debugmessage.
 */
void handle_bad_irq(unsigned int irq, struct irq_desc *desc)
{
	print_irq_desc(irq, desc);
	kstat_incr_irqs_this_cpu(irq, desc);
	ack_bad_irq(irq);
}

/*
 * Special, empty irq handler:
 */
irqreturn_t no_action(int cpl, void *dev_id)
{
	return IRQ_NONE;
}

static void warn_no_thread(unsigned int irq, struct irqaction *action)
{
	if (test_and_set_bit(IRQTF_WARNED, &action->thread_flags))
		return;

	printk(KERN_WARNING "IRQ %d device %s returned IRQ_WAKE_THREAD "
	       "but no thread function available.", irq, action->name);
}

static void irq_wake_thread(struct irq_desc *desc, struct irqaction *action)
{
	/*
	 * In case the thread crashed and was killed we just pretend that
	 * we handled the interrupt. The hardirq handler has disabled the
	 * device interrupt, so no irq storm is lurking.
	 */
	if (action->thread->flags & PF_EXITING)
		return;

	/*
	 * Wake up the handler thread for this action. If the
	 * RUNTHREAD bit is already set, nothing to do.
	 */
	if (test_and_set_bit(IRQTF_RUNTHREAD, &action->thread_flags))
		return;

	/*
	 * It's safe to OR the mask lockless here. We have only two
	 * places which write to threads_oneshot: This code and the
	 * irq thread.
	 *
	 * This code is the hard irq context and can never run on two
	 * cpus in parallel. If it ever does we have more serious
	 * problems than this bitmask.
	 *
	 * The irq threads of this irq which clear their "running" bit
	 * in threads_oneshot are serialized via desc->lock against
	 * each other and they are serialized against this code by
	 * IRQS_INPROGRESS.
	 *
	 * Hard irq handler:
	 *
	 *	spin_lock(desc->lock);
	 *	desc->state |= IRQS_INPROGRESS;
	 *	spin_unlock(desc->lock);
	 *	set_bit(IRQTF_RUNTHREAD, &action->thread_flags);
	 *	desc->threads_oneshot |= mask;
	 *	spin_lock(desc->lock);
	 *	desc->state &= ~IRQS_INPROGRESS;
	 *	spin_unlock(desc->lock);
	 *
	 * irq thread:
	 *
	 * again:
	 *	spin_lock(desc->lock);
	 *	if (desc->state & IRQS_INPROGRESS) {
	 *		spin_unlock(desc->lock);
	 *		while(desc->state & IRQS_INPROGRESS)
	 *			cpu_relax();
	 *		goto again;
	 *	}
	 *	if (!test_bit(IRQTF_RUNTHREAD, &action->thread_flags))
	 *		desc->threads_oneshot &= ~mask;
	 *	spin_unlock(desc->lock);
	 *
	 * So either the thread waits for us to clear IRQS_INPROGRESS
	 * or we are waiting in the flow handler for desc->lock to be
	 * released before we reach this point. The thread also checks
	 * IRQTF_RUNTHREAD under desc->lock. If set it leaves
	 * threads_oneshot untouched and runs the thread another time.
	 */
	desc->threads_oneshot |= action->thread_mask;

	/*
	 * We increment the threads_active counter in case we wake up
	 * the irq thread. The irq thread decrements the counter when
	 * it returns from the handler or in the exit path and wakes
	 * up waiters which are stuck in synchronize_irq() when the
	 * active count becomes zero. synchronize_irq() is serialized
	 * against this code (hard irq handler) via IRQS_INPROGRESS
	 * like the finalize_oneshot() code. See comment above.
	 */
	atomic_inc(&desc->threads_active);

	wake_up_process(action->thread);
}

irqreturn_t
handle_irq_event_percpu(struct irq_desc *desc, struct irqaction *action)
{
	struct pt_regs *regs = get_irq_regs();
	u64 ip = regs ? instruction_pointer(regs) : 0;
	irqreturn_t retval = IRQ_NONE;
	unsigned int flags = 0, irq = desc->irq_data.irq;

	do {
		irqreturn_t res;

		trace_irq_handler_entry(irq, action);
#ifdef CONFIG_MCST
		if (((desc->istate & (IRQS_ONESHOT | IRQS_DO_ONESHOT)) ==
			(IRQS_ONESHOT | IRQS_DO_ONESHOT)) &&
			(action->flags & IRQF_ONESHOT) &&
			!irqd_irq_masked(&desc->irq_data)) {
			/*
			 * It can be if we just added ONESHOT irq handler to
			 * not ONESHOT desk when interrupt had being handled.
			 * Just skip it for this time.
			 * If interrupt is really raised
			 * we will handle it next time
			 */
			pr_info("Reject irq due to irq unmasked."
				"irq = %d, action = %s\n",
				irq, action->name ? action->name : "NULL");
			res = IRQ_NONE;
		} else {
			res = action->handler(irq, action->dev_id);
		}
#else
		res = action->handler(irq, action->dev_id);
#endif
		trace_irq_handler_exit(irq, action, res);

		if (WARN_ONCE(!irqs_disabled(),"irq %u handler %pF enabled interrupts\n",
			      irq, action->handler))
			local_irq_disable();

		switch (res) {
		case IRQ_WAKE_THREAD:
			/*
			 * Catch drivers which return WAKE_THREAD but
			 * did not set up a thread function
			 */
			if (unlikely(!action->thread_fn)) {
				warn_no_thread(irq, action);
				break;
			}

			irq_wake_thread(desc, action);

			/* Fall through to add to randomness */
		case IRQ_HANDLED:
			flags |= action->flags;
			break;

		default:
			break;
		}

		retval |= res;
		action = action->next;
	} while (action);

#ifndef CONFIG_PREEMPT_RT_FULL
	add_interrupt_randomness(irq, flags, ip);
#else
	desc->random_ip = ip;
#endif

	if (!noirqdebug)
		note_interrupt(irq, desc, retval);
	return retval;
}

irqreturn_t handle_irq_event(struct irq_desc *desc)
{
	struct irqaction *action = desc->action;
	irqreturn_t ret;

	desc->istate &= ~IRQS_PENDING;
	irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);
	raw_spin_unlock(&desc->lock);

	ret = handle_irq_event_percpu(desc, action);

	raw_spin_lock(&desc->lock);
	irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);
	return ret;
}



#ifdef CONFIG_MCST_RT
int set_user_irq_thr(int irq)
{
	return -EINVAL;
#if 0
	ask_t *u_task = current;
	irq_desc_t *desc = irq_desc + irq;
	unsigned long flags;

	spin_lock_irqsave(&desc->lock, flags);
	if (desc->u_thread) {
		spin_unlock_irqrestore(&desc->lock, flags);
		printk("set_user_irq_thr FAIL for %s/%d: irq %d"
			"is attached to %s/%d\n",
			u_task->comm, u_task->pid, irq,
			desc->u_thread->comm, desc->u_thread->pid);
		return -1;
	}
	if (u_task->irq_to_be_proc) {
		spin_unlock_irqrestore(&desc->lock, flags);
		printk("set_user_irq_thr FAIL for %s/%d: "
			"irq %d is attached to this task\n",
			u_task->comm, u_task->pid,
			u_task->irq_to_be_proc);
		return -2;
	}
	if (desc->thread == 0) {
		spin_unlock_irqrestore(&desc->lock, flags);
		printk("set_user_irq_thr FAIL for %s/%d: irq %d nave not irq thread",
			u_task->comm, u_task->pid, u_task->irq_to_be_proc);
		return -3;
	}
	u_task->irq_to_be_proc = irq;
	desc->u_thread = u_task;
	spin_unlock_irqrestore(&desc->lock, flags);
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(set_user_irq_thr);

int unset_user_irq_thr(void)
{
	return -EINVAL;
#if 0
	task_t *u_task = current;
	irq_desc_t *desc;
	unsigned long flags;

	if (u_task->irq_to_be_proc == 0) return -1;
	desc = irq_desc + u_task->irq_to_be_proc;
	spin_lock_irqsave(&desc->lock, flags);
	u_task->irq_to_be_proc = 0;
	desc->u_thread = NULL;
	wake_up_process(desc->thread);
	spin_unlock_irqrestore(&desc->lock, flags);
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(unset_user_irq_thr);
#endif  // CONFIG_MCST_RT

