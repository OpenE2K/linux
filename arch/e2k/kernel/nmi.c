/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/delay.h>
#include <linux/irqflags.h>
#include <linux/rculist.h>
#include <linux/smp.h>
#include <asm/apic.h>
#include <asm/delay.h>

/*
 * NMI IPI support
 *
 * nmi_call_function_xxx() support is implemented here.
 *
 * These function work like smp_call_function() but they are
 * using non-maskable interrupts internally so they can be
 * used from interrupt context. They also accept an additional
 * 'timeout' parameter for more robust execution.
 *
 *
 * ATTENTION nmi_call_function_xxx() are actually more limited
 * than smp_call_function_xxx().
 *
 * 1) You cannot use ANY drivers (since they are usually NOT async-safe).
 *
 * 2) You cannot use printk() (as a consequence of 1).
 *
 * 3) Function must be fast and non-blocking.
 *
 * So instead of using printk() it is better to save your message
 * into a temporary buffer and later print that buffer from the function
 * which called nmi_call_function_xxx().
 */

#ifdef	CONFIG_SMP

enum {
	NMI_CSD_FLAG_LOCK		= 0x01,
	NMI_CSD_FLAG_SYNCHRONOUS	= 0x02,
};

struct nmi_call_single_data {
	union {
		struct list_head list;
		struct llist_node llist;
	};
	smp_call_func_t func;
	void *info;
	u16 flags;
};

struct nmi_call_function_data {
	struct nmi_call_single_data	csd[NR_CPUS];
	struct cpumask		cpumask;
	struct cpumask		cpumask_ipi;
};

static struct llist_head __cacheline_aligned_in_smp call_single_queue[NR_CPUS];
static struct nmi_call_function_data __cacheline_aligned_in_smp
		nmi_cfd_data[NR_CPUS];
static struct nmi_call_single_data nmi_csd_data[NR_CPUS];

void nmi_call_function_init(void)
{
	int i;

	for_each_possible_cpu(i)
		init_llist_head(&call_single_queue[i]);
}

/*
 * nmi_csd_lock/nmi_csd_unlock used to serialize access to per-cpu csd resources
 *
 * For non-synchronous ipi calls the csd can still be in use by the
 * previous function call. For multi-cpu calls its even more interesting
 * as we'll have to ensure no other cpu is observing our csd.
 */
static void nmi_csd_lock_wait(struct nmi_call_single_data *csd,
			      int timeout_msec)
{
	if (timeout_msec) {
		int waited_us = 0;
		int one_wait_us = 10;

		while (READ_ONCE(csd->flags) & NMI_CSD_FLAG_LOCK) {
			udelay(one_wait_us);
			waited_us += one_wait_us;
			if (waited_us >= USEC_PER_MSEC * timeout_msec) {
				pr_alert("nmi_csd_lock_wait(): wait exit on timeout\n");
				break;
			}
		}
	} else {
		while (READ_ONCE(csd->flags) & NMI_CSD_FLAG_LOCK)
			cpu_relax();
	}

	/*
	 * Make sure that whatever data was changed by the called
	 * function is available now
	 */
	smp_mb();
}

static void nmi_csd_lock(struct nmi_call_single_data *csd)
{
	nmi_csd_lock_wait(csd, 30000);
	csd->flags |= NMI_CSD_FLAG_LOCK;

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified nmi_call_single_data structure:
	 */
	smp_mb();
}

static void nmi_csd_unlock(struct nmi_call_single_data *csd)
{
	if (unlikely(!(csd->flags & NMI_CSD_FLAG_LOCK)))
		pr_alert("Error in nmi_call_function(): caller did not lock the queue entry\n");

	/*
	 * ensure we're all done before releasing data:
	 */
	smp_store_release(&csd->flags, 0);
}

/*
 * nmi_call_function_single - Run a function on a specific CPU
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait until function has completed on other CPUs.
 * @timeout_msec: Maximum waiting time in milliseconds (0 means
 *        no timeout).
 *
 * Unlike smp_call_function_single(), this function can be called from
 * interrupt context because it uses non-maskable interrupts internally.
 *
 * Returns 0 on success, else a negative status code.
 *
 * ATTENTION
 *
 * 1) You cannot use ANY drivers (since they are usually NOT async-safe).
 *
 * 2) You cannot use printk() (as a consequence of 1).
 *
 * 3) Function must be fast and non-blocking.
 */
static int __nmi_call_function_single(int cpu, void (*func) (void *info), void *info,
		int wait, int timeout_msec, bool offline)
{
	struct nmi_call_single_data *csd;
	struct nmi_call_single_data csd_stack = {
		.flags = NMI_CSD_FLAG_LOCK | NMI_CSD_FLAG_SYNCHRONOUS
	};
	unsigned long flags, nmi_flags;
	int this_cpu, err = 0;

	/*
	 * Can deadlock when called with NMI interrupts disabled.
	 */
	if (unlikely(psr_and_upsr_nm_irqs_disabled())) {
		WARN_ONCE(1, "nmi_call_function() called with NMIs disabled");
		wait = 0;
	}

	raw_local_irq_save(flags);

	this_cpu = raw_smp_processor_id();

	csd = &csd_stack;
	if (!wait) {
		csd = &nmi_csd_data[this_cpu];
		nmi_csd_lock(csd);
	}

	if (cpu == this_cpu) {
		raw_all_irq_save(nmi_flags);
		func(info);
		raw_all_irq_restore(nmi_flags);
		goto out;
	}

	if (unlikely((unsigned) cpu >= nr_cpu_ids ||
			offline && cpu_online(cpu) ||
			!offline && !cpu_online(cpu))) {
		err = -ENXIO;
		goto out;
	}

	csd->func = func;
	csd->info = info;

	/* Send a message to the target CPU */
	if (llist_add(&csd->llist, &call_single_queue[cpu]))
		apic->send_IPI_mask(cpumask_of(cpu), NMI_VECTOR);

	/* Optionally wait for the CPU to complete */
	if (wait)
		nmi_csd_lock_wait(csd, timeout_msec);

out:
	raw_local_irq_restore(flags);

	return err;
}

int nmi_call_function_single(int cpu, void (*func) (void *info), void *info,
		int wait, int timeout_msec)
{
	return __nmi_call_function_single(cpu, func, info, wait, timeout_msec, false);
}

int nmi_call_function_single_offline(int cpu, void (*func) (void *info), void *info,
		int wait, int timeout_msec)
{
	return __nmi_call_function_single(cpu, func, info, wait, timeout_msec, true);
}

/**
 * nmi_call_function(): Run a function on all other CPUs.
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait (atomically) until function has completed
 *        on other CPUs.
 * @timeout_msec: Maximum waiting time in milliseconds (0 means
 *        no timeout).
 *
 * Returns 0.
 *
 * The main difference between this and smp_call_function() is that
 * here we use NMIs to send interrupts. So only non-maskable interrupts
 * must be enabled when calling it.
 *
 * ATTENTION
 *
 * 1) You cannot use ANY drivers (since they are usually NOT async-safe).
 *
 * 2) You cannot use printk() (as a consequence of 1).
 *
 * 3) Function must be fast and non-blocking.
 */
static int nmi_call_function_many(const struct cpumask *mask,
		void (*func)(void *), void *info, int wait, int timeout_msec)
{
	struct nmi_call_function_data *cfd;
	int cpu, next_cpu, this_cpu = raw_smp_processor_id();

	/*
	 * Can deadlock when called with NMI interrupts disabled.
	 */
	if (unlikely(psr_and_upsr_nm_irqs_disabled())) {
		WARN_ONCE(1, "nmi_call_function() called with NMIs disabled");
		wait = 0;
	}

	/*
	 * Should not be possible since we always disable interrupts
	 * in NMI handlers.
	 */
	WARN_ON_ONCE(in_nmi());

	/* Try to fastpath.  So, what's a CPU they want? Ignoring this one. */
	cpu = cpumask_first_and(mask, cpu_online_mask);
	if (cpu == this_cpu)
		cpu = cpumask_next_and(cpu, mask, cpu_online_mask);

	/* No online cpus?  We're done. */
	if (cpu >= nr_cpu_ids)
		return 0;

	/* Do we have another CPU which isn't us? */
	next_cpu = cpumask_next_and(cpu, mask, cpu_online_mask);
	if (next_cpu == this_cpu)
		next_cpu = cpumask_next_and(next_cpu, mask, cpu_online_mask);

	/* Fastpath: do that cpu by itself. */
	if (next_cpu >= nr_cpu_ids)
		return nmi_call_function_single(cpu, func, info, wait,
						timeout_msec);

	cfd = &nmi_cfd_data[this_cpu];

	cpumask_and(&cfd->cpumask, mask, cpu_online_mask);
	cpumask_clear_cpu(this_cpu, &cfd->cpumask);

	/* Some callers race with other cpus changing the passed mask */
	if (unlikely(!cpumask_weight(&cfd->cpumask)))
		return 0;

	cpumask_clear(&cfd->cpumask_ipi);
	for_each_cpu(cpu, &cfd->cpumask) {
		struct nmi_call_single_data *csd = &cfd->csd[cpu];

		nmi_csd_lock(csd);
		if (wait)
			csd->flags |= NMI_CSD_FLAG_SYNCHRONOUS;
		csd->func = func;
		csd->info = info;

		if (llist_add(&csd->llist, &call_single_queue[cpu]))
			cpumask_set_cpu(cpu, &cfd->cpumask_ipi);
	}

	/* Send a message to all CPUs in the map */
	apic->send_IPI_mask_allbutself(&cfd->cpumask_ipi, NMI_VECTOR);

	/* Optionally wait for the CPUs to complete */
	if (wait) {
		for_each_cpu(cpu, &cfd->cpumask) {
			struct nmi_call_single_data *csd;

			csd = &cfd->csd[cpu];
			nmi_csd_lock_wait(csd, timeout_msec);
		}
	}

	return 0;
}

int nmi_call_function(void (*func)(void *), void *info, int wait,
		int timeout_msec)
{
	unsigned long flags;
	int ret;

	raw_local_irq_save(flags);
	ret = nmi_call_function_many(cpu_online_mask, func, info, wait,
				     timeout_msec);
	raw_local_irq_restore(flags);

	return ret;
}

int nmi_call_function_mask(const cpumask_t *mask,
		void (*func)(void *), void *info, int wait, int timeout_msec)
{
	unsigned long flags;
	int ret;

	raw_local_irq_save(flags);
	ret = nmi_call_function_many(mask, func, info, wait, timeout_msec);
	raw_local_irq_restore(flags);

	return ret;
}

/*
 * Invoked to handle an NMI IPI (currently such IPIs
 * are used only to call functions).
 */
noinline void nmi_call_function_interrupt(void)
{
	struct llist_head *head;
	struct llist_node *entry;
	struct nmi_call_single_data *csd, *csd_next;
	int cpu = raw_smp_processor_id();

	head = &call_single_queue[cpu];
	entry = llist_del_all(head);
	entry = llist_reverse_order(entry);

	WARN_ONCE(!psr_and_upsr_nm_irqs_disabled(),
		"nmi_call_function() called with NMIs disabled");

	llist_for_each_entry_safe(csd, csd_next, entry, llist) {
		smp_call_func_t func = csd->func;
		void *info = csd->info;

		/* Do we wait until *after* callback? */
		if (csd->flags & NMI_CSD_FLAG_SYNCHRONOUS) {
			func(info);
			nmi_csd_unlock(csd);
		} else {
			nmi_csd_unlock(csd);
			func(info);
		}
	}
}
#else	/* ! CONFIG_SMP */
noinline void nmi_call_function_interrupt(void)
{
	panic("%s(): in not SMP mode\n", __func__);
}
#endif	/* CONFIG_SMP */

