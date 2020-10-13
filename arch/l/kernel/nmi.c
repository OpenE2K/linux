#include <linux/delay.h>
#include <linux/irqflags.h>
#include <linux/rculist.h>
#include <linux/smp.h>
#include <asm/apic.h>

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

enum {
	CSD_FLAG_LOCK		= 0x01,
};

struct call_function_data {
	struct call_single_data	csd;
	atomic_t		refs;
	cpumask_var_t		cpumask;
};

struct call_single_queue {
	struct list_head	list;
	raw_spinlock_t		lock;
};

static struct {
	struct list_head	queue;
	raw_spinlock_t		lock;
} call_function __cacheline_aligned_in_smp =
	{
		.queue	= LIST_HEAD_INIT(call_function.queue),
		.lock	= __RAW_SPIN_LOCK_UNLOCKED(call_function.lock),
	};

static struct call_function_data cfd_data[NR_CPUS];

/*
 * csd_lock/csd_unlock used to serialize access to per-cpu csd resources
 *
 * For non-synchronous ipi calls the csd can still be in use by the
 * previous function call. For multi-cpu calls its even more interesting
 * as we'll have to ensure no other cpu is observing our csd.
 */
static void csd_lock_wait(struct call_single_data *data, int timeout_msec)
{
	if (timeout_msec) {
		cycles_t start, now;

		start = get_cycles();
		while (data->flags & CSD_FLAG_LOCK) {
			now = get_cycles();
			if (timeout_msec <= ((now - start) * 1000)
					/ (loops_per_jiffy * HZ))
				break;
			cpu_relax();
		}
	} else {
		while (data->flags & CSD_FLAG_LOCK)
			cpu_relax();
	}

	/*
	 * Make sure that whatever data was changed by the called
	 * function is available now
	 */
	smp_mb();
}

static void csd_lock(struct call_single_data *data)
{
	csd_lock_wait(data, 10000);
	data->flags = CSD_FLAG_LOCK;

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified call_single_data structure:
	 */
	smp_mb();
}

static void csd_unlock(struct call_single_data *data)
{
	if (unlikely(!(data->flags & CSD_FLAG_LOCK))) {
		printk("Error in nmi_call_function(): caller did not "
				"lock the queue entry\n");
		dump_stack();
	}

	/*
	 * ensure we're all done before releasing data:
	 */
	smp_mb();

	data->flags &= ~CSD_FLAG_LOCK;
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
int nmi_call_function(void (*func)(void *), void *info, int wait,
		int timeout_msec)
{
	struct call_function_data *data;
	unsigned long flags, nmi_flags;
	int this_cpu;

	/*
	 * Can deadlock when called with NMI interrupts disabled.
	 */
	if (unlikely(raw_nmi_irqs_disabled())) {
		static int once = 1;

		if (once) {
			once = 0;
			printk("nmi_call_function() called with NMIs "
					"disabled");
			dump_stack();
		}

		wait = 0;
	}

	if (num_online_cpus() == 1)
		/* This happens regularly when an SMP-configured kernel
		 * runs on a UP system. */
		return 0;

	raw_local_irq_save(flags);

	this_cpu = raw_smp_processor_id();

	data = &cfd_data[this_cpu];

	csd_lock(&data->csd);

	data->csd.func = func;
	data->csd.info = info;
	cpumask_copy(data->cpumask, cpu_online_mask);
	cpumask_clear_cpu(this_cpu, data->cpumask);
	atomic_set(&data->refs, cpumask_weight(data->cpumask));

	raw_all_irq_save(nmi_flags);
	raw_spin_lock(&call_function.lock);
	/*
	 * If list.prev is NULL or poisoned then it is not queued anywhere.
	 * Otherwise we assume that it is already queued into the global
	 * call_function.queue (this can happen if csd_lock_wait() timed out).
	 *
	 * Using LIST_POISON2 is not a good hack, but it's still the only
	 * way to check RCU list for whether it is empty after list_del_rcu().
	 */
	if (!data->csd.list.prev || data->csd.list.prev == LIST_POISON2)
		/*
		 * Place entry at the _HEAD_ of the list, so that any cpu still
		 * observing the entry in generic_smp_call_function_interrupt()
		 * will not miss any other list entries:
		 */
		list_add(&data->csd.list, &call_function.queue);
	else
		printk("WARNING previous nmi_call_function() timed out, so "
				"some function calls can be lost\n");
	raw_spin_unlock(&call_function.lock);
	raw_all_irq_restore(nmi_flags);

	/* Send a message to all CPUs except self */
	apic->send_IPI_allbutself(NMI_VECTOR);

	/* Optionally wait for the CPUs to complete */
	if (wait)
		csd_lock_wait(&data->csd, timeout_msec);

	raw_local_irq_restore(flags);

	return 0;
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
int nmi_call_function_single(int cpu, void (*func) (void *info), void *info,
		int wait, int timeout_msec)
{
	struct call_function_data *data;
	unsigned long flags, nmi_flags;
	int this_cpu, err = 0;

	/*
	 * Can deadlock when called with NMI interrupts disabled.
	 */
	if (unlikely(raw_nmi_irqs_disabled())) {
		static int once = 1;

		if (once) {
			once = 0;
			printk("nmi_call_function() called with NMIs "
					"disabled");
			dump_stack();
		}

		wait = 0;
	}

	raw_local_irq_save(flags);

	this_cpu = raw_smp_processor_id();

	if (cpu == this_cpu) {
		func(info);
		goto out;
	}

	if (unlikely((unsigned)cpu >= nr_cpu_ids || !cpu_online(cpu))) {
		err = -ENXIO;	/* CPU not online */
		goto out;
	}

	data = &cfd_data[this_cpu];

	csd_lock(&data->csd);

	data->csd.func = func;
	data->csd.info = info;
	cpumask_clear(data->cpumask);
	cpumask_set_cpu(cpu, data->cpumask);
	atomic_set(&data->refs, 1);

	raw_all_irq_save(nmi_flags);
	raw_spin_lock(&call_function.lock);
	/*
	 * If list.prev is NULL or poisoned then it is not queued anywhere.
	 * Otherwise we assume that it is already queued into the global
	 * call_function.queue (this can happen if csd_lock_wait() timed out).
	 *
	 * Using LIST_POISON2 is not a good hack, but it's still the only
	 * way to check RCU list for whether it is empty after list_del_rcu().
	 */
	if (!data->csd.list.prev || data->csd.list.prev == LIST_POISON2)
		/*
		 * Place entry at the _HEAD_ of the list, so that any cpu still
		 * observing the entry in generic_smp_call_function_interrupt()
		 * will not miss any other list entries:
		 */
		list_add(&data->csd.list, &call_function.queue);
	else
		printk("WARNING previous nmi_call_function() timed out, so "
				"some function calls can be lost\n");
	raw_spin_unlock(&call_function.lock);
	raw_all_irq_restore(nmi_flags);

	/* Send a message to the target CPU */
	apic->send_IPI_mask(data->cpumask, NMI_VECTOR);

	/* Optionally wait for the CPU to complete */
	if (wait)
		csd_lock_wait(&data->csd, timeout_msec);

out:
	raw_local_irq_restore(flags);

	return err;
}

/*
 * Invoked to handle an NMI IPI (currently such IPIs
 * are used only to call functions).
 */
noinline void nmi_call_function_interrupt(void)
{
	struct call_function_data *data;
	unsigned long flags;
	int cpu = raw_smp_processor_id();

	/*
	 * Shouldn't receive this interrupt on a cpu that is not yet online.
	 */
	if (unlikely(!cpu_online(cpu))) {
		static int once = 1;

		if (once) {
			once = 0;
			printk("NMI IPI received on CPU#%d which "
					"is not online\n", cpu);
			dump_stack();
		}
	}

	/*
	 * raw_spin_unlock() in nmi_call_function() after adding a new
	 * entry serves as a memory barrier corresponding to this one.
	 * If we don't have this, then we may miss an entry on the list
	 * and never get another IPI to process it.
	 */
	smp_mb();

	/*
	 * It's ok to use list_for_each_rcu() here even though we may
	 * delete 'pos', since list_del_rcu() doesn't clear ->next
	 */
	raw_all_irq_save(flags);
	list_for_each_entry_rcu(data, &call_function.queue, csd.list) {
		int refs;

		if (!cpumask_test_and_clear_cpu(cpu, data->cpumask))
			continue;

		data->csd.func(data->csd.info);

		refs = atomic_dec_return(&data->refs);
		WARN_ON(refs < 0);
		if (!refs) {
			raw_spin_lock(&call_function.lock);
			list_del_rcu(&data->csd.list);
			raw_spin_unlock(&call_function.lock);

			csd_unlock(&data->csd);
		}
	}
	raw_all_irq_restore(flags);
}

