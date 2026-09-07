/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/slab.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <asm/hw_irq.h>
#include <asm/pic.h>

#include <asm/trace/irq_vectors.h>

#include "pic.h"

#ifndef NO_IRQ
#define NO_IRQ	((unsigned int)(-1))
#endif

static struct irq_domain *l_vector_domain;
static DEFINE_RAW_SPINLOCK(vector_lock);
static cpumask_var_t vector_searchmask;
static struct irq_matrix *vector_matrix;
static int managed_irq_shutdown_vector;
#ifdef CONFIG_SMP
static DEFINE_PER_CPU(struct hlist_head, cleanup_list);
#endif


void lock_vector_lock(void)
{
	/* Used to the online set of cpus does not change
	 * during assign_irq_vector.
	 */
	raw_spin_lock(&vector_lock);
}

void unlock_vector_lock(void)
{
	raw_spin_unlock(&vector_lock);
}

struct irq_cfg *irqd_cfg(struct irq_data *irqd)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);

	return picd ? &picd->hw_irq_cfg : NULL;
}

struct irq_cfg *irq_cfg(unsigned int irq)
{
	return irqd_cfg(irq_get_irq_data(irq));
}

static struct pic_chip_data *alloc_pic_chip_data(int node)
{
	struct pic_chip_data *picd;

	picd = kzalloc_node(sizeof(*picd), GFP_KERNEL, node);
	if (picd)
		INIT_HLIST_NODE(&picd->clist);
	return picd;
}

static void free_apic_chip_data(struct pic_chip_data *picd)
{
	kfree(picd);
}

static void apic_update_irq_cfg(struct irq_data *irqd, unsigned int vector,
				unsigned int cpu)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);

	lockdep_assert_held(&vector_lock);

	picd->hw_irq_cfg.vector = vector;
	picd->hw_irq_cfg.dest_apicid = apic_default_calc_apicid(cpu);
	irq_data_update_effective_affinity(irqd, cpumask_of(cpu));
	trace_vector_config(irqd->irq, vector, cpu,
			    picd->hw_irq_cfg.dest_apicid);
}

static void apic_update_vector(struct irq_data *irqd, unsigned int newvec,
			       unsigned int newcpu)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);
	struct irq_desc *desc = irq_data_to_desc(irqd);
	bool managed = irqd_affinity_is_managed(irqd);

	lockdep_assert_held(&vector_lock);

	trace_vector_update(irqd->irq, newvec, newcpu, picd->vector,
			    picd->cpu);

	/*
	 * If there is no vector associated or if the associated vector is
	 * the shutdown vector, which is associated to make PCI/MSI
	 * shutdown mode work, then there is nothing to release. Clear out
	 * prev_vector for this and the offlined target case.
	 */
	picd->prev_vector = 0;
	if (!picd->vector || picd->vector == managed_irq_shutdown_vector)
		goto setnew;
	/*
	 * If the target CPU of the previous vector is online, then mark
	 * the vector as move in progress and store it for cleanup when the
	 * first interrupt on the new vector arrives. If the target CPU is
	 * offline then the regular release mechanism via the cleanup
	 * vector is not possible and the vector can be immediately freed
	 * in the underlying matrix allocator.
	 */
	if (cpu_online(picd->cpu)) {
		picd->move_in_progress = true;
		picd->prev_vector = picd->vector;
		picd->prev_cpu = picd->cpu;
		WARN_ON_ONCE(picd->cpu == newcpu);
	} else {
		irq_matrix_free(vector_matrix, picd->cpu, picd->vector,
				managed);
		per_cpu(vector_irq, picd->cpu)[picd->vector] = VECTOR_SHUTDOWN;
	}

setnew:
	picd->vector = newvec;
	picd->cpu = newcpu;
	BUG_ON(!IS_ERR_OR_NULL(per_cpu(vector_irq, newcpu)[newvec]));
	per_cpu(vector_irq, newcpu)[newvec] = desc;
}

static void vector_assign_managed_shutdown(struct irq_data *irqd)
{
	unsigned int cpu = cpumask_first(cpu_online_mask);

	apic_update_irq_cfg(irqd, managed_irq_shutdown_vector, cpu);
}

static int reserve_managed_vector(struct irq_data *irqd)
{
	const struct cpumask *affmsk = irq_data_get_affinity_mask(irqd);
	struct pic_chip_data *picd = pic_chip_data(irqd);
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&vector_lock, flags);
	picd->is_managed = true;
	ret = irq_matrix_reserve_managed(vector_matrix, affmsk);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	trace_vector_reserve_managed(irqd->irq, ret);
	return ret;
}

static int
assign_vector_locked(struct irq_data *irqd, const struct cpumask *dest)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);
	unsigned int cpu = picd->cpu;
	int vector = picd->vector;

	lockdep_assert_held(&vector_lock);

	/*
	 * If the current target CPU is online and in the new requested
	 * affinity mask, there is no point in moving the interrupt from
	 * one CPU to another.
	 */
	if (vector && cpu_online(cpu) && cpumask_test_cpu(cpu, dest))
		return 0;

	/*
	 * Careful here. @apicd might either have move_in_progress set or
	 * be enqueued for cleanup. Assigning a new vector would either
	 * leave a stale vector on some CPU around or in case of a pending
	 * cleanup corrupt the hlist.
	 */
	if (picd->move_in_progress || !hlist_unhashed(&picd->clist))
		return -EBUSY;

	vector = irq_matrix_alloc(vector_matrix, dest, false, &cpu);

	trace_vector_alloc(irqd->irq, vector, vector);
	if (vector < 0)
		return vector;
	apic_update_vector(irqd, vector, cpu);
	apic_update_irq_cfg(irqd, vector, cpu);

	return 0;
}

static int assign_irq_vector(struct irq_data *irqd, const struct cpumask *dest)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&vector_lock, flags);
	cpumask_and(vector_searchmask, dest, cpu_online_mask);
	ret = assign_vector_locked(irqd, vector_searchmask);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	return ret;
}

static int assign_irq_vector_any_locked(struct irq_data *irqd)
{
	/* Get the affinity mask - either irq_default_affinity or (user) set */
	const struct cpumask *affmsk = irq_data_get_affinity_mask(irqd);
	int node = irq_data_get_node(irqd);

	if (node != NUMA_NO_NODE) {
		/* Try the intersection of @affmsk and node mask */
		cpumask_and(vector_searchmask, cpumask_of_node(node), affmsk);
		if (!assign_vector_locked(irqd, vector_searchmask))
			return 0;
	}

	/* Try the full affinity mask */
	cpumask_and(vector_searchmask, affmsk, cpu_online_mask);
	if (!assign_vector_locked(irqd, vector_searchmask))
		return 0;

	if (node != NUMA_NO_NODE) {
		/* Try the node mask */
		if (!assign_vector_locked(irqd, cpumask_of_node(node)))
			return 0;
	}

	/* Try the full online mask */
	return assign_vector_locked(irqd, cpu_online_mask);
}


static int assign_irq_system_vector_locked(struct irq_data *irqd, bool percpu)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);
	int vector = picd->vector;

	lockdep_assert_held(&vector_lock);

	BUG_ON(vector);
	vector = irqd->hwirq;
	trace_vector_alloc(irqd->irq, vector, vector);

	picd->hw_irq_cfg.vector = vector;

	return 0;
}

static int assign_irq_system_vector(struct irq_data *irqd, bool percpu)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&vector_lock, flags);
	ret = assign_irq_system_vector_locked(irqd, percpu);
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	/* Can not be called with vector_lock held:
	 * irq_desc_lock_class & vector_lock circular
	 * locking dependency */
	if (percpu)
		irq_set_percpu_devid(irqd->irq);
	return ret;
}

static int
assign_irq_vector_policy(struct irq_data *irqd, bool system_vec, bool percpu)
{

	const struct cpumask *affmsk = irq_data_get_affinity_mask(irqd);
	if (system_vec)
		return assign_irq_system_vector(irqd, percpu);

	if (irqd_affinity_is_managed(irqd))
		return reserve_managed_vector(irqd);
	return assign_irq_vector(irqd, affmsk);
}

static int
assign_managed_vector(struct irq_data *irqd, const struct cpumask *dest)
{
	const struct cpumask *affmsk = irq_data_get_affinity_mask(irqd);
	struct pic_chip_data *picd = pic_chip_data(irqd);
	int vector, cpu;

	cpumask_and(vector_searchmask, dest, affmsk);

	/* set_affinity might call here for nothing */
	if (picd->vector && cpumask_test_cpu(picd->cpu, vector_searchmask))
		return 0;
	vector = irq_matrix_alloc_managed(vector_matrix, vector_searchmask,
					  &cpu);
	trace_vector_alloc_managed(irqd->irq, vector, vector);
	if (vector < 0)
		return vector;
	apic_update_vector(irqd, vector, cpu);
	apic_update_irq_cfg(irqd, vector, cpu);
	return 0;
}

static void clear_irq_vector(struct irq_data *irqd)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);
	bool managed = irqd_affinity_is_managed(irqd);
	unsigned int vector = picd->vector;

	lockdep_assert_held(&vector_lock);

	if (!vector)
		return;

	trace_vector_clear(irqd->irq, vector, picd->cpu, picd->prev_vector,
			   picd->prev_cpu);

	per_cpu(vector_irq, picd->cpu)[vector] = VECTOR_SHUTDOWN;
	irq_matrix_free(vector_matrix, picd->cpu, vector, managed);
	picd->vector = 0;

	/* Clean up move in progress */
	vector = picd->prev_vector;
	if (!vector)
		return;

	per_cpu(vector_irq, picd->prev_cpu)[vector] = VECTOR_SHUTDOWN;
	irq_matrix_free(vector_matrix, picd->prev_cpu, vector, managed);
	picd->prev_vector = 0;
	picd->move_in_progress = 0;
	hlist_del_init(&picd->clist);
}

static void l_vector_deactivate(struct irq_domain *dmn, struct irq_data *irqd)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);
	unsigned long flags;
	bool sys;
	struct irq_data *d = irq_domain_get_irq_data(dmn, irqd->irq);
	BUG_ON(!d);
	sys = !!d->hwirq;
	if (sys)
		return;
	trace_vector_deactivate(irqd->irq, picd->is_managed, false);

	/* Regular fixed assigned interrupt */
	if (!picd->is_managed)
		return;

	raw_spin_lock_irqsave(&vector_lock, flags);
	clear_irq_vector(irqd);
	vector_assign_managed_shutdown(irqd);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
}

static int activate_managed(struct irq_data *irqd)
{
	const struct cpumask *dest = irq_data_get_affinity_mask(irqd);
	int ret;

	cpumask_and(vector_searchmask, dest, cpu_online_mask);
	if (WARN_ON_ONCE(cpumask_empty(vector_searchmask))) {
		/* Something in the core code broke! Survive gracefully */
		pr_err("Managed startup for irq %u, but no CPU\n", irqd->irq);
		return -EINVAL;
	}

	ret = assign_managed_vector(irqd, vector_searchmask);
	/*
	 * This should not happen. The vector reservation got buggered.  Handle
	 * it gracefully.
	 */
	if (WARN_ON_ONCE(ret < 0)) {
		pr_err("Managed startup irq %u, no vector available\n",
		       irqd->irq);
	}
	return ret;
}

static int l_vector_activate(struct irq_domain *dmn, struct irq_data *irqd,
			       bool reserve)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);
	unsigned long flags;
	int ret = 0;
	bool sys;
	struct irq_data *d = irq_domain_get_irq_data(dmn, irqd->irq);
	BUG_ON(!d);
	sys = !!d->hwirq;
	if (sys)
		return 0;

	trace_vector_activate(irqd->irq, picd->is_managed, reserve);


	raw_spin_lock_irqsave(&vector_lock, flags);
	if (!picd->is_managed)
		assign_irq_vector_any_locked(irqd);
	else if (reserve || irqd_is_managed_and_shutdown(irqd))
		vector_assign_managed_shutdown(irqd);
	else
		ret = activate_managed(irqd);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	return ret;
}

static void vector_free_managed(struct irq_data *irqd)
{
	const struct cpumask *dest = irq_data_get_affinity_mask(irqd);
	struct pic_chip_data *picd = pic_chip_data(irqd);

	trace_vector_teardown(irqd->irq, picd->is_managed);

	if (picd->is_managed)
		irq_matrix_remove_managed(vector_matrix, dest);
}

static void l_vector_free_irqs(struct irq_domain *dmn,
				 unsigned int irq, unsigned int nr_irqs)
{
	struct pic_chip_data *picd;
	struct irq_data *irqd;
	unsigned long flags;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irqd = irq_domain_get_irq_data(l_vector_domain, irq + i);
		if (irqd && irqd->chip_data) {
			raw_spin_lock_irqsave(&vector_lock, flags);
			clear_irq_vector(irqd);
			vector_free_managed(irqd);
			picd = irqd->chip_data;
			irq_domain_reset_irq_data(irqd);
			raw_spin_unlock_irqrestore(&vector_lock, flags);
			free_apic_chip_data(picd);
		}
	}
}
static int l_vector_irq_map(struct irq_domain *dmn, unsigned int irq,
				   irq_hw_number_t hwirq)
{
	bool sys, percpu;
	int err, node;
	struct irq_data *irqd;
	struct pic_chip_data *picd;
	struct irq_chip *ic = dmn->host_data;
	struct irq_data *d = irq_get_irq_data(irq);
	BUG_ON(!d);
	BUG_ON(!ic);
	irqd = irq_domain_get_irq_data(dmn, irq);
	BUG_ON(!irqd);
	node = irq_data_get_node(irqd);
	WARN_ON_ONCE(irqd->chip_data);
	percpu = d == irqd;
	/* valid hwirq (vector) only for childless irqd */
	if (percpu)
		irqd->hwirq = hwirq;
	/* check if child irq-controller assigned vector for us */
	sys = irqd->hwirq != 0;

	picd = alloc_pic_chip_data(node);
	if (!picd) {
		err = -ENOMEM;
		goto error;
	}

	picd->irq = irq;
	irqd->chip = ic;
	irqd->chip_data = picd;
	if (percpu)
		irq_set_handler_locked(irqd, handle_percpu_devid_irq);

	irqd_set_single_target(irqd);
	/*
		* Prevent that any of these interrupts is invoked in
		* non interrupt context via e.g. generic_handle_irq()
		* as that can corrupt the affinity move state.
		*/
	irqd_set_handle_enforce_irqctx(irqd);

	/* Don't invoke affinity setter on deactivated interrupts */
	irqd_set_affinity_on_activate(irqd);

	err = assign_irq_vector_policy(irqd, sys, percpu);
	trace_vector_setup(irq, false, err);
	if (err) {
		irqd->chip_data = NULL;
		free_apic_chip_data(picd);
		goto error;
	}
	return 0;
error:
	l_vector_free_irqs(dmn, irq, 1);
	return err;
}

static int l_vector_alloc_irqs(struct irq_domain *dmn, unsigned int irq,
				 unsigned int nr_irqs, void *arg)
{
	int i, err;
	struct irq_fwspec *fwspec = arg;
	if (arg == NULL)
		return 0;

	for (i = 0; i < nr_irqs; i++) {
		bool percpu;
		unsigned int type;
		irq_hw_number_t hwirq = NO_IRQ;
		struct irq_data *d = irq_get_irq_data(irq);
		struct irq_data *irqd = irq_domain_get_irq_data(dmn, irq);
		BUG_ON(!d);
		BUG_ON(!irqd);
		percpu = d == irqd;
		if (percpu) {
			err = irq_domain_translate_twocell(dmn,
					fwspec, &hwirq, &type);
			if (err)
				goto error;
		}

		err = l_vector_irq_map(dmn, irq + i, hwirq);
		if (err)
			goto error;
	}

	return 0;

error:
	l_vector_free_irqs(dmn, irq, i ? i - 1 : i);
	return err;
}

#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
static void l_vector_debug_show(struct seq_file *m, struct irq_domain *d,
				  struct irq_data *irqd, int ind)
{
	struct pic_chip_data picd;
	unsigned long flags;

	if (!irqd) {
		irq_matrix_debug_show(m, vector_matrix, ind);
		return;
	}

	if (!irqd->chip_data) {
		seq_printf(m, "%*sVector: Not assigned\n", ind, "");
		return;
	}

	raw_spin_lock_irqsave(&vector_lock, flags);
	memcpy(&picd, irqd->chip_data, sizeof(picd));
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	seq_printf(m, "%*sVector: %5u\n", ind, "", picd.vector);
	seq_printf(m, "%*sTarget: %5u\n", ind, "", picd.cpu);
	if (picd.prev_vector) {
		seq_printf(m, "%*sPrevious vector: %5u\n", ind, "", picd.prev_vector);
		seq_printf(m, "%*sPrevious target: %5u\n", ind, "", picd.prev_cpu);
	}
	seq_printf(m, "%*smove_in_progress: %u\n", ind, "", picd.move_in_progress ? 1 : 0);
	seq_printf(m, "%*sis_managed:       %u\n", ind, "", picd.is_managed ? 1 : 0);
	seq_printf(m, "%*scleanup_pending:  %u\n", ind, "", !hlist_unhashed(&picd.clist));
}
#endif

static const struct irq_domain_ops l_vector_domain_ops = {
	.alloc		= l_vector_alloc_irqs,
	.free		= l_vector_free_irqs,
	.activate	= l_vector_activate,
	.deactivate	= l_vector_deactivate,
	.translate	= irq_domain_translate_twocell,
	.map		= l_vector_irq_map,
#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
	.debug_show	= l_vector_debug_show,
#endif
};

/* Online the local APIC infrastructure and initialize the vectors */
static int pic_starting_cpu(unsigned int cpu)
{
	lock_vector_lock();

	/* Online the vector matrix array for this CPU */
	irq_matrix_online(vector_matrix);

	/*
	 * Can get here after hibernation in which case `vector_irq`
	 * would be initialized in accordance with `pic_chip_data`.
	 * So avoid unconditional clearing of `vector_irq`.
	 */
	unlock_vector_lock();
	return 0;
}

static int pic_dying_cpu(unsigned int cpu)
{
	lock_vector_lock();
	irq_matrix_offline(vector_matrix);
	unlock_vector_lock();
	return 0;
}

#ifdef CONFIG_SMP
int pic_set_affinity(struct irq_data *irqd,
			     const struct cpumask *dest, bool force)
{
	int err;

	if (WARN_ON_ONCE(!irqd_is_activated(irqd)))
		return -EIO;

	raw_spin_lock(&vector_lock);
	cpumask_and(vector_searchmask, dest, cpu_online_mask);
	if (irqd_affinity_is_managed(irqd))
		err = assign_managed_vector(irqd, vector_searchmask);
	else
		err = assign_vector_locked(irqd, vector_searchmask);
	raw_spin_unlock(&vector_lock);
	return err ? err : IRQ_SET_MASK_OK;
}

static void free_moved_vector(struct pic_chip_data *picd)
{
	unsigned int vector = picd->prev_vector;
	unsigned int cpu = picd->prev_cpu;
	bool managed = picd->is_managed;

	/*
	 * Managed interrupts are usually not migrated away
	 * from an online CPU, but CPU isolation 'managed_irq'
	 * can make that happen.
	 * 1) Activation does not take the isolation into account
	 *    to keep the code simple
	 * 2) Migration away from an isolated CPU can happen when
	 *    a non-isolated CPU which is in the calculated
	 *    affinity mask comes online.
	 */
	trace_vector_free_moved(picd->irq, cpu, vector, managed);
	irq_matrix_free(vector_matrix, cpu, vector, managed);
	per_cpu(vector_irq, cpu)[vector] = VECTOR_UNUSED;
	hlist_del_init(&picd->clist);
	picd->prev_vector = 0;
	picd->move_in_progress = 0;
}

void smp_irq_move_cleanup_interrupt(void)
{
	struct hlist_head *clhead = this_cpu_ptr(&cleanup_list);
	struct pic_chip_data *picd;
	struct hlist_node *tmp;

	/* Prevent vectors vanishing under us */
	raw_spin_lock(&vector_lock);

	hlist_for_each_entry_safe(picd, tmp, clhead, clist) {
		unsigned int vector = picd->prev_vector;
		/*
		 * Paranoia: Check if the vector that needs to be cleaned
		 * up is registered at the APICs IRR. If so, then this is
		 * not the best time to clean it up. Clean it up in the
		 * next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
		 * to this CPU. IRQ_MOVE_CLEANUP_VECTOR is the lowest
		 * priority external vector, so on return from this
		 * interrupt the device interrupt will happen first.
		 */
		if (pic_check_vector_to_be_cleaned(vector))
			continue;

		free_moved_vector(picd);
	}

	raw_spin_unlock(&vector_lock);
}

static void __send_cleanup_vector(struct pic_chip_data *picd)
{
	unsigned int cpu;

	raw_spin_lock(&vector_lock);
	picd->move_in_progress = 0;
	cpu = picd->prev_cpu;
	if (cpu_online(cpu)) {
		hlist_add_head(&picd->clist, per_cpu_ptr(&cleanup_list, cpu));
		pic_send_cleanup_vector(cpumask_of(cpu));
	} else {
		picd->prev_vector = 0;
	}
	raw_spin_unlock(&vector_lock);
}

void send_cleanup_vector(struct irq_cfg *cfg)
{
	struct pic_chip_data *picd;

	picd = container_of(cfg, struct pic_chip_data, hw_irq_cfg);
	if (picd->move_in_progress)
		__send_cleanup_vector(picd);
}

void irq_complete_move(struct irq_cfg *cfg)
{
	struct pic_chip_data *picd;

	picd = container_of(cfg, struct pic_chip_data, hw_irq_cfg);
	if (likely(!picd->move_in_progress))
		return;

	/*
	 * If the interrupt arrived on the new target CPU, cleanup the
	 * vector on the old target CPU. A vector check is not required
	 * because an interrupt can never move from one vector to another
	 * on the same CPU.
	 */
	if (picd->cpu == smp_processor_id())
		__send_cleanup_vector(picd);
}

void irq_force_complete_move(struct irq_desc *desc)
{
	struct pic_chip_data *picd;
	struct irq_data *irqd;
	unsigned int vector;

	/*
	 * The function is called for all descriptors regardless of which
	 * irqdomain they belong to. For example if an IRQ is provided by
	 * an irq_chip as part of a GPIO driver, the chip data for that
	 * descriptor is specific to the irq_chip in question.
	 *
	 * Check first that the chip_data is what we expect
	 * (pic_chip_data) before touching it any further.
	 */
	irqd = irq_domain_get_irq_data(l_vector_domain,
				       irq_desc_get_irq(desc));
	if (!irqd)
		return;

	raw_spin_lock(&vector_lock);
	picd = pic_chip_data(irqd);
	if (!picd)
		goto unlock;

	/*
	 * If prev_vector is empty, no action required.
	 */
	vector = picd->prev_vector;
	if (!vector)
		goto unlock;

	/*
	 * This is tricky. If the cleanup of the old vector has not been
	 * done yet, then the following setaffinity call will fail with
	 * -EBUSY. This can leave the interrupt in a stale state.
	 *
	 * All CPUs are stuck in stop machine with interrupts disabled so
	 * calling __irq_complete_move() would be completely pointless.
	 *
	 * 1) The interrupt is in move_in_progress state. That means that we
	 *    have not seen an interrupt since the io_apic was reprogrammed to
	 *    the new vector.
	 *
	 * 2) The interrupt has fired on the new vector, but the cleanup IPIs
	 *    have not been processed yet.
	 */
	if (picd->move_in_progress) {
		/*
		 * In theory there is a race:
		 *
		 * set_ioapic(new_vector) <-- Interrupt is raised before update
		 *			      is effective, i.e. it's raised on
		 *			      the old vector.
		 *
		 * So if the target cpu cannot handle that interrupt before
		 * the old vector is cleaned up, we get a spurious interrupt
		 * and in the worst case the ioapic irq line becomes stale.
		 *
		 * But in case of cpu hotplug this should be a non issue
		 * because if the affinity update happens right before all
		 * cpus rendezvous in stop machine, there is no way that the
		 * interrupt can be blocked on the target cpu because all cpus
		 * loops first with interrupts enabled in stop machine, so the
		 * old vector is not yet cleaned up when the interrupt fires.
		 *
		 * So the only way to run into this issue is if the delivery
		 * of the interrupt on the apic/system bus would be delayed
		 * beyond the point where the target cpu disables interrupts
		 * in stop machine. I doubt that it can happen, but at least
		 * there is a theoretical chance. Virtualization might be
		 * able to expose this, but AFAICT the IOAPIC emulation is not
		 * as stupid as the real hardware.
		 *
		 * Anyway, there is nothing we can do about that at this point
		 * w/o refactoring the whole fixup_irq() business completely.
		 * We print at least the irq number and the old vector number,
		 * so we have the necessary information when a problem in that
		 * area arises.
		 */
		pr_warn("IRQ fixup: irq %d move in progress, old vector %d\n",
			irqd->irq, vector);
	}
	free_moved_vector(picd);
unlock:
	raw_spin_unlock(&vector_lock);
}

#ifdef CONFIG_HOTPLUG_CPU

#if 0	/* not used */
/*
 * Note, this is not accurate accounting, but at least good enough to
 * prevent that the actual interrupt move will run out of vectors.
 */
static int lapic_can_unplug_cpu(void)
{
	unsigned int rsvd, avl, tomove, cpu = smp_processor_id();
	int ret = 0;

	raw_spin_lock(&vector_lock);
	tomove = irq_matrix_allocated(vector_matrix);

	avl = irq_matrix_available(vector_matrix, true);
	if (avl < tomove) {
		pr_warn("CPU %u has %u vectors, %u available. Cannot disable CPU\n",
			cpu, tomove, avl);
		ret = -ENOSPC;
		goto out;
	}
	rsvd = irq_matrix_reserved(vector_matrix);
	if (avl < rsvd) {
		pr_warn("Reserved vectors %u > available %u. IRQ request may fail\n",
			rsvd, avl);
	}
out:
	raw_spin_unlock(&vector_lock);
	return ret;
}
#endif /* if 0 */
#endif /* HOTPLUG_CPU */
#endif /* SMP */

static int __init
pic_of_init(struct device_node *np, struct device_node *parent,
		struct pic_params *p)
{
	int ret;

	ret = pic_get_vector_by_name(np, NULL, "MSV managed irq shutdown vector",
					&managed_irq_shutdown_vector);
	if (WARN(ret, "Please update device tree\n"))
		return ret;

	l_vector_domain = irq_domain_create_tree(of_node_to_fwnode(np), &l_vector_domain_ops,
					p->ic);
	BUG_ON(l_vector_domain == NULL);

	BUG_ON(!alloc_cpumask_var(&vector_searchmask, GFP_KERNEL));

	/*
	 * Allocate the vector matrix allocator data structure and limit the
	 * search area.
	 */
	vector_matrix = irq_alloc_matrix(NR_VECTORS, FIRST_EXTERNAL_VECTOR + 1,
					 p->end_vector);
	BUG_ON(!vector_matrix);
	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_VECTOR_STARTING,
				  "l/irq/vector:starting",
				  pic_starting_cpu, pic_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		return ret;

	return pic_init_smp(l_vector_domain, np, p);
}
#ifdef CONFIG_L_LOCAL_APIC
static int __init apic_of_init(struct device_node *np,
			struct device_node *parent)
{
	struct pic_params p = {
		.ic = &lapic_controller,
		.end_vector = FIRST_SYSTEM_VECTOR,
		.pic_smp_error_interrupt = apic_smp_error_interrupt,
		.pic_smp_spurious_interrupt = apic_smp_spurious_interrupt,
	};
	int ret = pic_of_init(np, parent, &p);
	if (ret)
		return ret;
	return apic_init(np, &p);
}
IRQCHIP_DECLARE(apic, "mcst,apic", apic_of_init);
#endif
#ifdef CONFIG_EPIC
static int __init epic_of_init(struct device_node *np,
			struct device_node *parent)
{
	int ret;
	struct pic_params p = {
		.ic = &epic_controller,
		.end_vector = FIRST_EPIC_SYSTEM_VECTOR,
		.pic_smp_error_interrupt = epic_smp_error_interrupt,
		.pic_smp_spurious_interrupt = epic_smp_spurious_interrupt,
	};
	ret = pic_of_init(np, parent, &p);
	if (ret)
		return ret;
	return epic_init(np, &p);
}
IRQCHIP_DECLARE(epic, "mcst,epic", epic_of_init);
#endif
