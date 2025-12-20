/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/tlb.h>
#include <linux/percpu-defs.h>
#include <linux/spinlock.h>
#include <asm/kvm/async_pf.h>
#include <asm/kvm/hypercall.h>
#include <asm/irq_vectors.h>
#include <asm/kvm_host.h>


/* Task waiting for async page fault completion */
struct pv_apf_wait_task {
	struct hlist_node link;
	struct task_struct *task;
	u32 apf_id;
};

/*
 * Cache to store tasks waiting for async page fault completion.
 * The key is apf_id = vcpu->arch.apf.id << 12 | vcpu->id .
 */
static struct pv_apf_wait_bucket {
	raw_spinlock_t lock;
	struct hlist_head list;
} pv_apf_cache[KVM_APF_CACHE_SIZE];

/*
 * Descriptor of async page fault event, filled by host
 *
 * @apf_reson - type of async page fault event
 * 3 possible values:
 * KVM_APF_NO - no async page fault occurred.
 * KVM_APF_PAGE_IN_SWAP - physical page was swapped out by host,
 * need to suspend current process until it will be loaded from swap.
 * KVM_APF_PAGE_READY - physical page is loaded from swap and ready for access,
 * need to wake up process waiting for loading of this page.
 *
 * @apf_id- unique identifier for async page fault event
 * Needed by irq handler epic_apf_wake
 * apf_id = vcpu->arch.apf.id << 12 | vcpu->id
 */
struct pv_apf_event {
	u32 apf_reason;
	u32 apf_id;
};

static DEFINE_PER_CPU(struct pv_apf_event, pv_apf_event);

u32 pv_apf_read_and_reset_reason(void)
{
	u32 apf_reason = this_cpu_read(pv_apf_event.apf_reason);

	this_cpu_write(pv_apf_event.apf_reason, KVM_APF_NO);
	return apf_reason;
}

static u32 pv_apf_read_and_reset_id(void)
{
	u32 apf_id = this_cpu_read(pv_apf_event.apf_id);

	this_cpu_write(pv_apf_event.apf_id, 0);
	return apf_id;
}

/*
 * Wake up task, waiting for async page fault completion
 */
static void pv_apf_wake_one_task(struct pv_apf_wait_task *wait_task)
{
	hlist_del_init(&wait_task->link);

	if (wait_task->task) {
		wake_up_process(wait_task->task);
		wait_task->task = NULL;
	}
}

/*
 * Lookup for task with required apf_id in pv_apf_cache hash bucket
 */
static struct pv_apf_wait_task *pv_apf_find_wait_task(
					struct pv_apf_wait_bucket *wait_bucket,
					u32 apf_id)
{
	struct hlist_node *wait_entry;

	hlist_for_each(wait_entry, &wait_bucket->list) {
		struct pv_apf_wait_task *wait_task =
			hlist_entry(wait_entry, typeof(*wait_task), link);
		if (wait_task->apf_id == apf_id)
			return wait_task;
	}

	return NULL;
}

/*
 * Suspend current task to wait for completion of async page fault handling.
 */
void pv_apf_wait(void)
{
	struct pv_apf_wait_task new_wait_task, *exist_wait_task;
	unsigned long flags;
	u32 apf_id = pv_apf_read_and_reset_id();

	/* Get hash bucket in pv_apf_cache */
	u32 key = hash_32(apf_id, KVM_APF_HASH_BITS);
	struct pv_apf_wait_bucket *wait_bucket = &pv_apf_cache[key];

	raw_spin_lock_irqsave(&wait_bucket->lock, flags);

	exist_wait_task = pv_apf_find_wait_task(wait_bucket, apf_id);

	if (exist_wait_task) {
		/*
		 * pv_apf_wake was called ahead of pv_apf_wait.
		 * Delete dummy entry from cache and do not suspend
		 * current task.
		 */
		hlist_del(&exist_wait_task->link);
		kfree(exist_wait_task);

		raw_spin_unlock_irqrestore(&wait_bucket->lock, flags);

		return;
	}

	/* Add current task in pv_apf_cache */
	new_wait_task.apf_id = apf_id;
	new_wait_task.task = current;
	hlist_add_head(&new_wait_task.link, &wait_bucket->list);

	raw_spin_unlock_irqrestore(&wait_bucket->lock, flags);


	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);

		/* Check if current task was woken up by pv_apf_wake */
		if (hlist_unhashed(&new_wait_task.link))
			break;

		/*
		 * Suspend current task until it will be woken
		 * up by pv_apf_wake
		 */
		schedule();
	}

	__set_current_state(TASK_RUNNING);
}

/*
 * Wake up task, which waits for async page fault completion
 */
void pv_apf_wake(void)
{
	u32 apf_id = pv_apf_read_and_reset_id();

	/* Get hash bucket in pv_apf_cache */
	u32 key = hash_32(apf_id, KVM_APF_HASH_BITS);
	struct pv_apf_wait_bucket *wait_bucket = &pv_apf_cache[key];

	struct pv_apf_wait_task *wait_task;
	unsigned long flags;

	raw_spin_lock_irqsave(&wait_bucket->lock, flags);

	wait_task = pv_apf_find_wait_task(wait_bucket, apf_id);

	if (!wait_task) {
		/*
		 * pv_apf_wake was called ahead of pv_apf_wait.
		 * Add dummy entry in pv_apf_cache with this apf_id and
		 * do not wake up any tasks.
		 */
		wait_task = kzalloc(sizeof(*wait_task), GFP_ATOMIC);
		E2K_KVM_BUG_ON(!wait_task);
		wait_task->apf_id = apf_id;
		hlist_add_head(&wait_task->link, &wait_bucket->list);

		raw_spin_unlock_irqrestore(&wait_bucket->lock, flags);

		return;
	}

	/* Waiting task is present in pv_apf_cache, wake up it */
	pv_apf_wake_one_task(wait_task);

	raw_spin_unlock_irqrestore(&wait_bucket->lock, flags);
}

/*
 * Translate gva to gpa
 */
static phys_addr_t gva_to_gpa(void *gva)
{
	return node_kernel_address_to_phys(numa_node_id(),
			(unsigned long) gva);
}

/*
 * Enable async page fault handling on current cpu
 */
static void pv_apf_enable_curr_cpu(void *info)
{
	struct pv_apf_event *event = this_cpu_ptr(&pv_apf_event);
	phys_addr_t apf_reason_gpa = gva_to_gpa(&event->apf_reason);
	phys_addr_t apf_id_gpa = gva_to_gpa(&event->apf_id);

	this_cpu_write(pv_apf_event.apf_reason, KVM_APF_NO);
	this_cpu_write(pv_apf_event.apf_id, 0);

	WARN_ON(HYPERVISOR_pv_enable_async_pf(apf_reason_gpa, apf_id_gpa,
				ASYNC_PF_WAKE_VECTOR, EPIC_CONTROLLER));
}

/*
 * Enable async page fault handling on all cpus
 */
static int __init pv_apf_enable(void)
{
	if (IS_HV_GM())
		on_each_cpu(&pv_apf_enable_curr_cpu, NULL, 1);

	return 0;
}
arch_initcall(pv_apf_enable);
