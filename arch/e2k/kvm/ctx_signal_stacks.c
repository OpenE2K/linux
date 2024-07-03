/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains interfaces for managing of separate signal stacks
 * for guest's contexts
 */

#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <asm/thread_info.h>
#include <asm/process.h>

#include <asm/kvm/mm.h>
#include <asm/kvm/thread_info.h>
#include <asm/kvm/ctx_signal_stacks.h>
#include <asm/kvm/switch.h>


struct ctx_signal_stack {
	u64 key;
	struct signal_stack signal_stack;
	struct rhash_head hash_entry;

	/* Lifetime of stack management */
	atomic_t state;
	struct work_struct work;
	struct rcu_head rcu_head;

	/* Host mm, tied to vcpu host process */
	struct mm_struct *mm;
};

static const struct rhashtable_params hash_params = {
	.key_len = sizeof_field(struct ctx_signal_stack, key),
	.key_offset = offsetof(struct ctx_signal_stack, key),
	.head_offset = offsetof(struct ctx_signal_stack, hash_entry),
	.automatic_shrinking = true,
};


/* Internal interfaces for managing ctx signal stack hash table */

/* Life-time management for ctx signal stack: take a reference */
static inline int
take_ctx_stack(struct ctx_signal_stack *stack, int new_state)
{
	int old_state, ret;

	for (;;) {
		/* Try to change stack state if it is ready for use */
		old_state = atomic_cmpxchg(&stack->state,
						CTX_STACK_READY, new_state);
		if (likely(old_state == CTX_STACK_READY)) {
			ret = 0;
			break;
		}
		if (unlikely(old_state == CTX_STACK_BUSY)) {
			ret = -EBUSY;
			break;
		}

		/* Wait for fork() to finish copying this context */
		while (atomic_read(&stack->state) == CTX_STACK_COPYING)
			cpu_relax();
	}

	return ret;
}

/* Life-time management for ctx signal stack: put a reference */
static inline void
put_ctx_stack(struct ctx_signal_stack *stack)
{
	atomic_set(&stack->state, CTX_STACK_READY);
}

/*
 * Allocate new ctx signal stack descriptor.
 * Allocate new signal stack if signal_stack parameter is 0, use
 * exisiting signal stack if signal_stack parameter is not 0.
 */
static struct ctx_signal_stack *
alloc_ctx_signal_stack(u64 key, struct signal_stack *signal_stack,
			unsigned long size, unsigned long used, int state)
{
	struct ctx_signal_stack *ctx_stack;
	unsigned long stack_base, stack_size, stack_used;

	ctx_stack = kzalloc(sizeof(*ctx_stack), GFP_KERNEL);
	if (!ctx_stack)
		return NULL;

	stack_base = signal_stack ? signal_stack->base :
					allocate_signal_stack(size);
	if (IS_ERR_VALUE(stack_base)) {
		kfree(ctx_stack);
		return NULL;
	}

	stack_size = signal_stack ? signal_stack->size : size;
	stack_used = signal_stack ? signal_stack->used : used;
	ctx_stack->key = key;
	ctx_stack->signal_stack.base = stack_base;
	ctx_stack->signal_stack.size = stack_size;
	ctx_stack->signal_stack.used = stack_used;
	atomic_set(&ctx_stack->state, state);
	ctx_stack->mm = current->mm;

	return ctx_stack;
}

/* Free ctx signal stack descriptor and signal stack itself */
static void free_ctx_signal_stack(void *ptr, void *unused)
{
	u64 ts_flag;
	struct ctx_signal_stack *stack = (struct ctx_signal_stack *)ptr;
	struct mm_struct *mm = stack->mm;
	int downgraded;

	mmap_write_lock(mm);
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	downgraded = __do_munmap(mm, stack->signal_stack.base,
			stack->signal_stack.size, NULL, true);
	clear_ts_flag(ts_flag);
	if (downgraded == 1) {
		mmap_read_unlock(mm);
	} else {
		mmap_write_unlock(mm);
	}

	kfree(stack);
}

/* Work thread function, which calls freeing of ctx signal stack */
static void ctx_stack_free_work_fn(struct work_struct *work)
{
	struct ctx_signal_stack *stack =
				container_of(work, typeof(*stack), work);

	free_ctx_signal_stack(stack, NULL);
}

/* rcu call-back for delayed freeing of ctx signal stack */
static void rcu_free_ctx_signal_stack(struct rcu_head *head)
{
	struct ctx_signal_stack *stack = container_of(head,
						typeof(*stack), rcu_head);

	INIT_WORK(&stack->work, ctx_stack_free_work_fn);
	/* Use system_long_wq to avoid slowing system down too much */
	queue_work(system_long_wq, &stack->work);
}

/* Make full copy of ctx signal stack descriptor */
static struct ctx_signal_stack *
copy_ctx_signal_stack(struct ctx_signal_stack *stack)
{
	struct ctx_signal_stack *new_stack;
	u64 ts_flag;
	int ret;

	/* Allocate new ctx stack descriptor */
	new_stack = alloc_ctx_signal_stack(stack->key, NULL,
			stack->signal_stack.size, stack->signal_stack.used,
			atomic_read(&stack->state));
	if (!new_stack)
		return NULL;

	/* Copy all data from old stack to new */
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = raw_copy_in_user((void *)new_stack->signal_stack.base,
				(const void *)stack->signal_stack.base,
				stack->signal_stack.used);
	clear_ts_flag(ts_flag);

	if (ret) {
		free_ctx_signal_stack(new_stack, NULL);
		return NULL;
	}

	return new_stack;
}


/* External interfaces for working with context's stacks hash table */

/* Alloc and init new hash table for signal stacks of guest contexts */
struct rhashtable *alloc_gst_ctx_sig_stacks_ht(void)
{
	struct rhashtable *ht = kzalloc(sizeof(*ht), GFP_KERNEL);

	if (!ht)
		return NULL;

	if (rhashtable_init(ht, &hash_params)) {
		kfree(ht);
		return NULL;
	} else {
		return ht;
	}
}

/* Free hash table for signal stacks of guest contexts */
void free_gst_ctx_sig_stacks_ht(struct rhashtable *ht)
{
	if (!ht)
		return;

	rhashtable_free_and_destroy(ht, free_ctx_signal_stack, NULL);
	kfree(ht);
}

/* Copy guest contexts hash table */
struct rhashtable *copy_gst_ctx_sig_stacks_ht(void)
{
	struct kvm_vcpu *vcpu;
	gmm_struct_t *gmm;
	gthread_info_t *gti;
	u64 curr_ctx_key;
	struct signal_stack *curr_sig_stack;
	struct rhashtable *ht, *new_ht;
	struct ctx_signal_stack *old_stack, *new_stack;
	struct rhashtable_iter iter;
	int ret;

	/* Get guest ctx signal stacks hash table for current process */
	WARN_ON(!ts_host_at_vcpu_mode());
	vcpu = current_thread_info()->vcpu;
	gti = pv_vcpu_get_gti(vcpu);
	gmm = gti->gmm;
	ht = gmm->ctx_stacks;
	curr_ctx_key = gti->curr_ctx_key;
	curr_sig_stack = &current_thread_info()->signal_stack;
	WARN_ON(!ht);

	/* Allocate and init new hash table for gst signal stacks */
	new_ht = alloc_gst_ctx_sig_stacks_ht();
	if (!new_ht)
		return NULL;

	/* Copy all context stacks from old hash table to new */
	rhashtable_walk_enter(ht, &iter);

	do {
		rhashtable_walk_start(&iter);

		while ((old_stack = rhashtable_walk_next(&iter)) &&
				!IS_ERR(old_stack)) {

			ret = take_ctx_stack(old_stack, CTX_STACK_COPYING);
			if (ret)
				continue;

			rhashtable_walk_stop(&iter);

			/* Copy single ctx signal stack */
			new_stack = copy_ctx_signal_stack(old_stack);
			if (!new_stack) {
				put_ctx_stack(old_stack);
				goto copy_failed;
			}

			/* Add copied ctx signal stack to new hash table */
			ret = rhashtable_lookup_insert_key(new_ht,
							&new_stack->key,
							&new_stack->hash_entry,
							hash_params);
			if (ret) {
				free_ctx_signal_stack(new_stack, NULL);
				if (ret != -EEXIST) {
					put_ctx_stack(old_stack);
					goto copy_failed;
				}
			}

			put_ctx_stack(old_stack);

			rhashtable_walk_start(&iter);
		}

		rhashtable_walk_stop(&iter);
	} while (cond_resched(), old_stack == ERR_PTR(-EAGAIN));

	rhashtable_walk_exit(&iter);

	return new_ht;

copy_failed:
	free_gst_ctx_sig_stacks_ht(new_ht);
	return NULL;
}

/*
 * Add new ctx signal stack descriptor in gst ctx signal stacks hash table.
 * Allocates new space for signal stack if signal_stack parameter is 0, uses
 * existing signal stack if signal_stack parameter is not 0.
 */
int add_gst_ctx_signal_stack(struct rhashtable *ht,
			struct signal_stack *signal_stack,
			u64 key, int state)
{
	int ret;
	struct ctx_signal_stack *stack;

	/* Get hash table for current guest process */
	WARN_ON(!ts_host_at_vcpu_mode());

	/* Allocate new ctx signal stacks descriptor */
	stack = alloc_ctx_signal_stack(key, signal_stack, PAGE_SIZE, 0, state);
	if (!stack)
		return -ENOMEM;

	/* Insert new ctx signal stack into hash table */
	ret = rhashtable_lookup_insert_fast(ht, &stack->hash_entry,
					hash_params);
	return ret;
}

/*
 * Remove ctx signal stack descriptor from gst ctx signal stacks hash table.
 * Frees both ctx signal stack descriptor and signal stacks itself.
 */
void remove_gst_ctx_signal_stack(u64 key)
{
	struct kvm_vcpu *vcpu;
	struct rhashtable *ht;
	struct ctx_signal_stack *stack;

	/* Get hash table for current guest process */
	WARN_ON(!ts_host_at_vcpu_mode());
	vcpu = current_thread_info()->vcpu;
	ht = pv_vcpu_get_gti(vcpu)->gmm->ctx_stacks;

	rcu_read_lock();

	/*
	 * Check if ctx signal stack with this key exists in hash table.
	 * If stack found hash table, remove it
	 */
	stack = rhashtable_lookup(ht, &key, hash_params);
	if (stack)
		rhashtable_remove_fast(ht, &stack->hash_entry, hash_params);

	rcu_read_unlock();

	/* Free ctx stack descriptor after the end of grace period */
	if (stack)
		call_rcu(&stack->rcu_head, &rcu_free_ctx_signal_stack);
}

/* Switch from current ctx signal stacks to another ctx signal stack */
int switch_gst_ctx_signal_stack(u64 to_key)
{
	struct kvm_vcpu *vcpu;
	gthread_info_t *gti;
	struct rhashtable *ht;
	struct signal_stack *curr_sig_stack;
	u64 curr_ctx_key;
	struct ctx_signal_stack *curr_stack, *to_stack;
	int ret1, ret2, ret;
	u64 to_base, new_to_base, to_used, to_size, enlarge_size,
		from_base, context_size;

	/* Get ctx signal stacks hash table for current guest process */
	WARN_ON(!ts_host_at_vcpu_mode());
	vcpu = current_thread_info()->vcpu;
	gti = pv_vcpu_get_gti(vcpu);
	ht = gti->gmm->ctx_stacks;

	/* Get current signal stack and curr ctx key */
	curr_sig_stack = &current_thread_info()->signal_stack;
	curr_ctx_key = gti->curr_ctx_key;

	rcu_read_lock();

	/* Lookup for current stack in gst ctx stacks hash table */
	curr_stack = rhashtable_lookup(ht, &curr_ctx_key, hash_params);
	if (!curr_stack)
		ret1 = -ENOENT;
	else
		ret1 = 0;

	/* Lookup for next stacks in gst ctx stacks hash table */
	to_stack = rhashtable_lookup(ht, &to_key, hash_params);
	if (!to_stack)
		ret2 = -ENOENT;
	else
		ret2 = take_ctx_stack(to_stack, CTX_STACK_BUSY);

	rcu_read_unlock();

	if (ret1 || ret2) {
		ret = ret1 ? ret1 : ret2;
		goto out;
	}

	/* Upadte curr ctx stack parameters in hash table */
	curr_stack->signal_stack.base = curr_sig_stack->base;
	curr_stack->signal_stack.size = curr_sig_stack->size;
	curr_stack->signal_stack.used = curr_sig_stack->used;

	/*
	 * Enlarge new ctx stack if there is no enough space in it to copy
	 * last saved signal context from curr stack to it.
	 */
	to_base = to_stack->signal_stack.base;
	to_used = to_stack->signal_stack.used;
	to_size = to_stack->signal_stack.size;
	context_size = sizeof(struct signal_stack_context);
	enlarge_size = round_up(context_size, PAGE_SIZE);
	from_base = curr_stack->signal_stack.base;

	if (to_used + context_size > to_size) {
		new_to_base = remap_e2k_stack(to_base, to_size,
					to_size + enlarge_size, false);
		if (IS_ERR_VALUE(new_to_base)) {
			ret = -ENOMEM;
			goto out;
		}

		to_stack->signal_stack.base = new_to_base;
		to_stack->signal_stack.size = to_size + enlarge_size;
		to_stack->signal_stack.used = to_used;
	}

	/* "Move" last saved signal context from old stacks to new */
	to_stack->signal_stack.used += context_size;
	curr_stack->signal_stack.used -= context_size;

	/* Switch current signal stack to signal stacks of new context */
	curr_sig_stack->base = to_stack->signal_stack.base;
	curr_sig_stack->size = to_stack->signal_stack.size;
	curr_sig_stack->used = to_stack->signal_stack.used;
	gti->curr_ctx_key = to_key;

	ret = 0;
out:
	if (to_stack)
		put_ctx_stack(to_stack);

	return ret;
}
