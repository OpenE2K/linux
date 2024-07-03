/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Makecontext/freecontext implementation for Elbrus architecture
 *
 * 1. Every context has a user hardware stack associated with it.
 * Those stacks are organized in a hash table with "struct coroutine"
 * as entries.
 *
 * 2. Contexts are a property of a process so the hash table is located
 * in 'mm_struct' structure (mm->context.hw_contexts).
 *
 * 3. There can be multiple contexts in userspace (think "struct ucontext")
 * associated with the same hardware stack (think "struct coroutine"),
 * and we have to be able to find corresponding coroutine from ucontext.
 * To do that we need some key which will uniquely identify "struct coroutine".
 *
 * Forked child must be able to just copy kernel contexts without modifying
 * userspace. Thus using kernel pointers as a key is out of question.
 * So we will use whatever ends up in "pt_regs->stacks.sbr" as a key with
 * one caveat: we skip altstack entries entirely and find the first sbr.
 *
 * 4. Stacks that are in use have coroutine->state set to prevent them
 * from being freed under our feet. This state is checked to make sure
 * that setcontext/swapcontext is only possible to an unused stack.
 *
 * 5. When we switch to a context that is on current hardware stack, we
 * do a longjmp to a saved location. The same limitations as for setjmp/longjmp
 * apply.
 *
 * When we switch to a context that is on another hardware stack, we
 * first save current context and switch all registers, then check if
 * stack unwinding is necessary (and do a longjmp if it is).
 *
 * 6. When context created by makecontext() exits it should return
 * to the kernel trampoline which will switch to kernel data stack
 * and then switch to the context mentioned in uc_link or call do_exit().
 *
 * 7. The original context from main() is not in the hash table, but we
 * have to put it there on the first switch.
 *
 * 8. There are 2 ways defined in POSIX to save a context: getcontext()
 * and swapcontext().  So on e2k user application calls into glibc which
 * in turn makes a system call into kernel, and %cr registers contain
 * information about glibc's frame and not the application's one.
 *
 * To work around this:
 *  - sys_swapcontext will save %cr registers from the previous user's frame;
 *  - fast_sys_getcontext does not save %cr registers, instead it is done in
 *    glibc (because there is no performant way to do so in a fast syscall).
 *
 * 9. Synchronization is based on Documentation/RCU/rcuref.rst, pattern C,
 * with a twist: we need to mark current context "busy" so that no other
 * thread will use it simultaneously with current thread.

enum {STATE_BIAS = 1U, ALIVE_BIAS=1U<<16};
enum {
	HWC_STATE_READY = 0U,
	HWC_STATE_BUSY = 1U
};

union hw_context_lifetime {
	refcount_t refcount;
	struct {
		u16 state;
		u16 alive;
	};
} lifetime;

1. add() {
    alloc_object
    ...
    // For main context also set HWC_STATE_BUSY
    el->lifetime.alive = 1;
    el->lifetime.state = (main) ? HWC_STATE_BUSY : HWC_STATE_READY;
    spin_lock(&list_lock);
    add_element
    spin_unlock(&list_lock);
}

2. search_and_reference() {
    rcu_read_lock();
    el = search_for_element
    for (;;) {
	old_state = cmpxchg(&el->lifetime.state,
			    HWC_STATE_READY, new_state);
	if (likely(old_state == HWC_STATE_READY))
		break;
	if (old_state == HWC_STATE_BUSY) {
		el = NULL;
		break;
	}

	while (READ_ONCE(el->lifetime.state) == HWC_STATE_COPYING)
	    cpu_relax();
    }
    ...
    rcu_read_unlock();
    this_hw_context = el
}

3. This will be called only for BUSY contexts
release_referenced() {
    el = this_hw_context
    this_hw_context = NULL
    if (refcount_sub_and_test(state << HWC_STATE_SHIFT, &el->lifetime.refcount))
	kfree(el);
    ...
}

4. delete() {
    spin_lock(&list_lock);
    ...
    remove_element
    spin_unlock(&list_lock);
    ...
    call_rcu(&el->rcu_head, &element_free);
    ...
}

5. element_free() {
    if (refcount_sub_and_test(HWC_ALIVE_BIAS, &el->lifetime.refcount))
	kfree(el);
}
 */

#include <linux/delay.h>
#include <linux/mmu_context.h>
#include <linux/rhashtable.h>
#include <linux/sched/mm.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/context_tracking.h>

#include <asm/cpu.h>
#include <asm/copy-hw-stacks.h>
#include <asm/getsp_adj.h>
#include <asm/fpu/api.h>
#include <asm/mmu_context.h>
#include <asm/mmu.h>
#include <asm/regs_state.h>
#include <asm/trap_table.h>
#include <asm/traps.h>
#include <asm/e2k_debug.h>
#include <asm/ucontext.h>
#include <asm/proc_context_stacks.h>
#include <asm/protected_syscalls.h>
#include <asm/kvm/ctx_signal_stacks.h>

#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#include <asm/e2k_ptypes.h>
#include <asm/prot_loader.h>
#endif /* CONFIG_PROTECTED_MODE */

#define	DEBUG_CTX_MODE	0	/* setcontext/swapcontext */
#define	DebugCTX(...)	DebugPrint(DEBUG_CTX_MODE, ##__VA_ARGS__)


static inline u64 context_current_key(void)
{
	struct pt_regs __user *u_regs = signal_pt_regs_last();

	if (u_regs) {
		u64 top;

		if (__get_user(top, &u_regs->stacks.top))
			return -EFAULT;

		return top;
	}

	return current_thread_info()->u_stack.top;
}

static u32 ctx_key_hashfn(const void *data, u32 len, u32 seed)
{
	u64 key = *(const u64 *) data;
	return jhash_2words(key, key >> 32, seed);
}

static u32 ctx_obj_hashfn(const void *data, u32 len, u32 seed)
{
	const struct coroutine *ctx = data;
	u64 key = ctx->key;
	return jhash_2words(key, key >> 32, seed);
}

static inline int ctx_obj_cmpfn(struct rhashtable_compare_arg *arg,
				const void *obj)
{
	const u64 *key = arg->key;
	const struct coroutine *ctx = obj;
	return *key != ctx->key;
}

static const struct rhashtable_params hash_params = {
	.key_len = sizeof_field(struct coroutine, key),
	.key_offset = offsetof(struct coroutine, key),
	.head_offset = offsetof(struct coroutine, hash_entry),
	.hashfn = &ctx_key_hashfn,
	.obj_hashfn = &ctx_obj_hashfn,
	.obj_cmpfn = &ctx_obj_cmpfn,
	.automatic_shrinking = true,
};


static struct kmem_cache *hw_context_cache;

static __init int hw_context_cache_init(void)
{
	hw_context_cache = KMEM_CACHE(coroutine,
			SLAB_PANIC | SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT);

	return 0;
}
late_initcall(hw_context_cache_init);

/**
 * alloc_hw_context - allocate kernel stacks for a context
 * @main_context - is this main thread's context?
 * @u_stk_size - user data stack size
 *
 * For the main thread stacks are already allocated and we only
 * have to save their parameters.
 */
static struct coroutine *alloc_hw_context(bool main_context, size_t u_stk_size,
		unsigned long key)
{
	struct coroutine *ctx;
	hw_stack_t *hw_stacks;

	ctx = kmem_cache_zalloc(hw_context_cache, GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->key = key;
	/* For main context it is referenced from the beginning
	 * (see search_and_reference() above) */
	ctx->lifetime.alive = 1;
	ctx->lifetime.state = (main_context) ? HWC_STATE_BUSY : HWC_STATE_READY;

	INIT_LIST_HEAD(&ctx->ti.old_u_pcs_list);
	INIT_LIST_HEAD(&ctx->ti.getsp_adj);

	if (main_context) {
		/*
		 * Stacks have been allocated already
		 */
		ctx->ti.u_hw_stack = current_thread_info()->u_hw_stack;

		DebugCTX("ctx %lx allocated for main\n", ctx);
		return ctx;
	}

	hw_stacks = &ctx->ti.u_hw_stack;
	define_user_hw_stacks_sizes(hw_stacks);

	if (alloc_user_hw_stacks(hw_stacks, get_hw_ps_user_size(hw_stacks),
				 get_hw_pcs_user_size(hw_stacks)))
		goto free_context;

	DebugCTX("allocated ctx %lx with key=0x%lx and user stacks p: %px, pc: %px\n",
		ctx, key, GET_PS_BASE(hw_stacks), GET_PCS_BASE(hw_stacks));

	return ctx;

free_context:
	kmem_cache_free(hw_context_cache, ctx);

	DebugCTX("failed\n");
	return NULL;
}

/**
 * free_hw_context - free kernel stacks
 * @ctx - context to free
 * @ctx_in_use - free "struct coroutine" but keep the context itself
 * @keep_hw_stacks - set if we want to keep hardware stacks mapped
 */
static void free_hw_context(struct coroutine *ctx, bool ctx_in_use,
		bool keep_hw_stacks)
{
	if (!ctx_in_use) {
		free_user_old_pc_stack_areas(&ctx->ti.old_u_pcs_list);
		free_getsp_adj(&ctx->ti.getsp_adj);

		/*
		 * If the whole process is exiting we do not free
		 * address space - it is neither needed nor possible
		 * because by the time of destroy_context() call
		 * current->mm pointer has been set to NULL already.
		 */
		if (!keep_hw_stacks) {
			free_signal_stack(&ctx->ti.signal_stack);
			free_user_hw_stacks(&ctx->ti.u_hw_stack);
		}
	}

	DebugCTX("ctx %lx freed (%s stack areas, %s stack memory)\n",
			ctx, ctx_in_use ? "without" : "with",
			keep_hw_stacks ? "without" : "with");

	kmem_cache_free(hw_context_cache, ctx);
}

static inline int take_reference(struct coroutine *ctx, u16 new_state)
{
	/* search_and_reference() (see above) */
	u16 old_state;
	int ret;

	for (;;) {
		old_state = cmpxchg(&ctx->lifetime.state,
			    HWC_STATE_READY, new_state);
		if (likely(old_state == HWC_STATE_READY)) {
			ret = 0;
			break;
		}
		if (old_state == HWC_STATE_BUSY) {
			ret = -EBUSY;
			break;
		}

		/* Wait for fork() to finish copying this context */
		while (READ_ONCE(ctx->lifetime.state) == HWC_STATE_COPYING)
			cpu_relax();
	}

	return ret;
}

static inline int release_reference(struct coroutine *ctx, u16 ref_state)
{
	int ret;

	/* release_referenced() (see above) */
	ret = refcount_sub_and_test(ref_state << HWC_STATE_SHIFT,
			&ctx->lifetime.refcount);
	if (unlikely(ret))
		free_hw_context(ctx, false, false);

	return ret;
}


static void context_free_work_fn(struct work_struct *work)
{
	struct coroutine *ctx = container_of(work, typeof(*ctx), work);
	struct mm_struct *mm = ctx->mm;

	kthread_use_mm(mm);
	free_hw_context(ctx, false, false);
	kthread_unuse_mm(mm);

	mmput(mm);
}

static void context_free_rcu(struct rcu_head *head)
{
	struct coroutine *ctx = container_of(head, typeof(*ctx), rcu_head);

	if (refcount_sub_and_test(HWC_ALIVE_BIAS, &ctx->lifetime.refcount)) {
		INIT_WORK(&ctx->work, context_free_work_fn);
		/* Use system_long_wq to avoid slowing system down too much */
		queue_work(system_long_wq, &ctx->work);
	} else {
		mmput_async(ctx->mm);
	}
}

static void context_free(struct coroutine *ctx)
{
	/*
	 * element_free() (see above).
	 *
	 * For performance reasons (we do not want to wait for a grace period
	 * in a user thread) the context is freed as follows:
	 * 1) rcu kthread waits for the grace period to end and wakes a kworker
	 *    (because it's not possible to unmap user hardware stacks from
	 *    softirq context which is used by call_rcu())
	 * 2) kworker thread will unmap user hardware stacks and free kernel
	 *    memory.
	 * 3) In the unlikely case that the context is still in use by some
	 *    other thread it will be freed by that thread instead.
	 */
	mmget(current->mm);
	ctx->mm = current->mm;
	call_rcu(&ctx->rcu_head, &context_free_rcu);
}

void hw_context_deactivate_mm(struct task_struct *dead_task)
{
	struct thread_info *ti = task_thread_info(dead_task);
	mm_context_t *mm_context = &dead_task->mm->context;
	struct coroutine *ctx;

	if (!ti->this_hw_context)
		return;

	/*
	 * After thread exits, remove corresponding context from the hash table.
	 */
	ctx = ti->this_hw_context;
	ti->this_hw_context = NULL;

	if (WARN_ON_ONCE(ctx->lifetime.state != HWC_STATE_BUSY))
		return;

	if (!release_reference(ctx, HWC_STATE_BUSY)) {
		/* delete() (see above) */

		/* freecontext() hasn't been called yet, so remove
		 * the context ourselves. Be careful of concurrent
		 * freecontext() execution. */
		if (rhashtable_remove_fast(&mm_context->hw_contexts,
				&ctx->hash_entry, hash_params)) {
			pr_info_ratelimited("%s [%d]: context in use was found to be freed by freecontext_e2k()\n",
					current->comm, current->pid);
			return;
		}

		context_free(ctx);
	}
}

static int copy_context(struct task_struct *p,
		struct coroutine *dst, const struct coroutine *src)
{
	int ret;

	memcpy(dst, src, sizeof(*dst));

	INIT_LIST_HEAD(&dst->ti.old_u_pcs_list);
	INIT_LIST_HEAD(&dst->ti.getsp_adj);
	dst->lifetime.alive = 1;
	if (src == current_thread_info()->this_hw_context)
		dst->lifetime.state = HWC_STATE_BUSY;
	else
		dst->lifetime.state = HWC_STATE_READY;

	ret = __copy_old_u_pcs_list(&dst->ti.old_u_pcs_list,
				    &src->ti.old_u_pcs_list);
	if (ret)
		return ret;

	ret = __copy_getsp_adj(&dst->ti.getsp_adj, &src->ti.getsp_adj);
	if (ret)
		return ret;

	DebugCTX("context 0x%lx copied to 0x%lx, key 0x%llx\n",
			src, dst, src->key);
	return 0;
}

static void hw_context_destroy_one(void *ptr, void *unused)
{
	DebugCTX("ctx %lx free on exit\n", ptr);

	/*
	 * No 'mm' at this point so don't try to free user stacks
	 */
	free_hw_context((struct coroutine *) ptr, false, true);
}

/**
 * hw_contexts_init - called on process creation to prepare contexts hash table
 * @mm - mm that is being created
 */
int hw_contexts_init(struct task_struct *p, mm_context_t *mm_context,
		bool is_fork)
{
	struct coroutine *ctx;
	struct rhashtable_iter iter;
	int ret;

	ret = rhashtable_init(&mm_context->hw_contexts, &hash_params);
	if (ret || !is_fork)
		return ret;

	/*
	 * Copy all contexts on fork
	 */
	rhashtable_walk_enter(&current->mm->context.hw_contexts, &iter);

	do {
		/* Allocate memory before taking HWC_STATE_COPYING
		 * reference to context, otherwise we might stall
		 * another thread which would spin in take_reference(). */
		struct coroutine *new = kmem_cache_alloc(hw_context_cache, GFP_KERNEL);
		if (!new) {
			ret = -ENOMEM;
			goto error_walk_exit;
		}

		rhashtable_walk_start(&iter);

		while ((ctx = rhashtable_walk_next(&iter)) && !IS_ERR(ctx)) {
			ret = take_reference(ctx, HWC_STATE_COPYING);
			if (ret)
				continue;

			rhashtable_walk_stop(&iter);

			ret = copy_context(p, new, ctx);
			if (ret) {
				free_hw_context(new, false, true);
				goto error_drop_reference;
			}

			ret = rhashtable_lookup_insert_key(
					&mm_context->hw_contexts, &new->key,
					&new->hash_entry, hash_params);
			if (ret) {
				free_hw_context(new, false, true);
				if (ret != -EEXIST)
					goto error_drop_reference;
			}

			(void) release_reference(ctx, HWC_STATE_COPYING);

			new = kmem_cache_alloc(hw_context_cache, GFP_KERNEL);
			if (!new) {
				ret = -ENOMEM;
				goto error_walk_exit;
			}

			rhashtable_walk_start(&iter);
		}

		rhashtable_walk_stop(&iter);

		kmem_cache_free(hw_context_cache, new);
	} while (cond_resched(), ctx == ERR_PTR(-EAGAIN));

	rhashtable_walk_exit(&iter);

	/*
	 * Copy current context if it exists
	 */
	if (current_thread_info()->this_hw_context) {
		struct coroutine *new = kmem_cache_alloc(hw_context_cache,
							  GFP_KERNEL);
		if (!new) {
			ret = -ENOMEM;
			goto error;
		}

		ret = copy_context(p, new,
				current_thread_info()->this_hw_context);
		if (ret) {
			free_hw_context(new, false, true);
			goto error;
		}

		ret = rhashtable_lookup_insert_key(
				&mm_context->hw_contexts, &new->key,
				&new->hash_entry, hash_params);
		if (ret) {
			free_hw_context(new, false, true);
			if (ret != -EEXIST)
				goto error;
		}

		task_thread_info(p)->this_hw_context = new;
	}

	return 0;


error_drop_reference:
	(void) release_reference(ctx, HWC_STATE_COPYING);

error_walk_exit:
	rhashtable_walk_exit(&iter);

error:
	rhashtable_free_and_destroy(&mm_context->hw_contexts,
			hw_context_destroy_one, NULL);

	DebugCTX("context copying on fork failed with %d\n", ret);
	return ret;
}

/**
 * hw_contexts_destroy - called on process exit to free all contexts
 * @mm - mm that is being freed
 */
void hw_contexts_destroy(mm_context_t *mm_context)
{
	/* By this point there is no one left to write to hash table */
	rhashtable_free_and_destroy(&mm_context->hw_contexts,
			hw_context_destroy_one, NULL);
}

static int set_user_ap(void __user *ptr, unsigned long addr, size_t len)
{
	unsigned long ts_flag;
	int ret;
	e2k_ptr_t qptr = MAKE_AP(addr, len);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __put_user_tagged_16_offset(qptr.lo, qptr.hi, ETAGAPQ,
			ptr, machine.qnr1_offset);
	clear_ts_flag(ts_flag);

	return ret;
}

struct longjmp_regs {
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
};

/**
 * makecontext_prepare_user_stacks - set up all stacks for a user function execution
 * @ctx: hardware context
 * @func: user function
 * @args_size: size of all arguments
 * @args: pointer to arguments
 * @u_stk_base: user data stack base
 * @u_stk_size: user data stack size
 * @format: 32, 64 or 128 mode
 * @ucp: user-provided ucontext
 *
 * The first frame in the context is set to point to a kernel function
 * which will handle return from @func, and the second frame points to
 * @func.
 */
static int makecontext_prepare_user_stacks(struct longjmp_regs *user_regs,
		struct coroutine *ctx, void __user *func,
		u64 args_size, u64 __user *args,
		void __user *u_stk_base, size_t u_stk_size,
		int format, const void __user *ucp)
{
	struct pt_regs *regs = current_pt_regs();
	e2k_stacks_t stacks;
	e2k_mem_crs_t __user *cs_frames;
	e2k_mem_crs_t crs_user, crs_trampoline;
	void __user *trampoline_ps_frame;
	void __user *ps_frame;
	char args_buf[args_size];
	u64 args_registers_size, args_stack_size, func_frame_size;
	unsigned long func_frame_ptr, ts_flag;
	const void __user *link;
	bool protected = (format == CTX_128_BIT);
	int ret;

	if (ALIGN(args_size, 16) + (protected ? 16 : 0) > u_stk_size)
		return -EINVAL;

	AW(stacks.pcsp_lo) = 0;
	AS(stacks.pcsp_lo).base = (unsigned long) GET_PCS_BASE(&ctx->ti.u_hw_stack);
	AS(stacks.pcsp_lo).rw = 3;
	AS(stacks.pcsp_hi).size = get_hw_pcs_user_size(&ctx->ti.u_hw_stack);

	AW(stacks.psp_lo) = 0;
	AS(stacks.psp_lo).base = (unsigned long) GET_PS_BASE(&ctx->ti.u_hw_stack);
	AS(stacks.psp_lo).rw = 3;
	AS(stacks.psp_hi).size = get_hw_ps_user_size(&ctx->ti.u_hw_stack);

	/*
	 * Leave space for trampoline's frame so that there is space
	 * for the user function to return to _and_ for one empty
	 * frame which is needed for return trick to work in
	 * user_hw_stacks_restore().
	 */
	AS(stacks.pcsp_hi).ind = 3 * SZ_OF_CR;

	/*
	 * And this is space for user function and makecontext_trampoline()
	 */
	AS(stacks.psp_hi).ind = 2 * C_ABI_PSIZE(protected) * EXT_4_NR_SZ;

	trampoline_ps_frame = GET_PS_BASE(&ctx->ti.u_hw_stack);
	ps_frame = GET_PS_BASE(&ctx->ti.u_hw_stack) +
		   C_ABI_PSIZE(protected) * EXT_4_NR_SZ;

	/*
	 * Set chain stack for the trampoline and user function
	 */
	cs_frames = (e2k_mem_crs_t __user *) GET_PCS_BASE(&ctx->ti.u_hw_stack);

	/*
	 * Calculate user function frame's parameters.
	 */
	if (protected) {
		args_registers_size = min(args_size, (u64) 128 - 16);
		/* Data stack must be 16-bytes aligned. */
		func_frame_size = ALIGN(args_size, 16) + 16;
	} else {
		args_registers_size = min(args_size, 64ULL);
		/* Data stack must be 16-bytes aligned. */
		func_frame_size = ALIGN(args_size, 16);
	}
	args_stack_size = args_size - args_registers_size;
	func_frame_ptr = (unsigned long) u_stk_base + u_stk_size
			- func_frame_size;
	if (!access_ok((void __user *) func_frame_ptr, func_frame_size))
		return -EFAULT;
	DebugCTX("arguments: base 0x%lx, size %lld (regs %lld + stack %lld)\n",
			args, args_size, args_registers_size, args_stack_size);

	stacks.top = (unsigned long) u_stk_base + u_stk_size;
	AS(stacks.usd_hi).ind = 0;
	AS(stacks.usd_hi).size = u_stk_size - func_frame_size;
	if (protected) {
		e2k_pusd_lo_t pusd_lo;

		/* Check that the stack does not cross 4Gb boundary */
		if (((unsigned long) u_stk_base & ~0xffffffffULL) !=
		    (stacks.top & ~0xffffffffULL)) {
			DebugCTX("stack crosses 4Gb boundary\n");
			return -EINVAL;
		}

		/*
		 * Set PSL to 2 (we must allow for two returns:
		 * first to user function and second to the trampoline)
		 */
		AW(pusd_lo) = 0;
		AS(pusd_lo).base = func_frame_ptr;
		AS(pusd_lo).rw = 3;
		AS(pusd_lo).psl = 2;

		/*
		 * Set 'protected' bit
		 */
		AS(pusd_lo).p = 1;

		AW(stacks.usd_lo) = AW(pusd_lo);

		/*
		 * Put descriptor of user function frame in %qr0.
		 */
		if (set_user_ap(ps_frame, func_frame_ptr, args_size + 16))
			return -EFAULT;
		ps_frame += EXT_4_NR_SZ;
	} else {
		AW(stacks.usd_lo) = 0;
		AS(stacks.usd_lo).base = func_frame_ptr;
		AS(stacks.usd_lo).rw = 3;
	}

	/*
	 * Put uc_link pointer into trampoline frame
	 */
	if (format == CTX_64_BIT) {
		const struct ucontext __user *ucp_64 = ucp;
		link = &ucp_64->uc_link;
#ifdef CONFIG_COMPAT
	} else if (format == CTX_32_BIT) {
		const struct ucontext_32 __user *ucp_32 = ucp;
		link = &ucp_32->uc_link;
#endif
	} else {
		const struct ucontext_prot __user *ucp_128 = ucp;
		link = &ucp_128->uc_link;
	}

	/*
	 * Copy args from user memory to allocated kernel buffer
	 * to avoid faults when further accessing user memory
	 */
	if (copy_from_user_with_tags((void *) &args_buf, args, args_size))
		return -EFAULT;

	ret = mkctxt_prepare_hw_user_stacks(func, (void *) &args_buf,
			args_registers_size, AS(stacks.usd_hi).size,
			format, trampoline_ps_frame, ps_frame, cs_frames, link);
	if (ret)
		return -EFAULT;

	if (args_stack_size) {
		DebugCTX("Copying stack arguments to 0x%lx\n",
				(void __user *) func_frame_ptr + 64);
		if (copy_to_user_with_tags((void __user *) func_frame_ptr +
				(protected ? 128 : 64),
				((void *) &args_buf) + args_registers_size,
				args_stack_size))
			return -EFAULT;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_from_user(&crs_user, cs_frames + 3, SZ_OF_CR);
	ret |= __copy_from_user(&crs_trampoline, cs_frames + 2, SZ_OF_CR);
	clear_ts_flag(ts_flag);

	if (ret)
		return -EFAULT;

	ctx->regs.crs = crs_user;
	/*
	 * do_swapcontext() loads values from ctx->prev_ctx,
	 * this way it's faster.
	 */
	ctx->prev_crs = crs_trampoline;

	/*
	 * Initialize thread_info
	 */
	ctx->ti.u_stack.bottom = (unsigned long) u_stk_base;
	ctx->ti.u_stack.size = u_stk_size;
	ctx->ti.u_stack.top = (unsigned long) u_stk_base + u_stk_size;
	ctx->ti.signal_stack.base = 0;
	ctx->ti.signal_stack.size = 0;
	ctx->ti.signal_stack.used = 0;

	/*
	 * Prepare new pt_regs
	 */
	ctx->regs.wd = regs->wd;
	ctx->regs.kernel_entry = regs->kernel_entry;

	ctx->regs.stacks = stacks;

	/*
	 * Save parameters for jumping through sys_setcontext()->do_longjmp()
	 */
	user_regs->pcsp_lo = stacks.pcsp_lo;
	user_regs->pcsp_hi = stacks.pcsp_hi;
	user_regs->cr0_hi = ctx->prev_crs.cr0_hi;
	user_regs->cr1_lo = ctx->prev_crs.cr1_lo;
	user_regs->cr1_hi = ctx->prev_crs.cr1_hi;

	return 0;
}

static inline struct coroutine *coroutine_lookup_and_get(u64 key,
		mm_context_t *mm_context)
{
	struct coroutine *ctx;

	rcu_read_lock();

	ctx = rhashtable_lookup(&mm_context->hw_contexts, &key, hash_params);
	if (unlikely(!ctx)) {
		ctx = ERR_PTR(-ESRCH);
	} else {
		int ret = take_reference(ctx, HWC_STATE_BUSY);
		if (ret)
			ctx = ERR_PTR(ret);
	}

	rcu_read_unlock();

	return ctx;
}

/**
 * coroutine_lookup_by_addr_and_get() - search for coroutine
 * @mm: process to search in
 * @stack_ptr: data stack pointer to try deriving key from it (fast path)
 * @pcsp_base: chain stack pointer to use for search if fast path fails
 *
 * Same as `coroutine_lookup_and_get()` but instead of immediately using
 * key to index into hash table we manually search through corouines.
 *
 * Return: coroutine on success and `PTR_ERR()` on failure.
 */
static struct coroutine *coroutine_lookup_by_addr_and_get(struct mm_struct *mm,
		unsigned long stack_ptr, unsigned long pcsp_base)
{
	struct coroutine *ctx = NULL;
	struct rhashtable_iter iter;

	/*
	 * Fastpath: try to guess key from jmp_usd_lo
	 */
	mmap_read_lock(mm);
	struct vm_area_struct *vma = find_vma_intersection(mm, stack_ptr, stack_ptr + 1);
	u64 guessed_stack_top = (vma) ? vma->vm_end : 0;
	mmap_read_unlock(mm);

	if (guessed_stack_top) {
		rcu_read_lock();
		ctx = rhashtable_lookup(&mm->context.hw_contexts,
					     &guessed_stack_top, hash_params);

		if (ctx && !__find_in_old_u_pcs_list(pcsp_base, NULL, &ctx->ti.u_hw_stack,
						     &ctx->ti.old_u_pcs_list)) {
			int ret = take_reference(ctx, HWC_STATE_BUSY);
			rcu_read_unlock();

			if (unlikely(ret)) {
				SIGDEBUG_PRINT("SIGKILL. longjmp(): trying to jump into another coroutine but it is currently executing\n");
				force_sig(SIGKILL);
				ctx = ERR_PTR(ret);
			}

			return ctx;
		}
		rcu_read_unlock();
	}

	/*
	 * Slowpath: duly search through all contexts if guessing didn't work
	 */
	rhashtable_walk_enter(&mm->context.hw_contexts, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((ctx = rhashtable_walk_next(&iter)) && !IS_ERR(ctx)) {
			if (!__find_in_old_u_pcs_list(pcsp_base, NULL, &ctx->ti.u_hw_stack,
						      &ctx->ti.old_u_pcs_list)) {
				int ret = take_reference(ctx, HWC_STATE_BUSY);
				if (unlikely(ret))
					ctx = ERR_PTR(ret);
				break;
			}
		}
		rhashtable_walk_stop(&iter);
	} while (cond_resched(), ctx == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);

	if (likely(ctx && !IS_ERR(ctx)))
		return ctx;

	if (!ctx) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted setjmp_buf\n");
		ctx = ERR_PTR(-ESRCH);
	} else {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): trying to jump into another coroutine but it is currently executing\n");
	}
	force_sig(SIGKILL);
	return ctx;
}

/**
 * save_main_coroutine() - allocate and initialize the main coroutine in hash table
 * @key_p: context key will be returned here
 * @mm_context: current mm context
 * @format: compat, 64 bit or protected
 *
 * Return: coroutine pointer on success and ERR_PTR() on error
 */
static struct coroutine *save_main_coroutine(u64 *key_p,
		mm_context_t *mm_context, int format)
{
	int ret;

	/* We are saving the main context - which means this has not
	 * been initialized yet. */
	BUG_ON(current_thread_info()->this_hw_context);

	u64 key = context_current_key();
	if (IS_ERR_VALUE(key))
		return ERR_PTR(key);

	if (key_p)
		*key_p = key;

	DebugCTX("will save main context, key 0x%llx\n", key);
	struct coroutine *ctx = alloc_hw_context(true, current_thread_info()->u_stack.size, key);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->ptr_format = format;

	/* add() (see above) */
	if ((ret = rhashtable_lookup_insert_key(&mm_context->hw_contexts, &key,
						&ctx->hash_entry, hash_params))) {
		DebugCTX("insert failed with %d\n", ret);
		free_hw_context(ctx, true, false);
		return ERR_PTR(ret);
	}
	current_thread_info()->this_hw_context = ctx;

	/* Create signal stack on host side for this context */
	add_ctx_signal_stack(key, true);

	return ctx;
}

/**
 * makecontext_prepare_ucp_contents - initialize user structure
 * @ucp - structure to initialize
 * @format, @sigsetsize, @key, @user_regs - values to initialize with
 */
static int makecontext_prepare_ucp_contents(void __user *ucp, int format,
		int sigsetsize, u64 key, const struct longjmp_regs *user_regs)
{
#ifdef CONFIG_COMPAT
	struct ucontext_32 __user *ucp_32 = ucp;
#endif
	struct ucontext __user *ucp_64 = ucp;
#ifdef CONFIG_PROTECTED_MODE
	struct ucontext_prot __user *ucp_128 = ucp;
#endif
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	int ret;

	/*
	 * Initialize user structure
	 */
	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr);

	if (format == CTX_64_BIT) {
		ret = __clear_user(&ucp_64->uc_sigmask, sigsetsize);
		ret = ret ?: __put_user(key, &ucp_64->uc_mcontext.sbr);
		ret = ret ?: __put_user(AW(user_regs->cr0_hi), &ucp_64->uc_mcontext.cr0_hi);
		ret = ret ?: __put_user(AW(user_regs->cr1_lo), &ucp_64->uc_mcontext.cr1_lo);
		ret = ret ?: __put_user(AW(user_regs->cr1_hi), &ucp_64->uc_mcontext.cr1_hi);
		ret = ret ?: __put_user(AW(user_regs->pcsp_lo), &ucp_64->uc_mcontext.pcsp_lo);
		/* See comment about SZ_OF_CR for 32-bit mode */
		ret = ret ?: __put_user(AW(user_regs->pcsp_hi) - SZ_OF_CR,
					&ucp_64->uc_mcontext.pcsp_hi);
		ret = ret ?: __put_user(AW(fpcr), &ucp_64->uc_extra.fpcr);
		ret = ret ?: __put_user(AW(fpsr), &ucp_64->uc_extra.fpsr);
		ret = ret ?: __put_user(AW(pfpfr), &ucp_64->uc_extra.pfpfr);
#ifdef CONFIG_COMPAT
	} else if (format == CTX_32_BIT) {
		ret = __clear_user(&ucp_32->uc_sigmask, sigsetsize);
		ret = ret ?: __put_user(key, &ucp_32->uc_mcontext.sbr);
		ret = ret ?: __put_user(AW(user_regs->cr0_hi), &ucp_32->uc_mcontext.cr0_hi);
		ret = ret ?: __put_user(AW(user_regs->cr1_lo), &ucp_32->uc_mcontext.cr1_lo);
		ret = ret ?: __put_user(AW(user_regs->cr1_hi), &ucp_32->uc_mcontext.cr1_hi);
		ret = ret ?: __put_user(AW(user_regs->pcsp_lo), &ucp_32->uc_mcontext.pcsp_lo);
		/* Nasty hack: this is a new context so there is no point in
		 * calling do_swapcontext() -> do_longjmp().  So we manually
		 * subtract SZ_OF_CR here to avoid the call; it would've been
		 * done otherwise because the newly created context does not
		 * have glibc's swapcontext() function in it and the check
		 * before the call would return false positive. */
		ret = ret ?: __put_user(AW(user_regs->pcsp_hi) - SZ_OF_CR,
					&ucp_32->uc_mcontext.pcsp_hi);
		ret = ret ?: __put_user(AW(fpcr), &ucp_32->uc_extra.fpcr);
		ret = ret ?: __put_user(AW(fpsr), &ucp_32->uc_extra.fpsr);
		ret = ret ?: __put_user(AW(pfpfr), &ucp_32->uc_extra.pfpfr);
#endif
#ifdef CONFIG_PROTECTED_MODE
	} else { /* CTX_128_BIT */
		ret = __clear_user(&ucp_128->uc_sigmask, sigsetsize);
		ret = ret ?: __put_user(key, &ucp_128->uc_mcontext.sbr);
		ret = ret ?: __put_user(AW(user_regs->cr0_hi), &ucp_128->uc_mcontext.cr0_hi);
		ret = ret ?: __put_user(AW(user_regs->cr1_lo), &ucp_128->uc_mcontext.cr1_lo);
		ret = ret ?: __put_user(AW(user_regs->cr1_hi), &ucp_128->uc_mcontext.cr1_hi);
		ret = ret ?: __put_user(AW(user_regs->pcsp_lo), &ucp_128->uc_mcontext.pcsp_lo);
		/* See comment about SZ_OF_CR for 32-bit mode */
		ret = ret ?: __put_user(AW(user_regs->pcsp_hi) - SZ_OF_CR,
					&ucp_128->uc_mcontext.pcsp_hi);
		ret = ret ?: __put_user(AW(fpcr), &ucp_128->uc_extra.fpcr);
		ret = ret ?: __put_user(AW(fpsr), &ucp_128->uc_extra.fpsr);
		ret = ret ?: __put_user(AW(pfpfr), &ucp_128->uc_extra.pfpfr);
#endif
	}

	return ret ? -EFAULT : 0;
}

static int makecontext_prepare_ctx_and_ucp(struct coroutine *ctx,
		void __user *ucp, int sigsetsize, int format,
		void __user *func, u64 args_size, void __user *args,
		void __user *u_stk_base, size_t u_stk_size, u64 key)
{
	struct longjmp_regs user_regs;

	ctx->ptr_format = format;

	int ret = makecontext_prepare_user_stacks(&user_regs, ctx,
			func, args_size, args,
			u_stk_base, u_stk_size, format, ucp);
	if (ret)
		return ret;

	return makecontext_prepare_ucp_contents(ucp,
			format, sigsetsize, key, &user_regs);
}

static long do_makecontext(void __user *ucp, void (*func)(void),
		u64 args_size, void __user *args, int sigsetsize, int format)
{
#ifdef CONFIG_COMPAT
	struct ucontext_32 __user *ucp_32 = ucp;
#endif
	struct ucontext __user *ucp_64 = ucp;
#ifdef CONFIG_PROTECTED_MODE
	struct ucontext_prot __user *ucp_128 = ucp;
#endif
	void __user *u_stk_base;
	size_t u_stk_size;
	struct coroutine *ctx, *same_key_ctx;
	mm_context_t *mm_context = &current->mm->context;
	u64 key;
	int ret;

	DebugCTX("ucp %lx started\n", ucp);

	ret = -EFAULT;

	if (format == CTX_64_BIT &&
		   access_ok(ucp, offsetofend(struct ucontext, uc_extra.pfpfr))) {
		ret = __get_user(u_stk_base, &ucp_64->uc_stack.ss_sp);
		ret = (ret) ?: __get_user(u_stk_size, &ucp_64->uc_stack.ss_size);
		if (ret)
			return ret;
#ifdef CONFIG_COMPAT
	} else if (format == CTX_32_BIT &&
	    access_ok(ucp, offsetofend(struct ucontext_32, uc_extra.pfpfr))) {
		u32 __u_stk_base;

		ret = __get_user(__u_stk_base, &ucp_32->uc_stack.ss_sp);
		ret = (ret) ?: __get_user(u_stk_size, &ucp_32->uc_stack.ss_size);
		if (ret)
			return ret;

		u_stk_base = (void __user *) (unsigned long) __u_stk_base;
#endif
	}
#ifdef CONFIG_PROTECTED_MODE
	else if (access_ok(ucp, offsetofend(struct ucontext_prot, uc_extra.pfpfr))) {
		/* CTX_128_BIT */
		e2k_ptr_t stack_ptr;
		size_t size;
		u8 tag;

		ret = __get_user_tagged_16(stack_ptr.lo, stack_ptr.hi, tag,
					   &ucp_128->uc_stack.ss_sp);
		ret = (ret) ?: __get_user(u_stk_size, &ucp_128->uc_stack.ss_size);
		if (ret)
			return ret;

		DebugCTX("stack_ptr.size/u_stk_size : 0x%x / 0x%zx\n",
			 stack_ptr.size, u_stk_size);

		if (tag != ETAGAPQ) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
					       "makecontext", tag, "ucontext_t",
					       "uc_stack.ss_sp", stack_ptr.lo, stack_ptr.hi);
			return -EFAULT;
		}

		size = e2k_ptr_size(stack_ptr.lo, stack_ptr.hi, u_stk_size);
		if (!size) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
					"makecontext", "uc_stack.ss_sp", size,
					"uc_stack.ss_size", u_stk_size);
			return -EFAULT;
		}

		u_stk_base = (void __user *) E2K_PTR_PTR(stack_ptr);
	}
#endif
	if (ret)
		return ret;

	u_stk_size -= PTR_ALIGN(u_stk_base, E2K_ALIGN_USTACK_BOUNDS) - u_stk_base;
	u_stk_base = PTR_ALIGN(u_stk_base, E2K_ALIGN_USTACK_BOUNDS);
	u_stk_size = round_down(u_stk_size, E2K_ALIGN_USTACK_BOUNDS);
	DebugCTX("user stack at %lx, size=%lx\n", u_stk_base, u_stk_size);

	if (!access_ok(u_stk_base, u_stk_size))
		return -EFAULT;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	key = (unsigned long) u_stk_base + u_stk_size;
	ctx = coroutine_lookup_and_get(key, mm_context);
	if (!IS_ERR(ctx)) {
		/* Fast path: if context with the same key
		 * exists and is not used, we can just use it. */
		free_user_old_pc_stack_areas(&ctx->ti.old_u_pcs_list);
		free_getsp_adj(&ctx->ti.getsp_adj);
		free_signal_stack(&ctx->ti.signal_stack);

		memset(&ctx->regs, 0, sizeof(ctx->regs));
		memset(&ctx->prev_crs, 0, sizeof(ctx->prev_crs));

		ret = makecontext_prepare_ctx_and_ucp(ctx, ucp, sigsetsize, format,
				func, args_size, args, u_stk_base, u_stk_size, key);
		if (ret) {
			remove_ctx_signal_stack(ctx->key);

			/* The context is broken since we have
			 * failed to reuse it, just drop it now. */
			if (!rhashtable_remove_fast(&mm_context->hw_contexts,
					&ctx->hash_entry, hash_params))
				context_free(ctx);

			return ret;
		}

		/* Successfully reused, now mark the context as ready */
		if (release_reference(ctx, HWC_STATE_BUSY)) {
			pr_info_ratelimited("%s [%d]: context 0x%px was passed to makecontext_e2k() and freecontext_e2k() at the same time\n",
					current->comm, current->pid, ucp);
			return -EINVAL;
		}

		DebugCTX("ctx %lx reused, key=%llx\n", ctx, key);
	} else {
		/* Slow path: duly allocate a new context */
		ctx = alloc_hw_context(false, u_stk_size, key);
		if (!ctx)
			return -ENOMEM;

		ret = makecontext_prepare_ctx_and_ucp(ctx, ucp, sigsetsize, format,
				func, args_size, args, u_stk_base, u_stk_size, key);
		if (ret) {
			free_hw_context(ctx, false, false);
			return ret;
		}

		do {
			rcu_read_lock();

			/* add() (see above) */
			same_key_ctx = rhashtable_lookup_get_insert_key(&mm_context->hw_contexts,
					&ctx->key, &ctx->hash_entry, hash_params);
			if (IS_ERR(same_key_ctx)) {
				rcu_read_unlock();
				free_hw_context(ctx, false, false);
				return PTR_ERR(same_key_ctx);
			}

			/*
			 * If there is a context with the same key then silently
			 * drop it.  This is for programs like gccgo where it is
			 * hard to properly handle an error from makecontext().
			 */
			if (likely(!same_key_ctx)) {
				rcu_read_unlock();
			} else {
				/* delete() (see above) */
				ret = rhashtable_remove_fast(&mm_context->hw_contexts,
						&same_key_ctx->hash_entry, hash_params);
				rcu_read_unlock();

				remove_ctx_signal_stack(same_key_ctx->key);

				if (!ret) {
					DebugCTX("removed duplicate ctx %lx with the same key\n",
							same_key_ctx);
					context_free(same_key_ctx);
				}
			}
		} while (same_key_ctx);

		/* Create signal stack on host side for this context */
		add_ctx_signal_stack(ctx->key, false);

		DebugCTX("added ctx %lx with key %llx\n", ctx, key);
	}

	return 0;
}

SYSCALL_DEFINE5(makecontext, struct ucontext __user *, ucp,
		void __user *, func, u64, args_size, void __user *, args,
		int, sigsetsize)
{
	return do_makecontext(ucp, func, args_size, args, sigsetsize, CTX_64_BIT);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE5(makecontext, struct ucontext_32 __user *, ucp,
		void __user *, func, u64, args_size, void __user *, args,
		int,  sigsetsize)
{
	return do_makecontext(ucp, func, args_size, args,
			sigsetsize, CTX_32_BIT);
}
#endif

#ifdef CONFIG_PROTECTED_MODE
long protected_sys_makecontext(struct ucontext_prot __user *ucp,
		void __user *func, u64 args_size, void __user *args, int sigsetsize)
{
	return do_makecontext(ucp, func, args_size, args,
			sigsetsize, CTX_128_BIT);
}
#endif

static long do_freecontext(u64 key)
{
	mm_context_t *mm_context = &current->mm->context;
	struct coroutine *ctx;
	long ret;

	/* delete() (see above) */
	rcu_read_lock();

	ctx = rhashtable_lookup(&mm_context->hw_contexts, &key, hash_params);
	if (!ctx) {
		ret = -ENOENT;
	} else if (ctx == current_thread_info()->this_hw_context) {
		ret = -EBUSY;
	} else {
		ret = rhashtable_remove_fast(&mm_context->hw_contexts,
					  &ctx->hash_entry, hash_params);
	}

	rcu_read_unlock();

	DebugCTX("ctx %lx for key 0x%llx, ret %ld\n", ctx, key, ret);
	if (ret)
		return ret;

	remove_ctx_signal_stack(ctx->key);

	context_free(ctx);

	return 0;
}


SYSCALL_DEFINE1(freecontext, struct ucontext __user *, ucp)
{
	u64 free_key;

	if (get_user(free_key, &ucp->uc_mcontext.sbr))
		return -EFAULT;

	return do_freecontext(free_key);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE1(freecontext, struct ucontext_32 __user *, ucp)
{
	u64 free_key;

	if (get_user(free_key, &ucp->uc_mcontext.sbr))
		return -EFAULT;

	return do_freecontext(free_key);
}
#endif

#ifdef CONFIG_PROTECTED_MODE
long protected_sys_freecontext(struct ucontext_prot __user *ucp)
{
	u64 free_key;

	if (get_user(free_key, &ucp->uc_mcontext.sbr))
		return -EFAULT;

	return do_freecontext(free_key);
}
#endif

struct userspace_context {
	u64 sigset;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
};

/*
 * Actually do the switch to another hardware stack described by ucp.
 *
 * Called from sys_setcontext() or sys_swapcontext().
 */
__always_inline /* Just to copy less in user_hw_stacks_copy_full() */
static void switch_hw_contexts(struct pt_regs *__restrict regs,
		struct coroutine *__restrict prev_ctx,
		struct coroutine *__restrict next_ctx,
		struct userspace_context *fpu_context)
{
	struct thread_info *ti = current_thread_info();
	e2k_mem_crs_t *__restrict k_crs = (e2k_mem_crs_t *__restrict)
					AS(ti->k_pcsp_lo).base;
	e2k_pcshtp_t pcshtp = regs->stacks.pcshtp;
	e2k_pshtp_t pshtp = regs->stacks.pshtp;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;

#if DEBUG_CTX_MODE
	DebugCTX("Before switching:\n");
	print_stack_frames(current, NULL, 0);
#endif

	if (fpu_context) {
		fpcr = fpu_context->fpcr;
		fpsr = fpu_context->fpsr;
		pfpfr = fpu_context->pfpfr;
	}

	/*
	 * 2) Fill the bottom of kernel stack with the next context's data
	 */

	/* Now that we can no longer fail we can modify the next context.
	 *
	 * IMPORTANT: must not fail after this point, or will have to
	 * free the @next_ctx. */

	raw_all_irq_disable();

	E2K_FLUSHC;
	update_kernel_crs(k_crs, &next_ctx->regs.crs, &next_ctx->prev_crs,
			&prev_ctx->prev_crs);

	/*
	 * 3) Switch thread_info
	 */
	prev_ctx->ti.u_stack = ti->u_stack;
	prev_ctx->ti.u_hw_stack = ti->u_hw_stack;
	prev_ctx->ti.signal_stack = ti->signal_stack;
	prev_ctx->ti.switched_flags = ti->flags & TIF_COROUTINES_SPECIFIC;
	/* Not everything in pt_regs should be saved and restored
	 * (e.g. system call number), so copy only the necessary part. */
	prev_ctx->regs.stacks = regs->stacks;
	prev_ctx->regs.crs = regs->crs;
	prev_ctx->regs.wd = regs->wd;
	/* 'kernel_entry' might be 0 if we get here through uc_link */
	prev_ctx->regs.kernel_entry = regs->kernel_entry;

	/* Function calls are allowed after this point (actually this
	 * should go after k_crs[] modification above but we put it
	 * here to not hinder compiler optimizations) */
	barrier();

	list_splice_init(&ti->old_u_pcs_list, &prev_ctx->ti.old_u_pcs_list);
	list_splice_init(&next_ctx->ti.old_u_pcs_list, &ti->old_u_pcs_list);
	list_splice_init(&ti->getsp_adj, &prev_ctx->ti.getsp_adj);
	list_splice_init(&next_ctx->ti.getsp_adj, &ti->getsp_adj);

	regs->stacks = next_ctx->regs.stacks;
	regs->stacks.pcshtp = pcshtp;
	regs->stacks.pshtp = pshtp;
	regs->crs = next_ctx->regs.crs;
	regs->wd = next_ctx->regs.wd;
	/* 'kernel_entry' might be 0 if we get here through uc_link */
	regs->kernel_entry = next_ctx->regs.kernel_entry;

	if (fpu_context) {
		WRITE_FPCR_REG(fpcr);
		WRITE_FPSR_REG(fpsr);
		WRITE_PFPFR_REG(pfpfr);
	}

	ti->u_stack = next_ctx->ti.u_stack;
	ti->u_hw_stack = next_ctx->ti.u_hw_stack;
	ti->signal_stack = next_ctx->ti.signal_stack;
	ti->flags = (ti->flags & ~TIF_COROUTINES_SPECIFIC) |
		    (next_ctx->ti.switched_flags & TIF_COROUTINES_SPECIFIC);
#if DEBUG_CTX_MODE
	DebugCTX("After switching:\n");
	print_stack_frames(current, NULL, 0);
#endif
	raw_all_irq_enable();
}

/**
 * coroutine_switch_and_longjmp() - do a coroutine switch before longjmp
 * @pcsp_base: chain stack of needed coroutine
 * @jmp_info: result of user's setjmp() call
 * @retval: user's longjmp() argument
 */
long coroutine_switch_and_longjmp(unsigned long pcsp_base,
		struct jmp_info *jmp_info, u64 retval)
{
	struct mm_struct *mm = current->mm;
	struct coroutine *next_ctx;
	struct coroutine *prev_ctx = current_thread_info()->this_hw_context;
	unsigned long stack_ptr = AS((e2k_usd_lo_t) jmp_info->usd_lo).base;
	struct pt_regs *regs = current_thread_info()->pt_regs;
	int ret;

	next_ctx = coroutine_lookup_by_addr_and_get(mm, stack_ptr, pcsp_base);
	if (unlikely(IS_ERR(next_ctx)))
		return PTR_ERR(next_ctx);

	DebugCTX("found ctx 0x%lx with key 0x%llx for pcsp 0x%llx\n",
			next_ctx, next_ctx->key, jmp_info->pcsplo);

	int format = next_ctx->ptr_format;

	/*
	 * If this is the first time this thread is changing contexts
	 * we'll have to allocate memory for the main context.
	 */
	if (unlikely(!prev_ctx)) {
		prev_ctx = save_main_coroutine(NULL, &mm->context, format);
		if (unlikely(IS_ERR(prev_ctx)))
			return PTR_ERR(prev_ctx);
	}

	/*
	 * Save previous context's stack into userspace.
	 *
	 * This also ensures there is enough user data in the next context
	 * to fill the bottom of kernel stack (where user data lies), and
	 * SPILLs chain stack so that it can be saved in the next step
	 */
	ret = do_user_hw_stacks_copy_full(&regs->stacks, regs, NULL);
	if (unlikely(ret))
		return ret;

	if (unlikely(prev_ctx == next_ctx)) {
		SIGDEBUG_PRINT("SIGKILL. do_longjmp(): switch to another coroutine's stack requested but it is also used by current coroutine\n");
		force_sig(SIGKILL);
		return -EINVAL;
	}

	/*
	 * Do the switch
	 */
	DebugCTX("switching from ctx %lx to ctx %lx\n", prev_ctx, next_ctx);
	switch_hw_contexts(regs, prev_ctx, next_ctx, NULL);
	current_thread_info()->this_hw_context = next_ctx;

	(void) release_reference(prev_ctx, HWC_STATE_BUSY);

	/*
	 * Call jongjmp in proper coroutine
	 */
	DebugCTX("calling longjmp\n");
	u32 jmp_psize = AS((e2k_wd_t) ((u64) jmp_info->wd_hi32 << 32ULL)).psize;
	return do_longjmp(retval, jmp_info->sigmask,
			(e2k_cr0_hi_t) jmp_info->ip,
			(e2k_cr1_lo_t) jmp_info->cr1lo,
			(e2k_pcsp_lo_t) jmp_info->pcsplo, (e2k_pcsp_hi_t)
			(jmp_info->pcsphi + PCSHTP_SIGN_EXTEND(jmp_info->pcshtp)),
			jmp_info->br, jmp_psize);
}


#define LOAD_CTX(ucp, next_user_ctx, next_key) \
do { \
	*next_key = ucp->uc_mcontext.sbr; \
	next_user_ctx->sigset = *(u64 __user *) &ucp->uc_sigmask; \
	AW(next_user_ctx->fpcr) = ucp->uc_extra.fpcr; \
	AW(next_user_ctx->fpsr) = ucp->uc_extra.fpsr; \
	AW(next_user_ctx->pfpfr) = ucp->uc_extra.pfpfr; \
	AW(next_user_ctx->pcsp_lo) = ucp->uc_mcontext.pcsp_lo; \
	AW(next_user_ctx->pcsp_hi) = ucp->uc_mcontext.pcsp_hi; \
	AW(next_user_ctx->cr0_hi) = ucp->uc_mcontext.cr0_hi; \
	AW(next_user_ctx->cr1_lo) = ucp->uc_mcontext.cr1_lo; \
	AW(next_user_ctx->cr1_hi) = ucp->uc_mcontext.cr1_hi; \
} while (0)

#define SAVE_CTX(oucp, regs, prev_key, k_crs, current_blocked_sigset) \
do { \
	e2k_fpcr_t __fpcr = READ_FPCR_REG(); \
	e2k_fpsr_t __fpsr = READ_FPSR_REG(); \
	e2k_pfpfr_t __pfpfr = READ_PFPFR_REG(); \
 \
	*((u64 __user *) &oucp->uc_sigmask) = current_blocked_sigset.sig[0]; \
	oucp->uc_mcontext.sbr = prev_key; \
	oucp->uc_mcontext.cr0_hi = AW(k_crs->cr0_hi); \
	oucp->uc_mcontext.cr1_lo = AW(k_crs->cr1_lo); \
	oucp->uc_mcontext.cr1_hi = AW(k_crs->cr1_hi); \
	oucp->uc_mcontext.pcsp_lo = AW(regs->stacks.pcsp_lo); \
	/* We want stack to point to user frame that called us, \
	 * not to the glibc glue */ \
	oucp->uc_mcontext.pcsp_hi = AW(regs->stacks.pcsp_hi) - SZ_OF_CR; \
	oucp->uc_extra.fpcr = AW(__fpcr); \
	oucp->uc_extra.fpsr = AW(__fpsr); \
	oucp->uc_extra.pfpfr = AW(__pfpfr); \
} while (0)

#ifdef CONFIG_COMPAT
UACCESS_FN_DEFINE3(load_ctx_32_fn, const struct ucontext_32 __user *, ucp,
		struct userspace_context *__restrict, next_user_ctx,
		u64 *__restrict, next_key)
{
	LOAD_CTX(ucp, next_user_ctx, next_key);
	return 0;
}
#endif

UACCESS_FN_DEFINE3(load_ctx_64_fn, const struct ucontext __user *, ucp,
		struct userspace_context *__restrict, next_user_ctx,
		u64 *__restrict, next_key)
{
	LOAD_CTX(ucp, next_user_ctx, next_key);
	return 0;
}

#ifdef CONFIG_PROTECTED_MODE
UACCESS_FN_DEFINE3(load_ctx_128_fn, const struct ucontext_prot __user *, ucp,
		struct userspace_context *__restrict, next_user_ctx,
		u64 *__restrict, next_key)
{
	/* Use USER_LD in protected mode */
	USER_LD(*next_key, &ucp->uc_mcontext.sbr);
	USER_LD(next_user_ctx->sigset, (u64 __user *) &ucp->uc_sigmask);
	USER_LD(AW(next_user_ctx->fpcr), &ucp->uc_extra.fpcr);
	USER_LD(AW(next_user_ctx->fpsr), &ucp->uc_extra.fpsr);
	USER_LD(AW(next_user_ctx->pfpfr), &ucp->uc_extra.pfpfr);
	USER_LD(AW(next_user_ctx->pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	USER_LD(AW(next_user_ctx->pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	USER_LD(AW(next_user_ctx->cr0_hi), &ucp->uc_mcontext.cr0_hi);
	USER_LD(AW(next_user_ctx->cr1_lo), &ucp->uc_mcontext.cr1_lo);
	USER_LD(AW(next_user_ctx->cr1_hi), &ucp->uc_mcontext.cr1_hi);
	return 0;
}
#endif

#ifdef CONFIG_COMPAT
UACCESS_FN_DEFINE4(save_ctx_32_fn, struct ucontext_32 __user *, oucp,
		u64, prev_key, e2k_mem_crs_t *__restrict, k_crs,
		sigset_t, current_blocked_sigset)
{
	struct pt_regs *__restrict regs = current_thread_info()->pt_regs;
	SAVE_CTX(oucp, regs, prev_key, k_crs, current_blocked_sigset);
	return 0;
}
#endif

UACCESS_FN_DEFINE4(save_ctx_64_fn, struct ucontext __user *, oucp,
		u64, prev_key, e2k_mem_crs_t *__restrict, k_crs,
		sigset_t, current_blocked_sigset)
{
	struct pt_regs *__restrict regs = current_thread_info()->pt_regs;
	SAVE_CTX(oucp, regs, prev_key, k_crs, current_blocked_sigset);
	return 0;
}

#ifdef CONFIG_PROTECTED_MODE
UACCESS_FN_DEFINE4(save_ctx_128_fn, struct ucontext_prot __user *, oucp,
		u64, prev_key, e2k_mem_crs_t *__restrict, k_crs,
		sigset_t, current_blocked_sigset)
{
	struct pt_regs *__restrict regs = current_thread_info()->pt_regs;
	e2k_fpcr_t fpcr = READ_FPCR_REG();
	e2k_fpsr_t fpsr = READ_FPSR_REG();
	e2k_pfpfr_t pfpfr = READ_PFPFR_REG();

	/* Use USER_ST in protected mode */
	USER_ST(current_blocked_sigset.sig[0], ((u64 __user *) &oucp->uc_sigmask));
	USER_ST(prev_key, &oucp->uc_mcontext.sbr);
	USER_ST(AW(k_crs->cr0_hi), &oucp->uc_mcontext.cr0_hi);
	USER_ST(AW(k_crs->cr1_lo), &oucp->uc_mcontext.cr1_lo);
	USER_ST(AW(k_crs->cr1_hi), &oucp->uc_mcontext.cr1_hi);
	USER_ST(AW(regs->stacks.pcsp_lo), &oucp->uc_mcontext.pcsp_lo);
	/* We want stack to point to user frame that called us,
	 * not to the glibc glue */
	USER_ST(AW(regs->stacks.pcsp_hi) - SZ_OF_CR, &oucp->uc_mcontext.pcsp_hi);
	USER_ST(AW(fpcr), &oucp->uc_extra.fpcr);
	USER_ST(AW(fpsr), &oucp->uc_extra.fpsr);
	USER_ST(AW(pfpfr), &oucp->uc_extra.pfpfr);

	return 0;
}
#endif

#ifdef CONFIG_COMPAT
UACCESS_FN_DEFINE7(save_and_load_ctx_32_fn,
		const struct ucontext_32 __user *__restrict, ucp,
		struct userspace_context *__restrict, next_user_ctx,
		u64 *__restrict, next_key,
		struct ucontext_32 __user *__restrict, oucp,
		u64, prev_key, e2k_mem_crs_t *__restrict, k_crs,
		sigset_t, current_blocked_sigset)
{
	struct pt_regs *__restrict regs = current_thread_info()->pt_regs;
	SAVE_CTX(oucp, regs, prev_key, k_crs, current_blocked_sigset);
	LOAD_CTX(ucp, next_user_ctx, next_key);
	return 0;
}
#endif

UACCESS_FN_DEFINE7(save_and_load_ctx_64_fn,
		const struct ucontext __user *__restrict, ucp,
		struct userspace_context *__restrict, next_user_ctx,
		u64 *__restrict, next_key,
		struct ucontext __user *__restrict, oucp,
		u64, prev_key, e2k_mem_crs_t *__restrict, k_crs,
		sigset_t, current_blocked_sigset)
{
	struct pt_regs *__restrict regs = current_thread_info()->pt_regs;
	SAVE_CTX(oucp, regs, prev_key, k_crs, current_blocked_sigset);
	LOAD_CTX(ucp, next_user_ctx, next_key);
	return 0;
}

#ifdef CONFIG_PROTECTED_MODE
UACCESS_FN_DEFINE7(save_and_load_ctx_128_fn,
		const struct ucontext_prot __user *__restrict, ucp,
		struct userspace_context *__restrict, next_user_ctx,
		u64 *__restrict, next_key,
		struct ucontext_prot __user *__restrict, oucp,
		u64, prev_key, e2k_mem_crs_t *__restrict, k_crs,
		sigset_t, current_blocked_sigset)
{
	struct pt_regs *__restrict regs = current_thread_info()->pt_regs;
	e2k_fpcr_t fpcr = READ_FPCR_REG();
	e2k_fpsr_t fpsr = READ_FPSR_REG();
	e2k_pfpfr_t pfpfr = READ_PFPFR_REG();

	/* Use USER_ST in protected mode */
	USER_ST(current_blocked_sigset.sig[0], ((u64 __user *) &oucp->uc_sigmask));
	USER_ST(prev_key, &oucp->uc_mcontext.sbr);
	USER_ST(AW(k_crs->cr0_hi), &oucp->uc_mcontext.cr0_hi);
	USER_ST(AW(k_crs->cr1_lo), &oucp->uc_mcontext.cr1_lo);
	USER_ST(AW(k_crs->cr1_hi), &oucp->uc_mcontext.cr1_hi);
	USER_ST(AW(regs->stacks.pcsp_lo), &oucp->uc_mcontext.pcsp_lo);
	/* We want stack to point to user frame that called us,
	 * not to the glibc glue */
	USER_ST(AW(regs->stacks.pcsp_hi) - SZ_OF_CR, &oucp->uc_mcontext.pcsp_hi);
	USER_ST(AW(fpcr), &oucp->uc_extra.fpcr);
	USER_ST(AW(fpsr), &oucp->uc_extra.fpsr);
	USER_ST(AW(pfpfr), &oucp->uc_extra.pfpfr);

	/* Use USER_LD in protected mode */
	USER_LD(*next_key, &ucp->uc_mcontext.sbr);
	USER_LD(next_user_ctx->sigset, (u64 __user *) &ucp->uc_sigmask);
	USER_LD(AW(next_user_ctx->fpcr), &ucp->uc_extra.fpcr);
	USER_LD(AW(next_user_ctx->fpsr), &ucp->uc_extra.fpsr);
	USER_LD(AW(next_user_ctx->pfpfr), &ucp->uc_extra.pfpfr);
	USER_LD(AW(next_user_ctx->pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	USER_LD(AW(next_user_ctx->pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	USER_LD(AW(next_user_ctx->cr0_hi), &ucp->uc_mcontext.cr0_hi);
	USER_LD(AW(next_user_ctx->cr1_lo), &ucp->uc_mcontext.cr1_lo);
	USER_LD(AW(next_user_ctx->cr1_hi), &ucp->uc_mcontext.cr1_hi);

	return 0;
}
#endif

#if _NSIG != 64
# error We read u64 value here...
#endif
__always_inline /* For performance since some arguments are constants */
static long do_swapcontext(void __user *oucp, const void __user *ucp,
		bool save_prev_ctx, int format)
{
#ifdef CONFIG_COMPAT
	const struct ucontext_32 __user *ucp_32;
	struct ucontext_32 __user *oucp_32;
#endif
	const struct ucontext __user *ucp_64;
#ifdef CONFIG_PROTECTED_MODE
	const struct ucontext_prot __user *ucp_128;
	struct ucontext_prot __user *oucp_128;
#endif
	struct ucontext __user *oucp_64;
	u64 next_key, prev_key, sigset;
	sigset_t k_sigset, current_blocked_sigset = current->blocked;
	struct coroutine *prev_ctx;
	mm_context_t *mm_context = &current->mm->context;
	struct userspace_context next_user_ctx;
	struct pt_regs *regs = current_thread_info()->pt_regs;
	e2k_mem_crs_t *__restrict k_crs = (e2k_mem_crs_t *__restrict)
			AS(current_thread_info()->k_pcsp_lo).base;
	bool stacks_switched = false;
	int ret;

	DebugCTX("oucp=%lx ucp=%lx started\n", oucp, ucp);
	BUILD_BUG_ON(sizeof(current->blocked.sig[0]) != 8);

	prev_ctx = current_thread_info()->this_hw_context;

	/*
	 * 1) Check user pointers
	 */
	if (format == CTX_64_BIT) {
		ucp_64 = ucp;
		oucp_64 = oucp;
		if (!access_ok(ucp, offsetofend(struct ucontext, uc_extra.pfpfr)) ||
				save_prev_ctx && !access_ok(oucp,
					offsetofend(struct ucontext, uc_extra.pfpfr)))
			return -EFAULT;
#ifdef CONFIG_COMPAT
	} else if (format == CTX_32_BIT) {
		ucp_32 = ucp;
		oucp_32 = oucp;
		if (!access_ok(ucp, offsetofend(struct ucontext_32, uc_extra.pfpfr)) ||
				save_prev_ctx && !access_ok(oucp,
					offsetofend(struct ucontext_32, uc_extra.pfpfr)))
			return -EFAULT;

#endif
#ifdef CONFIG_PROTECTED_MODE
	} else {
		/* CTX_128_BIT */
		ucp_128 = ucp;
		oucp_128 = oucp;
		if (!access_ok(ucp, offsetofend(struct ucontext_prot, uc_extra.pfpfr)) ||
				save_prev_ctx && !access_ok(oucp,
					offsetofend(struct ucontext_prot, uc_extra.pfpfr)))
			return -EFAULT;
#endif
	}

	/*
	 * 2) If this is the first time this thread is changing contexts
	 * we'll have to allocate memory for the main context.
	 */
	if (likely(prev_ctx)) {
		prev_key = prev_ctx->key;
	} else {
		prev_ctx = save_main_coroutine(&prev_key, mm_context, format);
		if (unlikely(IS_ERR(prev_ctx)))
			return PTR_ERR(prev_ctx);
	}

	/*
	 * 3) Save previous context's stack into userspace.
	 *
	 * This also ensures there is enough user data in the next context
	 * to fill the bottom of kernel stack (where user data lies), and
	 * SPILLs chain stack so that it can be saved in the next step
	 * (see [k_crs]).
	 */
	ret = do_user_hw_stacks_copy_full(&regs->stacks, regs, NULL);
	if (unlikely(ret))
		return ret;

	/*
	 * 4) Save previous ucontext and load the next one.
	 */
	if (format == CTX_64_BIT) {
		if (!save_prev_ctx) {
			ret = __UACCESS_FN_CALL(load_ctx_64_fn, ucp_64,
					&next_user_ctx, &next_key);
		} else if (unlikely(ucp == oucp)) {
			return __UACCESS_FN_CALL(save_ctx_64_fn, oucp_64,
					prev_key, k_crs, current_blocked_sigset);
		} else {
			ret = __UACCESS_FN_CALL(save_and_load_ctx_64_fn,
					ucp_64, &next_user_ctx, &next_key, oucp_64,
					prev_key, k_crs, current_blocked_sigset);
		}
#ifdef CONFIG_COMPAT
	} else if (format == CTX_32_BIT) {
		if (!save_prev_ctx) {
			ret = __UACCESS_FN_CALL(load_ctx_32_fn, ucp_32,
					&next_user_ctx, &next_key);
		} else if (unlikely(ucp == oucp)) {
			return __UACCESS_FN_CALL(save_ctx_32_fn, oucp_32,
					prev_key, k_crs, current_blocked_sigset);
		} else {
			ret = __UACCESS_FN_CALL(save_and_load_ctx_32_fn,
					ucp_32, &next_user_ctx, &next_key, oucp_32,
					prev_key, k_crs, current_blocked_sigset);
		}
#endif
#ifdef CONFIG_PROTECTED_MODE
	} else { /* CTX_128_BIT */
		if (!save_prev_ctx) {
			ret = __UACCESS_FN_CALL(load_ctx_128_fn, ucp_128,
					&next_user_ctx, &next_key);
		} else if (unlikely(ucp == oucp)) {
			return __UACCESS_FN_CALL(save_ctx_128_fn, oucp_128,
					prev_key, k_crs, current_blocked_sigset);
		} else {
			ret = __UACCESS_FN_CALL(save_and_load_ctx_128_fn,
					ucp_128, &next_user_ctx, &next_key, oucp_128,
					prev_key, k_crs, current_blocked_sigset);
		}
#endif
	}

	if (unlikely(ret))
		return -EFAULT;

	DebugCTX("prev_key %llx, next_key %llx\n", prev_key, next_key);

	/*
	 * 5) Do the switch
	 */
	if (prev_key != next_key) {
		struct coroutine *next_ctx;

		next_ctx = coroutine_lookup_and_get(next_key, mm_context);
		if (unlikely(IS_ERR(next_ctx)))
			return PTR_ERR(next_ctx);

		DebugCTX("switching from ctx %lx to ctx %lx\n", prev_ctx, next_ctx);

		switch_hw_contexts(regs, prev_ctx, next_ctx, &next_user_ctx);
		current_thread_info()->this_hw_context = next_ctx;

		(void) release_reference(prev_ctx, HWC_STATE_BUSY);

		stacks_switched = true;
	} else {
		WRITE_FPCR_REG(next_user_ctx.fpcr);
		WRITE_FPSR_REG(next_user_ctx.fpsr);
		WRITE_PFPFR_REG(next_user_ctx.pfpfr);
	}

	/*
	 * 6) Do we need to jump backwards in the new context?
	 *
	 * Skip glibc glue by subtracting SZ_OF_CR (the same this is done
	 * when saving context in getcontext() and for oucp in swapcontext())
	 */
	sigset = next_user_ctx.sigset;
	if (AS(regs->stacks.pcsp_lo).base + AS(regs->stacks.pcsp_hi).ind - SZ_OF_CR !=
			AS(next_user_ctx.pcsp_lo).base + AS(next_user_ctx.pcsp_hi).ind ||
			k_crs[0].cr0_hi.ip != next_user_ctx.cr0_hi.ip) {
		/* A hack to make do_longjmp() restore
		 * blocked signals mask */
		sigset |= sigmask(SIGKILL);

		DebugCTX("calling longjmp\n");
		/* There is no place in struct ucontext to save %wd.psize
		 * without breaking ABI, so we assume C calling convention
		 * value of 4 (8 for protected mode). */
		return do_longjmp(0, sigset, next_user_ctx.cr0_hi,
				next_user_ctx.cr1_lo, next_user_ctx.pcsp_lo,
				next_user_ctx.pcsp_hi, AS(next_user_ctx.cr1_hi).br,
				format == CTX_128_BIT ? 0x80 : 0x40);
	}

	if (stacks_switched)
		complete_long_jump(regs, true, next_key);

	k_sigset.sig[0] = sigset;
	if (!sigequalsets(&current_blocked_sigset, &k_sigset))
		set_current_blocked(&k_sigset);

	return 0;
}

SYSCALL_DEFINE3(swapcontext, struct ucontext __user *, oucp,
		const struct ucontext __user *, ucp, int, sigsetsize)
{
	if (unlikely(sigsetsize != sizeof(sigset_t)))
		return -EINVAL;

	return do_swapcontext(oucp, ucp, true, CTX_64_BIT);
}

SYSCALL_DEFINE2(setcontext, const struct ucontext __user *, ucp, int, sigsetsize)
{
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	return do_swapcontext(NULL, ucp, false, CTX_64_BIT);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(swapcontext, struct ucontext_32 __user *, oucp,
		const struct ucontext_32 __user *, ucp, int, sigsetsize)
{
	if (unlikely(sigsetsize != sizeof(sigset_t)))
		return -EINVAL;

	return do_swapcontext(oucp, ucp, true, CTX_32_BIT);
}

COMPAT_SYSCALL_DEFINE2(setcontext, const struct ucontext_32 __user *, ucp, int, sigsetsize)
{
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	return do_swapcontext(NULL, ucp, false, CTX_32_BIT);
}
#endif

#ifdef CONFIG_PROTECTED_MODE
long protected_sys_swapcontext(struct ucontext_prot __user *oucp,
		const struct ucontext_prot __user *ucp, int sigsetsize)
{
	if (unlikely(sigsetsize != sizeof(sigset_t)))
		return -EINVAL;

	return do_swapcontext(oucp, ucp, true, CTX_128_BIT);
}

long protected_sys_setcontext(const struct ucontext_prot __user *ucp,
		int sigsetsize)
{
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	return do_swapcontext(NULL, ucp, false, CTX_128_BIT);
}
#endif
