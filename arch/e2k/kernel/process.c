/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file handles the arch-dependent parts of process handling
 */

#include <linux/compat.h>
#include <linux/context_tracking.h>
#include <linux/elf-randomize.h>
#include <linux/types.h>
#include <linux/elfcore.h>
#include <linux/elf.h>
#include <linux/ftrace.h>
#include <linux/hw_breakpoint.h>
#include <linux/jhash.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/smpboot.h>
#include <linux/random.h>
#include <linux/sched/debug.h>
#include <linux/sched/hotplug.h>
#include <linux/tick.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#include <linux/sched/idle.h>
#include <linux/security.h>
#include <linux/sched/mm.h>

#include <trace/events/power.h>

#include <asm/atomic.h>
#include <asm/coredump.h>
#include <asm/cpu.h>
#include <asm/irq.h>
#include <asm/fpu/api.h>
#include <asm/getsp_adj.h>
#include <asm/process.h>
#include <asm/copy-hw-stacks.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/regs_state.h>
#include <asm/hw_stacks.h>
#include <asm/p2v/boot_init.h>
#include <asm/e2k_debug.h>
#include <asm/ucontext.h>
#include <asm/softirq_stack.h>
#include <asm/switch_to.h>
#include <asm/trap_table.h>
#include <asm/mmu.h>

#ifdef CONFIG_PROTECTED_MODE
#include <asm/e2k_ptypes.h>
#include <asm/prot_loader.h>
#include <asm/protected_mode.h>
#include <asm/protected_syscalls.h>
#endif /* CONFIG_PROTECTED_MODE */

#include <../../../kernel/time/tick-sched.h>


#undef	DEBUG_PROCESS_MODE
#undef	DebugP
#define	DEBUG_PROCESS_MODE	0	/* processes */
#define DebugP(...)		DebugPrint(DEBUG_PROCESS_MODE, ##__VA_ARGS__)

#undef	DEBUG_EXECVE_MODE
#undef	DebugEX
#define	DEBUG_EXECVE_MODE	0	/* execve and exit */
#define DebugEX(...)		DebugPrint(DEBUG_EXECVE_MODE, ##__VA_ARGS__)

#undef	DEBUG_GUEST_EXEC_MODE
#undef	DebugGEX
#define DEBUG_GUEST_EXEC_MODE	0	/* guest execve debugging */
#define DebugGEX(...)		DebugPrint(DEBUG_GUEST_EXEC_MODE, ##__VA_ARGS__)

#undef	DEBUG_DATA_STACK_MODE
#undef	DebugDS
#define	DEBUG_DATA_STACK_MODE	0	/* user data stack */
#define DebugDS(...)		DebugPrint(DEBUG_DATA_STACK_MODE, ##__VA_ARGS__)

#undef	DEBUG_CU_MODE
#undef	DebugCU
#define	DEBUG_CU_MODE		0	/* compilation unit */
#define DebugCU(...)		DebugPrint(DEBUG_CU_MODE, ##__VA_ARGS__)

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Hard Stack Clone and Alloc */
#define	DebugHS(...)		DebugPrint(DEBUG_HS_MODE, ##__VA_ARGS__)

#undef	DEBUG_COPY_USER_MODE
#undef	DebugCPY
#define	DEBUG_COPY_USER_MODE	0	/* KVM process copy debug */
#define	DebugCPY(...)		DebugPrint(DEBUG_COPY_USER_MODE, ##__VA_ARGS__)

#undef	DEBUG_CLONE_USER_MODE
#undef	DebugCLN
#define	DEBUG_CLONE_USER_MODE	0	/* KVM thread clone debug */
#define	DebugCLN(...)		DebugPrint(DEBUG_CLONE_USER_MODE, ##__VA_ARGS__)

#undef	DEBUG_CORE_DUMP
#undef	DebugCD
#define	DEBUG_CORE_DUMP		0	/* coredump */
#define DebugCD(...)		DebugPrint(DEBUG_CORE_DUMP, ##__VA_ARGS__)

#undef	DEBUG_CUI_MODE
#undef	DebugCUI
#define	DEBUG_CUI_MODE		0	/* finding compilation unit */
#define DebugCUI(...)		DebugPrint(DEBUG_CUI_MODE, ##__VA_ARGS__)


struct user_stack_free_work {
	unsigned long		stack_base;
	e2k_size_t		max_stack_size;
	struct mm_struct	*mm;
	struct delayed_work	work;
};


/*
 * Clear unallocated memory pointers which can be allocated for parent task
 */
static void clear_thread_info(struct task_struct *task)
{
	struct thread_struct	*thread = &task->thread;
	thread_info_t		*thread_info = task_thread_info(task);

	DebugEX("started for task 0x%px CPU #%d\n", task, task_cpu(task));

	thread_info->k_usd = ZEROED_USD;
	thread_info->k_psp = ZEROED_PSP;
	thread_info->k_pcsp = ZEROED_PCSP;

	thread->sw_regs.tcd = 0;

	thread_info->this_hw_context = NULL;

	thread_info->pt_regs = NULL;

	SET_PS_BASE(&thread_info->u_hw_stack, NULL);
	SET_PCS_BASE(&thread_info->u_hw_stack, NULL);

	thread_info->old_ps_base = NULL;
	thread_info->old_ps_size = 0;
	thread_info->old_pcs_base = NULL;
	thread_info->old_pcs_size = 0;

	INIT_LIST_HEAD(&thread_info->old_u_pcs_list);

	INIT_LIST_HEAD(&thread_info->getsp_adj);

	thread_info->status = 0;

#if defined(CONFIG_SECONDARY_SPACE_SUPPORT)
	thread_info->rp_start = 0;
	thread_info->rp_end = 0;
	thread_info->last_ic_flush_cpu = -1;
	thread_info->bc_flags = 0;
#endif

#ifdef CONFIG_PROTECTED_MODE
	thread_info->pm_robust_list.lo = 0;
	thread_info->pm_robust_list.hi = 0;
#endif

	/* clear virtualization support fields into thread info */
	clear_virt_thread_struct(thread_info);
}

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	memcpy(dst, src, sizeof(*dst));
	clear_thread_info(dst);

	return 0;
}

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
char *debug_process_name = NULL;
int debug_process_name_len = 0;

static int __init debug_process_name_setup(char *str)
{
	debug_process_name = str;
	debug_process_name_len = strlen(debug_process_name);
	return 1;
}

__setup("procdebug=", debug_process_name_setup);
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

bool idle_nomwait = false;
static int __init mem_wait_idle_setup(char *str)
{
	if (strcmp(str, "nomwait") == 0) {
		/* disable memory wait type idle */
		idle_nomwait = true;
		pr_info("Disable memory wait type idle\n");
	} else {
		pr_warn("Unknown command line idle= arg %s, can be 'nomwait'\n",
			str);
	}
	return 1;
}

__setup("idle=", mem_wait_idle_setup);

const char *arch_vma_name(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_HW_STACK_PS)
		return "[procedure stack]";
	else if (vma->vm_flags & VM_HW_STACK_PCS)
		return "[chain stack]";
	else if (vma->vm_flags & VM_SIGNAL_STACK)
		return "[signal stack]";
	else if (vma->vm_flags & VM_CUT)
		return "[cut]";
	return NULL;
}

int native_clean_pc_stack_zero_frame_kernel(void *addr)
{
	int ret;
	e2k_mem_crs_t *pcs = addr;

	memset(pcs, 0, sizeof(*pcs));
	ret = 0;

	return ret;
}

/* We deliver signals only on top of frames with cr.pm=0,
 * so make sure even the last frame is duly initialized. */
int native_clean_pc_stack_zero_frame_user(void __priv *addr)
{
	e2k_mem_crs_t __priv *pcs = addr;

	return clear_priv(pcs, sizeof(*pcs)) ? -EFAULT : 0;
}

/* Hardware catches stack overflows so there is no need
 * to waste time setting up vmap area with guard pages.
 * Also clearing all 3 stacks is not necessary. */
static unsigned long *__alloc_thread_stack_node(int node, const void *caller)
{
	void *address = alloc_pages_exact_nid(node, THREAD_SIZE,
			(THREADINFO_GFP & ~__GFP_ZERO) | __GFP_NORETRY | __GFP_NOWARN);

#ifdef CONFIG_VMAP_STACK
	if (!address) {
		/* We do not cache vmalloc'ed stacks (alloc_pages() is
		 * used instead) so there is no need for manual accounting
		 * like memcg_charge_kernel_stack() does. */
		address = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN,
				THREADINFO_GFP & ~__GFP_ZERO, node, caller);
	}
#endif

	if (!address)
		return NULL;

	/* For hardware stacks uninitialized data usage is impossible
	 * so clear data stack only */
	clear_memory_8(address + KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_SIZE, ETAGEWD);

	if (cpu_has(CPU_HWBUG_FALSE_SS))
		clean_pc_stack_zero_frame_kernel(address + KERNEL_PC_STACK_OFFSET);

	return address;
}

static void __free_thread_stack(void *address)
{
#ifdef CONFIG_VMAP_STACK
	if (is_vmalloc_addr(address))
		return vfree(address);
#endif

	return free_pages_exact(address, THREAD_SIZE);
}

unsigned long *arch_alloc_thread_stack_node(struct task_struct *task, int node)
{
	unsigned long *stack = __alloc_thread_stack_node(node, __builtin_return_address(0));

#ifdef CONFIG_VMAP_STACK
	task->stack_vm_area = (is_vmalloc_addr(stack)) ? find_vm_area(stack) : NULL;
#endif

	return stack;
}

static void thread_stack_free_rcu(struct rcu_head *rh)
{
	__free_thread_stack(rh);
}

void arch_free_thread_stack(struct task_struct *task)
{
	struct thread_info *ti = task_thread_info(task);
	ti->k_psp = new_psp(0, 0, 0);
	ti->k_pcsp = new_pcsp(0, 0, 0);
	ti->k_usd = new_usd(0, 0, 0);

	call_rcu((struct rcu_head *) task->stack, thread_stack_free_rcu);

#ifdef CONFIG_VMAP_STACK
	task->stack_vm_area = NULL;
#endif
}

/* No cache - see __alloc_thread_stack_node() */
int free_vm_stack_cache(unsigned int cpu)
{
	return 0;
}

static void user_stack_free_work_fn(struct work_struct *work)
{
	struct user_stack_free_work *w;
	unsigned long ts_flag;
	unsigned long stack_base;
	e2k_size_t max_stack_size;
	struct mm_struct *mm;
	int ret;

	w = container_of(to_delayed_work(work), typeof(*w), work);
	stack_base = w->stack_base;
	max_stack_size = w->max_stack_size;
	mm = w->mm;

	kthread_use_mm(mm);
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = vm_munmap_notkillable(stack_base, max_stack_size);
	clear_ts_flag(ts_flag);
	DebugHS("stack base 0x%lx max stack size 0x%lx, munmap returned %d\n",
		stack_base, max_stack_size, ret);
	kthread_unuse_mm(mm);

	if (ret == 0) {
		kfree(w);
		mmput(mm);
	} else if (ret == -ENOMEM) {
		queue_delayed_work(system_long_wq, to_delayed_work(work),
				   msecs_to_jiffies(MSEC_PER_SEC));
	} else {
		BUG();
	}
}

static void free_user_stack(void __priv *stack_base, e2k_size_t max_stack_size)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = vm_munmap_notkillable((unsigned long) stack_base, max_stack_size);
	clear_ts_flag(ts_flag);
	DebugHS("stack base 0x%lx max stack size 0x%lx, munmap returned %d\n",
		(unsigned long) stack_base, max_stack_size, ret);
	if (ret == -ENOMEM) {
		struct user_stack_free_work *work = kmalloc(sizeof(*work), GFP_KERNEL);

		BUG_ON(!work);

		work->stack_base = (unsigned long) stack_base;
		work->max_stack_size = max_stack_size;
		work->mm = current->mm;

		mmget(current->mm);

		INIT_DELAYED_WORK(&work->work, user_stack_free_work_fn);
		queue_delayed_work(system_long_wq, &work->work,
				   msecs_to_jiffies(MSEC_PER_SEC));
	} else if (ret != 0) {
		BUG();
	}
}

static void __priv *alloc_user_hard_stack(size_t stack_size,
		unsigned long user_stacks_base, int type)
{
	e2k_addr_t		stack_addr;
	struct thread_info	*ti = current_thread_info();
	hw_stack_t		*u_hw_stacks = &ti->u_hw_stack;
	unsigned long		ts_flags;

	BUG_ON(!IS_ALIGNED(stack_size, PAGE_SIZE) || !current->mm);

	/*
	 * Do not reuse already freed memory of chain stack, otherwise
	 * there will be a problem with longjmp (we won't be able to find
	 * needed area unambiguously).
	 */
	if (type == HW_STACK_TYPE_PCS)
		user_stacks_base = max_t(unsigned long, user_stacks_base,
				(unsigned long) GET_PCS_BASE(u_hw_stacks));

	ts_flags = set_ts_flag(TS_MMAP_PRIVILEGED | TS_KERNEL_SYSCALL |
			((type == HW_STACK_TYPE_PS) ? TS_MMAP_PS : TS_MMAP_PCS));
	stack_addr = vm_mmap_notkillable(NULL, user_stacks_base, stack_size,
					 PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, 0);
	clear_ts_flag(ts_flags);

	if (IS_ERR_VALUE(stack_addr)) {
		DebugHS("mmap() returned error %ld\n", (long) stack_addr);
		WARN_ONCE(stack_addr != -ENOMEM, "vm_mmap failed with %ld\n",
			  stack_addr);
		return NULL;
	}

	if (stack_addr < user_stacks_base) {
		DebugHS("bad stack base\n");
		goto out_unmap;
	}

	DebugHS("stack addr 0x%lx, size 0x%lx\n", stack_addr, stack_size);

	return (void __priv *) stack_addr;

out_unmap:
	ts_flags = set_ts_flag(TS_KERNEL_SYSCALL);
	vm_munmap_notkillable(stack_addr, stack_size);
	clear_ts_flag(ts_flags);
	return NULL;
}

static void free_user_p_stack(hw_stack_area_t *ps)
{
	free_user_stack(ps->base, get_hw_ps_area_user_size(ps));
	ps->base = NULL;
}

static void free_user_pc_stack(hw_stack_area_t *pcs)
{
	free_user_stack(pcs->base, get_hw_pcs_area_user_size(pcs));
	pcs->base = NULL;
}

static void alloc_user_p_stack(struct hw_stack_area *ps, size_t stack_area_size)
{
	ps->base = alloc_user_hard_stack(stack_area_size,
					 USER_P_STACKS_BASE, HW_STACK_TYPE_PS);
	if (!ps->base)
		return;
	set_hw_ps_area_user_size(ps, stack_area_size);
}

static void alloc_user_pc_stack(struct hw_stack_area *pcs, size_t stack_area_size)
{
	pcs->base = alloc_user_hard_stack(stack_area_size,
					  USER_PC_STACKS_BASE, HW_STACK_TYPE_PCS);
	if (!pcs->base)
		return;

	if (clean_pc_stack_zero_frame_user(pcs->base)) {
		free_user_pc_stack(pcs);
		return;
	}

	set_hw_pcs_area_user_size(pcs, stack_area_size);
}

int alloc_user_hw_stacks(hw_stack_t *hw_stacks, size_t p_size, size_t pc_size)
{
	size_t p_limit = current->signal->rlim[RLIMIT_P_STACK_EXT].rlim_cur;
	size_t pc_limit = current->signal->rlim[RLIMIT_PC_STACK_EXT].rlim_cur;
	mm_context_t *context = &current->mm->context;

	p_size = round_up(min(p_size, p_limit), PAGE_SIZE);
	pc_size = round_up(min(pc_size, pc_limit), PAGE_SIZE);

	/* Fast path: check cache first */
	while (!list_empty(&context->cached_stacks)) {
		struct cached_stacks_entry *cached;
		size_t cached_p_size, cached_pc_size;

		spin_lock(&context->cached_stacks_lock);
		if ((cached = list_first_entry_or_null(&context->cached_stacks,
				struct cached_stacks_entry, list_entry))) {
			list_del(&cached->list_entry);
			context->cached_stacks_size -= cached->stack.pcs.size +
						       cached->stack.ps.size;
		}
		spin_unlock(&context->cached_stacks_lock);
		if (unlikely(!cached))
			continue;

		cached_p_size = cached->stack.ps.size;
		cached_pc_size = cached->stack.pcs.size;
		if (unlikely(cached_pc_size > pc_limit || cached_p_size > p_limit ||
			     cached_pc_size < pc_size || cached_p_size < p_size)) {
			/* User has changed limits on hardware stacks
			 * and this cached stack is too big now;
			 * or requirements for stacks have changed
			 * after this one was put into the cache. */
			free_user_p_stack(&cached->stack.ps);
			free_user_pc_stack(&cached->stack.pcs);
			kfree(cached);
			continue;
		}

		/* Found suitable stack.  We can avoid zeroing it:
		 * stacks are from the same mm anyway, and different
		 * threads of the same process don't have anything to
		 * hide from each other. */
		*hw_stacks = cached->stack;
		kfree(cached);
		return 0;
	}

	/* Slow path: actually mmap() stacks */
	alloc_user_p_stack(&hw_stacks->ps, p_size);
	if (!hw_stacks->ps.base)
		return -ENOMEM;

	alloc_user_pc_stack(&hw_stacks->pcs, pc_size);
	if (!hw_stacks->pcs.base) {
		free_user_p_stack(&hw_stacks->ps);
		return -ENOMEM;
	}

	return 0;
}

void free_user_hw_stacks(hw_stack_t *hw_stacks)
{
	mm_context_t *context = &current->mm->context;

	/* Fast path: try to put into cache first.
	 * Limit cached stacks size to reduce memory usage.
	 * Note that hardware stacks freeing is delayed to
	 * a kworker in some cases, thus we can't access
	 * 'current' here. */
	if (hw_stacks->ps.base && hw_stacks->pcs.base &&
	    context->cached_stacks_size + hw_stacks->ps.size +
	    hw_stacks->pcs.size < SZ_1M) {
		struct cached_stacks_entry *cached = kmalloc(sizeof(*cached), GFP_KERNEL);

		if (cached) {
			cached->stack = *hw_stacks;

			spin_lock(&context->cached_stacks_lock);
			INIT_LIST_HEAD(&cached->list_entry);
			list_add(&cached->list_entry, &context->cached_stacks);
			context->cached_stacks_size += hw_stacks->ps.size +
						       hw_stacks->pcs.size;
			spin_unlock(&context->cached_stacks_lock);

			hw_stacks->ps.base = NULL;
			hw_stacks->pcs.base = NULL;
			return;
		}
	}

	/* Slow path: actually munmap() stacks */
	if (hw_stacks->ps.base)
		free_user_p_stack(&hw_stacks->ps);
	if (hw_stacks->pcs.base)
		free_user_pc_stack(&hw_stacks->pcs);
}

void destroy_cached_stacks(mm_context_t *context)
{
	struct cached_stacks_entry *cached, *next;

	/* This is called upon mm freeing so
	 * there is no need to take the spinlock */
	list_for_each_entry_safe(cached, next, &context->cached_stacks, list_entry) {
		list_del(&cached->list_entry);
		kfree(cached);
	}
}

void free_user_old_pc_stack_areas(struct list_head *old_u_pcs_list)
{
	struct old_pcs_area	*user_old_pc_stack;
	struct old_pcs_area	*n;

	list_for_each_entry_safe(user_old_pc_stack, n, old_u_pcs_list,
				 list_entry) {
		list_del(&user_old_pc_stack->list_entry);
		kfree(user_old_pc_stack);
	}
}

void arch_release_task_struct(struct task_struct *tsk)
{
	/* free virtual part of task structure */
	free_virt_task_struct(tsk);
}

static u64 get_user_main_c_stack(unsigned long sp, unsigned long *stack_top)
{
	e2k_addr_t		stack_start;
	struct vm_area_struct	*vma;

	DebugDS("started: sp 0x%lx\n", sp);

	mmap_read_lock(current->mm);
	vma = find_vma(current->mm, sp);
	DebugDS("find_vma() returned VMA 0x%px start 0x%lx end 0x%lx\n",
		vma, vma->vm_start, vma->vm_end);

	BUG_ON(!(vma->vm_flags & VM_GROWSDOWN));

	*stack_top = round_down(vma->vm_end, E2K_ALIGN_USTACK_BOUNDS);
	stack_start = round_up(vma->vm_start, E2K_ALIGN_USTACK_BOUNDS);

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
	if (make_vma_pages_valid(vma, vma->vm_start, vma->vm_end)) {
		DebugDS("make valid failed\n");
		return 0;
	}
#endif

	mmap_read_unlock(current->mm);

	DebugDS("returns stack base 0x%lx\n", stack_start);
	return stack_start;
}

/*
 * This function allocates user's memory for needs of Compilation Unit Table.
 */

static int create_cu_table(struct mm_struct *mm, unsigned long *cut_size_p, int *cui_p)
{
	unsigned long cut_start, cut_size = USER_CUT_AREA_SIZE;
	unsigned long ts_flags;
	int cui;

	DebugCU("started: cut base 0x%lx, size 0x%lx\n",
		USER_CUT_AREA_BASE, cut_size);

	ts_flags = set_ts_flag(TS_MMAP_PRIVILEGED | TS_MMAP_CUT | TS_KERNEL_SYSCALL);
	cut_start = vm_mmap(NULL, USER_CUT_AREA_BASE, cut_size, PROT_READ | PROT_WRITE,
			    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0);
	clear_ts_flag(ts_flags);
	DebugCU("vm_mmap() returned %ld\n", cut_start);
	if (IS_ERR_VALUE(cut_start))
		return cut_start;

	if (TASK_IS_PROTECTED(current)) {
		DebugEX("create_cut_entry for new protected loader\n");
		cui = create_cut_entry(mm->context.tcount,
				       mm->start_code, mm->end_code,
				       mm->start_data, mm->end_data);
	} else {
		DebugEX("create_cut_entry for unprotected mode\n");
		cui = create_cut_entry(0,
			0L, current->thread.flags & E2K_FLAG_32BIT ?
				TASK32_SIZE : TASK_SIZE,
			0L, current->thread.flags & E2K_FLAG_32BIT ?
				TASK32_SIZE : TASK_SIZE);
	}
	if (cui < 0)
		return cui;

	BUG_ON(cui != (TASK_IS_PROTECTED(current) ?
		       USER_CODES_PROT_INDEX : USER_CODES_UNPROT_INDEX(current)));

	*cui_p = cui;
	*cut_size_p = cut_size;

	return 0;
}

static int
create_user_hard_stacks(hw_stack_t *hw_stacks, struct e2k_stacks *stacks)
{
	e2k_size_t	user_psp_size = get_hw_ps_user_size(hw_stacks);
	e2k_size_t	user_pcsp_size = get_hw_pcs_user_size(hw_stacks);
	int ret;

	ret = alloc_user_hw_stacks(hw_stacks, user_psp_size, user_pcsp_size);
	if (ret)
		return ret;

	DebugCLN("allocated user Procedure stack at %px, size 0x%lx,\n"
		 "Chain stack at %px, size 0x%lx\n",
		 hw_stacks->ps.base, user_psp_size, hw_stacks->pcs.base,
		 user_pcsp_size);

	stacks->psp = new_psp((unsigned long)GET_PS_BASE(hw_stacks), user_psp_size, 0);
	stacks->pcsp = new_pcsp((unsigned long)GET_PCS_BASE(hw_stacks),
			user_pcsp_size, 0);
	stacks->pshtp = (e2k_pshtp_t) {0};
	stacks->pcshtp = (e2k_pcshtp_t) {0};

	return 0;
}

/*
 * Functions create all user hardware stacks(PS & PCS) including
 * kernel part of the hardware stacks of current task
 */
void native_define_user_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	set_hw_ps_user_size(hw_stacks, USER_P_STACK_INIT_SIZE);
	set_hw_pcs_user_size(hw_stacks, USER_PC_STACK_INIT_SIZE);
}

void show_regs(struct pt_regs *regs)
{
	print_stack_frames(current, regs, 1);
	print_pt_regs(regs);
}

void __debug_signal_print(const char *message,
			  struct pt_regs *regs, bool print_stack)
{
	unsigned long return_ip;

	return_ip = get_return_ip(regs);
	if (regs->trap) {
		unsigned long trap_ip = get_trap_ip(regs);
		if (trap_ip == return_ip) {
			pr_info("%s: IP=%lx %s(pid=%d)\n",
				message, trap_ip, current->comm, current->pid);
		} else {
			pr_info("%s: IP=%lx (%%cr.IP=%lx) %s(pid=%d)\n",
				message, trap_ip, return_ip, current->comm, current->pid);
		}
	} else {
		pr_info("%s: IP=%lx %s(pid=%d)\n",
			message, return_ip, current->comm, current->pid);
	}

	if (print_stack)
		show_regs(regs);
}


static int check_wchan(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	unsigned long *p_ip = arg;
	unsigned long ip;

	ip = get_cr0_ip(frame->cr0);

	if (!in_sched_functions(ip)) {
		*p_ip = ip;
		return 1;
	}

	return 0;
}

unsigned long __get_wchan(struct task_struct *p)
{
	unsigned long ip = 0;

	parse_chain_stack(false, p, check_wchan, &ip);

	return ip;
}

static int free_user_hardware_stacks(hw_stack_t *u_hw_stacks)
{
	thread_info_t	*ti = current_thread_info();

	free_user_old_pc_stack_areas(&ti->old_u_pcs_list);
	DebugEX("freed user old PCS list head 0x%px\n", &ti->old_u_pcs_list);

	if (atomic_read(&current->mm->mm_users) <= 1) {
		DebugEX("last thread: do not free stacks - mmput will release all mm\n");
		SET_PS_BASE(u_hw_stacks, NULL);
		SET_PCS_BASE(u_hw_stacks, NULL);
		return 0;
	}

	BUG_ON((unsigned long) GET_PS_BASE(u_hw_stacks) >= TASK_SIZE ||
	       (unsigned long) GET_PCS_BASE(u_hw_stacks) >= TASK_SIZE);

	/*
	 * Don't free hw_stack (they are nedeed for coredump)
	 * The hw_stacks will be freeded in coredump_finish
	 */
	if (current->signal->core_state) {
		DebugCD("core dump detected\n");
		create_delayed_free_hw_stacks();
		SET_PS_BASE(u_hw_stacks, NULL);
		SET_PCS_BASE(u_hw_stacks, NULL);
		return 0;
	}

	if (GET_PS_BASE(u_hw_stacks) || GET_PCS_BASE(u_hw_stacks)) {
		DebugEX("will free user PS from base 0x%px, size 0x%lx, user PCS from base 0x%px, size 0x%lx\n",
			u_hw_stacks->ps.base, get_hw_ps_user_size(u_hw_stacks),
			u_hw_stacks->pcs.base, get_hw_pcs_user_size(u_hw_stacks));
	}
	free_user_hw_stacks(u_hw_stacks);

	return 0;
}

void fill_kernel_cut_entry(e2k_cute_t *cute_p, enum cud_flag cudf,
		u64 code_base, u64 code_sz, u64 glob_base, u64 glob_sz)
{
	memset(cute_p, 0, sizeof(*cute_p));
	cute_p->cud = new_cud(code_base, __ALIGN_MASK(code_sz, E2K_ALIGN_CODES_MASK), 1, cudf);
	cute_p->gd = new_gd(glob_base, __ALIGN_MASK(glob_sz, E2K_ALIGN_GLOBALS_MASK));
}

int __must_check fill_user_cut_entry(e2k_cute_t __priv *cute_p, enum cud_flag cudf,
		u64 code_base, u64 code_sz, u64 glob_base, u64 glob_sz)
{
	e2k_cute_t cute;

	fill_kernel_cut_entry(&cute, cudf, code_base, code_sz, glob_base, glob_sz);

	return copy_to_priv(cute_p, &cute, sizeof(cute)) ? -EFAULT : 0;
}

int create_cut_entry(int tcount,
		     u64 code_base, u64 code_sz,
		     u64 glob_base, u64 glob_sz)
{
	struct mm_struct *mm = current->mm;
	struct page *page;
	e2k_cute_t __priv *cute_p;
	enum cud_flag cudf;
	int free_cui, ret;

	if (TASK_IS_PROTECTED(current)) {
		down_write(&mm->context.cut_mask_lock);

		/* Find the first free entry in cut and occupy it */
		free_cui = find_next_zero_bit((unsigned long *)&mm->context.cut_mask,
					      USER_CUT_AREA_SIZE / sizeof(e2k_cute_t), 1);

		/* If no free cut entry found */
		if (free_cui == USER_CUT_AREA_SIZE / sizeof(e2k_cute_t)) {
			ret = -EFAULT;
		} else {
			__set_bit(free_cui, mm->context.cut_mask);
			ret = 0;
		}

		up_write(&mm->context.cut_mask_lock);

		if (ret)
			return ret;
	} else {
		/* not protected aplications should have zero CUI */
		free_cui = USER_CODES_UNPROT_INDEX(current);
	}

	/* Fill found cut entry by information about loaded module */
	cute_p = get_cut_entry_pointer(free_cui, &page);
	DebugCU("Create cut entry: cui = %d; tct = %d; code = 0x%llx: 0x%llx; data = 0x%llx : 0x%llx\n",
			free_cui, tcount, code_base, code_sz, glob_base, glob_sz);

	if (TASK_IS_PROTECTED(current)) {
		DebugCU("e2k_set_vmm_cui called for cui = %d; code 0x%llx : 0x%llx\n",
			 free_cui, code_base, code_base + code_sz);
		ret = e2k_set_vmm_cui(mm, free_cui, code_base, code_base + code_sz);
		if (ret)
			goto out_put;
		DebugCUI("created cui=%d code 0x%llx[0x%llx] glob 0x%llx[0x%llx]\n",
			 free_cui, code_base, code_sz, glob_base, glob_sz);
	}

	atomic_add_return(tcount, &mm->context.tstart);
	if (TASK_IS_PROTECTED(current)) {
		cudf = cud_m128;
	} else if (current->thread.flags & E2K_FLAG_32BIT) {
		cudf = cud_m32;
	} else {
		cudf = cud_m64;
	}
	ret = fill_user_cut_entry(cute_p, cudf, code_base, code_sz, glob_base, glob_sz);
	if (ret)
		goto out_put;

out_put:
	put_cut_entry_pointer(page);

	return (ret) ? ret : free_cui;
}

int free_cut_entry(u64 glob_base, u64 glob_sz,
		   u64 *code_base, u64 *code_sz)
{
	struct mm_struct *mm = current->mm;
	int error, removed_cui = -1, cui;

	/* Free cut entry with appropriate glob_base */
	down_write(&mm->context.cut_mask_lock);
	for (cui = 1; cui < USER_CUT_AREA_SIZE / sizeof(e2k_cute_t); cui++) {
		struct page *page;
		e2k_cute_t cute;
		e2k_cute_t __priv *cute_p = get_cut_entry_pointer(cui, &page);

		error = copy_from_priv(&cute, cute_p, sizeof(cute));
		if (error) {
			put_cut_entry_pointer(page);
			break;
		}

		if (GD_BASE(cute.gd) == glob_base && GD_SIZE(cute.gd) == glob_sz) {
			if (code_base)
				*code_base = CUD_BASE(cute.cud);
			if (code_sz)
				*code_sz = CUD_SIZE(cute.cud);
			fill_kernel_cut_entry(&cute, 0, 0, 0, 0, 0);

			error = copy_to_priv(cute_p, &cute, sizeof(cute));
			if (error) {
				put_cut_entry_pointer(page);
				break;
			}

			bitmap_clear((unsigned long *) &mm->context.cut_mask, cui, 1);
			removed_cui = cui;
		}

		put_cut_entry_pointer(page);
	}
	up_write(&mm->context.cut_mask_lock);

	/*
	 * If cut entry with appropriate glob_base and glob_sz was not found
	 */
	if (removed_cui > 0) {
		DebugCU("Free cut entry: cui = %d; code = 0x%llx: 0x%llx; data = 0x%llx : 0x%llx\n",
			removed_cui, *code_base, *code_sz, glob_base, glob_sz);
	} else {
		error = -EFAULT;
	}

	return error;
}

void start_thread(struct pt_regs *regs, unsigned long entry, unsigned long sp)
{
	thread_info_t *const ti = current_thread_info();
	struct mm_struct *mm = current->mm;
	unsigned long	u_stk_bottom, stack_top;
	bool protected = TASK_IS_PROTECTED(current);
	/*
	 * Historically entry function in glibc uses unprotected
	 * psize even for protected mode applications, so for
	 * compatibility we keep this behavior.
	 */
	size_t pframe_size_q = C_ABI_PSIZE_UNPROT;
	hw_stack_t u_hw_stack;
	e2k_stacks_t stacks;
	e2k_mem_crs_t crs;
	u64 __priv *pframe;
	e2k_size_t	cut_size;
	int		cui, ret, tag;
	u64		flags;
	e2k_qreg_t qr0;

	DebugP("entry 0x%lx sp 0x%lx\n", entry, sp);

	BUG_ON(!list_empty(&ti->old_u_pcs_list));
	BUG_ON(CURRENT_PS_BASE() || CURRENT_PCS_BASE());
	WARN_ON_ONCE(regs != current_pt_regs());

	sp = round_down(sp, (protected) ? E2K_ALIGN_PUSTACK_SIZE : E2K_ALIGN_USTACK_SIZE);

#if defined CONFIG_KVM_HOST_MODE && defined CONFIG_KVM_PARAVIRTUALIZATION
	if (ti->gthread_info) {
		/* It is guest thread: clear from old process */
		kvm_pv_clear_guest_thread_info(ti->gthread_info);
	}
#endif /* CONFIG_KVM_HOST_MODE */

	u_stk_bottom = get_user_main_c_stack(sp, &stack_top);
	if (!u_stk_bottom) {
		ret = -ENOMEM;
		DebugEX("is terminated: get_user_main_c_stack() failed and returned error %d\n",
			ret);
		goto fatal_error;
	}
	DebugEX("stack base 0x%lx top 0x%lx\n", u_stk_bottom, stack_top);

	define_user_hw_stacks_sizes(&u_hw_stack);
	ret = create_user_hard_stacks(&u_hw_stack, &stacks);
	if (ret) {
		DebugEX("Could not create user hardware stacks\n");
		goto fatal_error;
	}

	/*
	 * Set arguments
	 */
	if (protected) {
		/* new loader interface */
		unsigned long __user *p_base = (unsigned long __user *) mm->start_stack;

		if ((ret = get_user_tagged_16(qr0, tag, p_base)))
			goto fatal_error;
		if (tag != ETAGAPQ) {
			ret = -EPERM;
			goto fatal_error;
		}

		/* We may erase base descriptor from stack since
		 * no one will ever need it there. */
		if ((ret = put_user_tagged_16(((e2k_qreg_t) { .lo = 0, .hi = 0 }),
				ETAGEWQ, p_base)))
			goto fatal_error;
	} else {
		qr0.lo = 0;
		qr0.hi = 0;
		tag = 0;
	}
	stacks.psp = set_psp_ind(stacks.psp, pframe_size_q * EXT_4_NR_SZ);
	pframe = (u64 __priv *) PSP_BASE(stacks.psp);

	if (clear_priv(pframe, pframe_size_q * EXT_4_NR_SZ) ||
	    put_priv_tagged_16_offset(qr0, tag, &pframe[0], machine.qnr1_offset)) {
		ret = -EFAULT;
		goto fatal_error;
	}

	/*
	 * Allocate memory for CUT table
	 */
	ret = create_cu_table(mm, &cut_size, &cui);
	if (ret) {
		DebugEX("Can't create CU table.\n");
		goto fatal_error;
	}

	/*
	 * Init data stack values
	 */
	stacks.top = stack_top;
	stacks.usd = new_usd(u_stk_bottom, sp - u_stk_bottom, sp - u_stk_bottom);

	if (protected) {
		u64 ptr, ind;
		e2k_sbr_t u_sbr;

		u_sbr.base = USD_PTR(stacks.usd) & ~E2K_PROTECTED_STACK_BASE_MASK;
		ptr = USD_PTR(stacks.usd);
		ind = USD_IND(stacks.usd);

		/* Protected mode alignment requirements are stricter */
		u64 delta = ptr - round_down(ptr, E2K_ALIGN_PUSTACK_SIZE);
		ptr -= delta;
		ind -= delta;

		stacks.usd = new_pusd(ptr - ind, USD_SIZE(stacks.usd), ind, 2);

#ifdef CONFIG_PROTECTED_MODE
		/* Init Secure Computing execution mode: */
		arch_init_secure_computing_mode(NULL);
#endif
	}

	/*
	 * Init CR registers and chain stack
	 */
	ret = chain_stack_frame_init(&crs, entry, sp - u_stk_bottom, 0,
			E2K_USER_INITIAL_PSR, pframe_size_q,
			pframe_size_q, true);
	if (ret)
		goto fatal_error;

	stacks.pcsp = set_pcsp_ind(stacks.pcsp, SZ_OF_CR);
	stacks.pcshtp.ind += SZ_OF_CR;

	free_getsp_adj(&ti->getsp_adj);

	/* save local data & hardware stacks pointers */
	ti->u_stack.bottom = u_stk_bottom;
	ti->u_stack.size = stack_top - u_stk_bottom;
	ti->u_stack.top = stack_top;

	/*
	 * Set CU descriptor (register) to point to the CUT base.
	 */
	ti->u_cutd = (e2k_cutd_t) { .base = USER_CUT_AREA_BASE };
	write_CUTD_reg(ti->u_cutd);

	/*
	 * Set FPU registers in accordance with E2K API specifications.
	 */
	INIT_FPU_REGISTERS();

	if (cpu_has(CPU_FEAT_MADM))
		native_write_MADMR_reg((e2k_madmr_t) { .word = 0 });

	/*
	 * The next function can be paravirtualized and do various actions:
	 *	on host (or pure native mode) should only return 0 to continue
	 * switching and start of new user
	 *	on guest should switch to created user stacks and start from
	 * user entry point (to do all into one hypercall) Function can
	 * return 1 on exit from user or negative error code
	 */
	flags = 0;
	if (TASK_IS_BINCO(current))
		flags |= BIN_COMP_CODE_TASK_FLAG;
	if (current->thread.flags & E2K_FLAG_32BIT)
		flags |= BIN_32_CODE_TASK_FLAG;
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE)
		flags |= PROTECTED_CODE_TASK_FLAG;
	ret = switch_to_new_user(&stacks, &u_hw_stack, ti->u_cutd.base,
				 cut_size, entry, cui, flags, !user_mode(regs));
	if (ret == 0) {
		/* native or host kernel case: */
		/* continue switching to new user process */
	} else if (ret < 0) {
		/* paravirtualized guest function case: */
		/* error occurred while switching */
		DebugGEX("error %d occurred while switch to new user\n", ret);
		goto fatal_error;
	} else if (ret > 0) {
		/* paravirtualized guest function case: */
		/* guest execve() completed and returned from user */
		panic("return from user execve(), return value %d\n", ret);
	}

	native_write_RPR_reg(INITIAL_ZEROED_RPR);

	regs->stacks = stacks;
	regs->crs = crs;
	regs->wd.psize = 0;
	ti->u_hw_stack = u_hw_stack;

	regs->rndpr = E2K_INITIAL_RNDPR;

	return;

fatal_error:
	DebugEX("fatal error %d: send KILL signal\n", ret);

	if (!user_mode(regs)) {
		/* Nowhere to return to, just exit */
		pr_err("%s(): fatal error %d on kernel\n", __func__, ret);
		do_exit(SIGKILL);
	}

	send_sig(SIGKILL, current, 0);
}
EXPORT_SYMBOL(start_thread);


/*
 * Idle related variables and functions
 */
unsigned long boot_option_idle_override = 0;
EXPORT_SYMBOL(boot_option_idle_override);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static void save_binco_regs(struct sw_regs *sw_regs)
{

	/* Save intel regs from processor. For binary compiler. */
	NATIVE_SAVE_BINCO_REGS(sw_regs);
}
#else /* !CONFIG_SECONDARY_SPACE_SUPPORT: */
static inline void save_binco_regs(struct sw_regs *sw_regs) { }
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

void init_sw_user_regs(struct sw_regs *sw_regs, bool save_global_gregs,
		       bool save_binco_regs_needed)
{
	/*
	 * New process will start with interrupts disabled.
	 * They will be enabled in schedule_tail() (user's upsr
	 * is saved in pt_regs and does not need to be corrected).
	 */
	if (IS_IRQ_MASK_GLOBAL()) {
		/* global IRQs mask is placed in PSR */
		sw_regs->psr	= E2K_KERNEL_PSR_GLOB_IRQ_DISABLED;
		sw_regs->upsr	= E2K_KERNEL_UPSR_GLOB_IRQ_DISABLED;
	} else {
		/* global IRQs mask is placed in UPSR */
		sw_regs->upsr	= E2K_KERNEL_UPSR_LOC_IRQ_DISABLED;
	}

	sw_regs->fpu.fpcr = native_read_FPCR_reg();
	sw_regs->fpu.fpsr = native_read_FPSR_reg();
	sw_regs->fpu.pfpfr = native_read_PFPFR_reg();

	sw_regs->cutd = native_read_CUTD_reg();
	sw_regs->osem = osem_calculate(false, TASK_IS_PROTECTED(current));

	if (cpu_has(CPU_FEAT_MADM)) {
		if (TASK_IS_PROTECTED(current)) {
			sw_regs->madmr = native_read_MADMR_reg();
		} else {
			sw_regs->madmr = (e2k_madmr_t) { .word = 0L };
		}
	}

	if (save_global_gregs) {
		machine.save_global_gregs(&sw_regs->u_gregs);
	} else {
		memset(&sw_regs->u_gregs, 0, sizeof(sw_regs->u_gregs));
	}

	if (save_binco_regs_needed)
		save_binco_regs(sw_regs);

	sw_regs->idr = read_IDR_reg();
}

static void set_default_registers(struct task_struct *new_task,
		bool save_global_gregs, bool save_local_gregs)
{
	struct local_gregs *new_l_gregs;
	struct sw_regs *new_sw_regs = &new_task->thread.sw_regs;
	struct thread_info *new_ti = task_thread_info(new_task);
	unsigned long addr = (unsigned long) new_task->stack;

	memset(new_sw_regs, 0, sizeof(*new_sw_regs));

	memset(&new_task->thread.debug.regs, 0,
	       sizeof(new_task->thread.debug.regs));

	clear_ptrace_hw_breakpoint(new_task);

	new_sw_regs->uaccess_max = user_addr_max();

	/*
	 * Calculate kernel stacks registers
	 */
	new_ti->k_psp = new_psp(addr + KERNEL_P_STACK_OFFSET, KERNEL_P_STACK_SIZE, 0);
	new_ti->k_pcsp = new_pcsp(addr + KERNEL_PC_STACK_OFFSET, KERNEL_PC_STACK_SIZE, 0);
	new_ti->k_usd = new_usd(addr + KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_SIZE,
				KERNEL_C_STACK_SIZE);

	/*
	 * Prepare registers for first schedule() to a new task
	 */
	new_sw_regs->top = addr + KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET;
	/* According to C call convention caller must allocate space
	 * for callee in data stack.  Do it here for possible calls
	 * in __switch_to() after USD switch. */
	new_sw_regs->usd = decr_usd_ind(new_ti->k_usd, 64);
	new_sw_regs->psp = new_ti->k_psp;
	new_sw_regs->pcsp = new_ti->k_pcsp;

	new_l_gregs = &new_task->thread.u_gregs;
	if (save_local_gregs) {
		tagged_memcpy_8(&new_l_gregs->g, &current->thread.u_gregs.g,
				sizeof(new_l_gregs->g));
		new_l_gregs->bgr = current->thread.u_gregs.bgr;
	} else {
		memset(&new_l_gregs->g, 0, sizeof(new_l_gregs->g));
		new_l_gregs->bgr = E2K_INITIAL_BGR;
	}

	init_sw_user_regs(new_sw_regs, save_global_gregs, TASK_IS_BINCO(current));
}

asmlinkage pid_t sys_clone_thread(unsigned long clone_flags, unsigned long stack_base,
		unsigned long long stack_size, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long flags = clone_flags;
	struct kernel_clone_args args = {};

	if (!access_ok((void __user *) stack_base, stack_size))
		return -ENOMEM;

	if (!flags)
		flags = SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES;

	args.flags	 = (flags & ~CSIGNAL);
	args.pidfd	 = parent_tidptr;
	args.child_tid	 = child_tidptr;
	args.parent_tid	 = parent_tidptr;
	args.exit_signal = (flags & CSIGNAL);
	/* kernel_clone() expects the upper bound here when !CONFIG_STACK_GROWSUP */
	args.stack	 = stack_base + stack_size;
	args.stack_size	 = stack_size;
	args.tls	 = tls;

	return kernel_clone(&args);
}

/*
 * Get return IP for n level below pt_regs return IP
 */
e2k_addr_t get_nested_kernel_IP(pt_regs_t *regs, int n)
{
	e2k_addr_t	IP = 0UL;
	e2k_cr0_t	cr0;
	e2k_addr_t	base;
	s64		cr_ind;
	u64		flags;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	base = PCSP_BASE(regs->stacks.pcsp);
	cr_ind = PCSP_IND(regs->stacks.pcsp);

	while (--n) {
		if (cr_ind <= 0) {
			panic("get_nested_kernel_IP(): procedure chain stack underflow\n");
		}
		cr_ind = cr_ind - SZ_OF_CR;
		cr0 = *get_kernel_cr0_p(base, cr_ind);
		IP = get_cr0_ip(cr0);
	}

	raw_all_irq_restore(flags);
	return IP;
}

/**
 * native_copy_kernel_stacks - prepare for return to kernel function
 * @stacks - allocated stacks' parameters (will be corrected)
 * @crs - chain stack frame will be returned here
 * @fn - function to return to
 * @arg - function's argument
 *
 * Note that cr1_lo.psr value is taken from PSR register. This means
 * that interrupts and sge are expected to be enabled by caller.
 */
int native_copy_kernel_stacks(struct task_struct *new_task,
			      unsigned long fn, unsigned long arg)
{
	struct sw_regs *new_sw_regs = &new_task->thread.sw_regs;

	/*
	 * How kernel thread creation works.
	 *
	 * 1) After schedule() to the new kthread we return to __ret_from_fork()
	 * with wbs=0 (i.e. returned value ends up in %r0).
	 * 2) __ret_from_fork() calls schedule_tail() to finish the things
	 * for scheduler.
	 * 3) __ret_from_fork() calls @fn directly.
	 * 4) If kernel_execve() was called then after return to __ret_from_fork()
	 * it will in turn return to user.
	 */

	/*
	 * Reserve space in hardware stacks for __ret_from_fork and zero frame
	 */
	new_sw_regs->pcsp = set_pcsp_ind(new_sw_regs->pcsp, 2 * SZ_OF_CR);

	return 0;
}

static struct pt_regs *reserve_child_pt_regs(struct sw_regs *new_sw_regs,
					     struct task_struct *new_task)
{
	struct pt_regs *new_regs;

#ifdef CONFIG_KVM_GUEST_KERNEL
	unsigned long stack_top, stack_bottom;

	stack_top = (unsigned long) new_task->stack + KERNEL_C_STACK_OFFSET +
			KERNEL_C_STACK_SIZE;
	stack_bottom = USD_BASE(new_sw_regs->usd);

	BUG_ON(USD_IND(new_sw_regs->usd) < KERNEL_PT_REGS_SIZE);

	/* allocate pt_regs structute from top of the stack
	new_sw_regs->usd.base -= KERNEL_PT_REGS_SIZE;
	new_sw_regs->usd.size -= KERNEL_PT_REGS_SIZE;

	AS(new_sw_regs->crs.cr1_hi).ussz -= KERNEL_PT_REGS_SIZE / 16;

	new_regs = (struct pt_regs *) (stack_top - KERNEL_PT_REGS_SIZE);
	 */

	/* allocate pt_regs structute from bottom of the stack
	 * Overlay of areas cannot now controlled by hardware because of
	 * guest does not report stack borders changes to host.
	 * TODO that it need implement simple light hypercall
	new_sw_regs->usd_hi.USD_hi_size -= KERNEL_PT_REGS_SIZE;
	 */
	new_regs = (struct pt_regs *)stack_bottom;

	return new_regs;
#else
	/* allocate pt_regs structure from top of the stack */
	new_regs = (struct pt_regs *) (new_sw_regs->top - KERNEL_PT_REGS_SIZE);

	new_sw_regs->usd = decr_usd_ind(new_sw_regs->usd, KERNEL_PT_REGS_SIZE);
	new_sw_regs->top -= KERNEL_PT_REGS_SIZE;

	if (!cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		new_sw_regs->crs.cr1 = set_cr1_ussz(new_sw_regs->crs.cr1,
				get_cr1_ussz(new_sw_regs->crs.cr1) - KERNEL_PT_REGS_SIZE);
	}
#endif

	return new_regs;
}

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
static void ktimes_account_copy_thread(struct thread_info *new_ti)
{
	int i;
	scall_times_t *new_scall_times;

	for (i = 0; i < (sizeof(new_ti->times)) / sizeof(u16); i++)
		((u16 *)(new_ti->times))[i] = new_task->pid;
	new_ti->times_num = 1;
	new_ti->times_index = 1;
	new_scall_times = &(new_ti->times[0].of.syscall);
	new_ti->times[0].type = SYSTEM_CALL_TT;
	new_ti->fork_scall_times = new_scall_times;
	new_scall_times->syscall_num = regs->scall_times->syscall_num;
	if (regs->scall_times)
		new_scall_times->syscall_num = regs->scall_times->syscall_num;
	else
		new_scall_times->syscall_num = -1;
	new_scall_times->signals_num = 0;
}
#else
static void ktimes_account_copy_thread(struct thread_info *new_ti) { }
#endif


/**
 * *_clone_prepare_spilled_user_stacks - prepare user's part of kernel stacks
 *				       for a new thread
 * @child_stacks: child PSP/PCSP/USD/SBR registers
 * @child_crs: child CR registers
 * @regs: parent registers
 */
int native_clone_prepare_spilled_user_stacks(e2k_stacks_t *child_stacks,
					     const e2k_mem_crs_t *child_crs,
					     const struct pt_regs *regs,
					     struct sw_regs *new_sw_regs,
					     struct thread_info *new_ti,
					     unsigned long clone_flags)
{
	const struct thread_info *old_ti = current_thread_info();
	u64 ps_copy_size;
	s64 u_pshtp_size, u_pcshtp_size, parent_pshtp_size;
	unsigned long flags;
	void __priv *child_pframe;

	u_pshtp_size = PSHTP_MEM_INDEX(child_stacks->pshtp);
	u_pcshtp_size = child_stacks->pcshtp.ind;

	/*
	 * After clone child has new empty stacks
	 */
	if (WARN_ON_ONCE(u_pshtp_size || u_pcshtp_size))
		do_exit(SIGKILL);

	/*
	 * Leave one empty frame that will be loaded to %CR
	 * registers when the top user frame starts executing.
	 */
	new_sw_regs->pcsp = incr_pcsp_ind(new_sw_regs->pcsp, SZ_OF_CR);
	child_stacks->pcsp = incr_pcsp_ind(child_stacks->pcsp, SZ_OF_CR);
	child_stacks->pcshtp.ind += SZ_OF_CR;

	/*
	 * Copy last chain stack frame from parent (needed only for vfork()).
	 */
	if (clone_flags & CLONE_VFORK) {
		e2k_mem_crs_t *cframe;
		unsigned long parent_pcshtp_size;

		parent_pcshtp_size = regs->stacks.pcshtp.ind;
		if (WARN_ON_ONCE(parent_pcshtp_size < SZ_OF_CR))
			do_exit(SIGKILL);
		cframe = (e2k_mem_crs_t *) (PCSP_BASE(old_ti->k_pcsp) +
					    parent_pcshtp_size - SZ_OF_CR);

		raw_all_irq_save(flags);
		COPY_STACKS_TO_MEMORY();
		memcpy((void *) (PCSP_BASE(new_ti->k_pcsp) + PCSP_IND(new_sw_regs->pcsp)),
		       cframe, SZ_OF_CR);
		raw_all_irq_restore(flags);
		DebugCLN("last chain stack frame from parent copyed to\n"
			 "kernel stack %llx from %px, size 0x%lx\n",
			 PCSP_BASE(new_ti->k_pcsp) + PCSP_IND(new_sw_regs->pcsp),
			 cframe, SZ_OF_CR);

		new_sw_regs->pcsp = incr_pcsp_ind(new_sw_regs->pcsp, SZ_OF_CR);
		child_stacks->pcsp = incr_pcsp_ind(child_stacks->pcsp, SZ_OF_CR);
		child_stacks->pcshtp.ind += SZ_OF_CR;

		ps_copy_size = (child_crs->cr1.wbs + cframe->cr1.wbs) * EXT_4_NR_SZ;
	} else {
		ps_copy_size = child_crs->cr1.wbs * EXT_4_NR_SZ;
	}

	/*
	 * Copy procedure stack from parent.
	 */
	child_pframe = (void __priv *) PSP_PTR(child_stacks->psp);
	parent_pshtp_size = PSHTP_MEM_INDEX(regs->stacks.pshtp);

	if (ps_copy_size > parent_pshtp_size) {
		void __priv *parent_pframe;
		u64 size;

		size = ps_copy_size - parent_pshtp_size;
		parent_pframe = (void __priv *) (PSP_PTR(regs->stacks.psp) - ps_copy_size);

		if (copy_in_priv(child_pframe, parent_pframe, size)) {
			pr_err("%s(): copying of parent procedure frames to child failed\n",
			       __func__);
			return -EFAULT;
		}
		DebugCLN("parent procedure stack frames from %px copyed to\n"
			 "childe stack %px, size 0x%llx\n",
			 parent_pframe, child_pframe, size);

		child_pframe += size;
		child_stacks->psp = incr_psp_ind(child_stacks->psp, size);
		ps_copy_size -= size;
	}

	raw_all_irq_save(flags);
	COPY_STACKS_TO_MEMORY();
	tagged_memcpy_8((void *) PSP_BASE(new_ti->k_psp),
			(void *) (PSP_BASE(old_ti->k_psp) + parent_pshtp_size -
				 ps_copy_size), ps_copy_size);
	raw_all_irq_restore(flags);
	DebugCLN("parent kernel procedure stack frames from %px copyed to\n"
		 "childe stack %px, size 0x%llx\n",
		 (void *) (PSP_BASE(old_ti->k_psp) + parent_pshtp_size - ps_copy_size),
		 (void *) PSP_BASE(new_ti->k_psp), ps_copy_size);

	new_sw_regs->psp = set_psp_ind(new_ti->k_psp, ps_copy_size);
	child_stacks->pshtp.ind += PSP_IND_TO_PSHTP(ps_copy_size);
	child_stacks->psp = incr_psp_ind(child_stacks->psp, ps_copy_size);

	if (child_stacks->pshtp.ind) {
		child_stacks->pshtp.fx = 1;
		child_stacks->pshtp.fxind = 0x10;
	}

	return 0;
}

/**
 * *_copy_spilled_user_stacks - copy user's part of kernel hardware stacks
 * @child_stacks: copy of parent task registers
 */
void native_copy_spilled_user_stacks(struct e2k_stacks *child_stacks,
				     e2k_mem_crs_t *child_crs, struct sw_regs *new_sw_regs,
				     const struct thread_info *new_ti)
{
	const struct thread_info *old_ti = current_thread_info();
	s64 u_pshtp_size, u_pcshtp_size;
	unsigned long flags;

	u_pshtp_size = PSHTP_MEM_INDEX(child_stacks->pshtp);
	u_pcshtp_size = child_stacks->pcshtp.ind;
	DebugCPY("procedure stack size to copy (PSHTP) 0x%llx\n", u_pshtp_size);
	DebugCPY("chain stack size to copy (PCSHTP) 0x%llx\n", u_pcshtp_size);

	if (WARN_ON_ONCE(u_pshtp_size < 0 || u_pcshtp_size < 0))
		do_exit(SIGKILL);

	raw_all_irq_save(flags);
	COPY_STACKS_TO_MEMORY();
	tagged_memcpy_8((void *) PSP_BASE(new_ti->k_psp),
			(void *) PSP_BASE(old_ti->k_psp), u_pshtp_size);
	memcpy((void *) PCSP_BASE(new_ti->k_pcsp),
	       (void *) PCSP_BASE(old_ti->k_pcsp), u_pcshtp_size);
	raw_all_irq_restore(flags);
	DebugCPY("user's part of procedure stack copyed to %px from %px size 0x%llx\n",
		 (void *) PSP_BASE(new_ti->k_psp),
		 (void *) PSP_BASE(old_ti->k_psp), u_pshtp_size);
	DebugCPY("user's part of chain stack copyed to %px from %px size 0x%llx\n",
		 (void *) PCSP_BASE(new_ti->k_pcsp),
		 (void *) PCSP_BASE(old_ti->k_pcsp), u_pcshtp_size);

	new_sw_regs->psp = incr_psp_ind(new_sw_regs->psp, u_pshtp_size);
	new_sw_regs->pcsp = incr_pcsp_ind(new_sw_regs->pcsp, u_pcshtp_size);
	DebugCPY("procedure stack ind is now 0x%llx\n", PSP_IND(new_sw_regs->psp));
	DebugCPY("chain stack ind is now 0x%llx\n", PCSP_IND(new_sw_regs->pcsp));

	if (child_stacks->pshtp.ind) {
		child_stacks->pshtp.fx = 1;
		child_stacks->pshtp.fxind = 0x10;
	}
}

static int calculate_dstack_size(struct mm_struct *mm,
				 unsigned long *sp, unsigned long *stack_size)
{
	struct vm_area_struct *vma, *cur, *prev;
	u64 delta;

	mmap_read_lock(mm);
	vma = find_vma_prev(mm, *sp + *stack_size - 1, &prev);
	if (!vma || *sp + *stack_size <= vma->vm_start)
		goto out_efault;

	cur = vma;

	if (*stack_size) {
		MA_STATE(mas, &mm->mm_mt, prev->vm_start, prev->vm_start);

		/*
		 * Check passed area
		 */
		while (*sp < cur->vm_start) {
			if (!prev || cur->vm_start != prev->vm_end ||
			    ((cur->vm_flags ^ prev->vm_flags) & VM_GROWSDOWN))
				goto out_efault;

			cur = prev;
			prev = mas_prev(&mas, 0);
		}
	} else {
		/*
		 * We assume here that the stack area is contained
		 * in a single vma.
		 */
		*stack_size = *sp - cur->vm_start;
		*sp = cur->vm_start;
	}

	if (*stack_size > MAX_USD_SIZE) {
		delta = *stack_size - MAX_USD_SIZE;

		*sp += delta;
		*stack_size -= delta;
	}

	mmap_read_unlock(mm);

	/* Align the stack */

	delta = round_up(*sp, E2K_ALIGN_USTACK_BOUNDS) - *sp;
	*sp += delta;
	*stack_size -= delta;

	delta = *stack_size - round_down(*stack_size, E2K_ALIGN_USTACK_BOUNDS);
	*stack_size -= delta;

	if ((s64) *stack_size < 0)
		return -EINVAL;

	return 0;

out_efault:
	mmap_read_unlock(mm);

	return -EFAULT;
}

static int prepare_ret_from_fork(struct task_struct *new_task,
		const struct kernel_clone_args *args)
{
	struct sw_regs *new_sw_regs = &new_task->thread.sw_regs;
	u64 usd_size = USD_IND(new_sw_regs->usd);
	int ret;

	ret = chain_stack_frame_init(&new_sw_regs->crs, (unsigned long) __ret_from_fork,
		usd_size, 0, E2K_KERNEL_PSR_ENABLED,
		0, C_ABI_PSIZE(TASK_IS_PROTECTED(new_task)), false);
	if (ret)
		return ret;

	new_task->thread.clone.fn = args->fn;
	if (args->fn) {
		new_task->thread.clone.fn_arg = args->fn_arg;
		task_thread_info(new_task)->upsr = E2K_USER_INITIAL_UPSR;
	}

	return 0;
}

/*
 * Set a new TLS for the child thread.
 */
static void set_new_tls(struct global_gregs *g_gregs, unsigned long tls,
			const struct pt_regs *regs)
{
	if (!TASK_IS_PROTECTED(current)) {
		g_gregs->g[13].base = tls;
	} else {
		e2k_qreg_t tls = { .lo = regs->dargs[8], .hi = regs->dargs[9] };
		u32 tls_tag = (regs->tags >> (4 * 10)) & 0xff;

		if (regs->kernel_entry != 8) {
			pr_info_ratelimited("Unknown entry (%d) in tls copy\n",
					    regs->kernel_entry);
		}
		store_tagged_qword(&g_gregs->g[12].base, tls, tls_tag, 16);
	}
}

int copy_thread(struct task_struct *new_task, const struct kernel_clone_args *args)
{
	unsigned long clone_flags = args->flags;
	unsigned long sp = args->stack;
	unsigned long stack_size = args->stack_size;
	unsigned long tls = args->tls;
	struct thread_info *new_ti = task_thread_info(new_task);
	struct sw_regs *new_sw_regs = &new_task->thread.sw_regs;
	struct pt_regs *childregs, *regs = current_thread_info()->pt_regs;
	bool save_global_gregs = (args->fn == NULL);
	bool save_local_gregs = (args->fn == NULL && !(clone_flags & CLONE_VM));
	int ret;

	ktimes_account_copy_thread(new_ti);

	/* Initialize sw_regs with default values */
	set_default_registers(new_task, save_global_gregs, save_local_gregs);

	/* Set __ret_from_fork frame to be called right after __switch_to() */
	ret = prepare_ret_from_fork(new_task, args);
	if (ret)
		return ret;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	/*
	 * Set attributes for binary compiler
	 */
	if (TASK_IS_BINCO(current) && (current_thread_info()->bc_flags & BC_CHILD_IS_SERVING)) {
		new_ti->bc_flags |= BC_IS_SERVING | BC_CHILD_IS_SERVING;

		/* First serving thread should be moved to outer ns */
		if (!(current_thread_info()->bc_flags & BC_IS_SERVING))
			new_ti->bc_flags |= BC_IS_OUTMOST;
	}
#endif

	childregs = reserve_child_pt_regs(new_sw_regs, new_task);

	if (args->fn) {
		memset(childregs, 0, sizeof(*childregs));
		childregs->stacks.usd = new_sw_regs->usd;
		childregs->stacks.top = new_sw_regs->top;
		new_ti->pt_regs = childregs;
		return copy_kernel_stacks(new_task, (unsigned long) args->fn,
				(unsigned long) args->fn_arg);
	}

	*childregs = *regs;
	clear_fork_child_pt_regs(childregs);
	childregs->wd.psize_d = 2 * C_ABI_PSIZE(TASK_IS_PROTECTED(new_task));
	new_ti->pt_regs = childregs;

	if (clone_flags & CLONE_SETTLS)
		set_new_tls(&new_sw_regs->u_gregs, tls, regs);

	/*
	 * Update data stack if needed
	 */
	if (sp) {
		/* Generic code gives us the upper bound, convert to the lower bound */
		sp -= stack_size;

		if (TASK_IS_PROTECTED(new_task) && stack_size)
			set_ti_thread_flag(new_ti, TIF_USD_NOT_EXPANDED);

		ret = calculate_dstack_size(new_task->mm, &sp, &stack_size);
		if (ret)
			return ret;

		if (TASK_IS_PROTECTED(new_task) && !cpu_has(CPU_FEAT_V7_CPU_REGS)) {
			childregs->stacks.top = (sp + stack_size) & ~E2K_PROTECTED_STACK_BASE_MASK;
			childregs->stacks.usd = new_pusd(sp, stack_size, stack_size, 1);
		} else {
			childregs->stacks.top = sp + stack_size;
			childregs->stacks.usd =	new_usd(sp, stack_size, stack_size);
		}

		new_ti->u_stack.bottom = sp;
		new_ti->u_stack.top = sp + stack_size;
		new_ti->u_stack.size = stack_size;

		childregs->crs.cr1 = set_cr1_ussz(childregs->crs.cr1,
					(cpu_has(CPU_FEAT_V7_CPU_REGS)) ? 0 : stack_size);
	} else {
		/* We are executing on the same data stacks, so copy their info */
		ret = copy_getsp_adj(new_ti, current_thread_info());
		if (ret)
			return ret;
	}

	if (clone_flags & CLONE_VM) {
		/*
		 * User thread creation
		 */
		ret = create_user_hard_stacks(&new_ti->u_hw_stack, &childregs->stacks);
		if (ret)
			return ret;

		ret = clone_prepare_spilled_user_stacks(&childregs->stacks, &childregs->crs,
							regs, new_sw_regs, new_ti, clone_flags);
		if (ret)
			return ret;

		/*
		 * New thread will use different signal stack
		 */
		new_ti->signal_stack.base = NULL;
		new_ti->signal_stack.size = 0;
		new_ti->signal_stack.used = 0;

		childregs->rndpr = E2K_INITIAL_RNDPR;

		childregs->aasr = E2K_NULL_AASR;
	} else {
		/*
		 * User process creation
		 */
		ret = copy_spilled_user_stacks(&childregs->stacks, &childregs->crs,
					       new_sw_regs, new_ti);
		if (ret)
			return ret;

		ret = copy_old_u_pcs_list(new_ti, current_thread_info());
		if (ret)
			return ret;

		/*
		 * Stacks of the fork'ed process are located at the same address
		 */
		new_ti->u_hw_stack = current_thread_info()->u_hw_stack;
#ifdef CONFIG_PROTECTED_MODE
		/* Secure Computing execution mode: */
		new_task->mm->context.pm_sc_debug_mode = current->mm->context.pm_sc_debug_mode;
#endif
	}

	/*
	 * __ret_from_fork() does not restore user CR registers (because
	 * handle_sys_call() does not do it for performance reasons), so
	 * make sure they are FILLed by hardware.
	 */
	memcpy((void *) (PCSP_BASE(new_ti->k_pcsp) + PCSP_IND(new_sw_regs->pcsp)),
	       &childregs->crs, SZ_OF_CR);
	new_sw_regs->pcsp = incr_pcsp_ind(new_sw_regs->pcsp, SZ_OF_CR);

	return 0;
}

void native_deactivate_mm(struct task_struct *dead_task, struct mm_struct *mm)
{
	struct thread_info *ti = task_thread_info(dead_task);
	struct pt_regs *regs = ti->pt_regs;
	int ret;

	if (!mm)
		return;

	DebugEX("entered for task 0x%px %d [%s], mm 0x%px\n",
		dead_task, dead_task->pid, dead_task->comm, mm);
	BUG_ON(dead_task != current);

#if defined(CONFIG_E2K) && defined(CONFIG_PROTECTED_MODE)
	if (unlikely(ti->pm_robust_list.hi)) {
		pm_exit_robust_list(dead_task);
		ti->pm_robust_list.lo = 0;
		ti->pm_robust_list.hi = 0;
	}
#endif

	/*
	 * There may be coredump in progress
	 */
	if (regs) {
		do_user_hw_stacks_copy_full(&regs->stacks, regs, NULL);
		/* Also clear leftover user frames (as for why there
		 * are 2 of them see user_hw_stacks_copy_full()) */
		memset(current->stack + KERNEL_PC_STACK_OFFSET, 0, 2 * SZ_OF_CR);
	}

	/*
	 * Do not want any surprises from MLT later on.
	 */
	/* FIXME: MLT support is not yet implemented for guest kernel */
	if (!paravirt_enabled())
		invalidate_MLT();

	hw_context_deactivate_mm(dead_task);

	/*
	 * Clear pointers in pt_regs before dropping mappings (to avoid
	 * dangling pointers).  Keep ti->pt_regs intact because e.g.
	 * sys_strace can still access it for syscall return value.
	 */
	if (regs) {
		memset(&regs->stacks, 0, sizeof(regs->stacks));
		barrier();
	}

	/*
	 * Free user hardware stacks, as kernel created them and only kernel
	 * knows about them. We must free both physical and virtual memory.
	 */
	ret = free_user_hardware_stacks(&ti->u_hw_stack);
	if (ret) {
		pr_err("%s(): Could not free user hardware stacks, error %d\n",
		       __func__, ret);
		dump_stack();
	}

	free_signal_stack(&ti->signal_stack);

	DebugEX("successfully finished\n");
}

void release_thread(struct task_struct *dead_task)
{
	DebugP("is empty function for task %s pid %d\n",
	       dead_task->comm, dead_task->pid);
}

void exit_thread(struct task_struct *task)
{
	thread_info_t *ti = task_thread_info(task);

	DebugP("CPU#%d : started for %s pid %d, user data stack base 0x%lx\n",
	       smp_processor_id(), current->comm, current->pid,
	       ti->u_stack.bottom);

	free_getsp_adj(&ti->getsp_adj);

	if (task != current) {
		if (task->mm) {
			/* We don't have to free virtual memory if this was
			 * a fork (and we'd have to switch mm to do it). */
			if (task->mm != current->mm) {
				SET_PS_BASE(&ti->u_hw_stack, NULL);
				SET_PCS_BASE(&ti->u_hw_stack, NULL);
				return;
			}
			BUG_ON(current->mm != current->active_mm);

			/* It is possible that copy_process() failed after
			 * allocating stacks in copy_thread(). In this case
			 * we must free the allocated stacks. */
			free_user_hw_stacks(&ti->u_hw_stack);
		}

		return;
	}


#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	if (debug_process_name != NULL &&
	    !strncmp(current->comm, debug_process_name, debug_process_name_len)) {
		sys_e2k_print_kernel_times(current, ti->times,
					   ti->times_num, ti->times_index);
	}
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

	DebugP("exit_thread exited.\n");
}

void machine_restart(char * __unused)
{
	DebugP("machine_restart entered.\n");

	if (machine.restart != NULL)
		machine.restart(__unused);

	DebugP("machine_restart exited.\n");
}
EXPORT_SYMBOL(machine_restart);

void machine_halt(void)
{
	DebugP("machine_halt entered.\n");

	if (machine.halt != NULL)
		machine.halt();

	DebugP("machine_halt exited.\n");
}

void machine_power_off(void)
{
	DebugP("machine_power_off entered.\n");

	if (machine.power_off != NULL)
		machine.power_off();

	DebugP("machine_power_off exited.\n");
}

/*
 * We use this if we don't have any better
 * idle routine..
 */
void native_default_idle(void)
{
	/* Using interceptable wait by default even before cpuidle
	 * initialization speeds up virtual machine boot on highly
	 * loaded servers by avoiding meaningless hogging of CPUs
	 * with idle loops. */
	C1_enter_v3();
	local_irq_enable();
}
EXPORT_SYMBOL(native_default_idle);

void arch_cpu_idle_enter(void)
{
	/* It works under CONFIG_E2K_PROFILING flag only */
	cpu_idle_time();
}

void arch_cpu_idle_exit(void)
{
	/* It works under CONFIG_E2K_PROFILING flag only */
	calculate_cpu_idle_time();
}

void arch_cpu_idle(void)
{
	default_idle();
}

void flush_thread(void)
{
	DebugP("flush_thread entered.\n");

	NATIVE_SET_GREGS_EMPTY(true, false);
	memset(&current->thread.u_gregs.g, 0, sizeof(current->thread.u_gregs.g));
	current->thread.u_gregs.bgr = E2K_INITIAL_BGR;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	current_thread_info()->last_ic_flush_cpu = -1;
#endif
	flush_ptrace_hw_breakpoint(current);

	/* Disable preemption to work with per-cpu variables in native_clear_user_only_regs() */
	preempt_disable();
	native_clear_user_only_regs();
	preempt_enable();

	set_max_u_border();

	DebugP("flush_thread exited.\n");
}

int dump_fpu(struct pt_regs *regs, elf_fpregset_t *fpu)
{
	return 0;
}


/*
 *		For coredump
 *
 *	The threads can't free hw_stacks because coredump will
 *	used those stacks and
 *	the threads must free pc & p stacks after finish_coredump
 *	struct delayed_hw_stack is used to create delayed free hw_stacks
 *
 *	core_state->delay_free_stacks -> list of struct delayed_hw_stack
 *	for all threads
 */
struct delayed_hw_stack {
	struct list_head list_entry;
	hw_stack_t hw_stacks;	/* hardware stacks state */
};

void clear_delayed_free_hw_stacks(void)
{
	struct core_state *core_state = current->signal->core_state;
	struct delayed_hw_stack *delayed_hw_stack, *n;
	mm_context_t *context = &current->mm->context;

	DebugCD(" %s  beginn pid=%d core_state=%px mm=%px context=%px\n",
			__func__, current->pid, core_state, current->mm, context);
	if (!core_state) {
		return;
	}

	down_write(&context->core_lock);
	list_for_each_entry_safe(delayed_hw_stack, n,
				 &context->delay_free_stacks, list_entry) {
		__list_del_entry(&delayed_hw_stack->list_entry);
		free_user_hw_stacks(&delayed_hw_stack->hw_stacks);
		kfree(delayed_hw_stack);
	}
	up_write(&context->core_lock);
}

void create_delayed_free_hw_stacks(void)
{
	struct core_state *core_state = current->signal->core_state;
	mm_context_t *context = &current->mm->context;
	struct delayed_hw_stack *delayed_hw_stack;
	thread_info_t *ti = task_thread_info(current);

	DebugCD("begin core_state=%px\n", core_state);

	if (!core_state) {
		return;
	}

	delayed_hw_stack = kmalloc(sizeof(struct delayed_hw_stack), GFP_KERNEL);
	BUG_ON(delayed_hw_stack == NULL);

	/* copy lists */
	INIT_LIST_HEAD(&delayed_hw_stack->list_entry);
	delayed_hw_stack->hw_stacks = ti->u_hw_stack;

	down_write(&context->core_lock);
	list_add_tail(&delayed_hw_stack->list_entry,
		      &context->delay_free_stacks);
	up_write(&context->core_lock);
}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static __always_inline void flush_ic_on_switch(void)
{
	struct thread_info *ti = current_thread_info();
	int cpu = raw_smp_processor_id();

	if (unlikely(ti->last_ic_flush_cpu >= 0 &&
		     ti->last_ic_flush_cpu != cpu)) {
		ti->last_ic_flush_cpu = cpu;
		__flush_icache_all();
	}
}
#else
static __always_inline void flush_ic_on_switch(void) { }
#endif

/*
 * Tricks for __switch_to(), sys_clone(), sys_fork().
 * When we switch_to() to a new kernel thread or a forked process,
 * it works as follows:
 *
 * 1. __schedule() calls switch_to() (which is defined to __switch_to()
 * and is inlined) for the new task.
 *
 * 2. __switch_to() does E2K_FLUSHCPU and saves and sets the new stacks regs.
 *
 * 3. When __switch_to() returns there will be a FILL operation
 * and __schedule() window for a next process will be loaded into
 * register file.
 *
 * 4. When creating a new thread/process, __ret_from_fork() window
 * will be FILLed instead.
 *
 * 5. Return value of system call in child will be that of __ret_from_fork().
 */
notrace noinline
__interrupt /* just to have USFS == 0 for v7 when real switch */
struct task_struct *__sched __switch_to(struct task_struct *prev,
				    struct task_struct *next)
{
#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
	const pgd_t *current_k_pgd = NULL;
	int node = numa_node_id();
#endif

	/* Save interrupt mask state and disable NMIs */
	SAVE_IRQ_AND_ALL_CLI(AW(prev->thread.sw_regs.psr),
			     AW(prev->thread.sw_regs.upsr));

	NATIVE_SAVE_TASK_REGS_TO_SWITCH(prev);

	native_set_current_thread_info(task_thread_info(next), next);
#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
	if (!MMU_IS_SEPARATE_PT()) {
		current_k_pgd = mm_node_pgd(&init_mm, node);
	}
#endif

	NATIVE_RESTORE_TASK_REGS_TO_SWITCH(next, prev->mm == next->mm);
#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
	if (!MMU_IS_SEPARATE_PT()) {
		/* Update k_root_ptb in case [next] migrated to current NUMA
		 * node from another node that uses different mm_node_pgd().
		 * Also this initializes it for newly forked tasks. */
		next->thread.regs.k_root_ptb = __pa(current_k_pgd);
	}
#endif

	flush_ic_on_switch();

	/* Restore interrupt mask and enable NMIs */
	RESTORE_IRQ_REG(AW(next->thread.sw_regs.psr),
			AW(next->thread.sw_regs.upsr));

	return prev;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}

int find_cui_by_ip(unsigned long ip)
{
	struct mm_struct *mm = current->mm;
	e2k_cute_t __priv *cut = (e2k_cute_t __priv *) USER_CUT_AREA_BASE;
	int i, cui = -ESRCH;

	ip &= E2K_VA_MASK; /* we need only address part of ip over here */

	if (!TASK_IS_PROTECTED(current) || is_trampoline(mm, ip))
		return USER_CODES_UNPROT_INDEX(current);

	down_write(&mm->context.cut_mask_lock);

	for_each_set_bit(i, mm->context.cut_mask,
			 USER_CUT_AREA_SIZE / sizeof(e2k_cute_t)) {
		e2k_cute_t cute;

		if (get_priv(cute.cud.lo, &cut[i].cud.lo) ||
		    get_priv(cute.cud.hi, &cut[i].cud.hi)) {
			cui = -EFAULT;
			break;
		}

		if (ip >= CUD_BASE(cute.cud) && ip < CUD_BASE(cute.cud) + CUD_SIZE(cute.cud)) {
			cui = i;
			DebugCUI("found cui=%d: ip=0x%lx cud_base=0x%llx cud_size=0x%llx\n",
				i, ip, CUD_BASE(cute.cud), CUD_SIZE(cute.cud));
			break;
		}
		DebugCUI("cui<>%d: ip=0x%lx cud_base=0x%llx cud_size=0x%llx\n",
			i, ip, CUD_BASE(cute.cud), CUD_SIZE(cute.cud));
	}

	up_write(&mm->context.cut_mask_lock);

	return cui;
}

SYSCALL_DEFINE5(arch_prctl, int, option,
		unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)
{
	long error;

	error = security_task_prctl(option, arg2, arg3, arg4, arg5);
	if (error != -ENOSYS)
		return error;

	error = 0;
	switch (option) {
#ifdef CONFIG_PROTECTED_MODE
		/* returns PM debug mode status: */
	case PR_PM_DBG_MODE_GET:
		error = current->mm->context.pm_sc_debug_mode;
		break;
		/* resets PM debug mode status and returns previous status: */
	case PR_PM_DBG_MODE_RESET:
		error = current->mm->context.pm_sc_debug_mode;
		current->mm->context.pm_sc_debug_mode = get_sysctld_default_syscall_debug_mode();
		break;
		/* sets PM debug mode status and returns previous status: */
	case PR_PM_DBG_MODE_SET:
		error = current->mm->context.pm_sc_debug_mode;
		current->mm->context.pm_sc_debug_mode = arg2;
		/* RM-18187 */
		if ((current->mm->context.pm_sc_debug_mode & PM_MM_FREE_PTR_MODE_MASK) == 0)
			current->mm->context.pm_sc_debug_mode |= PM_MM_DEFAULT_FREE_PTR_MODE;
		/* RM-18187 */
		break;
	case PR_PM_DBG_MODE_ADD:
		error = current->mm->context.pm_sc_debug_mode;
		current->mm->context.pm_sc_debug_mode |= arg2;
		break;
	case PR_PM_DBG_MODE_DEL:
		error = current->mm->context.pm_sc_debug_mode;
		current->mm->context.pm_sc_debug_mode &= ~arg2;
		/* RM-18187 */
		if ((current->mm->context.pm_sc_debug_mode & PM_MM_FREE_PTR_MODE_MASK) == 0)
			current->mm->context.pm_sc_debug_mode |= PM_MM_DEFAULT_FREE_PTR_MODE;
		/* RM-18187 */
		break;
#endif /* CONFIG_PROTECTED_MODE */
	default:
#ifdef CONFIG_PROTECTED_MODE
		if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK)
			pr_err("Unknown option 0x%x in 'arch_prctl' syscall\n",
			       option);
#endif /* CONFIG_PROTECTED_MODE */
		error = -EINVAL;
		break;
	}
	return error;
}

/**
 * chain_stack_frame_init - initialize chain stack frame for current
 *			    task from provided parameters
 * @crs: frame to initialize
 * @fn_ptr: IP to return to
 * @dstack_free_size: free size of data stack _after_ return
 * @dstack_frame_size: frame size in data stack _after_ return
 * @wbs: cr1_lo.wbs value
 * @wpsz: cr1_lo.wpsz value
 * @user: execute in user or kernel mode
 *
 * We could try to deduce @user and cui from @fn_ptr by comparing it
 * to TASK_SIZE but we must not: if user controls @fn_ptr value then
 * this would be a security hole.
 */
int chain_stack_frame_init(e2k_mem_crs_t *crs, unsigned long fn,
			   size_t dstack_free_size, size_t dstack_frame_size,
			   e2k_psr_t psr, int wbs, int wpsz, bool user)
{
	if (user && psr.pm)
		return -EPERM;

	memset(crs, 0, sizeof(*crs));

	set_cr0_ip(crs->cr0, fn);
	crs->cr1.psr = psr.all;
	crs->cr1.wbs = wbs;
	crs->cr1.wpsz = wpsz;
	crs->cr1 = set_cr1_ussz(crs->cr1, (cpu_has(CPU_FEAT_V7_CPU_REGS)) ?
					  dstack_frame_size : dstack_free_size);

	if (user) {
		int cui = find_cui_by_ip(fn);
		if (cui < 0)
			return cui;
		crs->cr1.cui = cui;
		if (!cpu_has(CPU_FEAT_ISET_V6))
			crs->cr1.ic = 0;
	} else {
		crs->cr1.cui = KERNEL_CODES_INDEX;
		if (!cpu_has(CPU_FEAT_ISET_V6))
			crs->cr1.ic = 1;
	}

	return 0;
}

#ifdef CONFIG_PREEMPT_RT
static int __init e2k_idle_init(void)
{
	cpu_idle_poll_ctrl(true);
	return 0;
}
arch_initcall(e2k_idle_init);
#endif

void arch_setup_new_exec(void)
{
	write_OSEM_reg_value(osem_calculate(false, TASK_IS_PROTECTED(current)));
	clear_thread_flag(TIF_USD_NOT_EXPANDED);
}

#ifdef CONFIG_SOFTIRQ_ON_OWN_STACK
static DEFINE_PER_CPU(void *, softirq_stack_ptr);

int irq_init_percpu_irqstack(unsigned int cpu)
{
	if (per_cpu(softirq_stack_ptr, cpu))
		return 0;

	void *address = alloc_pages_exact_nid(cpu_to_node(cpu), THREAD_SIZE,
				     GFP_KERNEL_ACCOUNT | __GFP_RETRY_MAYFAIL);
	if (!address)
		return -ENOMEM;

	if (cpu_has(CPU_HWBUG_FALSE_SS))
		clean_pc_stack_zero_frame_kernel(address + KERNEL_PC_STACK_OFFSET);

	per_cpu(softirq_stack_ptr, cpu) = address;

	return 0;
}

void do_softirq_own_stack(void)
{
	unsigned long flags;
	struct e2k_stack prev_stacks, next_stacks;

	unsigned long base = (unsigned long) __this_cpu_read(softirq_stack_ptr);
	if (unlikely(WARN_ON_ONCE(!base))) {
		__do_softirq();
		return;
	}

	raw_all_irq_save(flags);
	NATIVE_FLUSHCPU;

	prev_stacks.top = AW(native_read_SBR_reg());
	prev_stacks.usd = native_read_USD_reg();
	prev_stacks.psp = native_read_PSP_reg();
	prev_stacks.pcsp = native_read_PCSP_reg();
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		prev_stacks.usd = incr_usd_ind(prev_stacks.usd, read_USFS_reg());
	}
	raw_all_irq_restore(flags);

	/* Trap for warning in __parse_chain_stack() */
	u64 pcs_ind = PCSP_IND(prev_stacks.pcsp);
	struct pt_regs *regs = current_pt_regs();
	unsigned long spilled_to_kernel = (regs) ? regs->stacks.pcshtp.ind
						 : min_t(u64, pcs_ind, SZ_OF_CR);
	WARN_ON_ONCE(spilled_to_kernel > pcs_ind);

	raw_all_irq_save(flags);
	NATIVE_FLUSHCPU;

	next_stacks.pcsp = new_pcsp(base + KERNEL_PC_STACK_OFFSET,
				    KERNEL_PC_STACK_SIZE, 0);
	next_stacks.psp = new_psp(base + KERNEL_P_STACK_OFFSET,
				  KERNEL_P_STACK_SIZE, 0);
	next_stacks.top = base + KERNEL_C_STACK_OFFSET + KERNEL_C_STACK_SIZE;
	next_stacks.usd = new_usd(base + KERNEL_C_STACK_OFFSET,
				  KERNEL_C_STACK_SIZE, KERNEL_C_STACK_SIZE);

	native_write_stacks(next_stacks.psp, next_stacks.pcsp,
			    next_stacks.usd, TOS(e2k_sbr_t, next_stacks.top));

	current->thread.before_softirq = prev_stacks;
	current->thread.on_softirq_stack = true;
	raw_all_irq_restore(flags);

	__do_softirq();

	raw_all_irq_save(flags);
	native_write_stacks(prev_stacks.psp, prev_stacks.pcsp,
			    prev_stacks.usd, TOS(e2k_sbr_t, prev_stacks.top));
	current->thread.on_softirq_stack = false;
	raw_all_irq_restore(flags);
}
NOKPROBE_SYMBOL(do_softirq_own_stack);
#endif /* CONFIG_SOFTIRQ_ON_OWN_STACK */
