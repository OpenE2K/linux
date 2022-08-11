/*
 *  arch/e2k/kernel/process.c
 *
 * This file handles the arch-dependent parts of process handling
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/compat.h>
#include <linux/context_tracking.h>
#include <linux/types.h>
#include <linux/elf.h>
#include <linux/ftrace.h>
#include <linux/hw_breakpoint.h>
#include <linux/jhash.h>
#include <linux/rmap.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>
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
#include <linux/sched/idle.h>
#include <linux/security.h>
#include <linux/mmu_context.h>
#include <linux/sched/mm.h>

#include <trace/events/power.h>

#include <asm/atomic.h>
#include <asm/coredump.h>
#include <asm/cpu.h>
#include <asm/getsp_adj.h>
#include <asm/process.h>
#include <asm/copy-hw-stacks.h>
#include <asm/a.out.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/regs_state.h>
#include <asm/hw_stacks.h>
#include <asm/p2v/boot_init.h>
#include <asm/e2k_debug.h>
#include <asm/ucontext.h>
#include <asm/switch_to.h>
#include <asm/trap_table.h>
#include <asm/mmu.h>

#ifdef CONFIG_MONITORS
#include <asm/monitors.h>
#endif /* CONFIG_MONITORS */

#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#include <asm/e2k_ptypes.h>
#include <asm/prot_loader.h>
#endif /* CONFIG_PROTECTED_MODE */

#include <../../../kernel/time/tick-sched.h>


#undef	DEBUG_PROCESS_MODE
#undef	DebugP
#define	DEBUG_PROCESS_MODE	0	/* processes */
#define DebugP(...)	DebugPrint(DEBUG_PROCESS_MODE, ##__VA_ARGS__)

#undef	DEBUG_QUEUED_TASK_MODE
#undef	DebugQT
#define	DEBUG_QUEUED_TASK_MODE	0	/* queue task and release */
#define DebugQT(...)	DebugPrint(DEBUG_QUEUED_TASK_MODE, ##__VA_ARGS__)

#undef	DEBUG_QUEUED_STACK_MODE
#undef	DebugQS
#define	DEBUG_QUEUED_STACK_MODE	0	/* queue stck and release */
#define DebugQS(...)	DebugPrint(DEBUG_QUEUED_STACK_MODE, ##__VA_ARGS__)

#undef	DEBUG_EXECVE_MODE
#undef	DebugEX
#define	DEBUG_EXECVE_MODE	0	/* execve and exit */
#define DebugEX(...)	DebugPrint(DEBUG_EXECVE_MODE, ##__VA_ARGS__)

#undef	DEBUG_GUEST_EXEC_MODE
#undef	DebugGEX
#define DEBUG_GUEST_EXEC_MODE	0	/* guest execve debugging */
#define DebugGEX(...)	DebugPrint(DEBUG_GUEST_EXEC_MODE, ##__VA_ARGS__)

#undef	DEBUG_DATA_STACK_MODE
#undef	DebugDS
#define	DEBUG_DATA_STACK_MODE	0	/* user data stack */
#define DebugDS(...)	DebugPrint(DEBUG_DATA_STACK_MODE, ##__VA_ARGS__)

#undef	DEBUG_CU_MODE
#undef	DebugCU
#define	DEBUG_CU_MODE		0	/* compilation unit */
#define DebugCU(...)		DebugPrint(DEBUG_CU_MODE, ##__VA_ARGS__)

#undef	DEBUG_US_MODE
#undef	DebugUS
#define	DEBUG_US_MODE		0	/* user stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_MODE, ##__VA_ARGS__)

#undef	DEBUG_KS_MODE
#undef	DebugKS
#define	DEBUG_KS_MODE		0	/* kernel stacks */
#define DebugKS(...)		DebugPrint(DEBUG_KS_MODE, ##__VA_ARGS__)

#undef	DEBUG_US_FRAMES_MODE
#undef	DebugUSF
#define	DEBUG_US_FRAMES_MODE	0	/* user stack frames */
#define DebugUSF(...)		DebugPrint(DEBUG_US_FRAMES_MODE, ##__VA_ARGS__)

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Hard Stack Clone and Alloc */
#define	DebugHS(...)		DebugPrint(DEBUG_HS_MODE, ##__VA_ARGS__)

#undef	DEBUG_SPRs_MODE
#define	DEBUG_SPRs_MODE		0	/* stack pointers registers */

#undef	DEBUG_COPY_USER_MODE
#undef	DebugCPY
#define	DEBUG_COPY_USER_MODE	0	/* KVM process copy debug */
#define	DebugCPY(fmt, args...)						\
({									\
	if (DEBUG_COPY_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

extern bool debug_clone_guest;
#undef	DEBUG_CLONE_USER_MODE
#undef	DebugCLN
#define	DEBUG_CLONE_USER_MODE	0	/* KVM thread clone debug */
#define	DebugCLN(fmt, args...)						\
({									\
	if (DEBUG_CLONE_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_CpuR_MODE
#define	DEBUG_CpuR_MODE		0	/* CPU registers */

#undef	DEBUG_CORE_DUMP
#undef	DebugCD
#define	DEBUG_CORE_DUMP		0	/* coredump */
#define DebugCD(...)		DebugPrint(DEBUG_CORE_DUMP, ##__VA_ARGS__)


struct user_stack_free_work {
	unsigned long		stack_base;
	e2k_size_t		max_stack_size;
	struct mm_struct	*mm;
	struct delayed_work	work;
};


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
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

bool idle_nomwait = false;
static int __init mem_wait_idle_setup(char *str)
{
	if (strcmp(str, "nomwait") == 0) {
		/* disable memory wait type idle */
		idle_nomwait = true;
		pr_info("Disable memory wait type idle\n");
	} else {
		pr_warning("Unknown command line idle= arg %s, can be 'nomwait'\n",
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
	return NULL;
}

static void clean_pc_stack_zero_frame(void *addr, bool user)
{
	unsigned long ts_flag;
	e2k_mem_crs_t *pcs = addr;

	if (user)
		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	__clear_user(pcs, sizeof(*pcs));
	if (user)
		clear_ts_flag(ts_flag);
}

unsigned long *__alloc_thread_stack_node(int node)
{
	void *address;
	struct page *page;

	//TODO when arch-indep. part is fixed switch back to
	//alloc_pages_exact_nid() instead to not waste memory.
	page = alloc_pages_node(node,
			GFP_KERNEL_ACCOUNT | __GFP_NORETRY | __GFP_NOWARN,
			THREAD_SIZE_ORDER);
	address = (page) ? page_address(page) : NULL;
#ifdef CONFIG_VMAP_STACK
	if (!address)
		address = __vmalloc_node_range(THREAD_SIZE, THREAD_ALIGN,
				VMALLOC_START, VMALLOC_END, GFP_KERNEL_ACCOUNT,
				PAGE_KERNEL, 0, node,
				__builtin_return_address(0));
#endif

	if (cpu_has(CPU_HWBUG_FALSE_SS) && address)
		clean_pc_stack_zero_frame(address + KERNEL_PC_STACK_OFFSET, false);

	return address;
}


unsigned long *alloc_thread_stack_node(struct task_struct *task, int node)
{
	unsigned long *stack = __alloc_thread_stack_node(node);
	task->stack = stack;
#ifdef CONFIG_VMAP_STACK
	task->stack_vm_area = find_vm_area(stack);
#endif
	return stack;
}

void __free_thread_stack(void *address)
{
#ifdef CONFIG_VMAP_STACK
	if (!is_vmalloc_addr(address))
		__free_pages(virt_to_page(address), THREAD_SIZE_ORDER);
	else
		vfree(address);
#else
	free_pages_exact(address, THREAD_SIZE);
#endif
}

void free_thread_stack(struct task_struct *task)
{
	struct thread_info *ti = task_thread_info(task);

	if (!task->stack)
		return;

	AW(ti->k_psp_lo) = 0;
	AW(ti->k_psp_hi) = 0;
	AW(ti->k_pcsp_lo) = 0;
	AW(ti->k_pcsp_hi) = 0;
	AW(ti->k_usd_lo) = 0;
	AW(ti->k_usd_hi) = 0;

	__free_thread_stack(task->stack);
	task->stack = NULL;
#ifdef CONFIG_VMAP_STACK
	task->stack_vm_area = NULL;
#endif
}

int free_vm_stack_cache(unsigned int cpu)
{
	return 0;
}

static void user_stack_free_work_fn(struct work_struct *work)
{
	struct user_stack_free_work *w;
	unsigned long stack_base;
	e2k_size_t max_stack_size;
	struct mm_struct *mm;
	int ret;

	w = container_of(to_delayed_work(work), typeof(*w), work);
	stack_base = w->stack_base;
	max_stack_size = w->max_stack_size;
	mm = w->mm;

	use_mm(mm);
	ret = vm_munmap_notkillable(stack_base, max_stack_size);
	DebugHS("stack base 0x%lx max stack size 0x%lx, munmap returned %d\n",
		stack_base, max_stack_size, ret);
	unuse_mm(mm);

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

static void free_user_stack(void *stack_base, e2k_size_t max_stack_size)
{
	int ret;

	ret = vm_munmap_notkillable((unsigned long) stack_base, max_stack_size);
	DebugHS("stack base 0x%llx max stack size 0x%lx, munmap returned %d\n",
			(u64) stack_base, max_stack_size, ret);
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

static void *alloc_user_hard_stack(size_t stack_size,
		unsigned long user_stacks_base, int type)
{
	e2k_addr_t		stack_addr;
	struct thread_info	*ti = current_thread_info();
	hw_stack_t		*u_hw_stacks = &ti->u_hw_stack;
	e2k_addr_t		u_ps_base;
	e2k_addr_t		u_pcs_base;
	unsigned long		ti_status;

	BUG_ON(!IS_ALIGNED(stack_size, PAGE_SIZE) || !current->mm);

	/*
	 * In the case of pseudo discontinuous user hardware stacks one
	 * shouldn't reuse already freed memory of user hardware stacks,
	 * otherwise there will be a problem with longjmp (we won't be
	 * able to find needed area unambiguously).
	 */
	if (GET_PS_BASE(u_hw_stacks)) {
		u_ps_base = (e2k_addr_t)GET_PS_BASE(u_hw_stacks);
		user_stacks_base = max(user_stacks_base, u_ps_base);
	}

	if (GET_PCS_BASE(u_hw_stacks)) {
		u_pcs_base = (e2k_addr_t)GET_PCS_BASE(u_hw_stacks);
		user_stacks_base = max(user_stacks_base, u_pcs_base);
	}

	ti_status = (type == HW_STACK_TYPE_PS) ? TS_MMAP_PS : TS_MMAP_PCS;
	ti_status |= TS_MMAP_PRIVILEGED;

	current_thread_info()->status |= ti_status;
	stack_addr = vm_mmap_notkillable(NULL, user_stacks_base, stack_size,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
	current_thread_info()->status &= ~ti_status;

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

	return (void *) stack_addr;

out_unmap:
	vm_munmap_notkillable(stack_addr, stack_size);
	return NULL;
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

	if (cpu_has(CPU_HWBUG_FALSE_SS))
		clean_pc_stack_zero_frame(pcs->base, true);

	set_hw_pcs_area_user_size(pcs, stack_area_size);
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

struct cached_stacks_entry {
	hw_stack_t stack;
	/* Entry in mm_context_t->cached_stacks */
	struct list_head list_entry;
};

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

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, sp);
	DebugDS("find_vma() returned VMA 0x%px start 0x%lx end 0x%lx\n",
		vma, vma->vm_start, vma->vm_end);

	BUG_ON(!(vma->vm_flags & VM_GROWSDOWN));

	*stack_top = vma->vm_end;
	stack_start = vma->vm_start;

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
	if (make_vma_pages_valid(vma, vma->vm_start, vma->vm_end)) {
		DebugDS("make valid failed\n");
		return 0;
	}
#endif

	up_read(&current->mm->mmap_sem);

	DebugDS("returns stack base 0x%lx\n", stack_start);
	return stack_start;
}

/*
 * This function allocates user's memory for needs of Compilation Unit Table.
 */

static int create_cu_table(struct mm_struct *mm, unsigned long *cut_size_p,
		int *cui_p)
{
	unsigned long cut_start, cut_size = USER_CUT_AREA_SIZE;
	int cui;

	DebugCU("started: cut base 0x%lx, size 0x%lx\n",
			USER_CUT_AREA_BASE, cut_size);

	set_ts_flag(TS_MMAP_PRIVILEGED);
	cut_start = vm_mmap_notkillable(NULL, USER_CUT_AREA_BASE, cut_size,
			PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0);
	clear_ts_flag(TS_MMAP_PRIVILEGED);
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
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t 	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t 	pcsp_hi;
	int ret;

	ret = alloc_user_hw_stacks(hw_stacks, user_psp_size, user_pcsp_size);
	if (ret)
		return ret;

	DebugCLN("allocated user Procedure stack at %px, size 0x%lx, Chain stack at %px, size 0x%lx\n",
			hw_stacks->ps.base, user_psp_size,
			hw_stacks->pcs.base, user_pcsp_size);

	AW(psp_lo) = 0;
	AW(psp_hi) = 0;
	AW(pcsp_lo) = 0;
	AW(pcsp_hi) = 0;

	AS(psp_lo).base = (unsigned long) GET_PS_BASE(hw_stacks);
	AS(psp_hi).size = user_psp_size;
	AS(pcsp_lo).base = (unsigned long) GET_PCS_BASE(hw_stacks);
	AS(pcsp_hi).size = user_pcsp_size;

	stacks->psp_lo = psp_lo;
	stacks->psp_hi = psp_hi;
	stacks->pcsp_lo = pcsp_lo;
	stacks->pcsp_hi = pcsp_hi;
	AW(stacks->pshtp) = 0;
	stacks->pcshtp = 0;

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

static int check_wchan(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, int flags, void *arg)
{
	unsigned long *p_ip = arg;
	unsigned long ip;

	ip = AS(frame->cr0_hi).ip << 3;

	if (!in_sched_functions(ip)) {
		*p_ip = ip;
		return 1;
	}

	return 0;
}

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long ip = 0;

	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;

	parse_chain_stack(0, p, check_wchan, &ip);

	return ip;
}

int free_user_hardware_stacks(hw_stack_t *u_hw_stacks)
{
	thread_info_t	*ti = current_thread_info();

	free_user_old_pc_stack_areas(&ti->old_u_pcs_list);
	DebugEX("freed user old PCS list head 0x%px\n",
		&ti->old_u_pcs_list);

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
	if (current->mm->core_state) {
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

static inline void
native_goto_new_user_hard_stk(e2k_stacks_t *stacks)
{
	unsigned long flags;

	DebugEX("will switch stacks\n");

	raw_all_irq_save(flags);

	/*
	 * Optimization to do not flush chain stack.
	 *
	 * Old stacks are not needed anymore, do not flush procedure
	 * registers and chain registers - only strip sizes
 	 */
	STRIP_PSHTP_WINDOW();
	STRIP_PCSHTP_WINDOW();

	/*
	 * There might be a FILL operation still going right now.
	 * Wait for it's completion before going further - otherwise
	 * the next FILL on the new PSP/PCSP registers will race
	 * with the previous one.
	 *
	 * The first and the second FILL operations will use different
	 * addresses because we will change PSP/PCSP registers, and
	 * thus loads/stores from these two FILLs can race with each
	 * other leading to bad register file (containing values from
	 * both stacks).
	 */
	E2K_WAIT(_ma_c);

	/*
	 * Since we are switching to user stacks their sizes
	 * have been stripped already, so use RAW_* writes.
	 */
	NATIVE_NV_WRITE_PSP_REG(stacks->psp_hi, stacks->psp_lo);
	NATIVE_NV_WRITE_PCSP_REG(stacks->pcsp_hi, stacks->pcsp_lo);

	raw_all_irq_restore(flags);
}

#define printk printk_fixed_args
#define panic panic_fixed_args
__section(".entry.text")
notrace noinline __interrupt void
do_switch_to_user_func(start_fn start_func, e2k_size_t us_size, int cui)
{
	e2k_cr0_hi_t 	cr_ip;
	e2k_cr1_lo_t	cr1_lo;
	e2k_cr1_hi_t 	cr_ussz;
	e2k_psr_t	psr;
#ifdef	CONFIG_PROTECTED_MODE
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_pusd_lo_t	pusd_lo;
	e2k_pusd_hi_t	pusd_hi;
	e2k_usbr_t	u_sbr;
#endif	/* CONFIG_PROTECTED_MODE */

	DebugCU("func = 0x%016lx\n", *((long *)start_func));
	DebugP("entered: func 0x%px\n", start_func);
	DebugSPRs("start");

	cr_ip = NATIVE_NV_READ_CR0_HI_REG();
	cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	cr_ussz = NATIVE_NV_READ_CR1_HI_REG();

	/*
	 * Go to down to sys_exec() procedure chain stack using PSCP info
	 * And get 'ussz' field of 'sys_exec()' function to restore
	 * user stack state before 'switch_to_user_func()' call
	 */
	AS_STRUCT(cr_ussz).ussz = us_size >> 4;

	AS_WORD(psr) = 0;
	AS_STRUCT(psr).sge = 1;
	AS_STRUCT(psr).ie = 1;			/* sti(); */
	AS_STRUCT(psr).nmie = 1;		/* nmi enable */
	AS_STRUCT(psr).pm = 0;			/* user mode */
	AS_STRUCT(cr1_lo).psr = AS_WORD(psr);
	AS_STRUCT(cr_ip).ip = (u64)start_func >> 3;	/* start user IP */

	/*
	 * Force CUD/GD/TSD update by the values stored in CUTE
	 * Entry #1 - for both 32bit and protected mode
	 */
	AS(cr1_lo).cui = cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		AS(cr1_lo).ic = 0;

	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(cr_ussz);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr_ip);

#ifdef CONFIG_CLI_CHECK_TIME
	sti_return();
#endif

#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		usd_hi = NATIVE_NV_READ_USD_HI_REG();
		usd_lo = NATIVE_NV_READ_USD_LO_REG();

		AW(u_sbr) = AS_STRUCT(usd_lo).base &
				~E2K_PROTECTED_STACK_BASE_MASK;

		AW(pusd_lo) = 0;
		AW(pusd_hi) = 0;
		AS_STRUCT(pusd_lo).base = AS_STRUCT(usd_lo).base &
						E2K_PROTECTED_STACK_BASE_MASK;
		AS_STRUCT(pusd_lo).base &= ~E2K_ALIGN_PUSTACK_MASK;
		AS_STRUCT(pusd_lo).p = 1;
		AS_STRUCT(pusd_hi).size = AS_STRUCT(usd_hi).size &
						~E2K_ALIGN_PUSTACK_MASK;
		AS_STRUCT(pusd_lo).psl = 2;
		AS_STRUCT(pusd_lo).rw = RW_ENABLE;

		NATIVE_NV_WRITE_USBR_USD_REG(u_sbr, pusd_hi, pusd_lo);
		ENABLE_US_CLW();
	} else {
		DISABLE_US_CLW();
	}
#endif /* CONFIG_PROTECTED_MODE */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	if (current_thread_info()->pt_regs) {
		E2K_SAVE_CLOCK_REG(current_thread_info()->pt_regs->
						scall_times->scall_done);
		E2K_SAVE_CLOCK_REG(current_thread_info()->pt_regs->
				scall_times->end);
	}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */


	/* Set global registers to empty state to prevent other user */
	/* or kernel current pointers access */
	INIT_G_REGS();


	/*
	 * User function will be executed under PSR interrupts control
	 * and kernel should return interrupts mask control to PSR register
	 * The follow function should do it
	 */
	complete_switch_to_user_func();

	/* Prevent kernel information leakage. 4 quadro registers
	 * already contain user's parameters.*/
#ifndef CONFIG_CPU_HW_CLEAR_RF
# if E2K_MAXSR != 112
#  error Must clear all registers here
# endif
	E2K_CLEAR_RF_108();
#endif
}
#undef printk
#undef panic

void  fill_cut_entry(e2k_cute_t *cute_p,
		unsigned long code_base, unsigned  code_sz,
		unsigned long glob_base, unsigned  glob_sz)
{
	CUTE_CUD_BASE(cute_p) = code_base;
	CUTE_CUD_SIZE(cute_p) =
		ALIGN_TO_MASK(code_sz, E2K_ALIGN_CODES_MASK);
	CUTE_CUD_C(cute_p) = CUD_CFLAG_SET;

	CUTE_GD_BASE(cute_p) = glob_base;
	CUTE_GD_SIZE(cute_p) =
		ALIGN_TO_MASK(glob_sz, E2K_ALIGN_GLOBALS_MASK);
}

int create_cut_entry(int tcount,
		unsigned long code_base, unsigned  code_sz,
		unsigned long glob_base, unsigned  glob_sz)
{
	struct mm_struct *mm = current->mm;
	register e2k_cute_t *cute_p;	/* register for workaround against */
							/* gcc bug */
	unsigned long ts_flag;
	int free_cui;
	int error = 0;
#ifdef CONFIG_PROTECTED_MODE
	int retval;
#endif

	if (TASK_IS_PROTECTED(current)) {
		mutex_lock(&mm->context.cut_mask_lock);

		/* Find the first free entry in cut and occupy it */
		free_cui = find_next_zero_bit(
				(unsigned long *) &mm->context.cut_mask,
				USER_CUT_AREA_SIZE/sizeof(e2k_cute_t), 1);

		/* If no free cut entry found */
		if (free_cui == USER_CUT_AREA_SIZE/sizeof(e2k_cute_t))
			error = -EFAULT;
		else
			bitmap_set((unsigned long *) &mm->context.cut_mask,
					free_cui, 1);

		mutex_unlock(&mm->context.cut_mask_lock);

		if (error)
			return error;
	} else {
		/* not protected aplications should have zero CUI */
		free_cui = USER_CODES_UNPROT_INDEX(current);
	}

	/* Fill found cut entry by information about loaded module */
	cute_p = (e2k_cute_t *) USER_CUT_AREA_BASE + free_cui;
	DebugCU("Create cut entry: cui = %d; tct = %d; code = 0x%lx: 0x%x; "
		"data = 0x%lx : 0x%x\n", free_cui, tcount, code_base, code_sz,
		glob_base, glob_sz);
#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		DebugCU("e2k_set_vmm_cui called for cui = %d; code 0x%lx : 0x%lx\n",
			free_cui, code_base, code_base + code_sz);
		retval = e2k_set_vmm_cui(mm, free_cui, code_base,
					 code_base + code_sz);
		if (retval)
			return retval;
  	}
#endif

	/* cute_p is user address, read it carefully */
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	TRY_USR_PFAULT {
		fill_cut_entry(cute_p, code_base, code_sz, glob_base, glob_sz);
		CUTE_TSD_BASE(cute_p) =
			atomic_add_return(tcount, &mm->context.tstart) - tcount;
		CUTE_TSD_SIZE(cute_p) = tcount;
	} CATCH_USR_PFAULT {
		error = -EFAULT;
	} END_USR_PFAULT
	clear_ts_flag(ts_flag);

	/* If something was wrong with access to cut */
	if (error)
		return error;

	return free_cui;
}

int free_cut_entry(unsigned long glob_base, size_t glob_sz,
		unsigned long *code_base, size_t *code_sz)
{
	struct mm_struct *mm = current->mm;
	register e2k_cute_t *cute_p;	/* register for workaround against */
							/* gcc bug */
	unsigned long ts_flag;
	int cui;
	int error = 0;
	int removed_cui = -1;

	/* Free cut entry with appropriate glob_base */
	mutex_lock(&mm->context.cut_mask_lock);
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	TRY_USR_PFAULT {
		for (cui = 1; cui < USER_CUT_AREA_SIZE/sizeof(e2k_cute_t);
			cui++) {
			cute_p = (e2k_cute_t *) USER_CUT_AREA_BASE + cui;
			if (CUTE_GD_BASE(cute_p) == glob_base &&
					CUTE_GD_SIZE(cute_p) == glob_sz) {
				if (code_base)
					*code_base = CUTE_CUD_BASE(cute_p);
				if (code_sz)
					*code_sz = CUTE_CUD_SIZE(cute_p);
				fill_cut_entry(cute_p, 0, 0, 0, 0);
				bitmap_clear((unsigned long *)
					&mm->context.cut_mask, cui, 1);
				removed_cui = cui;
			}
		}
	} CATCH_USR_PFAULT {
		error = -EFAULT;
	} END_USR_PFAULT
	clear_ts_flag(ts_flag);
	mutex_unlock(&mm->context.cut_mask_lock);

	/*
	 * If cut entry with appropriate glob_base and glob_sz was not found
	 */
	if (removed_cui > 0) {
		DebugCU("Free cut entry: cui = %d; ", removed_cui);
		if (code_base && code_sz)
			DebugCU("code = 0x%lx: 0x%lx; ", *code_base, *code_sz);
		DebugCU("data = 0x%lx : 0x%lx\n", glob_base, glob_sz);
	} else {
		error = -EFAULT;
	}

	return error;
}

/**
 * do_sys_execve - switch to the thread's context (stacks, CUT, etc)
 * @entry: user function to call
 * @sp: user stack's top
 * @kernel: called by a kernel thread
 *
 * This is always called as the last step when exec()'ing a user binary.
 */
long __attribute__((no_caller_stack))
do_sys_execve(unsigned long entry, unsigned long sp, int kernel)
{
	thread_info_t *const ti = current_thread_info();
	struct mm_struct *mm = current->mm;
	start_fn	start;
	e2k_stacks_t	stacks;
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	unsigned long	u_stk_bottom, u_stk_sz, stack_top;
	hw_stack_t	hw_stacks;
	e2k_cutd_t	cutd;
	e2k_size_t	cut_size;
	int		cui, ret;
	u64		flags;

	BUG_ON(!list_empty(&ti->old_u_pcs_list));
	BUG_ON(CURRENT_PS_BASE() || CURRENT_PCS_BASE());

	if (TASK_IS_PROTECTED(current))
		sp &= ~E2K_ALIGN_PUSTACK_MASK;
	else
		sp &= ~E2K_ALIGN_USTACK_MASK;

	start = (start_fn) entry;

	/* it is actual for guest kernel */
	clear_vm_thread_flags();

#ifdef	CONFIG_KVM_HOST_MODE
	if (ti->gthread_info) {
		/* It is guest thread: clear from old process */
		kvm_pv_clear_guest_thread_info(ti->gthread_info);
	}
#endif	/* CONFIG_KVM_HOST_MODE */

	u_stk_bottom = get_user_main_c_stack(sp, &stack_top);
	if (!u_stk_bottom) {
		ret = -ENOMEM;
		DebugEX("is terminated: get_user_main_c_stack() failed and returned error %d\n",
			ret);
		goto fatal_error;
	}
	u_stk_sz = sp - u_stk_bottom;

	usd_hi = NATIVE_NV_READ_USD_HI_REG();
	usd_lo = NATIVE_NV_READ_USD_LO_REG();

	AS_STRUCT(usd_lo).base = sp;
	AS_STRUCT(usd_lo).p = 0;
	AS_STRUCT(usd_hi).size = u_stk_sz;

	DebugEX("stack base 0x%lx size 0x%lx top 0x%lx\n",
		u_stk_bottom, u_stk_sz, stack_top);

	define_user_hw_stacks_sizes(&hw_stacks);
	ret = create_user_hard_stacks(&hw_stacks, &stacks);
	if (ret) {
		DebugEX("Could not create user hardware stacks\n");
		goto fatal_error;
	}

	/*
	 * Here we go with CUT handling.
	 */

	/* Allocate memory for CUT table (2Mb) */
	ret = create_cu_table(mm, &cut_size, &cui);
	if (ret) {
		DebugEX("Can't create CU table.\n");
		goto fatal_error;
	}

	/*
	* Set CU descriptor (register) to point to the CUT base.
	*/
	cutd.CUTD_base = USER_CUT_AREA_BASE;
	ti->u_cutd = cutd;
	WRITE_CUTD_REG(cutd);

	flags = 0;
	if (TASK_IS_BINCO(current))
		flags |= BIN_COMP_CODE_TASK_FLAG;
	if (current->thread.flags & E2K_FLAG_32BIT)
		flags |= BIN_32_CODE_TASK_FLAG;
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE)
		flags |= PROTECTED_CODE_TASK_FLAG;

	/*
	 * We don't return to handle_sys_call() so call
	 * syscall_trace_leave() and co manually.
	 */
	if (unlikely(ti->flags & _TIF_WORK_SYSCALL_TRACE)) {
		struct pt_regs *regs = current_pt_regs();

		if (regs && user_mode(regs)) {
			if (!TASK_IS_PROTECTED(current))
				SAVE_SYSCALL_RVAL(regs, 0);
			else
				SAVE_PSYSCALL_RVAL(regs, 0, 0, 0, 0, 0, 0);
			syscall_trace_leave(regs);
		}
	}

	/*
	 * Set some special registers in accordance with
	 * E2K API specifications.
	 */
	INIT_SPECIAL_REGISTERS();

	free_getsp_adj(&ti->getsp_adj);

	/*
	 * Switch to user hard stacks should be last action in the function
	 * to avoid starting of scheduler on this process. Scheduler should not
	 * cause switching from or to user hard and soft stacks, because MMU
	 * context switching precedes to stacks spilling and switching.
	 * In this case stacks of current task will be spilled to user space
	 * of the next task
	 */

	raw_all_irq_disable();

	stacks.usd_lo = usd_lo;
	stacks.usd_hi = usd_hi;
	stacks.top = stack_top & ~E2K_ALIGN_STACKS_BASE_MASK;

	/* save local data & hardware stacks pointers */
	ti->u_stack.bottom = stacks.usd_lo.USD_lo_base -
			     stacks.usd_hi.USD_hi_size;
	ti->u_stack.size = stacks.usd_hi.USD_hi_size;
	ti->u_stack.top = stacks.top;

	/*
	 * The next function can be paravirtualized and do various actions:
	 *	on host (or pure native mode) should only return 0 to continue
	 * switching and start of new user
	 *	on guest should switch to created user stacks and start from
	 * user entry point (to do all into one hypercall) Function can
	 * return 1 on exit from user or negative error code
	 */
	ret = switch_to_new_user(&stacks, &hw_stacks,
			cutd.CUTD_base, cut_size, entry, cui, flags, kernel);
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

	INIT_G_REGS();

#if defined CONFIG_FUNCTION_GRAPH_TRACER
	/*
	 * We won't ever return from this function and we are on a new stack
	 * so remove all tracing entries.
	 */
	current->curr_ret_stack = -1;
#endif

	user_enter();

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	thread_info->times_num = 0;
#endif  /* CONFIG_KERNEL_TIMES_ACCOUNT */

	/*
	 * And now just switch to user's data stack and function
	 */

	raw_all_irq_disable();

	NATIVE_NV_WRITE_USBR_USD_REG_VALUE(
			stack_top & ~E2K_ALIGN_STACKS_BASE_MASK,
			AW(usd_hi), AW(usd_lo));

	/*
	 * Switch to the hardware stacks in the new user space.
	 * Note that we now we work on user stacks, so must be
	 * very careful after this point...
	 */
	goto_new_user_hard_stk(&stacks);
	ti->u_hw_stack = hw_stacks;

	/* from here process is new user process and empty pt_regs history */
	ti->pt_regs = NULL;

	NATIVE_WRITE_RPR_HI_REG_VALUE(0);
	NATIVE_WRITE_RPR_LO_REG_VALUE(0);

	if (TASK_IS_PROTECTED(current)) {
                unsigned long *p_base_lo, *p_base_hi;
                unsigned long base_lo, base_hi;

		init_sem_malloc(&mm->context.umpools);
		/* new loader interface */
		p_base_lo = (unsigned long *) mm->start_stack;
		p_base_hi = p_base_lo + 1;
		base_lo = *p_base_lo;
		base_hi = *p_base_hi;
		/* We may erase base descriptor from stack since
		 * no one will ever need it there. */
                *p_base_lo = 0;
                *p_base_hi = 0;
		E2K_JUMP_WITH_ARGUMENTS(protected_switch_to_user_func,
				5, base_lo, base_hi, start, u_stk_sz, cui);
	} else {
		E2K_JUMP_WITH_ARGUMENTS(switch_to_user_func,
				4, 0, start, u_stk_sz, cui);
	}

fatal_error:
	E2K_LMS_HALT_OK;

	DebugEX("fatal error %d: send KILL signal\n", ret);

	if (kernel)
		/* Nowhere to return to, just exit */
		do_exit(SIGKILL);

	send_sig(SIGKILL, current, 0);

	return ret;
}

long e2k_sys_execve(const char __user *filename,
		    const char __user *const __user *argv,
		    const char __user *const __user *envp)
{
	int ret;

	set_ts_flag(TS_USER_EXECVE);
	ret = sys_execve(filename, argv, envp);
	clear_ts_flag(TS_USER_EXECVE);
	if (!ret)
		ret = do_sys_execve(current_thread_info()->execve.entry,
				    current_thread_info()->execve.sp, false);

	return ret;
}

#ifdef CONFIG_COMPAT
long compat_e2k_sys_execve(const char __user *filename,
			   const compat_uptr_t __user *argv,
			   const compat_uptr_t __user *envp)
{
	int ret;

	set_ts_flag(TS_USER_EXECVE);
	ret = compat_sys_execve(filename, argv, envp);
	clear_ts_flag(TS_USER_EXECVE);
	if (!ret)
		ret = do_sys_execve(current_thread_info()->execve.entry,
				    current_thread_info()->execve.sp, false);

	return ret;
}
#endif

long e2k_sys_execveat(int fd, const char __user *filename,
		      const char __user *const __user *argv,
		      const char __user *const __user *envp,
		      int flags)
{
	int ret;

	set_ts_flag(TS_USER_EXECVE);
	ret = sys_execveat(fd, filename, argv, envp, flags);
	clear_ts_flag(TS_USER_EXECVE);
	if (!ret)
		ret = do_sys_execve(current_thread_info()->execve.entry,
				    current_thread_info()->execve.sp, false);

	return ret;
}

#ifdef CONFIG_COMPAT
long compat_e2k_sys_execveat(int fd, const char __user *filename,
		      const compat_uptr_t __user *argv,
		      const compat_uptr_t __user *envp,
		      int flags)
{
	int ret;

	set_ts_flag(TS_USER_EXECVE);
	ret = compat_sys_execveat(fd, filename, argv, envp, flags);
	clear_ts_flag(TS_USER_EXECVE);
	if (!ret)
		ret = do_sys_execve(current_thread_info()->execve.entry,
				    current_thread_info()->execve.sp, false);

	return ret;
}
#endif

static inline int
native_prepare_start_thread_frames(unsigned long entry, unsigned long sp)
{
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_mem_crs_t *crs;
	unsigned long *frame;
	unsigned long flags;
	bool flush_chain, flush_procedure;

	raw_all_irq_save(flags);

	psp_lo = NATIVE_NV_READ_PSP_LO_REG();
	pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

	flush_chain = (pcsp_hi.PCSP_hi_ind < 2 * SZ_OF_CR);
	/* Assume a maximum of 4 do_sys_execve()'s parameters */
	flush_procedure = (psp_hi.PSP_hi_ind < 2 * EXT_4_NR_SZ);

	if (flush_chain)
		E2K_FLUSHC;
	if (flush_procedure)
		E2K_FLUSHR;

	/*
	 * Change IP of the last frame to do_sys_execve().
	 */
	crs = (e2k_mem_crs_t *) (pcsp_lo.PCSP_lo_base + SZ_OF_CR);

	crs->cr0_hi.CR0_hi_ip = (unsigned long) &do_sys_execve >> 3;

	/*
	 * Put do_sys_execve()'s parameters into the procedure stack.
	 */
	frame = (unsigned long *) psp_lo.PSP_lo_base;

	frame[0] = entry;
	if (machine.native_iset_ver < E2K_ISET_V5) {
		frame[1] = sp;
		/* Skip frame[2] and frame[3] - they hold extended data */
	} else {
		frame[2] = sp;
		/* Skip frame[1] and frame[3] - they hold extended data */
	}
	frame[4] = true;

	raw_all_irq_restore(flags);

	return 0;
}
int native_do_prepare_start_thread_frames(unsigned long entry, unsigned long sp)
{
	return native_prepare_start_thread_frames(entry, sp);
}

void start_thread(struct pt_regs *regs, unsigned long entry, unsigned long sp)
{
	int ret;

	DebugP("entry 0x%lx sp 0x%lx\n", entry, sp);

	current_thread_info()->execve.entry = entry;
	current_thread_info()->execve.sp = sp;

	/*
	 * If called from user mode then do_sys_execve() will
	 * be called manually from ttable_entry().
	 */
	if (test_ts_flag(TS_USER_EXECVE))
		return;

	ret = prepare_start_thread_frames(entry, sp);
	if (ret != 0) {
		pr_err("%s(): could not prepare stack frames to return "
			"to do_sys_execve(), error %d",
			__func__, ret);
		do_exit(SIGKILL);
	}

	return;	/* to prepared kernel thread stack frames to call */
		/* do_sys_execve(entry, sp) */
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
	NATIVE_SAVE_INTEL_REGS(sw_regs);
}
#else /* !CONFIG_SECONDARY_SPACE_SUPPORT: */
static inline void save_binco_regs(struct sw_regs *sw_regs) { }
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

void init_sw_user_regs(struct sw_regs *sw_regs,
		bool save_gregs, bool save_binco_regs_needed)
{
	/*
	 * New process will start with interrupts disabled.
	 * They will be enabled in schedule_tail() (user's upsr
	 * is saved in pt_regs and does not need to be corrected).
	 */
	sw_regs->upsr	= E2K_KERNEL_UPSR_DISABLED;

	sw_regs->fpcr	= NATIVE_NV_READ_FPCR_REG();
	sw_regs->fpsr	= NATIVE_NV_READ_FPSR_REG();
	sw_regs->pfpfr	= NATIVE_NV_READ_PFPFR_REG();
	sw_regs->cutd	= NATIVE_NV_READ_CUTD_REG();

#ifdef CONFIG_GREGS_CONTEXT
	if (save_gregs) {
		machine.save_gregs(&sw_regs->gregs);
	}
#endif /* CONFIG_GREGS_CONTEXT */

	if (save_binco_regs_needed)
		save_binco_regs(sw_regs);
}

static void set_default_registers(struct task_struct *new_task, bool save_gregs)
{
	struct sw_regs *new_sw_regs = &new_task->thread.sw_regs;
	struct thread_info *new_ti = task_thread_info(new_task);
	unsigned long addr = (unsigned long) new_task->stack;

	memset(new_sw_regs, 0, sizeof(*new_sw_regs));

	memset(&new_task->thread.debug.regs, 0,
			sizeof(new_task->thread.debug.regs));

	clear_ptrace_hw_breakpoint(new_task);

	/*
	 * Calculate kernel stacks registers
	 */
	AW(new_ti->k_psp_lo) = 0;
	AS(new_ti->k_psp_lo).base = addr + KERNEL_P_STACK_OFFSET;
	AW(new_ti->k_psp_hi) = 0;
	AS(new_ti->k_psp_hi).size = KERNEL_P_STACK_SIZE;
	AW(new_ti->k_pcsp_lo) = 0;
	AS(new_ti->k_pcsp_lo).base = addr + KERNEL_PC_STACK_OFFSET;
	AW(new_ti->k_pcsp_hi) = 0;
	AS(new_ti->k_pcsp_hi).size = KERNEL_PC_STACK_SIZE;
	AW(new_ti->k_usd_lo) = 0;
	AS(new_ti->k_usd_lo).base = addr + KERNEL_C_STACK_OFFSET +
				    KERNEL_C_STACK_SIZE;
	AW(new_ti->k_usd_hi) = 0;
	AS(new_ti->k_usd_hi).size = KERNEL_C_STACK_SIZE;

	/*
	 * Prepare registers for first schedule() to a new task
	 */
	new_sw_regs->top = (u64) new_task->stack + KERNEL_C_STACK_SIZE +
			   KERNEL_C_STACK_OFFSET;
	new_sw_regs->usd_lo  = new_ti->k_usd_lo;
	new_sw_regs->usd_hi  = new_ti->k_usd_hi;
	new_sw_regs->psp_lo  = new_ti->k_psp_lo;
	new_sw_regs->psp_hi  = new_ti->k_psp_hi;
	new_sw_regs->pcsp_lo = new_ti->k_pcsp_lo;
	new_sw_regs->pcsp_hi = new_ti->k_pcsp_hi;

	init_sw_user_regs(new_sw_regs, save_gregs, TASK_IS_BINCO(current));
}

asmlinkage pid_t sys_clone_thread(unsigned long clone_flags, long stack_base,
		unsigned long long stack_size, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	struct pt_regs *regs = current_pt_regs();
	long rval, flags = clone_flags;
	struct kernel_clone_args args;

	if (!access_ok(stack_base, stack_size))
		return -ENOMEM;

	if (!flags)
		flags = SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES;

	args.flags	 = (flags & ~CSIGNAL);
	args.pidfd	 = parent_tidptr;
	args.child_tid	 = child_tidptr;
	args.parent_tid	 = parent_tidptr;
	args.exit_signal = (flags & CSIGNAL);
	args.stack	 = stack_base;
	args.stack_size	 = stack_size;
	args.tls	 = tls;

	rval = _do_fork(&args);

        return rval;
}

/*
 * Get return IP for n level below pt_regs return IP
 */
e2k_addr_t
get_nested_kernel_IP(pt_regs_t *regs, int n)
{
	e2k_addr_t	IP = 0UL;
	e2k_cr0_hi_t	cr0_hi;
	e2k_addr_t	base;
	s64		cr_ind;
	u64		flags;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	base = regs->stacks.pcsp_lo.PCSP_lo_base;
	cr_ind = regs->stacks.pcsp_hi.PCSP_hi_ind;

	while (--n) {
		if (cr_ind <= 0) {
			panic("get_nested_kernel_IP(): procedure chain "
				"stack underflow\n");
		}
		cr_ind = cr_ind  - SZ_OF_CR;
		get_kernel_cr0_hi(&cr0_hi, base, cr_ind);
		IP = AS_STRUCT(cr0_hi).ip << 3;
	}

        raw_all_irq_restore(flags);
	return IP;
}

static void reserved_frame(void)
{
	panic("kthread must not return, but it did");
}

/**
 * copy_kernel_stacks - prepare for return to kernel function
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
	e2k_mem_crs_t crs;
	e2k_psr_t psr;
	unsigned long *p_frame, reserved_frame_size;
	e2k_mem_crs_t *c_frames;
	int ret;

	/*
	 * How kernel thread creation works.
	 *
	 * 1) After schedule() to the new kthread we return to __ret_from_fork()
	 * with wbs=0 (i.e. returned value ends up in %r0).
	 * 2) __ret_from_fork() calls schedule_tail() to finish the things
	 * for scheduler.
	 * 3) When __ret_from_fork() returns @fn frame will be FILLed along
	 * with function's argument.
	 */

	/*
	 * Reserve space in hardware stacks for:
	 * __ret_from_fork <= @fn(@arg) <= reserved_frame()
	 *
	 * reserved_frame() is used solely to print an error when @fn returns
	 */
	AS(new_sw_regs->pcsp_hi).ind = 3 * SZ_OF_CR;

	reserved_frame_size = 4 * EXT_4_NR_SZ;
	AS(new_sw_regs->psp_hi).ind = EXT_4_NR_SZ + reserved_frame_size;

	/*
	 * Prepare @fn's argument
	 */
	p_frame = (unsigned long *) (AS(new_sw_regs->psp_lo).base +
					reserved_frame_size);
	*p_frame = arg;

	/*
	 * Prepare @fn's frame in chain stack.
	 */
	psr = NATIVE_NV_READ_PSR_REG();
	/* function kernel_thread() can be started from trap to dump */
	/* all stacks state on VMs and VCPUs */
	BUG_ON((psr.PSR_sge == 0) && !current_is_in_trap());
	ret = chain_stack_frame_init(&crs, (void *) fn,
			AS(new_sw_regs->usd_hi).size, psr, 1, 0, false);
	if (ret)
		return ret;

	c_frames = (e2k_mem_crs_t *) AS(new_sw_regs->pcsp_lo).base;
	c_frames[2] = crs;

	/*
	 * Prepare frame to catch errors
	 */
	AS(crs.cr0_hi).ip = (u64) reserved_frame >> 3;
	AS(crs.cr1_lo).wbs = reserved_frame_size / EXT_4_NR_SZ;

	c_frames[1] = crs;

	memset((void *) AS(new_sw_regs->psp_lo).base, 0, reserved_frame_size);

	return 0;
}

static struct pt_regs *reserve_child_pt_regs(struct sw_regs *new_sw_regs,
		struct task_struct *new_task)
{
	struct pt_regs *new_regs;
	unsigned long stack_top, stack_bottom, regs_size;

	stack_top = (unsigned long) new_task->stack + KERNEL_C_STACK_OFFSET +
			KERNEL_C_STACK_SIZE;
	stack_bottom = new_sw_regs->usd_lo.USD_lo_base -
				new_sw_regs->usd_hi.USD_hi_size;
	regs_size = round_up(sizeof(*new_regs), E2K_ALIGN_STACK);

	BUG_ON(AS(new_sw_regs->usd_hi).size < regs_size);

	/* allocate pt_regs structute from top of the stack
	AS(new_sw_regs->usd_lo).base -= regs_size;
	AS(new_sw_regs->usd_hi).size -= regs_size;

	AS(new_sw_regs->crs.cr1_hi).ussz -= regs_size / 16;

	new_regs = (struct pt_regs *) (stack_top - regs_size);
	 */

	/* allocate pt_regs structute from bottom of the stack
	 * Overlay of areas cannot now controlled by hardware because of
	 * guest does not report stack borders changes to host.
	 * TODO that it need implement simple light hypercall
	new_sw_regs->usd_hi.USD_hi_size -= regs_size;
	 */
	new_regs = (struct pt_regs *)stack_bottom;

	return new_regs;
}

/*
 * Clear unallocated memory pointers which can be allocated for parent task
 */
void clear_thread_info(struct task_struct *task)
{
	struct thread_struct	*thread = &task->thread;
	thread_info_t		*thread_info = task_thread_info(task);

	DebugEX("started for task 0x%px CPU #%d\n", task, task_cpu(task));

	AW(thread_info->k_usd_lo) = 0;
	AW(thread_info->k_usd_hi) = 0;
	AW(thread_info->k_psp_lo) = 0;
	AW(thread_info->k_psp_hi) = 0;
	AW(thread_info->k_pcsp_lo) = 0;
	AW(thread_info->k_pcsp_hi) = 0;

#ifdef CONFIG_TC_STORAGE
	thread->sw_regs.tcd = 0;
#endif

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
#endif

#if defined(CONFIG_E2K) && defined(CONFIG_PROTECTED_MODE)
	thread_info->pm_robust_list = NULL;
#endif

	/* clear virtualization support fields into thread info */
	clear_virt_thread_struct(thread_info);
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
		const e2k_mem_crs_t *child_crs, const struct pt_regs *regs,
		struct sw_regs *new_sw_regs, struct thread_info *new_ti,
		unsigned long clone_flags)
{
	const struct thread_info *old_ti = current_thread_info();
	u64 ps_copy_size;
	s64 u_pshtp_size, u_pcshtp_size, parent_pshtp_size;
	unsigned long flags;
	void __user *child_pframe;
	int ret;

	u_pshtp_size = GET_PSHTP_MEM_INDEX(child_stacks->pshtp);
	u_pcshtp_size = PCSHTP_SIGN_EXTEND(child_stacks->pcshtp);

	/*
	 * After clone child has new empty stacks
	 */
	if (WARN_ON_ONCE(u_pshtp_size || u_pcshtp_size))
		do_exit(SIGKILL);

	/*
	 * Leave one empty frame that will be loaded to %CR
	 * registers when the top user frame starts executing.
	 */
	AS(new_sw_regs->pcsp_hi).ind += SZ_OF_CR;
	child_stacks->pcshtp += SZ_OF_CR;
	AS(child_stacks->pcsp_hi).ind += SZ_OF_CR;

	/*
	 * Copy last chain stack frame from parent (needed only for vfork()).
	 */
	if (clone_flags & CLONE_VFORK) {
		e2k_mem_crs_t *cframe;
		unsigned long parent_pcshtp_size;

		parent_pcshtp_size = PCSHTP_SIGN_EXTEND(regs->stacks.pcshtp);
		if (WARN_ON_ONCE(parent_pcshtp_size < SZ_OF_CR))
			do_exit(SIGKILL);
		cframe = (e2k_mem_crs_t *) (AS(old_ti->k_pcsp_lo).base +
					    parent_pcshtp_size - SZ_OF_CR);

		raw_all_irq_save(flags);
		COPY_STACKS_TO_MEMORY();
		memcpy((void *) (AS(new_ti->k_pcsp_lo).base +
				 AS(new_sw_regs->pcsp_hi).ind),
		       cframe, SZ_OF_CR);
		raw_all_irq_restore(flags);
		DebugCLN("last chain stack frame from parent copyed to "
			"kernel stack %px from %px, size 0x%lx\n",
			(void *)(new_ti->k_pcsp_lo.PCSP_lo_base +
					AS(new_sw_regs->pcsp_hi).ind),
			cframe, SZ_OF_CR);

		AS(new_sw_regs->pcsp_hi).ind += SZ_OF_CR;
		child_stacks->pcshtp += SZ_OF_CR;
		AS(child_stacks->pcsp_hi).ind += SZ_OF_CR;

		ps_copy_size = (AS(child_crs->cr1_lo).wbs +
				AS(cframe->cr1_lo).wbs) * EXT_4_NR_SZ;
	} else {
		ps_copy_size = AS(child_crs->cr1_lo).wbs * EXT_4_NR_SZ;
	}


	/*
	 * Copy procedure stack from parent.
	 */
	child_pframe = (void __user *) (AS(child_stacks->psp_lo).base +
					AS(child_stacks->psp_hi).ind);
	parent_pshtp_size = GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);

	if (ps_copy_size > parent_pshtp_size) {
		void __user *parent_pframe;
		unsigned long ts_flag;
		u64 size;

		size = ps_copy_size - parent_pshtp_size;
		parent_pframe = (void __user *)	(AS(regs->stacks.psp_lo).base +
						 AS(regs->stacks.psp_hi).ind -
						 ps_copy_size);

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __copy_to_user_with_tags(child_pframe, parent_pframe,
						size);
		clear_ts_flag(ts_flag);
		if (ret) {
			pr_err("%s(): copying of parent procedure frames to "
				"child failed\n",
				__func__);
			return -EFAULT;
		}
		DebugCLN("parent procedure stack frames from %px copyed to "
			"childe stack %px, size 0x%llx\n",
			parent_pframe, child_pframe, size);

		child_pframe += size;
		AS(child_stacks->psp_hi).ind += size;
		ps_copy_size -= size;
	}

	raw_all_irq_save(flags);
	COPY_STACKS_TO_MEMORY();
	tagged_memcpy_8((void *) AS(new_ti->k_psp_lo).base,
	       (void *) (AS(old_ti->k_psp_lo).base + parent_pshtp_size -
			 ps_copy_size), ps_copy_size);
	raw_all_irq_restore(flags);
	DebugCLN("parent kernel procedure stack frames from %px copyed to "
		"childe stack %px, size 0x%llx\n",
		(void *) (AS(old_ti->k_psp_lo).base + parent_pshtp_size -
							ps_copy_size),
		(void *) AS(new_ti->k_psp_lo).base, ps_copy_size);

	AS(new_sw_regs->psp_hi).ind += ps_copy_size;
	AS(child_stacks->pshtp).ind += PSP_IND_TO_PSHTP(ps_copy_size);
	AS(child_stacks->psp_hi).ind += ps_copy_size;

	if (AS(child_stacks->pshtp).ind) {
		AS(child_stacks->pshtp).fx = 1;
		AS(child_stacks->pshtp).fxind = 0x10;
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

	u_pshtp_size = GET_PSHTP_MEM_INDEX(child_stacks->pshtp);
	u_pcshtp_size = PCSHTP_SIGN_EXTEND(child_stacks->pcshtp);
	DebugCPY("procedure stack size to copy (PSHTP) 0x%llx\n",
		u_pshtp_size);
	DebugCPY("chain stack size to copy (PCSHTP) 0x%llx\n",
		u_pcshtp_size);

	if (WARN_ON_ONCE(u_pshtp_size < 0 || u_pcshtp_size < 0))
		do_exit(SIGKILL);

	raw_all_irq_save(flags);
	COPY_STACKS_TO_MEMORY();
	tagged_memcpy_8((void *) AS(new_ti->k_psp_lo).base,
			(void *) AS(old_ti->k_psp_lo).base, u_pshtp_size);
	memcpy((void *) AS(new_ti->k_pcsp_lo).base,
			(void *) AS(old_ti->k_pcsp_lo).base, u_pcshtp_size);
	raw_all_irq_restore(flags);
	DebugCPY("user's part of procedure stack copyed to %px from %px "
		"size 0x%llx\n",
		(void *)new_ti->k_psp_lo.PSP_lo_base,
		(void *)old_ti->k_psp_lo.PSP_lo_base, u_pshtp_size);
	DebugCPY("user's part of chain stack copyed to %px from %px "
		"size 0x%llx\n",
		(void *)new_ti->k_pcsp_lo.PCSP_lo_base,
		(void *)old_ti->k_pcsp_lo.PCSP_lo_base, u_pcshtp_size);

	AS(new_sw_regs->psp_hi).ind += u_pshtp_size;
	AS(new_sw_regs->pcsp_hi).ind += u_pcshtp_size;
	DebugCPY("procedure stack ind is now 0x%x\n",
		new_sw_regs->psp_hi.PSP_hi_ind);
	DebugCPY("chain stack ind is now 0x%x\n",
		new_sw_regs->pcsp_hi.PCSP_hi_ind);

	if (AS(child_stacks->pshtp).ind) {
		AS(child_stacks->pshtp).fx = 1;
		AS(child_stacks->pshtp).fxind = 0x10;
	}
}

static int calculate_dstack_size(struct mm_struct *mm,
		unsigned long *sp, unsigned long *stack_size)
{
	struct vm_area_struct *vma, *cur, *prev;
	u64 delta;

	down_read(&mm->mmap_sem);
	vma = find_vma_prev(mm, *sp + *stack_size - 1, &prev);
	if (!vma || *sp + *stack_size <= vma->vm_start)
		goto out_efault;

	cur = vma;

	if (*stack_size) {
		/*
		 * Check passed area
		 */
		while (*sp < cur->vm_start) {
			if (!prev || cur->vm_start != prev->vm_end ||
			    ((cur->vm_flags ^ prev->vm_flags) & VM_GROWSDOWN))
				goto out_efault;

			cur = prev;
			prev = prev->vm_prev;
		}
	} else {
		/*
		 * We assume here that the stack area is contained
		 * in a single vma.
		 */
		*stack_size = *sp - cur->vm_start;
		*sp = cur->vm_start;
	}

	if (*stack_size > MAX_USD_HI_SIZE) {
		delta = *stack_size - MAX_USD_HI_SIZE;

		*sp += delta;
		*stack_size -= delta;
	}

	up_read(&mm->mmap_sem);

	/* Align the stack */

	delta = round_up(*sp, E2K_ALIGN_STACK) - *sp;
	*sp += delta;
	*stack_size -= delta;

	delta = *stack_size - round_down(*stack_size, E2K_ALIGN_STACK);
	*stack_size -= delta;

	if ((s64) *stack_size < 0)
		return -EINVAL;

	return 0;

out_efault:
	up_read(&mm->mmap_sem);

	return -EFAULT;
}

static void prepare_ret_from_fork(e2k_mem_crs_t *crs, u64 usd_size)
{
	memset(crs, 0, sizeof(*crs));

	crs->cr0_lo.fields.pf = -1ULL;
	crs->cr0_hi.fields.ip = (unsigned long) __ret_from_fork >> 3;
	crs->cr1_lo.fields.psr = AW(E2K_KERNEL_PSR_ENABLED);
	crs->cr1_lo.fields.cui = KERNEL_CODES_INDEX;
	crs->cr1_lo.fields.ic = !cpu_has(CPU_FEAT_ISET_V6);
	crs->cr1_lo.fields.wbs = 0;
	crs->cr1_lo.fields.wpsz = 4;
	crs->cr1_hi.fields.ussz = usd_size / 16;
}

int copy_thread_tls(unsigned long clone_flags, unsigned long sp,
		unsigned long stack_size, struct task_struct *new_task,
		unsigned long tls)
{
	struct thread_info *new_ti = task_thread_info(new_task);
	struct sw_regs *new_sw_regs = &new_task->thread.sw_regs;
	struct pt_regs *childregs, *regs = current_thread_info()->pt_regs;
	int ret;

	ktimes_account_copy_thread(new_ti);

	/*
	 * Initialize sw_regs with default values
	 */
	set_default_registers(new_task, true);

	/*
	 * Set __ret_from_fork frame to be called right after __switch_to()
	 */
	prepare_ret_from_fork(&new_sw_regs->crs, AS(new_sw_regs->usd_hi).size);

	/*
	 * For kernel threads @sp is a function and @stacks_size is its argument
	 */
	if (current->flags & PF_KTHREAD)
		return copy_kernel_stacks(new_task, sp, stack_size);

	/*
	 * Set a new TLS for the child thread.
	 */
	if (clone_flags & CLONE_SETTLS) {
		if (!TASK_IS_PROTECTED(current)) {
			new_sw_regs->gregs.g[13].base = tls;
		} else {
			u64 tls_lo = 0;
			u64 tls_hi = 0;
			u32 tls_lo_tag = 0;
			u32 tls_hi_tag = 0;
			u64 args_ptr;

			switch (regs->kernel_entry) {
			case 8:
				tls_lo = regs->args[9];
				tls_hi = regs->args[10];
				tls_lo_tag = regs->tags >> (4*10) & 0xf;
				tls_hi_tag = regs->tags >> (4*11) & 0xf;
				break;
			case 10:
				args_ptr = __E2K_PTR_PTR(regs->args[4],
						 regs->args[5], GET_SBR_HI());
				/* Copy TLS argument with tags. */
				TRY_USR_PFAULT {
					NATIVE_LOAD_TAGGED_QWORD_AND_TAGS(
						((u64 *) args_ptr) + 4,
						tls_lo, tls_hi,
						tls_lo_tag, tls_hi_tag);
				} CATCH_USR_PFAULT {
					pr_warn("Bad tls on entry10\n");
				} END_USR_PFAULT
				break;
			default:
				pr_warn("Unknown entry in tls copy\n");
			}
			__NATIVE_STORE_TAGGED_QWORD(
				&new_sw_regs->gregs.g[12].base,
				tls_lo, tls_hi, tls_lo_tag, tls_hi_tag, 16);
		}
	}

	childregs = reserve_child_pt_regs(new_sw_regs, new_task);

	*childregs = *regs;
	clear_fork_child_pt_regs(childregs);
	new_ti->pt_regs = childregs;

	/*
	 * Update data stack if needed
	 */
	if (sp) {
		if (TASK_IS_PROTECTED(new_task) && stack_size)
			set_ti_thread_flag(new_ti, TIF_USD_NOT_EXPANDED);

		ret = calculate_dstack_size(new_task->mm, &sp, &stack_size);
		if (ret)
			return ret;

		if (TASK_IS_PROTECTED(current)) {
			e2k_pusd_lo_t pusd_lo;

			childregs->stacks.top = (sp + stack_size) &
						~0xffffffffUL;
			AW(pusd_lo) = 0;
			AS(pusd_lo).base = (sp + stack_size) & 0xffffffffUL;
			AS(pusd_lo).psl = 1;
			AS(pusd_lo).p = 1;
			AS(pusd_lo).rw = RW_ENABLE;
			AW(childregs->stacks.usd_lo) = AW(pusd_lo);
		} else {
			childregs->stacks.top = sp + stack_size;
			AS(childregs->stacks.usd_lo).base = sp + stack_size;
		}
		AS(childregs->stacks.usd_hi).size = stack_size;

		new_ti->u_stack.bottom = sp;
		new_ti->u_stack.top = sp + stack_size;
		new_ti->u_stack.size = stack_size;

		AS(childregs->crs.cr1_hi).ussz = stack_size / 16;
	}

	if (clone_flags & CLONE_VM) {
		/*
		 * User thread creation
		 */
		ret = create_user_hard_stacks(&new_ti->u_hw_stack,
					      &childregs->stacks);
		if (ret)
			return ret;

		ret = clone_prepare_spilled_user_stacks(&childregs->stacks,
				&childregs->crs, regs, new_sw_regs, new_ti,
				clone_flags);
		if (ret)
			return ret;

		/* TODO FIXME on fork g_list should be copied, not zeroed */
		clear_g_list(task_thread_info(new_task));

		/*
		 * New thread will use different signal stack
		 */
		new_ti->signal_stack.base = 0;
		new_ti->signal_stack.size = 0;
		new_ti->signal_stack.used = 0;
	} else {
		/*
		 * User process creation
		 */
		copy_spilled_user_stacks(&childregs->stacks, &childregs->crs,
					 new_sw_regs, new_ti);

		ret = copy_old_u_pcs_list(new_ti, current_thread_info());
		if (ret)
			return ret;

		ret = copy_getsp_adj(new_ti, current_thread_info());
		if (ret)
			return ret;

		/*
		 * Stacks of the fork'ed process are located at the same address
		 */
		new_ti->u_hw_stack = current_thread_info()->u_hw_stack;

#ifdef CONFIG_PROTECTED_MODE
		if (new_task->thread.flags & E2K_FLAG_PROTECTED_MODE &&
				!(clone_flags & CLONE_VM))
			init_pool_malloc(current, new_task);
#endif

		if (MONITORING_IS_ACTIVE)
			init_monitors(new_task);
	}

	/*
	 * __ret_from_fork() does not restore user CR registers (because
	 * handle_sys_call() does not do it for performance reasons), so
	 * make sure they are FILLed by hardware.
	 */
	memcpy((void *) (AS(new_ti->k_pcsp_lo).base +
			 AS(new_sw_regs->pcsp_hi).ind),
			&childregs->crs, SZ_OF_CR);
	AS(new_sw_regs->pcsp_hi).ind += SZ_OF_CR;

	return 0;
}

void native_deactivate_mm(struct task_struct *dead_task, struct mm_struct *mm)
{
	struct thread_info *ti = task_thread_info(dead_task);
	struct pt_regs *regs = ti->pt_regs;
	int ret;

	if (!mm)
		return;

	DebugEX("entered for task 0x%px %d [%s], mm 0x%lx\n",
		dead_task, dead_task->pid, dead_task->comm, mm);
	BUG_ON(dead_task != current);

#if defined(CONFIG_E2K) && defined(CONFIG_PROTECTED_MODE)
	if (unlikely(ti->pm_robust_list)) {
		pm_exit_robust_list(dead_task);
		ti->pm_robust_list = NULL;
	}
#endif

	/*
	 * There may be coredump in progress
	 */
	if (regs)
		do_user_hw_stacks_copy_full(&regs->stacks, regs, NULL);

#ifdef CONFIG_MLT_STORAGE
	/*
	 * Do not want any surprises from MLT later on.
	 */
	/* FIXME: MLT support is not yet implemented for guest kernel */
	if (!paravirt_enabled())
		machine.invalidate_MLT();
#endif

	hw_context_deactivate_mm(dead_task);

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

#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
	if (current->pobjs)
		pthread_exit();
#endif

#ifdef CONFIG_PROTECTED_MODE
	free_global_sp();
#endif /* CONFIG_PROTECTED_MODE */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	if (debug_process_name != NULL &&
			!strncmp(current->comm, debug_process_name,
				 debug_process_name_len)) {
		sys_e2k_print_kernel_times(current, ti->times,
				ti->times_num, ti->times_index);
	}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#ifdef	CONFIG_KVM_HOST_MODE
	/* FIXME: it should be without ifdef/endif */
	kvm_resume_vm_thread();
#endif	/* CONFIG_KVM_HOST_MODE */

#ifdef CONFIG_MONITORS
	if (MONITORING_IS_ACTIVE) {
		process_monitors(current);
		add_dead_proc_events(current);
	}
#endif /* CONFIG_MONITORS */

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
	/* loop is done by the caller */
	local_irq_enable();
}
EXPORT_SYMBOL(native_default_idle);

void arch_cpu_idle_enter()
{
	/* It works under CONFIG_E2K_PROFILING flag only */
	cpu_idle_time();
}

void arch_cpu_idle_exit()
{
	/* It works under CONFIG_E2K_PROFILING flag only */
	calculate_cpu_idle_time();
}

void arch_cpu_idle()
{
	default_idle();
}

void flush_thread(void)
{
	DebugP("flush_thread entered.\n");

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	current_thread_info()->last_ic_flush_cpu = -1;
#endif
	flush_ptrace_hw_breakpoint(current);

	DebugP("flush_thread exited.\n");
}

int dump_fpu( struct pt_regs *regs, void *fpu )
{
	DebugP("dump_fpu entered.\n");
	DebugP("dump_fpu exited.\n");

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

void clear_delayed_free_hw_stacks(struct mm_struct *mm)
{
	struct core_state *core_state = mm->core_state;
	struct delayed_hw_stack *delayed_hw_stack, *n;
	mm_context_t *context = &mm->context;

	DebugCD(" %s  beginn pid=%d core_state=%px mm=%px context=%px\n",
			__func__, current->pid, core_state, mm, context);
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
	struct mm_struct *mm = current->mm;
	struct core_state *core_state = mm->core_state;
	mm_context_t *context = &mm->context;
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
notrace
struct task_struct *__switch_to(struct task_struct *prev,
				struct task_struct *next)
{
	thread_info_t *next_ti = task_thread_info(next);

	/* Save interrupt mask state and disable NMIs */
	UPSR_ALL_SAVE_AND_CLI(AW(prev->thread.sw_regs.upsr));

	NATIVE_SAVE_TASK_REGS_TO_SWITCH(prev);

	native_set_current_thread_info(task_thread_info(next), next);

	NATIVE_RESTORE_TASK_REGS_TO_SWITCH(next, next_ti);

	flush_ic_on_switch();

	/* Restore interrupt mask and enable NMIs */
	UPSR_RESTORE(AW(next->thread.sw_regs.upsr));

	return prev;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}

int find_cui_by_ip(unsigned long ip)
{
	struct mm_struct *mm = current->mm;
	e2k_cute_t __user *cut = (e2k_cute_t __user *) USER_CUT_AREA_BASE;
	int i, cui = -ESRCH;

	if (!TASK_IS_PROTECTED(current))
		return USER_CODES_UNPROT_INDEX(current);

	mutex_lock(&mm->context.cut_mask_lock);

	for_each_set_bit(i, mm->context.cut_mask,
			USER_CUT_AREA_SIZE/sizeof(e2k_cute_t)) {
		e2k_cute_dw0_t dw0;
		e2k_cute_dw1_t dw1;

		if (__get_user(AW(dw0), &AW(cut[i].dw0)) ||
		    __get_user(AW(dw1), &AW(cut[i].dw1))) {
			cui = -EFAULT;
			break;
		}

		if (ip >= AS(dw0).cud_base &&
				ip < AS(dw0).cud_base + AS(dw1).cud_size) {
			cui = i;
			break;
		}
	}

	mutex_unlock(&mm->context.cut_mask_lock);

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
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		error = current->mm->context.pm_sc_debug_mode;
		break;
		/* resets PM debug mode status and returns '0': */
	case PR_PM_DBG_MODE_RESET:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		error = current->mm->context.pm_sc_debug_mode;
		current->mm->context.pm_sc_debug_mode = PM_SC_DBG_MODE_DEFAULT;
		break;
		/* sets PM debug mode status and returns previous status: */
	case PR_PM_DBG_MODE_SET:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = current->mm->context.pm_sc_debug_mode;
		current->mm->context.pm_sc_debug_mode = arg2
							| PM_SC_DBG_MODE_INIT;
		break;
	case PR_PM_DBG_MODE_ADD:
		if (!arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		current->mm->context.pm_sc_debug_mode |= arg2;
		break;
	case PR_PM_DBG_MODE_DEL:
		if (!arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		current->mm->context.pm_sc_debug_mode &= ~arg2;
		break;
#endif /* CONFIG_PROTECTED_MODE */
	default:
		if (current->mm->context.pm_sc_debug_mode
			& PM_SC_DBG_MODE_CHECK)
			pr_err("Unknown option 0x%x in 'arch_prctl' syscall\n",
				option);
		error = -EINVAL;
		break;
	}
	return error;
}

/**
 * chain_stack_frame_init - initialize chain stack frame for current
 *			    task from provided parameters
 * @crs - frame to initialize
 * @fn_ptr - IP to return to
 * @dstack_size - free size of data stack _after_ return
 * @wbs - cr1_lo.wbs value
 * @wpsz - cr1_lo.wpsz value
 * @user - execute in user or kernel mode
 *
 * We could try to derive @user and cui from @fn_ptr by comparing it
 * to TASK_SIZE but we must not: if user controls @fn_ptr value then
 * this would be a security hole.
 */
int chain_stack_frame_init(e2k_mem_crs_t *crs, void *fn_ptr,
		size_t dstack_size, e2k_psr_t psr,
		int wbs, int wpsz, bool user)
{
	unsigned long fn = (unsigned long) fn_ptr;

	if (user && psr.pm)
		return -EPERM;

	memset(crs, 0, sizeof(*crs));

	AS(crs->cr0_lo).pf = -1ULL;
	AS(crs->cr0_hi).ip = fn >> 3;
	AS(crs->cr1_lo).psr = AW(psr);
	AS(crs->cr1_lo).wbs = wbs;
	AS(crs->cr1_lo).wpsz = wpsz;
	AS(crs->cr1_hi).ussz = dstack_size / 16;

	if (user) {
		int cui = find_cui_by_ip(fn);
		if (cui < 0)
			return cui;
		if (machine.native_iset_ver < E2K_ISET_V6)
			AS(crs->cr1_lo).ic = 0;
		AS(crs->cr1_lo).cui = cui;
	} else {
		if (machine.native_iset_ver < E2K_ISET_V6)
			AS(crs->cr1_lo).ic = 1;
		AS(crs->cr1_lo).cui = KERNEL_CODES_INDEX;
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
