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
#include <linux/jhash.h>
#include <linux/tick.h>
#include <linux/ftrace.h>
#include <linux/rmap.h>
#include <linux/elf.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/pm.h>
#include <linux/cpuidle.h>

#include <asm/atomic.h>
#include <asm/cpu.h>
#include <asm/process.h>
#include <asm/a.out.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/regs_state.h>
#include <asm/boot_init.h>
#include <asm/e2k_debug.h>
#include <asm/sge.h>
#include <asm/ucontext.h>

#ifdef CONFIG_MONITORS
#include <asm/monitors.h>
#endif /* CONFIG_MONITORS */

#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#include <asm/e2k_ptypes.h>
#include <asm/prot_loader.h>
#endif /* CONFIG_PROTECTED_MODE */

#undef	DEBUG_PROCESS_MODE
#undef	DebugP
#define	DEBUG_PROCESS_MODE	0	/* processes */
#define DebugP(...)		DebugPrint(DEBUG_PROCESS_MODE ,##__VA_ARGS__)

#undef	DEBUG_TASK_MODE
#undef	DebugT
#define	DEBUG_TASK_MODE		0	/* tasks */
#define DebugT(...)		DebugPrint(DEBUG_TASK_MODE ,##__VA_ARGS__)

#undef	DEBUG_QUEUED_TASK_MODE
#undef	DebugQT
#define	DEBUG_QUEUED_TASK_MODE	0	/* queue task and release */
#define DebugQT(...)		DebugPrint(DEBUG_QUEUED_TASK_MODE ,##__VA_ARGS__)

#undef	DEBUG_QUEUED_STACK_MODE
#undef	DebugQS
#define	DEBUG_QUEUED_STACK_MODE	0	/* queue stck and release */
#define DebugQS(...)		DebugPrint(DEBUG_QUEUED_STACK_MODE ,##__VA_ARGS__)

#undef	DEBUG_EXECVE_MODE
#undef	DebugEX
#define	DEBUG_EXECVE_MODE	0	/* execve and exit */
#define DebugEX(...)		DebugPrint(DEBUG_EXECVE_MODE ,##__VA_ARGS__)

#undef	DEBUG_DATA_STACK_MODE
#undef	DebugDS
#define	DEBUG_DATA_STACK_MODE	0	/* user data stack */
#define DebugDS(...)		DebugPrint(DEBUG_DATA_STACK_MODE ,##__VA_ARGS__)

#undef	DEBUG_EXPAND_STACK_MODE
#undef	DebugES
#define	DEBUG_EXPAND_STACK_MODE	0	/* expand stack */
#define DebugES(...)		DebugPrint(DEBUG_EXPAND_STACK_MODE ,##__VA_ARGS__)


#undef	DEBUG_EXPAND_STACK_GDB
#undef	DebugES_GDB
#define	DEBUG_EXPAND_STACK_GDB	0	/* expand stack for gdb*/
#define DebugES_GDB(...)		DebugPrint(DEBUG_EXPAND_STACK_GDB ,##__VA_ARGS__)

#undef	DEBUG_CU_MODE
#undef	DebugCU
#define	DEBUG_CU_MODE		0	/* compilation unit */
#define DebugCU(...)		DebugPrint(DEBUG_CU_MODE ,##__VA_ARGS__)

#undef	DEBUG_US_MODE
#undef	DebugUS
#define	DEBUG_US_MODE		0	/* user stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_MODE ,##__VA_ARGS__)

#undef	DEBUG_KS_MODE
#undef	DebugKS
#define	DEBUG_KS_MODE		0	/* kernel stacks */
#define DebugKS(...)		DebugPrint(DEBUG_KS_MODE ,##__VA_ARGS__)

#undef	DEBUG_ST_MODE
#undef	DebugST
#define	DEBUG_ST_MODE		0	/* all stacks manipulation */
#define DebugST(...)		DebugPrint(DEBUG_ST_MODE ,##__VA_ARGS__)

#undef	DEBUG_SD_MODE
#undef	DebugSD
#define	DEBUG_SD_MODE		0	/* go stack down */
#define DebugSD(...)		DebugPrint(DEBUG_SD_MODE ,##__VA_ARGS__)

#undef	DEBUG_CT_MODE
#undef	DebugCT
#define	DEBUG_CT_MODE		0	/* copy thread */
#define DebugCT(...)		DebugPrint(DEBUG_CT_MODE ,##__VA_ARGS__)

#undef	DEBUG_CL_MODE
#undef	DebugCL
#define	DEBUG_CL_MODE		0	/* clone thread */
#define DebugCL(...)		DebugPrint(DEBUG_CL_MODE ,##__VA_ARGS__)

#undef	DEBUG_FORK_MODE
#undef	DebugF
#define	DEBUG_FORK_MODE		0	/* fork process */
#define DebugF(...)		DebugPrint(DEBUG_FORK_MODE ,##__VA_ARGS__)

#undef	DebugNUMA
#undef	DEBUG_NUMA_MODE
#define	DEBUG_NUMA_MODE		0	/* NUMA */
#define DebugNUMA(...)		DebugPrint(DEBUG_NUMA_MODE ,##__VA_ARGS__)

#define	DEBUG_32		0	/* processes */
#define DebugP_32(...)		DebugPrint(DEBUG_32 ,##__VA_ARGS__)

#undef DEBUG_HS_MODE
#define	DEBUG_HS_MODE		0	/* Hard Stack Clone and Alloc */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE ,##__VA_ARGS__)

#undef	DEBUG_HS_FAIL_MODE
#undef	DebugHSF
#define	DEBUG_HS_FAIL_MODE	0	/* Hard Stack Clone and Alloc */
					/* failure */
#define DebugHSF(...)		DebugPrint(DEBUG_HS_FAIL_MODE ,##__VA_ARGS__)

#define DEBUG_FTRACE_MODE	0
#if DEBUG_FTRACE_MODE
# define DebugFTRACE(...)	pr_info(__VA_ARGS__)
#else
# define DebugFTRACE(...)
#endif

#define	DEBUG_CTX_MODE		0	/* setcontext/swapcontext */
#if DEBUG_CTX_MODE
#define	DebugCTX(...)		DebugPrint(DEBUG_CTX_MODE ,##__VA_ARGS__)
#else
#define DebugCTX(...)
#endif

#undef	DEBUG_SPRs_MODE
#define	DEBUG_SPRs_MODE		0	/* stack pointers registers */

#undef	DEBUG_CpuR_MODE
#define	DEBUG_CpuR_MODE		0	/* CPU registers */

#undef	DEBUG_SWREGS_MODE
#define	DEBUG_SWREGS_MODE	0	/* switch registers */

enum {
	HW_STACK_TYPE_PS,
	HW_STACK_TYPE_PCS
};

unsigned long idle_halt;
EXPORT_SYMBOL(idle_halt);
unsigned long idle_nomwait;
EXPORT_SYMBOL(idle_nomwait);

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	memcpy(dst, src, sizeof(*dst));

	return 0;
}

char *debug_process_name = NULL;
int debug_process_name_len = 0;

static int __init debug_process_name_setup(char *str)
{
	debug_process_name = str;
	debug_process_name_len = strlen(debug_process_name);
	return 1;
}

__setup("procdebug=", debug_process_name_setup);

extern void schedule_tail(struct task_struct *prev);
extern struct machdep machine;
typedef	void (*start_fn)(u64 __start);

#ifdef CONFIG_PROTECTED_MODE
extern void * rtl_GetNextInitFunction(rtl_Unit_t *unit_p, void **entry_pp);
#endif /* CONFIG_PROTECTED_MODE */

static void release_hw_stacks(struct thread_info *);

/*
 * SLAB cache for task_struct structures (task) & thread_info (ti)
 */
struct kmem_cache __nodedata *task_cachep = NULL;
struct kmem_cache __nodedata *thread_cachep = NULL;
#ifdef	CONFIG_NUMA
struct kmem_cache __nodedata *node_policy_cache = NULL;
#endif	/* CONFIG_NUMA */

static DEFINE_PER_CPU(struct list_head, hw_stacks_to_free_list);
static DEFINE_PER_CPU(struct task_struct *, kfree_hw_stacks_task);


/*
 * User hardware stack mode
 */
int uhws_mode = UHWS_MODE_PSEUDO;
static int __init uhws_setup(char *str)
{
	if (!strcmp(str, "cont"))
		uhws_mode = UHWS_MODE_CONT;
	else if (!strcmp(str, "pseudo"))
		uhws_mode = UHWS_MODE_PSEUDO;
	else
		pr_err("Unknown user hardware stack mode\n");
	return 1;
}
__setup("uhws=", uhws_setup);

const char *arch_vma_name(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_HW_STACK_PS)
		return "[procedure stack]";
	else if (vma->vm_flags & VM_HW_STACK_PCS)
		return "[chain stack]";
	return NULL;
}

void queue_hw_stack_to_free(struct task_struct *task)
{
	struct thread_info *ti = task_thread_info(task);
	struct task_struct *daemon;
	unsigned long flags;
	int cpu;

	DebugQS("started on CPU %d for task 0x%p %d (%s)\n",
		raw_smp_processor_id(), task, task->pid, task->comm);

	local_irq_save(flags);

	/*
	 * We've already taken a reference to the task_struct
	 */

	cpu = smp_processor_id();

	list_add_tail(&ti->hw_stacks_to_free,
		      &per_cpu(hw_stacks_to_free_list, cpu));

	local_irq_restore(flags);

	daemon = per_cpu(kfree_hw_stacks_task, cpu);

	if (daemon && daemon->state != TASK_RUNNING)
		wake_up_process(daemon);
}

static void free_queued_hw_stacks(int cpu)
{
	struct list_head *head;
	struct thread_info *ti;

	head = &__get_cpu_var(hw_stacks_to_free_list);

	raw_local_irq_disable();
	while (!list_empty(head)) {
		ti = list_entry(
			head->next, struct thread_info, hw_stacks_to_free);
		BUG_ON(!ti || !ti->task);

		list_del_init(&ti->hw_stacks_to_free);

		raw_local_irq_enable();

		DebugQS("on CPU %d will free hw stacks for task 0x%p %d (%s)\n",
			cpu, ti->task, ti->task->pid, ti->task->comm);

		release_hw_stacks(ti);

		put_task_struct(ti->task);

		raw_local_irq_disable();
		BUG_ON(cpu != raw_smp_processor_id());
	}
	raw_local_irq_enable();
}

static int kfree_hw_stacksd(void *data)
{
	int cpu = (int) (unsigned long) data;

	while (kthread_should_stop() == 0) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		__set_current_state(TASK_RUNNING);

		free_queued_hw_stacks(cpu);
	}

	return 0;
}

static int create_kfree_hw_stacks_tasks()
{
	int cpu;

	for_each_possible_cpu(cpu) {
		per_cpu(kfree_hw_stacks_task, cpu) =
				kthread_create_on_cpu(kfree_hw_stacksd,
						      (void *) cpu, cpu,
						      "kfree_hw_stacksd/%u");
		BUG_ON(IS_ERR(per_cpu(kfree_hw_stacks_task, cpu)));
		kthread_unpark(per_cpu(kfree_hw_stacks_task, cpu));
	}

	return 0;
}
arch_initcall(create_kfree_hw_stacks_tasks);

void __init
task_caches_init(void)
{
	int cpu;
#ifdef	CONFIG_NUMA
	int nid;
#endif	/* ! CONFIG_NUMA */

	task_cachep = kmem_cache_create("task_struct",
					sizeof(struct task_struct), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (!task_cachep)
		panic("Cannot create task structures SLAB cache");

	thread_cachep = kmem_cache_create("thread_info",
					sizeof(struct thread_info), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (!thread_cachep)
		panic("Cannot create thread info structures SLAB cache");

#ifdef	CONFIG_NUMA
	node_policy_cache = kmem_cache_create("node_mempolicy",
					sizeof(struct mempolicy), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (!node_policy_cache)
		panic("Cannot create memory policy structures SLAB cache");

	for_each_node_has_dup_kernel(nid) {
		*node_task_cachep(nid) = task_cachep;
		*node_thread_cachep(nid) = thread_cachep;
		*the_node_policy_cache(nid) = node_policy_cache;
	}
#endif	/* ! CONFIG_NUMA */

	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(&per_cpu(hw_stacks_to_free_list, cpu));
}

void *alloc_kernel_c_stack()
{
	int node = tsk_fork_get_node(current);
	void *addr;

	addr = alloc_pages_exact_nid(node, KERNEL_C_STACK_SIZE,
				     GFP_KERNEL | __GFP_NOWARN);
	if (!addr)
		addr = vmalloc_node(KERNEL_C_STACK_SIZE, node);

	return addr;
}

void free_kernel_c_stack(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		free_pages_exact(addr, KERNEL_C_STACK_SIZE);
}

static void *alloc_kernel_p_stack(struct thread_info *ti)
{
	int node = tsk_fork_get_node(current);
	void *addr;

	addr = alloc_pages_exact_nid(node, KERNEL_P_STACK_SIZE,
				     GFP_KERNEL | __GFP_NOWARN);
	if (!addr)
		addr = vmalloc_node(KERNEL_P_STACK_SIZE, node);

	return addr;
}

static void free_kernel_p_stack(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		free_pages_exact(addr, KERNEL_P_STACK_SIZE);
}

static void *alloc_kernel_pc_stack(struct thread_info *ti)
{
	int node = tsk_fork_get_node(current);
	void *addr;

	addr = alloc_pages_exact_nid(node, KERNEL_PC_STACK_SIZE,
				     GFP_KERNEL | __GFP_NOWARN);
	if (!addr)
		addr = vmalloc_node(KERNEL_PC_STACK_SIZE, node);

	return addr;
}

static void free_kernel_pc_stack(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		free_pages_exact(addr, KERNEL_PC_STACK_SIZE);
}

static void free_user_stack(void *stack_base, e2k_size_t max_stack_size,
		e2k_size_t kernel_part_size)
{
	int retval;

	DebugUS("started: stack base 0x%llx max stack size 0x%lx, kernel part size 0x%lx\n",
		(u64) stack_base, max_stack_size, kernel_part_size);
	set_ts_flag(TS_KERNEL_SYSCALL);
	retval = vm_munmap((unsigned long) stack_base,
			   max_stack_size + kernel_part_size);
	clear_ts_flag(TS_KERNEL_SYSCALL);
	DebugUS("do_munmap() returned %d\n", retval);
	if (retval) {
		pr_err("Could not do munmap: error %d\n", retval);
		BUG();
	}
	DebugUS("freed stack base 0x%llx stack size 0x%lx\n",
		(u64) stack_base, max_stack_size + kernel_part_size);
}

static void *alloc_user_hard_stack(size_t stack_size, size_t present_offset,
		size_t present_size, size_t kernel_size,
		unsigned long user_stacks_base, unsigned long user_stacks_end,
		int type)
{
	e2k_addr_t		stack_addr;
	struct vm_area_struct	*vma;
	struct thread_info	*ti = current_thread_info();
	e2k_addr_t		u_ps_base, u_pcs_base;
	unsigned long		ti_status;
	int			ret = 0;

	BUG_ON(!IS_ALIGNED(kernel_size, PAGE_SIZE) ||
	       !IS_ALIGNED(stack_size, PAGE_SIZE) ||
	       !IS_ALIGNED(present_size, PAGE_SIZE));
	BUG_ON(!current->mm);

	if (!UHWS_PSEUDO_MODE)
		stack_size += kernel_size;

	BUG_ON(!present_size);
	present_size += kernel_size;

	if (present_size > stack_size) {
		DebugHS("alloc_user_hard_stack(): present_size 0x%lx > stack_size 0x%lx\n",
			present_size, stack_size);
		return NULL;
	}

	DebugHS("started: stack size 0x%lx, including present 0x%lx (user 0x%lx/kernel 0x%lx)\n",
			stack_size, present_size, present_size - kernel_size,
			kernel_size);

	/*
	 * In the case of pseudo discontinuous user hardware stacks one
	 * shouldn't reuse already freed memory of user hardware stacks,
	 * otherwise there will be a problem with longjmp (we won't be
	 * able to find needed area unambiguously).
	 */
	if (UHWS_PSEUDO_MODE) {
		if (ti->cur_ps) {
			u_ps_base = (e2k_addr_t)ti->cur_ps->base;
			user_stacks_base = max(user_stacks_base, u_ps_base);
		}

		if (ti->cur_pcs) {
			u_pcs_base = (e2k_addr_t)ti->cur_pcs->base;
			user_stacks_base = max(user_stacks_base, u_pcs_base);
		}
	}

	/*
	 * Hardware stacks are essentially divided into 4 parts:
	 * 1) Allocated area below current window;
	 * 2) Current resident window (as described by PSP and PCSP registers);
	 * 3) Allocated but unused area above current window;
	 * 4) Unallocated area.
	 *
	 * They have the following flags set:
	 * 1) VM_READ | VM_WRITE
	 * 2) VM_READ | VM_WRITE | VM_DONTCOPY | VM_DONTMIGRATE | VM_HW_STACK
	 * 3) VM_READ | VM_WRITE | VM_DONTCOPY
	 * 4) VM_DONTCOPY | VM_DONTMIGRATE | VM_DONTEXPAND
	 *
	 * Initially only 2) and 4) areas exist so we can set
	 * (VM_DONTCOPY | VM_DONTMIGRATE) on the whole vma in
	 * vm_mmap() below.
	 *
	 * We also set VM_DONTEXPAND initially to remove VM_LOCKED
	 * from 4) area in case it is set in current->mm->def_flags,
	 * but remove it later for 2) area.
	 *
	 * And the whole stack area has VM_PRIVILEGED flag set to
	 * protect it from all user modifications with except for
	 * mlock/munlock.
	 *
	 * Also the whole stack area has VM_HW_STACK_P(C)S flag set.
	 */
	ti_status = (type == HW_STACK_TYPE_PS) ?
			TS_MMAP_HW_STACK_PS : TS_MMAP_HW_STACK_PCS;
	current_thread_info()->status |= ti_status;
	stack_addr = vm_mmap(NULL, user_stacks_base, stack_size,
				PROT_NONE,
				MAP_PRIVATE | MAP_ANONYMOUS,
				0);
	current_thread_info()->status &= ~ti_status;
	if (IS_ERR_VALUE(stack_addr)) {
		DebugHSF("mmap() returned error %ld\n", (long) stack_addr);
		WARN_ONCE(stack_addr != -ENOMEM, "vm_mmap failed with %lld\n",
				stack_addr);
		return NULL;
	}
	DebugHS("vm_mmap() returned stack addr 0x%lx\n", stack_addr);

	if (stack_addr < user_stacks_base ||
			stack_addr + stack_size > user_stacks_end) {
		DebugHSF("bad stack base or end\n");
		goto out_unmap;
	}

	down_write(&current->mm->mmap_sem);

	vma = find_vma(current->mm, stack_addr);
	if (vma->vm_start != stack_addr ||
			vma->vm_end != stack_addr + stack_size) {
		up_write(&current->mm->mmap_sem);
		pr_err("Invalid VMA structure start addr 0x%lx or end 0x%lx (should be <= 0x%lx & >= 0x%lx)\n",
			vma->vm_start, vma->vm_end,
			stack_addr, stack_addr + stack_size);
		BUG();
	}

	up_write(&current->mm->mmap_sem);

	BUG_ON((vma->vm_flags & VM_LOCKED) ||
	       (vma->vm_flags & (VM_DONTCOPY | VM_DONTMIGRATE) !=
				(VM_DONTCOPY | VM_DONTMIGRATE)));

	if (present_size) {
		/*
		 * One should not populate the resident part of new hardware
		 * stack area, if this area is allocated while hardware stack
		 * expanding. A part of the resident window will be populated
		 * by remapping of old hardware stack area, other part will be
		 * populated manually.
		 */
		bool populate = (present_offset) ? false : true;

		if ((ret = update_vm_area_flags(stack_addr + present_offset,
				present_size, VM_HW_STACK, VM_DONTEXPAND))) {
			DebugHSF("update_vm_area_flags returned %d\n", ret);
			goto out_unmap;
		}

		set_ts_flag(TS_KERNEL_SYSCALL);

		DebugHS("set PROT_READ | PROT_WRITE from 0x%lx to 0x%lx\n",
			stack_addr, stack_addr + present_offset + present_size);
		if ((ret = sys_mprotect(stack_addr,
					present_offset + present_size,
					PROT_READ | PROT_WRITE))) {
			DebugHSF("sys_mprotect returned %d\n", ret);
			goto out_unmap;
		}

		clear_ts_flag(TS_KERNEL_SYSCALL);

		DebugHS("mlock from 0x%lx to 0x%lx\n",
				stack_addr + present_offset,
				stack_addr + present_offset + present_size);
		if ((ret = mlock_hw_stack(stack_addr + present_offset,
					  present_size, populate))) {
			DebugHSF("mlock returned %d\n", ret);
			goto out_unmap;
		}

		if (!present_offset)
			goto out;

		if ((ret = update_vm_area_flags(stack_addr, present_offset, 0,
				VM_DONTCOPY | VM_DONTMIGRATE |
						VM_DONTEXPAND))) {
			DebugHSF("update_vm_area_flags returned %d\n", ret);
			goto out_unmap;
		}
	}

	if (present_offset) {
		/*
		 * One shouldn't populate this area, because it will be
		 * populated by remapping of old hardware stack area.
		 */
		if (current->mm->def_flags & VM_LOCKED) {
			DebugHS("mlock from 0x%lx to 0x%lx\n",
				stack_addr, stack_addr + present_offset);
			if ((ret = mlock_hw_stack(stack_addr,
					  present_offset, false))) {
				DebugHSF("mlock returned %d\n", ret);
				goto out_unmap;
			}
		}
	}

out:
	DebugHS("finished and returns stack base 0x%lx\n", stack_addr);
	return (void *) stack_addr;

out_unmap:
	set_ts_flag(TS_KERNEL_SYSCALL);
	vm_munmap(stack_addr, stack_size);
	clear_ts_flag(TS_KERNEL_SYSCALL);

	return NULL;
}

struct hw_stack_area *alloc_user_p_stack(size_t stack_area_size,
					 size_t present_offset,
					 size_t present_size)
{
	struct hw_stack_area *ps;

	ps = kmalloc(sizeof(struct hw_stack_area), GFP_KERNEL);
	if (!ps)
		return NULL;

	ps->base = alloc_user_hard_stack(stack_area_size, present_offset,
				present_size, KERNEL_P_STACK_SIZE,
				USER_P_STACKS_BASE,
				USER_P_STACKS_BASE + USER_P_STACKS_MAX_SIZE,
				HW_STACK_TYPE_PS);
	if (!ps->base) {
		kfree(ps);
		return NULL;
	}

	ps->size = stack_area_size - KERNEL_P_STACK_SIZE;
	ps->offset = present_offset;
	ps->top = present_offset + present_size;

	return ps;
}

static void *alloc_user_p_stack_cont(size_t max_stack_size, size_t present_size)
{
	return alloc_user_hard_stack(max_stack_size, 0, present_size,
			KERNEL_P_STACK_SIZE, USER_P_STACKS_BASE,
			USER_P_STACKS_BASE + USER_P_STACKS_MAX_SIZE,
			HW_STACK_TYPE_PS);
}

struct hw_stack_area *alloc_user_pc_stack(size_t stack_area_size,
					  size_t present_offset,
					  size_t present_size)
{
	struct hw_stack_area *pcs;

	pcs = kmalloc(sizeof(struct hw_stack_area), GFP_KERNEL);
	if (!pcs)
		return NULL;

	pcs->base = alloc_user_hard_stack(stack_area_size, present_offset,
			present_size, KERNEL_PC_STACK_SIZE, USER_PC_STACKS_BASE,
			USER_PC_STACKS_BASE + USER_PC_STACKS_MAX_SIZE,
			HW_STACK_TYPE_PCS);
	if (!pcs->base) {
		kfree(pcs);
		return NULL;
	}

	pcs->size = stack_area_size - KERNEL_PC_STACK_SIZE;
	pcs->offset = present_offset;
	pcs->top = present_offset + present_size;

	return pcs;
}

static void *alloc_user_pc_stack_cont(size_t max_stack_size,
				      size_t present_size)
{
	return alloc_user_hard_stack(max_stack_size, 0, present_size,
			KERNEL_PC_STACK_SIZE, USER_PC_STACKS_BASE,
			USER_PC_STACKS_BASE + USER_PC_STACKS_MAX_SIZE,
			HW_STACK_TYPE_PCS);
}

static void free_user_p_stack(struct hw_stack_area *ps, int free_desc)
{
	if (ps) {
		size_t present_size = ps->top - ps->offset +
				      KERNEL_P_STACK_SIZE;
		int ret;

		BUG_ON(!ps->base);

		DebugHS("munlock 0x%lx bytes from 0x%lx\n",
			present_size, ps->base + ps->offset);

		ret = munlock_hw_stack((unsigned long) ps->base + ps->offset,
				       present_size);
		BUG_ON(ret);

		free_user_stack(ps->base, ps->size, KERNEL_P_STACK_SIZE);

		if (free_desc)
			kfree(ps);
	}
}

static void free_user_p_stack_cont(void *stack_base, size_t max_stack_size,
			unsigned long present_offset, size_t present_top)
{
	size_t present_size = present_top - present_offset +
			      KERNEL_P_STACK_SIZE;
	int ret;

	DebugHS("munlock from 0x%p size 0x%lx\n",
		stack_base + present_offset, present_size);

	ret = munlock_hw_stack((unsigned long) stack_base + present_offset,
			       present_size);
	BUG_ON(ret);

	return free_user_stack(stack_base, max_stack_size, KERNEL_P_STACK_SIZE);
}

static void free_user_pc_stack(struct hw_stack_area *pcs, int free_desc)
{
	if (pcs) {
		size_t present_size = pcs->top - pcs->offset +
				      KERNEL_PC_STACK_SIZE;
		int ret;

		BUG_ON(!pcs->base);

		DebugHS("munlock 0x%lx bytes from 0x%lx\n",
			present_size, pcs->base + pcs->offset);

		ret = munlock_hw_stack((unsigned long) pcs->base + pcs->offset,
				       present_size);
		BUG_ON(ret);

		free_user_stack(pcs->base, pcs->size, KERNEL_PC_STACK_SIZE);

		if (free_desc)
			kfree(pcs);
	}
}

static void free_user_pc_stack_cont(void *stack_base, size_t max_stack_size,
			unsigned long present_offset, size_t present_top)
{
	size_t present_size = present_top - present_offset +
			      KERNEL_PC_STACK_SIZE;
	int ret;

	DebugHS("munlock from 0x%lx size 0x%lx\n",
		stack_base + present_offset, present_size);

	ret = munlock_hw_stack((unsigned long) stack_base + present_offset,
			       present_size);
	BUG_ON(ret);

	return free_user_stack(stack_base, max_stack_size,
			       KERNEL_PC_STACK_SIZE);
}

static void free_user_p_stack_areas(struct list_head *ps_list)
{
	struct hw_stack_area	*user_p_stack;
	struct hw_stack_area	*n;

	list_for_each_entry_safe(user_p_stack, n, ps_list, list_entry) {
		list_del(&user_p_stack->list_entry);
		free_user_p_stack(user_p_stack, true);
	}
}

static void free_user_pc_stack_areas(struct list_head *pcs_list)
{
	struct hw_stack_area	*user_pc_stack;
	struct hw_stack_area	*n;

	list_for_each_entry_safe(user_pc_stack, n, pcs_list, list_entry) {
		list_del(&user_pc_stack->list_entry);
		free_user_pc_stack(user_pc_stack, true);
	}
}

void free_user_old_pc_stack_areas(struct list_head *old_u_pcs_list)
{
	struct hw_stack_area	*user_old_pc_stack;
	struct hw_stack_area	*n;

	list_for_each_entry_safe(user_old_pc_stack, n, old_u_pcs_list,
				 list_entry) {
		list_del(&user_old_pc_stack->list_entry);
		kfree(user_old_pc_stack);
	}
}

struct task_struct *alloc_task_struct_node(int node)
{
	struct kmem_cache *p;
	int tmp;

	tmp = ts_get_node(current_thread_info());
	if (tmp != NUMA_NO_NODE)
		node = tmp;

	if (!node_has_online_mem(node)) {
		DebugT("node #%d has not memory, so alloc on default node\n",
			node);
		node = NUMA_NO_NODE;
	}

	p = kmem_cache_alloc_node(task_cachep, GFP_KERNEL, node);
	DebugT("NODE #%d CPU #%d allocated task struct 0x%p on node %d\n",
		numa_node_id(), smp_processor_id(), p, node);

	return (struct task_struct *) p;
}

void free_task_struct(struct task_struct *task)
{
	DebugP("started for task 0x%p (%s)\n", task, task->comm);

	kmem_cache_free(task_cachep, task);
}

static void initialize_thread_info(struct thread_info *ti)
{
	/*
	 * If an error occurs during copy_process(), we will check
	 * these fields and free user hardware stacks if needed.
	 */
	if (UHWS_PSEUDO_MODE) {
		ti->cur_ps = NULL;
		ti->cur_pcs = NULL;
	} else {
		ti->ps_base = NULL;
		ti->pcs_base = NULL;
	}
}

struct thread_info *alloc_thread_info_node(struct task_struct *task, int node)
{
	struct kmem_cache *ti;
	int tmp;

	tmp = ts_get_node(current_thread_info());
	if (tmp != NUMA_NO_NODE)
		node = tmp;

	if (!node_has_online_mem(node)) {
		DebugT("node #%d has not memory, so alloc on default node\n",
			node);
		node = NUMA_NO_NODE;
	}

	ti = kmem_cache_alloc_node(thread_cachep, GFP_KERNEL, node);

	if (ti)
		initialize_thread_info((struct thread_info *) ti);

	DebugT("NODE #%d CPU #%d allocated thread info 0x%p on node %d\n",
		numa_node_id(), smp_processor_id(), ti, node);

	return (struct thread_info *) ti;
}

void free_thread_info(struct thread_info *ti)
{
	DebugP("started for task %s\n", ti->task->comm);

	BUG_ON(test_ti_status_flag(ti, TS_MAPPED_HW_STACKS));
	BUG_ON(UHWS_PSEUDO_MODE && (ti->cur_ps || ti->cur_pcs));

	/*
	 * On e2k kernel data stack is not located together with
	 * thread_info cause it is too big.
	 */
	if (ti->k_stk_base) {
		DebugEX("free kernel C stack from 0x%lx\n", ti->k_stk_base);

		free_kernel_c_stack((void *) ti->k_stk_base);

		ti->k_stk_base = 0;
	}

	kmem_cache_free(thread_cachep, ti);
}


static u64 _get_user_main_c_stack(e2k_addr_t sp, e2k_size_t max_stack_size,
		e2k_size_t init_size, e2k_addr_t *stack_top)
{
	e2k_addr_t		stack_start, stack_end;
	struct vm_area_struct	*vma;

	DebugDS("started: sp 0x%lx max stack "
		"size 0x%lx init size 0x%lx\n",
		sp, max_stack_size, init_size);

	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, sp);
	DebugDS("find_vma() returned VMA 0x%p "
		"start 0x%lx end 0x%lx\n",
		vma, vma->vm_start, vma->vm_end);

	BUG_ON(!(vma->vm_flags & VM_GROWSDOWN));

	stack_end = vma->vm_end;
	*stack_top = stack_end;

#ifdef CONFIG_ALLOC_MAX_STACK
	stack_start = stack_end - max_stack_size;
#else
	stack_start = stack_end - init_size;
# ifdef CONFIG_MAKE_ALL_PAGES_VALID
	/* Leave the guard page out of stack
	 * (see comment before expand_user_data_stack()) */
	if (stack_start > vma->vm_start + PAGE_SIZE)
		stack_start = vma->vm_start + PAGE_SIZE;
# endif
#endif

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
	if (make_vma_pages_valid(vma, stack_start - PAGE_SIZE, stack_end)) {
		DebugDS("make valid failed\n");
		return 0;
	}
#endif

	DebugDS("start 0x%lx, end 0x%lx, init 0x%lx\n",
		stack_start, stack_end, init_size);

	/* Leave the guard page out of stack
	 * (see comment before expand_user_data_stack()) */
	if (stack_start - PAGE_SIZE < vma->vm_start) {
		DebugDS("will expand stack space "
			"from 0x%lx to 0x%lx\n",
			stack_start, vma->vm_start);
		if (expand_stack(vma, stack_start - PAGE_SIZE)) {
			up_write(&current->mm->mmap_sem);
			DebugDS("expand_stack() "
				"failed\n");
			return 0;
		}
	}
	up_write(&current->mm->mmap_sem);

	DebugDS("returns stack base 0x%lx\n",
		stack_start);
	return stack_start;
}

static u64 get_user_main_c_stack(e2k_addr_t sp, e2k_addr_t *stack_top)
{
	BUILD_BUG_ON(USER_MAIN_C_STACK_INIT_SIZE > USER_MAIN_C_STACK_SIZE);

	return _get_user_main_c_stack(sp, USER_MAIN_C_STACK_SIZE,
					USER_MAIN_C_STACK_INIT_SIZE,
					stack_top);
}

/*
 * This function allocates user's memory for needs of Compilation Unit Table.
 */

static int alloc_cu_table(e2k_addr_t cut_base_addr, e2k_size_t cut_size)
{
	e2k_addr_t	cut_start;

	DebugCU("started: cut base 0x%lx, size 0x%lx\n",
			cut_base_addr, cut_size);

	set_ts_flag(TS_KERNEL_SYSCALL);
	cut_start = vm_mmap(NULL, cut_base_addr, cut_size,
				PROT_READ | PROT_WRITE,
				MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0);
	clear_ts_flag(TS_KERNEL_SYSCALL);
	DebugCU("vm_mmap() returned %ld\n", (long) cut_start);

	return cut_start ? 0 : -ENOMEM;
}

static int
prepare_next_p_stack_area_before_switch(struct hw_stack_area *cur_u_ps,
	struct hw_stack_area *prev_u_ps)
{
	e2k_addr_t	from;
	e2k_size_t	sz;
	int		retval;

	/*
	 * One should munlock a part of resident area of the previous hardware
	 * stack area, that should become not resident, to remap already not
	 * locked pages.
	 */
	if (!(current->mm->def_flags & VM_LOCKED)) {
		from = (e2k_addr_t)(prev_u_ps->base + prev_u_ps->offset);
		sz = USER_P_STACK_BYTE_INCR;
		retval = munlock_hw_stack(from, sz);
		DebugHS("munlock 0x%lx from 0x%lx\n", sz, from);
		if (retval) {
			DebugHS("munlock_hw_stack() returned error\n");
			return retval;
		}
	}

	from = (e2k_addr_t)prev_u_ps->base;
	sz =  prev_u_ps->size + KERNEL_P_STACK_SIZE;
	DebugHS("remap 0x%lx bytes from 0x%lx to 0x%lx\n",
		sz, from, cur_u_ps->base);
	retval = remap_user_hard_stack(cur_u_ps->base, (void *)from, sz);
	if (retval) {
		DebugHS("remap_user_hard_stack() returned error\n");
		return retval;
	}

	/*
	 * While allocating new user hardware stack area, area for the resident
	 * part was mlocked, but was not populated. A part of new resident area
	 * was populated by remapping of the previous user hardware stack area.
	 * Other part of new resident area should be populated manually.
	 */
	from = (e2k_addr_t)cur_u_ps->base + cur_u_ps->top +
				KERNEL_P_STACK_SIZE - USER_P_STACK_BYTE_INCR;
	sz = USER_P_STACK_BYTE_INCR;
	DebugHS("populate 0x%lx bytes from 0x%lx\n", sz, from);

	retval = __mm_populate(from, sz, 0);
	if (retval)
		DebugHS("__mm_populate() returned error\n");

	return retval;
}

static void
prepare_prev_p_stack_area_after_switch(struct hw_stack_area *prev_u_ps)
{
	list_del(&prev_u_ps->list_entry);
	DebugHS("user Procedure stack area 0x%p was deleted from user Procedure stack areas list\n",
		prev_u_ps);
	free_user_p_stack(prev_u_ps, false);
}

int switch_to_next_p_stack_area(void)
{
	thread_info_t		*ti = current_thread_info();
	struct hw_stack_area	*cur_u_ps;
	struct hw_stack_area	*prev_u_ps;
	e2k_psp_lo_t		psp_lo;
	e2k_psp_hi_t		psp_hi;
	long			flags;
	int			retval;

	cur_u_ps = ti->cur_ps;
	prev_u_ps = list_entry(cur_u_ps->list_entry.prev,
			       struct hw_stack_area, list_entry);
	BUG_ON(cur_u_ps == prev_u_ps);
	DebugHS("cur_u_ps 0x%p prev_u_ps 0x%p\n",
		cur_u_ps, prev_u_ps);

	retval = prepare_next_p_stack_area_before_switch(cur_u_ps, prev_u_ps);
	if (retval) {
		DebugHS("prepare_next_p_stack_area_before_switch() returned error\n");
		return retval;
	}

	raw_all_irq_save(flags);
	E2K_FLUSHR;
	psp_hi = READ_PSP_HI_REG();
	psp_lo = READ_PSP_LO_REG();
	psp_hi.PSP_hi_ind = psp_hi.PSP_hi_ind - USER_P_STACK_BYTE_INCR;
	psp_hi.PSP_hi_size = cur_u_ps->top - cur_u_ps->offset +
			     KERNEL_P_STACK_SIZE;
	psp_lo.PSP_lo_base = (e2k_addr_t)cur_u_ps->base + cur_u_ps->offset;
	WRITE_PSP_REG(psp_hi, psp_lo);
	raw_all_irq_restore(flags);
	DebugHS("new PS state: base 0x%llx ind 0x%x size 0x%x\n",
		psp_lo.PSP_lo_base, psp_hi.PSP_hi_ind, psp_hi.PSP_hi_size);

	prepare_prev_p_stack_area_after_switch(prev_u_ps);

	return retval;
}

static int
prepare_next_pc_stack_area_before_switch(struct hw_stack_area *cur_u_pcs,
	struct hw_stack_area *prev_u_pcs)
{
	e2k_addr_t	from;
	e2k_size_t	sz;
	int		retval;

	/*
	 * One should munlock a part of resident area of the previous hardware
	 * stack area, that should become not resident, to remap already not
	 * locked pages.
	 */
	if (!(current->mm->def_flags & VM_LOCKED)) {
		from = (e2k_addr_t)(prev_u_pcs->base + prev_u_pcs->offset);
		sz = USER_PC_STACK_BYTE_INCR;
		retval = munlock_hw_stack(from, sz);
		DebugHS("munlock 0x%lx from 0x%lx\n", sz, from);
		if (retval) {
			DebugHS("munlock_hw_stack() returned error\n");
			return retval;
		}
	}

	from = (e2k_addr_t)prev_u_pcs->base;
	sz =  prev_u_pcs->size + KERNEL_PC_STACK_SIZE;
	DebugHS("remap 0x%lx bytes from 0x%lx to 0x%lx\n",
		sz, from, cur_u_pcs->base);
	retval = remap_user_hard_stack(cur_u_pcs->base, (void *)from, sz);
	if (retval) {
		DebugHS("remap_user_hard_stack() returned error\n");
		return retval;
	}

	/*
	 * While allocating new user hardware stack area, area for the resident
	 * part was mlocked, but was not populated. A part of new resident area
	 * was populated by remapping of the previous user hardware stack area.
	 * Other part of new resident area should be populated manually.
	 */
	from = (e2k_addr_t)cur_u_pcs->base + cur_u_pcs->top +
			KERNEL_PC_STACK_SIZE - USER_PC_STACK_BYTE_INCR;
	sz = USER_PC_STACK_BYTE_INCR;
	DebugHS("populate 0x%lx bytes from 0x%lx\n", sz, from);
	retval = __mm_populate(from, sz, 0);
	if (retval)
		DebugHS("__mm_populate() returned error\n");

	return retval;
}

static void
prepare_prev_pc_stack_area_after_switch(struct hw_stack_area *prev_u_pcs)
{
	struct thread_info *ti = current_thread_info();

	list_move_tail(&prev_u_pcs->list_entry, &ti->old_u_pcs_list);
	DebugHS("user Procedure chain stack area 0x%p was deleted from user Procedure chain stack areas list\n",
		prev_u_pcs);
	free_user_pc_stack(prev_u_pcs, false);
}

int switch_to_next_pc_stack_area(void)
{
	thread_info_t		*ti = current_thread_info();
	struct hw_stack_area	*cur_u_pcs;
	struct hw_stack_area	*prev_u_pcs;
	e2k_pcsp_lo_t		pcsp_lo;
	e2k_pcsp_hi_t		pcsp_hi;
	long			flags;
	int			retval;

	cur_u_pcs = ti->cur_pcs;
	prev_u_pcs = list_entry(cur_u_pcs->list_entry.prev,
				struct hw_stack_area, list_entry);
	BUG_ON(cur_u_pcs == prev_u_pcs);
	DebugHS("cur_u_pcs 0x%p prev_u_pcs 0x%p\n",
		cur_u_pcs, prev_u_pcs);

	retval = prepare_next_pc_stack_area_before_switch(
						cur_u_pcs, prev_u_pcs);
	if (retval) {
		DebugHS("prepare_next_pc_stack_area_before_switch() returned error\n");
		return retval;
	}

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_hi.PCSP_hi_ind = pcsp_hi.PCSP_hi_ind - USER_PC_STACK_BYTE_INCR;
	pcsp_hi.PCSP_hi_size = cur_u_pcs->top - cur_u_pcs->offset +
			       KERNEL_PC_STACK_SIZE;
	pcsp_lo.PCSP_lo_base = (e2k_addr_t)cur_u_pcs->base + cur_u_pcs->offset;
	WRITE_PCSP_REG(pcsp_hi, pcsp_lo);
	raw_all_irq_restore(flags);
	DebugHS("new PCS state: base 0x%llx ind 0x%x size 0x%x\n",
		pcsp_lo.PCSP_lo_base, pcsp_hi.PCSP_hi_ind,
		pcsp_hi.PCSP_hi_size);

	prepare_prev_pc_stack_area_after_switch(prev_u_pcs);

	return retval;
}

static inline int
clone_hard_stack_pte_range(struct mm_struct *dst, struct mm_struct *src,
	struct vm_area_struct *dst_vma,
	pmd_t *dst_pmd, pmd_t *src_pmd, e2k_addr_t address,
	e2k_addr_t end, long copy_size)
{
	pte_t		*src_pte;
	pte_t		*dst_pte;
	pte_t		*orig_src_pte;
	pte_t		*orig_dst_pte;
	spinlock_t	*src_ptl;
	spinlock_t	*dst_ptl;
	int		ret = 0;
	long		rss = 0;

	DebugHS("started: start 0x%lx "
		"end 0x%lx real size to copy 0x%lx "
		"dst_pmd 0x%p == 0x%lx src_pmd 0x%p == 0x%lx\n",
		address, end, copy_size,
		dst_pmd, pmd_val(*dst_pmd), src_pmd, pmd_val(*src_pmd));
	dst_pte = pte_alloc_map_lock(dst, dst_pmd, address, &dst_ptl);
	if (!dst_pte) {
		DebugHS("could "
			"not alloc PTE page for addr 0x%lx\n",
			address);
		return -ENOMEM;
	}
	src_pte = pte_offset_map(src_pmd, address);
	src_ptl = pte_lockptr(src, src_pmd);
	spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;
	arch_enter_lazy_mmu_mode();

	do {
		pte_t	pte;
		struct page *ptepage;
		struct page *new_page;

		DebugHS("will copy pte 0x%p == "
			"0x%lx from address 0x%lx to 0x%lx\n",
			src_pte, pte_val(*src_pte), address, end);
		pte = *src_pte;
		if (pte_none(pte)) {
			printk("clone_hard_stack_pte_range() could not be "
				"empty pte from addr 0x%lx to 0x%lx\n",
				address, (address + PAGE_SIZE) & PAGE_MASK);
			ret = -ENOMEM;
			break;
		}
		if (!pte_present(pte)) {
			printk("clone_hard_stack_pte_range() pte 0x%p "
				"== 0x%lx not present: could not be swaped\n",
				src_pte, pte_val(*src_pte));
			ret = -ENOMEM;
			break;
		}
		new_page = alloc_page_vma(GFP_ATOMIC, dst_vma, address);
		if (!new_page) {
			DebugHS("could allocate "
				"page for addr 0x%lx\n",
				address);
			ret = -ENOMEM;
			break;
		}
		/*
		 * Because we dropped the lock, we should re-check the
		 * entry, as somebody else could delete or swap it..
		 */
		if (pte_none(pte)) {
			DebugHS("pte 0x%p = "
				"0x%lx deleted, process is killing probably\n",
				src_pte, pte_val(*src_pte));
			ret = -ENOMEM;
			break;
		}
		if (!pte_present(pte)) {
			printk("clone_hard_stack_pte_range() pte 0x%p "
				"== 0x%lx was swaped, when it should be "
				"locked\n",
				src_pte, pte_val(*src_pte));
			ret = -ENOMEM;
			break;
		}
		ptepage = pte_page(pte);
		set_pte_at(dst, address, dst_pte, mk_clone_pte(new_page, pte));
		page_add_new_anon_rmap(new_page, dst_vma, address);
		++rss;
		DebugHS("copies and sets PTE 0x%p "
			"to new page 0x%lx (was 0x%lx) for address 0x%lx\n",
			dst_pte, pte_val(*dst_pte), pte_val(pte), address);
		if (copy_size > 0) {
			DebugHS("will copy page "
				"contents for address 0x%lx\n",
				address);
			copy_user_highpage(new_page, ptepage, address, dst_vma);
		}
		if (copy_size > PAGE_SIZE)
			copy_size -= PAGE_SIZE;
		else
			copy_size = 0;
	} while (dst_pte++, src_pte++, address += PAGE_SIZE, address != end);

	arch_leave_lazy_mmu_mode();
	spin_unlock(src_ptl);
	pte_unmap(orig_src_pte);
	add_mm_counter(dst, MM_ANONPAGES, rss);
	pte_unmap_unlock(orig_dst_pte, dst_ptl);
	DebugHS("finished and returns %d\n",
		ret);
	return ret;
}

static inline int
clone_hard_stack_pmd_range(struct mm_struct *dst, struct mm_struct *src,
	struct vm_area_struct *dst_vma,
	pud_t *dst_pud, pud_t *src_pud, e2k_addr_t address,
	e2k_addr_t end, long copy_size)
{
	e2k_addr_t	next;
	pmd_t		*src_pmd;
	pmd_t		*dst_pmd;
	int		ret = 0;

	DebugHS("started: start 0x%lx "
		"end 0x%lx real size to copy 0x%lx "
		"dst_pud 0x%p == 0x%lx src_pud 0x%p == 0x%lx\n",
		address, end, copy_size,
		dst_pud, pud_val(*dst_pud), src_pud, pud_val(*src_pud));
	dst_pmd = pmd_alloc(dst, dst_pud, address);
	if (!dst_pud) {
		DebugP("could "
			"not alloc PMD for addr 0x%lx\n",
			address);
		return -ENOMEM;
	}
	src_pmd = pmd_offset(src_pud, address);
	do {
		DebugHS("will copy pmd 0x%p == "
			"0x%lx from address 0x%lx to 0x%lx\n",
			src_pmd, pmd_val(*src_pmd), address, end);
		next = pmd_addr_end(address, end);
		if (pmd_none_or_clear_bad(src_pmd)) {
			DebugHS("will skip empty "
				"pte range from addr 0x%lx to 0x%lx\n",
				address, next);
			copy_size -= (next - address);
			if (copy_size <= 0)
				copy_size = 0;
			continue;
		}
		DebugHS("will clone pte range "
			"from address 0x%lx to 0x%lx size to copy 0x%lx\n",
			address, next, copy_size);
		ret = clone_hard_stack_pte_range(dst, src, dst_vma, dst_pmd,
			src_pmd, address, next, copy_size);
		if (ret != 0)
			break;
	} while (dst_pmd++, src_pmd++, address = next, address != end);
	DebugHS("finished and returns %d\n",
		ret);
	return ret;
}

static inline int
clone_hard_stack_pud_range(struct mm_struct *dst, struct mm_struct *src,
	struct vm_area_struct *dst_vma,
	pgd_t *dst_pgd, pgd_t *src_pgd,	e2k_addr_t address, e2k_addr_t end,
	long copy_size)
{
	e2k_addr_t	next;
	pud_t		*src_pud;
	pud_t		*dst_pud;
	int		ret = 0;

	DebugHS("started: start 0x%lx "
		"end 0x%lx real size to copy 0x%lx "
		"dst_pgd 0x%p == 0x%lx src_pgd 0x%p == 0x%lx\n",
		address, end, copy_size,
		dst_pgd, pgd_val(*dst_pgd), src_pgd, pgd_val(*src_pgd));
	dst_pud = pud_alloc(dst, dst_pgd, address);
	if (!dst_pud) {
		DebugP("could not "
			"alloc PUD for addr 0x%lx\n",
			address);
		return -ENOMEM;
	}
	src_pud = pud_offset(src_pgd, address);
	do {
		DebugHS("will copy pud 0x%p == "
			"0x%lx from address 0x%lx to 0x%lx\n",
			src_pud, pud_val(*src_pud), address, end);
		next = pud_addr_end(address, end);
		if (pud_none_or_clear_bad(src_pud)) {
			DebugHS("will skip empty "
				"or bad pmd range from addr 0x%lx to 0x%lx\n",
				address, next);
			copy_size -= (next - address);
			if (copy_size <= 0)
				copy_size = 0;
			continue;
		}
		DebugHS("will clone pmd range "
			"from address 0x%lx to 0x%lx size to copy 0x%lx\n",
			address, next, copy_size);
		ret = clone_hard_stack_pmd_range(dst, src, dst_vma, dst_pud,
			src_pud, address, next, copy_size);
		if (ret != 0)
			break;
	} while (dst_pud++, src_pud++, address = next, address != end);
	DebugHS("finished and returns %d\n",
		ret);
	return ret;
}

static inline int
clone_hard_stack_pgd_range(struct mm_struct *dst, struct mm_struct *src,
	struct vm_area_struct *dst_vma,
	e2k_addr_t stack_start, e2k_addr_t stack_end, long copy_size)
{
	e2k_addr_t	address = stack_start;
	e2k_addr_t	end = stack_end;
	e2k_addr_t	next;
	pgd_t		*src_pgd;
	pgd_t		*dst_pgd;
	int		ret = 0;

	DebugHS("started: start 0x%lx "
		"end 0x%lx real size to copy 0x%lx\n",
		stack_start, stack_end, copy_size);
	dst_pgd = pgd_offset(dst, address);
	src_pgd = pgd_offset(src, address);
	do {
		DebugHS("will copy pgd 0x%p == "
			"0x%lx from address 0x%lx and size 0x%lx "
			"to pgd 0x%p == 0x%lx\n",
			src_pgd, pgd_val(*src_pgd), address,
			stack_end - stack_start, dst_pgd, pgd_val(*dst_pgd));
		next = pgd_addr_end(address, end);
		if (pgd_none_or_clear_bad(src_pgd)) {
			DebugHS("will skip bad "
				"or none pud range from addr 0x%lx to 0x%lx\n",
				address, next);
			copy_size -= (next - address);
			if (copy_size < 0)
				copy_size = 0;
			continue;
		}
		DebugHS("will clone pud range "
			"from address 0x%lx to 0x%lx real size 0x%lx\n",
			address, next, copy_size);
		ret = clone_hard_stack_pud_range(dst, src, dst_vma, dst_pgd,
			src_pgd, address, next, copy_size);
		if (ret != 0)
			break;
	} while (dst_pgd++, src_pgd++, address = next, address != end);
	DebugHS("finished and returns %d\n",
		ret);
	return ret;
}

/*
 * The function clones user hardware stack from the parent task to new
 * (child) task, which has been created before by fork() system call.
 */
static int
clone_user_hard_stack(struct mm_struct *dst, struct mm_struct *src,
	e2k_addr_t stack_base, long stack_len, e2k_addr_t stack_end_addr,
	unsigned long clone_flags)
{
	struct vm_area_struct	*src_vma, *dst_vma;
	e2k_addr_t		stack_end;
	int			retval = 0;
	int			vma_count = 0;

	DebugHS("will start alloc VMA structure\n");
	vma_count = 0;
	down_read(&src->mmap_sem);
	do {
		src_vma = find_vma(src, stack_base);
		if (src_vma == NULL) {
			if (vma_count == 0) {
				DebugP("Could not find VM area\n");
				retval = -EINVAL;
				goto fail;
			}
			break;
		}
		DebugHS("found VMA 0x%p start 0x%lx, end 0x%lx, flags 0x%lx\n",
			src_vma, src_vma->vm_start, src_vma->vm_end,
			src_vma->vm_flags);
		vma_count ++;

		if (!(src_vma->vm_flags & VM_DONTCOPY)) {
			up_read(&src->mmap_sem);
			pr_err("Invalid flags 0x%lx of hardware stack VMA: start 0x%lx, end 0x%lx (should have VM_DONTCOPY flag)\n",
				src_vma->vm_flags, src_vma->vm_start,
				src_vma->vm_end);
			print_mmap(current);
			BUG();
		}
		
		if (!(src_vma->vm_flags & VM_LOCKED) &&
				stack_len != 0) {
			up_read(&src->mmap_sem);
			pr_err("Invalid flags 0x%lx of hardware stack VMA: start 0x%lx, end 0x%lx, stack (locked) size 0x%lx (should have VM_LOCKED flag)\n",
				src_vma->vm_flags, src_vma->vm_start,
				src_vma->vm_end, stack_len);
			BUG();
		}

		stack_end = (src_vma->vm_end < stack_end_addr) ?
					src_vma->vm_end :
					stack_end_addr;

		dst_vma = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
		if (!dst_vma) {
			DebugHS("Could not allocate VM area\n");
			retval = -ENOMEM;
			goto fail;
		}
		DebugHS("copy VMA old 0x%p to new 0x%p\n",
			src_vma, dst_vma);
		*dst_vma = *src_vma;
		if (dst_vma->vm_end > stack_end_addr)
			dst_vma->vm_end = stack_end_addr;
		if (dst_vma->vm_start < stack_base)
			dst_vma->vm_start = stack_base;
		dst_vma->vm_mm = dst;
		dst_vma->vm_prev = NULL;
		dst_vma->vm_next = NULL;
		dst_vma->anon_vma = NULL;
		INIT_LIST_HEAD(&dst_vma->anon_vma_chain);

		DebugHS("src VMA 0x%p anon-vma 0x%p == 0x%p\n",
			src_vma, &src_vma->anon_vma, src_vma->anon_vma);

		retval = vma_dup_policy(src_vma, dst_vma);
		if (retval) {
			DebugP("mpol_copy() failed and returns error %d\n",
				retval);
			goto fail_free_vma;
		}

		retval = insert_vm_struct(dst, dst_vma);
		if (retval) {
			goto fail_free_mempolicy;
			break;
		}
		vm_stat_account(dst, src_vma->vm_flags, src_vma->vm_file,
				vma_pages(src_vma));

		retval = anon_vma_prepare(dst_vma);
		if (retval)
			break;

		DebugHS("dst VMA 0x%p anon-vma 0x%p == 0x%p\n",
			dst_vma, &(dst_vma->anon_vma), dst_vma->anon_vma);

		if ((src_vma->vm_flags & VM_LOCKED) &&
		    (src_vma->vm_flags & (VM_READ| VM_WRITE | VM_EXEC))) {
			DebugHS("will copy from parent stack 0x%lx to child user, size 0x%lx byte(s)\n",
				stack_base, stack_len);
			retval = clone_hard_stack_pgd_range(dst, src,
					dst_vma, stack_base, stack_end,
					stack_len);
			DebugHS("clone_hard_stack_pgd_range returned %d\n",
				retval);
			if (retval)
				break;
		}
		DebugHS("succeeded\n");
		stack_len -= (stack_end - stack_base);
		if (stack_len < 0)
			stack_len = 0;
		stack_base = stack_end;
	} while (stack_base < stack_end_addr);

	up_read(&src->mmap_sem);

	return retval;

fail_free_mempolicy:
	mpol_put(vma_policy(dst_vma));

fail_free_vma:
	kmem_cache_free(vm_area_cachep, dst_vma);

fail:
	up_read(&src->mmap_sem);

	DebugP("failed and returns error %d\n",
			retval);

	return retval;
}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
static inline int __fix_return_values(
		unsigned long dst, unsigned long size, unsigned long delta)
{
	int last_not_copied_index = -1;
	int index;

	for (index = current->curr_ret_stack; index >= 0; index--) {
		unsigned long fp = current->ret_stack[index].fp + delta;
		e2k_mem_crs_t *frame;

		if (fp >= dst + size) {
			last_not_copied_index = index;
			DebugFTRACE("%d: skipping fp 0x%lx, limit 0x%lx - 0x%lx (entry %pS)\n",
					current->pid, fp, dst, dst + size,
					current->ret_stack[index].ret);
			continue;
		}
		if (fp < dst) {
			DebugFTRACE("%d: fp 0x%lx, limit 0x%lx - 0x%lx (did not restore %pS at original fp %lx)\n",
					current->pid, fp, dst, dst + size,
					current->ret_stack[index].ret,
					fp - delta);
			break;
		}

		frame = (e2k_mem_crs_t *) fp;
		DebugFTRACE("%d: replacing %pS with %pS at 0x%lx (user: %s)\n",
				current->pid, AW(frame->cr0_hi),
				current->ret_stack[index].ret, (u64) frame,
				current->mm ? "true" : "false");
		if (current->mm)
			__put_user(current->ret_stack[index].ret,
					&AW(frame->cr0_hi));
		else
			AW(frame->cr0_hi) = current->ret_stack[index].ret;
		--index;
	}

	return last_not_copied_index;
}

static void fix_return_values_in_chain_stack(struct mm_struct *mm,
		unsigned long dst, unsigned long src, unsigned long size,
		e2k_mem_crs_t *crs)
{
	unsigned long flags;
	struct mm_struct *oldmm;
	int was_mm_switch = 0, index, cpu;

	if (current->curr_ret_stack < 0 || !current->ret_stack)
		/* Tracing buffer is empty or the graph tracing never
		 * was enabled for the current task, nothing to do here... */
		return;

	DebugFTRACE("%d: ftrace: fixing chain stack\n", current->pid);

	oldmm = current->active_mm;
	if (mm != oldmm) {
		raw_all_irq_save(flags);

		cpu = raw_smp_processor_id();

		current->active_mm = mm;
		do_switch_mm(oldmm, mm, cpu);
		was_mm_switch = 1;
	}

	index = __fix_return_values(dst, size, dst - src);

	if (was_mm_switch) {
		current->active_mm = oldmm;
		do_switch_mm(mm, oldmm, cpu);

		raw_all_irq_restore(flags);
	}

	/*
	 * Last copied chain stack frame is stored in registers,
	 * check if it should be restored too.
	 */
	if (index >= 0 && current->ret_stack[index].fp == src + size) {
		DebugFTRACE("%d: replacing %pS with %pS at 0x%lx in registers\n",
				current->pid, AW(crs->cr0_hi),
				current->ret_stack[index].ret, dst + size);
		AW(crs->cr0_hi) = current->ret_stack[index].ret;
	}
}
#endif

/*
 * The function clones all user hardware stacks(PS & PCS)
 * from the parrent task to the new (child) task.
 */
static inline int
do_clone_all_user_hard_stacks(struct task_struct *new_task,
	e2k_addr_t ps_base, long ps_len, e2k_addr_t ps_end_addr,
	e2k_addr_t pcs_base, long pcs_len, e2k_addr_t pcs_end_addr,
	unsigned long clone_flags, e2k_mem_crs_t *new_crs)
{
	struct mm_struct *mm_from = current->mm;
	struct mm_struct *mm_to = new_task->mm;
	int	retval;

	DebugUS("started to clone stacks from task 0x%p to task 0x%p\n",
		current, new_task);
	DebugUS("will copy procedure stack from base 0x%lx, size 0x%lx, end addr 0x%lx\n",
		ps_base, ps_len, ps_end_addr);
	retval = clone_user_hard_stack(mm_to, mm_from,
			ps_base, ps_len, ps_end_addr, clone_flags);
	DebugUS("clone_user_hard_stack() returned %d\n", retval);
	if (retval)
		return retval;
	DebugUS("will copy chain stack from base 0x%lx, size 0x%lx, end addr 0x%lx\n",
		pcs_base, pcs_len, pcs_end_addr);
	retval = clone_user_hard_stack(mm_to, mm_from,
			pcs_base, pcs_len, pcs_end_addr, clone_flags);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (!retval)
		fix_return_values_in_chain_stack(mm_to,
				pcs_base, pcs_base, pcs_len, new_crs);
#endif
	DebugUS("finished and returns %d\n", retval);

	return retval;
}

/*
 * The function creates user hardware stacks(PS & PCS) excluding or
 * including kernel part of the hardware stacks of current task
 */
static int
create_user_hard_stacks(thread_info_t *thread_info, e2k_stacks_t *stacks,
	e2k_size_t user_psp_size, e2k_size_t user_psp_init_size,
	e2k_size_t user_pcsp_size, e2k_size_t user_pcsp_init_size)
{
	struct hw_stack_area	*user_psp_stk;
	struct hw_stack_area	*user_pcsp_stk;
	void		*user_psp_stk_cont;
	void		*user_pcsp_stk_cont;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t 	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t 	pcsp_hi;

	DebugUS("started\n");

	user_psp_size = get_max_psp_size(user_psp_size);
	user_pcsp_size = get_max_pcsp_size(user_pcsp_size);

	if (user_psp_init_size > user_psp_size) {
		user_psp_init_size = user_psp_size;
	}

	DebugUS("will allocate user Procedure stack\n");
	if (UHWS_PSEUDO_MODE) {
		user_psp_stk = alloc_user_p_stack(user_psp_size, 0,
						  user_psp_init_size);
		if (!user_psp_stk) {
			DebugHS("Could not allocate user Procedure stack\n");
			return -ENOMEM;
		}
		list_add_tail(&user_psp_stk->list_entry, &thread_info->ps_list);
		thread_info->cur_ps = user_psp_stk;
		DebugUS("user Procedure stack area 0x%p was added to user Procedure stack areas list\n",
			user_psp_stk);

	} else {
		user_psp_stk_cont = alloc_user_p_stack_cont(user_psp_size,
							    user_psp_init_size);
		if (!user_psp_stk_cont) {
			DebugHS("Could not allocate user Procedure stack\n");
			return -ENOMEM;
		}
	}
	DebugUS("allocated user Procedure stack at 0x%p, size 0x%lx, init size 0x%lx, kernel part size 0x%lx\n",
		(UHWS_PSEUDO_MODE) ? user_psp_stk->base : user_psp_stk_cont,
		user_psp_size, user_psp_init_size, KERNEL_P_STACK_SIZE);

	DebugUS("will allocate user Procedure Chain stack\n");
	if (UHWS_PSEUDO_MODE) {
		user_pcsp_stk = alloc_user_pc_stack(user_pcsp_size, 0,
						     user_pcsp_init_size);
		if (!user_pcsp_stk) {
			DebugHS("Could not allocate user Procedure Chain stack\n");
			free_user_p_stack(user_psp_stk, true);
			return -ENOMEM;
		}
		list_add_tail(&user_pcsp_stk->list_entry,
			      &thread_info->pcs_list);
		thread_info->cur_pcs = user_pcsp_stk;
		DebugUS("user Procedure Chain stack area 0x%p was added to user Procedure stack areas list\n",
			user_pcsp_stk);
	} else {
		user_pcsp_stk_cont = alloc_user_pc_stack_cont(user_pcsp_size,
							user_pcsp_init_size);
		if (!user_pcsp_stk_cont) {
			DebugHS("Could not allocate user Procedure Chain stack\n");
			free_user_p_stack_cont(user_psp_stk_cont,
					       user_psp_size, 0,
					       user_psp_init_size);
			return -ENOMEM;
		}
	}
	DebugUS("allocated user Procedure Chain stack at 0x%p, size 0x%lx, init size 0x%lx, kernel part size 0x%lx\n",
		(UHWS_PSEUDO_MODE) ? user_pcsp_stk->base : user_pcsp_stk_cont,
		user_pcsp_size, user_pcsp_init_size, KERNEL_PC_STACK_SIZE);

	psp_lo.PSP_lo_half = 0;
	psp_hi.PSP_hi_half = 0;
	if (UHWS_PSEUDO_MODE) {
		AS_STRUCT(psp_lo).base = (e2k_addr_t)user_psp_stk->base;
		AS_STRUCT(psp_hi).size = user_psp_stk->top;
	} else {
		AS_STRUCT(psp_lo).base = (e2k_addr_t)user_psp_stk_cont;
		AS_STRUCT(psp_hi).size = user_psp_init_size;
		thread_info->ps_base = user_psp_stk_cont;
		thread_info->ps_size = user_psp_size;
		thread_info->ps_offset = 0;
		thread_info->ps_top = user_psp_init_size;
	}
	stacks->psp_lo = psp_lo;
	stacks->psp_hi = psp_hi;

	pcsp_lo.PCSP_lo_half = 0;
	pcsp_hi.PCSP_hi_half = 0;
	if (UHWS_PSEUDO_MODE) {
		AS_STRUCT(pcsp_lo).base = (e2k_addr_t)user_pcsp_stk->base;
		AS_STRUCT(pcsp_hi).size = user_pcsp_stk->top;
	} else {
		AS_STRUCT(pcsp_lo).base = (e2k_addr_t)user_pcsp_stk_cont;
		AS_STRUCT(pcsp_hi).size = user_pcsp_init_size;
		thread_info->pcs_base = user_pcsp_stk_cont;
		thread_info->pcs_size = user_pcsp_size;
		thread_info->pcs_offset = 0;
		thread_info->pcs_top = user_pcsp_init_size;
	}
	stacks->pcsp_lo = pcsp_lo;
	stacks->pcsp_hi = pcsp_hi;

	DebugUS("succeeded\n");
	return 0;
}

/*
 * The function creates all user hardware stacks(PS & PCS) including and
 * kernel part of the hardware stacks of current task
 */
static int
create_all_user_hard_stacks(struct thread_info *ti, e2k_stacks_t *stacks)
{
	int	ret;

	DebugUS("will allocate user Procedure and Chain stacks\n");
	ret = create_user_hard_stacks(ti, stacks,
			(UHWS_PSEUDO_MODE) ?
				USER_P_STACK_AREA_SIZE : USER_P_STACK_SIZE,
			USER_P_STACK_INIT_SIZE,
			(UHWS_PSEUDO_MODE) ?
				USER_PC_STACK_AREA_SIZE : USER_PC_STACK_SIZE,
			USER_PC_STACK_INIT_SIZE);
	DebugUS("returned %d\n", ret);

	return ret;
}

void show_regs(struct pt_regs * regs)
{
	DebugP("show_regs entered.\n");
	print_task_pt_regs(regs);
	DebugP("show_regs exited.\n");
}

static int check_wchan(struct task_struct *p, e2k_mem_crs_t *frame,
		unsigned long frame_address, void *arg1, void *arg2, void *arg3)
{
	unsigned long *p_ip = arg1;
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

	parse_chain_stack(p, check_wchan, &ip, NULL, NULL);

	return ip;
}

/**
 * free_hw_stack_mappings - free user hw stacks which were mapped to kernel
 * @ti: the task's thread_info
 */
static void free_hw_stack_mappings(struct thread_info *ti)
{
	if (ti->mapped_p_stack) {
		free_vm_area(ti->mapped_p_stack);
		ti->mapped_p_stack = NULL;
	}

	if (ti->mapped_pc_stack) {
		free_vm_area(ti->mapped_pc_stack);
		ti->mapped_pc_stack = NULL;
	}
}

/**
 * unmap_hw_stack_mappings - unmap user hw stacks mappings which were mapped to
 *			     kernel
 * @ti: the task's thread_info
 */
static void unmap_hw_stack_mappings(struct thread_info *ti)
{
	/*
	 * Now we don't need the old mappings. Cache flush is not needed on e2k,
	 * and TLB flush is done on as-needed basis. This is possible because
	 * normally hardware stacks are accessed only by their owner, and in
	 * exceptional cases (parse_chain_stack(), print_stack()) we'll do a
	 * manual TLB flush.
	 */
	all_irq_disable();
	bitmap_fill(ti->need_tlb_flush, NR_CPUS);
	__clear_bit(smp_processor_id(), ti->need_tlb_flush);
	__flush_tlb_all();
	all_irq_enable();

	unmap_kernel_range_noflush((u64) ti->mapped_pc_stack->addr,
				   KERNEL_PC_STACK_SIZE);
	unmap_kernel_range_noflush((u64) ti->mapped_p_stack->addr,
				   KERNEL_P_STACK_SIZE);
}

/**
 * free_hw_stack_pages - free user hw stacks pages which were mapped to kernel
 * @ti: the task's thread_info
 */
static void free_hw_stack_pages(struct thread_info *ti)
{
	int i;

	clear_ti_status_flag(ti,
		TS_MAPPED_HW_STACKS | TS_MAPPED_HW_STACKS_INVALID);

	for (i = 0; i < KERNEL_PC_STACK_PAGES; i++) {
		struct page *page = ti->mapped_pc_pages[i];

		put_page(page);
	}

	for (i = 0; i < KERNEL_P_STACK_PAGES; i++) {
		struct page *page = ti->mapped_p_pages[i];

		put_page(page);
	}
}

enum {
	FKE_FIRST_FRAME,
	FKE_SEARCHING,
	FKE_FOUND
};

static int __find_kernel_entry(struct task_struct *task,
		e2k_mem_crs_t *frame, unsigned long frame_address,
		void *arg1, void *arg2, void *arg3)
{
	unsigned long *cs = arg1, *ps = arg2;
	int *state = arg3;

	/*
	 * Skip the first frame which contains find_kernel_entry()'s ip
	 * since it has already been accounted for in *cs and *ps.
	 */
	if (*state == FKE_FIRST_FRAME) {
		*state = FKE_SEARCHING;

		return 0;
	}

	if (!AS(frame->cr1_lo).pm) {
		/*
		 * Found!
		 */
		*state = FKE_FOUND;
		return 1;
	}

	*cs -= SZ_OF_CR;
	*ps -= AS(frame->cr1_lo).wbs * EXT_4_NR_SZ;

	return 0;
}

static int find_kernel_entry(unsigned long *cs, unsigned long *ps)
{
	e2k_pshtp_t	pshtp;
	e2k_pcshtp_t	pcshtp;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t 	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t 	pcsp_hi;
	unsigned long	flags;
	int state;

	raw_all_irq_save(flags);
	psp_lo = READ_PSP_LO_REG();
	psp_hi = READ_PSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_hi = READ_PCSP_HI_REG();
	pshtp = READ_PSHTP_REG();
	pcshtp = READ_PCSHTP_REG();
	raw_all_irq_restore(flags);

	*cs = AS(pcsp_lo).base + AS(pcsp_hi).ind + PCSHTP_SIGN_EXTEND(pcshtp);

	*ps = AS(psp_lo).base + AS(psp_hi).ind + GET_PSHTP_INDEX(pshtp);

	state = FKE_FIRST_FRAME;
	parse_chain_stack(NULL, __find_kernel_entry, cs, ps, &state);

	return (state == FKE_FOUND) ? 0 : -ESRCH;
}

static long get_hw_stack_pages(unsigned long start, unsigned long nr_pages,
			       struct page **pages)
{
	long i;
	struct mm_struct *mm = current->mm;
	unsigned int foll_flags = FOLL_GET | FOLL_WRITE |
				  FOLL_TOUCH | FOLL_NUMA;

	down_read(&mm->mmap_sem);

	i = 0;

	do {
		struct vm_area_struct *vma;

		vma = find_vma(mm, start);

		BUG_ON(!vma || (vma->vm_flags & (VM_IO | VM_PFNMAP)) ||
		       !(VM_WRITE & vma->vm_flags));

		do {
			struct page *page;

			page = follow_page(vma, start, foll_flags);
			BUG_ON(!page || IS_ERR(page));

			pages[i] = page;

			flush_anon_page(vma, page, start);
			flush_dcache_page(page);

			++i;
			start += PAGE_SIZE;
			--nr_pages;
		} while (nr_pages && start < vma->vm_end);
	} while (nr_pages);

	up_read(&mm->mmap_sem);

	return i;
}

void switch_to_kernel_hardware_stacks()
{
	struct thread_info *ti = current_thread_info();
	struct page **pages;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	unsigned long flags, cs, ps;
	int ret;

	if (test_ts_flag(TS_MAPPED_HW_STACKS_INVALID)) {
		BUG_ON(!test_ts_flag(TS_MAPPED_HW_STACKS));
		unmap_hw_stack_mappings(ti);
		free_hw_stack_pages(ti);
	}

	if (test_ts_flag(TS_MAPPED_HW_STACKS))
		return;

	if (AS(READ_PCSP_LO_REG()).base >= PAGE_OFFSET)
		/* On kernel stacks already, which means
		 * that we failed somewhere in do_sys_execve()
		 * before switching to user stacks. */
		return;

	ret = find_kernel_entry(&cs, &ps);
	if (ret) {
		/* makecontext_trampoline()->do_exit() case */
		cs = AS(READ_PCSP_LO_REG()).base;
		ps = AS(READ_PSP_LO_REG()).base;
	}

	cs = round_down(cs, PAGE_SIZE);
	ps = round_down(ps, PAGE_SIZE);

	/*
	 * Get the pages which hold current kernel stacks.
	 * They _must_ be present so we panic() on error.
	 */

	ret = get_hw_stack_pages(cs, KERNEL_PC_STACK_PAGES,
				 ti->mapped_pc_pages);
	if (unlikely(ret != KERNEL_PC_STACK_PAGES))
		panic("Could not remap chain stack from 0x%lx (ret %d)\n",
				cs, ret);

	ret = get_hw_stack_pages(ps, KERNEL_P_STACK_PAGES,
				 ti->mapped_p_pages);
	if (unlikely(ret != KERNEL_P_STACK_PAGES))
		panic("Could not remap procedure stack from 0x%lx (ret %d)\n",
				ps, ret);

	/*
	 * Actually map the pages...
	 */

	pages = ti->mapped_pc_pages;
	ret = map_vm_area(ti->mapped_pc_stack, PAGE_KERNEL_PCS, &pages);
	BUG_ON(ret);

	pages = ti->mapped_p_pages;
	ret = map_vm_area(ti->mapped_p_stack, PAGE_KERNEL_PS, &pages);
	BUG_ON(ret);

	set_ts_flag(TS_MAPPED_HW_STACKS);

	/*
	 * ... and switch to the new location.
	 */

	raw_all_irq_save(flags);
	E2K_FLUSHCPU;
	psp_lo = READ_PSP_LO_REG();
	psp_hi = READ_PSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_hi = READ_PCSP_HI_REG();

	AS(pcsp_hi).ind -= cs - AS(pcsp_lo).base;
	AS(psp_hi).ind -= ps - AS(psp_lo).base;

	AS(pcsp_lo).base = (unsigned long) ti->mapped_pc_stack->addr;
	AS(psp_lo).base = (unsigned long) ti->mapped_p_stack->addr;

	AS(pcsp_hi).size = KERNEL_PC_STACK_SIZE;
	AS(psp_hi).size = KERNEL_P_STACK_SIZE;

	WRITE_PSP_LO_REG(psp_lo);
	WRITE_PSP_HI_REG(psp_hi);
	WRITE_PCSP_LO_REG(pcsp_lo);
	WRITE_PCSP_HI_REG(pcsp_hi);
	raw_all_irq_restore(flags);

	DebugEX("new chain stack base 0x%llx, size 0x%x, ind 0x%x\n",
		 AS(pcsp_lo).base, AS(pcsp_hi).size, AS(pcsp_hi).ind);
	DebugEX("new procedure stack base 0x%llx, size 0x%x, ind 0x%x\n",
		 AS(psp_lo).base, AS(psp_hi).size, AS(psp_hi).ind);

#if defined CONFIG_FUNCTION_GRAPH_TRACER
	if (current->curr_ret_stack >= 0) {
		unsigned long pc_delta =
				(unsigned long) ti->mapped_pc_stack->addr - cs;
		int i;

		DebugFTRACE("%d: fixing stack in do_exit\n", current->pid);
		for (i = current->curr_ret_stack; i >= 0; i--) {
			DebugFTRACE("%d: correcting entry %pS fp %lx->%lx\n",
					current->pid, current->ret_stack[i].ret,
					current->ret_stack[i].fp,
					current->ret_stack[i].fp + pc_delta);
			current->ret_stack[i].fp += pc_delta;
		}
	}
#endif
}

static int free_user_hardware_stacks(void)
{
	thread_info_t		*ti = current_thread_info();

	if (UHWS_PSEUDO_MODE) {
		free_user_old_pc_stack_areas(&ti->old_u_pcs_list);
		DebugEX("freed user old PCS list head 0x%p\n",
			&ti->old_u_pcs_list);
	}

	if (atomic_read(&current->mm->mm_users) <= 1) {
		DebugEX("last thread: do not free stacks - mmput will release all mm\n");

		/*
		 * Do not free address space, free descriptors only.
		 */
		if (UHWS_PSEUDO_MODE) {
			struct hw_stack_area *user_p_stack, *user_pc_stack, *n;

			list_for_each_entry_safe(user_p_stack, n,
						 &ti->ps_list, list_entry) {
				kfree(user_p_stack);
			}
			INIT_LIST_HEAD(&ti->ps_list);
			ti->cur_ps = NULL;
			list_for_each_entry_safe(user_pc_stack, n,
						 &ti->pcs_list, list_entry) {
				kfree(user_pc_stack);
			}
			INIT_LIST_HEAD(&ti->pcs_list);
			ti->cur_pcs = NULL;
		}

		return 0;
	}

	DebugEX("thread #%d do free stacks\n",
		atomic_read(&current->mm->mm_users));

	BUG_ON((unsigned long) GET_PS_BASE(ti) >= TASK_SIZE ||
	       (unsigned long) GET_PCS_BASE(ti) >= TASK_SIZE);

	if (UHWS_PSEUDO_MODE) {
		free_user_p_stack_areas(&ti->ps_list);
		ti->cur_ps = NULL;
		DebugEX("freed user PS list head 0x%p, kernel part size 0x%lx\n",
			&ti->ps_list, KERNEL_P_STACK_SIZE);
		free_user_pc_stack_areas(&ti->pcs_list);
		ti->cur_pcs = NULL;
		DebugEX("freed user PCS list head 0x%p, kernel part size 0x%lx\n",
			&ti->pcs_list, KERNEL_PC_STACK_SIZE);
	} else {
		if (ti->ps_base) {
			free_user_p_stack_cont(ti->ps_base, ti->ps_size,
					       ti->ps_offset, ti->ps_size);
			ti->ps_base = NULL;
			DebugEX("freed user PS from base 0x%p, size 0x%lx, kernel part size 0x%lx\n",
				 ti->ps_base, ti->ps_size,
				 KERNEL_P_STACK_SIZE);
		}
		if (ti->pcs_base) {
			free_user_pc_stack_cont(ti->pcs_base, ti->pcs_size,
						ti->pcs_offset, ti->pcs_top);
			ti->pcs_base = NULL;
			DebugEX("freed user PCS from base 0x%p, size 0x%lx, kernel part size 0x%lx\n",
				 ti->pcs_base, ti->pcs_size,
				 KERNEL_PC_STACK_SIZE);
		}
	}

	return 0;
}

static inline void
goto_new_user_hard_stk(e2k_stacks_t *stacks)
{
	unsigned long flags;

	DebugEX("will switch stacks\n");

	raw_all_irq_save(flags);

	/*
	 * Wait for SPILL/FILL to issue all memory accesses
	 */
	E2K_FLUSH_WAIT;

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
	RAW_WRITE_PSP_REG(stacks->psp_hi, stacks->psp_lo);
	RAW_WRITE_PCSP_REG(stacks->pcsp_hi, stacks->pcsp_lo);

	/*
	 * We have switched to user stacks which are not expanded.
	 */
	clear_ts_flag(TS_HW_STACKS_EXPANDED);
	e2k_reset_sge();

	raw_all_irq_restore(flags);
}

#define printk printk_fixed_args
#define panic panic_fixed_args
notrace noinline __interrupt
void do_switch_to_user_func(start_fn start_func)
{
	e2k_cr0_hi_t 	cr_ip;
	e2k_cr1_lo_t 	cr_wd_psr;
	e2k_cr1_hi_t 	cr_ussz;
	e2k_cuir_t	cuir = {{ 0 }};
	e2k_psr_t	psr;
#ifdef	CONFIG_PROTECTED_MODE
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_pusd_lo_t	pusd_lo;
	e2k_pusd_hi_t	pusd_hi;
	u64		u_sbr;
#endif	/* CONFIG_PROTECTED_MODE */

	DebugCU("           func = 0x%016lx\n", *((long *)start_func));
	DebugP("entered: func 0x%p\n", start_func);
	DebugSPRs("start");

	AS_WORD(cr_ip) =  E2K_GET_DSREG_NV(cr0.hi);
	AS_WORD(cr_wd_psr) =  E2K_GET_DSREG_NV(cr1.lo);
	AS_WORD(cr_ussz) =  E2K_GET_DSREG_NV(cr1.hi);

	/*
	 * Go to down to sys_exec() procedure chain stack using PSCP info
	 * And get 'ussz' field of 'sys_exec()' function to restore
	 * user stack state before 'switch_to_user_func()' call
	 */
	AS_STRUCT(cr_ussz).ussz = current_thread_info()->u_stk_sz >> 4;

	AS_WORD(psr) = 0;
	AS_STRUCT(psr).sge = 1;
	AS_STRUCT(psr).ie = 1;			/* sti(); */
	AS_STRUCT(psr).nmie = 1;		/* nmi enable */
	AS_STRUCT(psr).pm = 0;			/* user mode */
	AS_STRUCT(cr_wd_psr).psr = AS_WORD(psr);
	AS_STRUCT(cr_ip).ip = (u64)start_func >> 3;	/* start user IP */

	/*
	 * Force CUD/GD/TSD update by the values stored in CUTE
	 * Entry #1 - for both 32bit and protected mode
	 */
	if ((current->thread.flags & E2K_FLAG_32BIT) ||
	    (current->thread.flags & E2K_FLAG_PROTECTED_MODE)) {
		AS_STRUCT(cuir).index = USER_CODES_32_INDEX;
	} else {
		AS_STRUCT(cuir).index = USER_CODES_START_INDEX;
	}
	AS_STRUCT(cr_wd_psr).cuir = AS_WORD(cuir);

	E2K_SET_DSREG_NV_NOIRQ(cr1.lo, AS_WORD(cr_wd_psr));
	E2K_SET_DSREG_NV_NOIRQ(cr1.hi, AS_WORD(cr_ussz));
	E2K_SET_DSREG_NV_NOIRQ(cr0.hi, AS_WORD(cr_ip));

#ifdef CONFIG_CLI_CHECK_TIME
	sti_return();
#endif

#ifdef CONFIG_PROTECTED_MODE
        if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
                u_sbr = READ_USBR_REG_VALUE();
                usd_hi = READ_USD_HI_REG();
                usd_lo = READ_USD_LO_REG();

                u_sbr = AS_STRUCT(usd_lo).base & 
				   ~E2K_PROTECTED_STACK_BASE_MASK;
                WRITE_SBR_REG_VALUE(u_sbr);

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

		WRITE_PUSD_REG(pusd_hi, pusd_lo);
		ENABLE_US_CLW();
        } else {
		DISABLE_US_CLW();
	}
#endif /* CONFIG_PROTECTED_MODE */


	/*
	 * User function will be executed under PSR interrupts control
	 * and kernel should return interrupts mask control to PSR register
	 * (if it needs)
	 * Set UPSR register in the initial state for user process
	 */
	SET_USER_UPSR();

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	if (current_thread_info()->pt_regs) {
		E2K_SAVE_CLOCK_REG(current_thread_info()->pt_regs->
						scall_times->scall_done);
		E2K_SAVE_CLOCK_REG(current_thread_info()->pt_regs->
				scall_times->end);
	}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	/* Prevent kernel pointers leakage to userspace.
	 * NOTE: this must be executed last. */
	E2K_SET_DGREG_NV(16, 0);
	E2K_SET_DGREG_NV(17, 0);
	E2K_SET_DGREG_NV(18, 0);
	E2K_SET_DGREG_NV(19, 0);

	/* Prevent kernel information leakage */
#if E2K_MAXSR != 112
# error Must clear all registers here
#endif
#ifndef CONFIG_E2S_CPU_RF_BUG
	E2K_CLEAR_RF_112();
#endif
}
#undef printk
#undef panic

extern void switch_to_user_func(long dummy, start_fn start_func);
#ifdef CONFIG_PROTECTED_MODE
extern void protected_switch_to_user_func(long r0, long r1,
		start_fn start_func);
#endif

int  create_cut_entry(int tcount,
		unsigned long code_base, unsigned  code_sz,
		unsigned long glob_base, unsigned  glob_sz)
{
	struct mm_struct *mm = current->mm;
	register e2k_cute_t *cute_p;	/* register for workaround against */
							/* gcc bug */
	unsigned int	cui;
#ifdef CONFIG_PROTECTED_MODE
	int retval;
#endif
	
	cui = atomic_add_return(1, &mm->context.cur_cui) - 1;
	cute_p = (e2k_cute_t *) USER_CUT_AREA_BASE + cui;
	DebugCU("cui = %d; tct = %d; code = 0x%lx: 0x%x; "
		"data = 0x%lx : 0x%x\n", cui, tcount, code_base, code_sz,
		glob_base, glob_sz);
#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		DebugCU("e2k_set_vmm_cui called for cui = %d; code 0x%lx : 0x%lx\n",
			cui, code_base, code_base + code_sz);
		retval = e2k_set_vmm_cui(mm, cui, code_base,
					 code_base + code_sz);
		if (retval)
			return retval;
  	}
#endif

//TODO 3.10 cute_p is user address, read it carefully
	CUTE_CUD_BASE(cute_p) = code_base;
	CUTE_CUD_SIZE(cute_p) =
		ALIGN_MASK(code_sz,E2K_ALIGN_CODES_MASK);
	CUTE_CUD_C(cute_p) = CUD_CFLAG_SET;

	CUTE_GD_BASE(cute_p) = glob_base;
	CUTE_GD_SIZE(cute_p) =
		ALIGN_MASK(glob_sz, E2K_ALIGN_GLOBALS_MASK);

	CUTE_TSD_BASE(cute_p) = atomic_add_return(tcount, &mm->context.tstart) -
				tcount;
	CUTE_TSD_SIZE(cute_p) = tcount;
	return 0;
}

/**
 * alloc_hw_stack_mappings - preallocates memory for hw stacks
 *			     mappings to kernel
 * @new_ti: the new task's thread_info
 *
 * We do not want to allocate memory in do_exit() path
 * (in case an OOM happens) so we set everything ready
 * beforehand.
 */
static int alloc_hw_stack_mappings(struct thread_info *new_ti)
{
	struct vm_struct *p_area, *pc_area;

	p_area = alloc_vm_area(KERNEL_P_STACK_SIZE, NULL);
	if (!p_area)
		goto out;

	pc_area = alloc_vm_area(KERNEL_PC_STACK_SIZE, NULL);
	if (!pc_area)
		goto out_free_p;

	new_ti->mapped_p_stack = p_area;
	new_ti->mapped_pc_stack = pc_area;

	return 0;


out_free_p:
	free_vm_area(p_area);
out:
	return -ENOMEM;
}

/**
 * do_sys_execve - switch to the thread's context (stacks, CUT, etc)
 * @entry: user function to call
 * @sp: user stack's top
 * @kernel: called by a kernel thread
 *
 * This is always called as the last step when exec()'ing a user binary.
 */
static long do_sys_execve(unsigned long entry, unsigned long sp, int kernel)
{
	thread_info_t *const ti = current_thread_info();
	struct mm_struct *mm = current->mm;
	start_fn	start;
	int		error;
	struct hw_stack_area *k_psp_area = NULL, *k_pcsp_area = NULL;
	void		*k_psp_stk = NULL, *k_pcsp_stk = NULL;
	e2k_stacks_t	stacks;
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_addr_t	stack_top;
	u64		u_stk_base, u_stk_sz;
	e2k_cutd_t	cutd;
	e2k_size_t	size;
	e2k_cute_t	*cute_p;

#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE)
		sp &= ~E2K_ALIGN_PUSTACK_MASK;
	else
#endif
		sp &= ~E2K_ALIGN_USTACK_MASK;

	start = (start_fn) entry;

	u_stk_base = (u64) get_user_main_c_stack((e2k_addr_t) sp, &stack_top);
	if (u_stk_base == 0) {
		error = -ENOMEM;
		DebugEX("is terminated: get_user_main_c_stack() failed and returned error %d\n",
			error);
		goto fatal_error;
	}
	u_stk_sz = sp - u_stk_base;

	usd_hi = READ_USD_HI_REG();
	usd_lo = READ_USD_LO_REG();

	AS_STRUCT(usd_lo).base = sp;
	AS_STRUCT(usd_lo).p = 0;
	AS_STRUCT(usd_hi).size = u_stk_sz;

	DebugEX("stack base 0x%lx size 0x%lx top 0x%lx\n",
		u_stk_base, u_stk_sz, stack_top);

	/*
	 * Free stack areas lists before switching to the new stacks.
	 * For user threads this is done by deactivate_mm().
	 */
	if (kernel) {
		if (UHWS_PSEUDO_MODE) {
			BUG_ON((unsigned long) ti->cur_ps->base < TASK_SIZE ||
			       (unsigned long) ti->cur_pcs->base < TASK_SIZE);
			BUG_ON(!list_is_singular(&ti->ps_list) ||
			       !list_is_singular(&ti->pcs_list));

			list_del(&ti->cur_ps->list_entry);
			k_psp_area = ti->cur_ps;
			ti->cur_ps = NULL;

			list_del(&ti->cur_pcs->list_entry);
			k_pcsp_area = ti->cur_pcs;
			ti->cur_pcs  = NULL;
		} else {
			BUG_ON((unsigned long) ti->ps_base < TASK_SIZE ||
			       (unsigned long) ti->pcs_base < TASK_SIZE);

			k_psp_stk = ti->ps_base;
			ti->ps_base = NULL;
			k_pcsp_stk = ti->pcs_base;
			ti->pcs_base = NULL;
		}
	} else {
		if (UHWS_PSEUDO_MODE) {
			BUG_ON(!list_empty(&ti->ps_list) ||
			       !list_empty(&ti->pcs_list));
			BUG_ON(!list_empty(&ti->old_u_pcs_list));
			BUG_ON(ti->cur_ps || ti->cur_pcs);
		}
	}

	if (kernel) {
		BUG_ON(ti->mapped_p_stack || ti->mapped_pc_stack);
		error = alloc_hw_stack_mappings(ti);
		if (error) {
			DebugEX("Could not allocate stacks mappings\n");
			goto fatal_error;
		}
	}

	error = create_all_user_hard_stacks(ti, &stacks);
	if (error) {
		DebugEX("Could not create user hardware stacks\n");
		goto fatal_error;
	}

	/*
	 * Here we go with CUT handling.
	 */

	/* Allocate memory for CUT table (2Mb) */
	cute_p = (e2k_cute_t *) USER_CUT_AREA_BASE;
	size   = (e2k_size_t) USER_CUT_AREA_SIZE;

	if (alloc_cu_table((e2k_addr_t) cute_p, size)) {
		DebugEX("Can't create CU table.\n");
		error = -ENOMEM;
		goto fatal_error;
	}

	/*
	 * Fill CUT entry #0 with zeroes.
	 * #0 can not be legally used in both 32bit and 3p modes.
	 */

	CUTE_CUD_BASE(cute_p)	= 0;
	CUTE_CUD_SIZE(cute_p)	= 0;
	CUTE_CUD_C   (cute_p)	= 0;

	CUTE_GD_BASE(cute_p)	= 0;
	CUTE_GD_SIZE(cute_p)	= 0;

	CUTE_TSD_BASE(cute_p)	= 0;
	CUTE_TSD_SIZE(cute_p)	= 0;


#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		DebugEX("create_cut_entry for new protected loader\n");
		error = create_cut_entry(mm->context.tcount,
					 mm->start_code, mm->end_code,
					 mm->start_data, mm->end_data);
	}
	else
#endif /* CONFIG_PROTECTED_MODE */ 
	{
		DebugEX("create_cut_entry for unprotected mode\n");
		error = create_cut_entry(0,
			0L, current->thread.flags & E2K_FLAG_32BIT ?
				TASK32_SIZE : 	TASK_SIZE,
			0L, current->thread.flags & E2K_FLAG_32BIT ?
				TASK32_SIZE : 	TASK_SIZE);
	}
	if (error) {
		DebugEX("Could not create CUT entry\n");
		goto fatal_error;
	}

	/*
	* Set CU descriptor (register) to point to the CUT base.
	*/
	cutd.CUTD_base  = USER_CUT_AREA_BASE;
	WRITE_CUTD_REG(cutd);

	/*
	 * We don't return to hard_sys_calls() so call
	 * syscall_trace_leave() manually.
	 */
	if (unlikely(ti->flags & _TIF_WORK_SYSCALL_TRACE)) {
		struct pt_regs *regs = current_pt_regs();

		if (regs && user_mode(regs))
			syscall_trace_leave(regs);
	}

	/*
	 * Set some special registers in accordance with
	 * E2K API specifications.
	 */

	INIT_SPECIAL_REGISTERS();
#ifdef CONFIG_GREGS_CONTEXT
	INIT_G_REGS();
	INIT_TI_GLOBAL_REGISTERS(current_thread_info());
#endif

#if defined CONFIG_FUNCTION_GRAPH_TRACER
	/*
	 * We won't ever return from this function and we are on a new stack
	 * so remove all tracing entries.
	 */
	current->curr_ret_stack = -1;
#endif

	/*
	 * Switch to the hardware stacks in the new user space.
	 * Note that we should not fail after this, otherwise
	 * deactivate_mm() won't switch to kernel hardware stacks
	 * (because it will not find kernel entry point), leading
	 * to all kinds of problems.
	 */
	goto_new_user_hard_stk(&stacks);

	/*
	 * Free the old hardware stacks after we've switched to the new ones
	 */
	if (kernel) {
		if (UHWS_PSEUDO_MODE) {
			free_kernel_p_stack(k_psp_area->base);
			free_kernel_pc_stack(k_pcsp_area->base);
			kfree(k_psp_area);
			kfree(k_pcsp_area);
		} else {
			free_kernel_p_stack(k_psp_stk);
			free_kernel_pc_stack(k_pcsp_stk);
		}
	} else {
		BUG_ON(!test_ts_flag(TS_MAPPED_HW_STACKS));
		unmap_hw_stack_mappings(ti);
		free_hw_stack_pages(ti);
	}

	ti->u_stk_base = u_stk_base;
	ti->u_stk_sz = u_stk_sz;
	ti->u_stk_top = stack_top;
	ti->pt_regs = NULL; /* Could have been allocated by a signal handler */
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	ti->times_num = 0;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	raw_local_irq_disable();

	user_enter();

	/*
	 * And now just switch to user's data stack and function
	 */

	raw_all_irq_disable();

	WRITE_SBR_REG_VALUE(stack_top & ~E2K_ALIGN_STACKS_BASE_MASK);
	WRITE_USD_REG(usd_hi, usd_lo);

	E2K_SET_DSREG(rpr.hi, 0);
	E2K_SET_DSREG(rpr.lo, 0);

#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
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
				3, base_lo, base_hi, start);
	} else {
		E2K_JUMP_WITH_ARGUMENTS(switch_to_user_func, 2, 0, start);
	}
#else
	E2K_JUMP_WITH_ARGUMENTS(switch_to_user_func, 2, 0, start);
#endif /* CONFIG_PROTECTED_MODE */


fatal_error:
	if (kernel) {
		if (UHWS_PSEUDO_MODE) {
			if (k_psp_area) {
				list_add(&k_psp_area->list_entry, &ti->ps_list);
				ti->cur_ps = k_psp_area;
			}
			if (k_pcsp_area) {
				list_add(&k_pcsp_area->list_entry,
					 &ti->pcs_list);
				ti->cur_pcs = k_pcsp_area;
			}
		} else {
			if (k_psp_stk)
				ti->ps_base = k_psp_stk;
			if (k_pcsp_stk)
				ti->pcs_base = k_pcsp_stk;
		}
	}

	DebugEX("fatal error %d: send KILL signal\n", error);

	if (kernel)
		/* Nowhere to return to, just exit */
		do_exit(SIGKILL);

	if (kernel)
		/* Nowhere to return to, just exit */
		do_exit(SIGKILL);

	send_sig(SIGKILL, current, 0);

	return error;
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

void start_thread(struct pt_regs *regs, unsigned long entry, unsigned long sp)
{
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_mem_crs_t *crs;
	unsigned long *frame;
	unsigned long flags;
	bool flush_chain, flush_procedure;

	DebugP("entry 0x%lx sp 0x%lx\n", entry, sp);

	current_thread_info()->execve.entry = entry;
	current_thread_info()->execve.sp = sp;

	/*
	 * If called from user mode then do_sys_execve() will
	 * be called manually from ttable_entry().
	 */
	if (test_ts_flag(TS_USER_EXECVE))
		return;

	raw_all_irq_save(flags);

	psp_lo = READ_PSP_LO_REG();
	pcsp_lo = READ_PCSP_LO_REG();
	psp_hi = READ_PSP_HI_REG();
	pcsp_hi = READ_PCSP_HI_REG();

	flush_chain = (AS(pcsp_hi).ind < 2 * SZ_OF_CR);
	/* Assume a maximum of 4 do_sys_execve()'s parameters */
	flush_procedure = (AS(psp_hi).ind < 2 * EXT_4_NR_SZ);

	if (flush_chain)
		E2K_FLUSHC;
	if (flush_procedure)
		E2K_FLUSHR;
	if (flush_chain || flush_procedure)
		E2K_FLUSH_WAIT;

	/*
	 * Change IP of the last frame to do_sys_execve().
	 */
	crs = (e2k_mem_crs_t *) (AS(pcsp_lo).base + SZ_OF_CR);

	AS(crs->cr0_hi).ip = (unsigned long) &do_sys_execve >> 3;

	/*
	 * Put do_sys_execve()'s parameters into the procedure stack.
	 */
	frame = (unsigned long *) AS(psp_lo).base;

	frame[0] = entry;
	if (machine.iset_ver < E2K_ISET_V5) {
		frame[1] = sp;
		/* Skip frame[2] and frame[3] - they hold extended data */
	} else {
		frame[2] = sp;
		/* Skip frame[1] and frame[3] - they hold extended data */
	}
	frame[4] = true;

	raw_all_irq_restore(flags);

	return;
}
EXPORT_SYMBOL(start_thread);


/*
 * Idle related variables and functions
 */
unsigned long boot_option_idle_override = 0;
EXPORT_SYMBOL(boot_option_idle_override);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static void save_binco_regs(struct task_struct *new_task)
{
	/* Save intel regs from processor. For binary compiler. */
	if (!TASK_IS_BINCO(current))
		return;

	SAVE_INTEL_REGS((&new_task->thread.sw_regs));
#ifdef CONFIG_TC_STORAGE
	E2K_FLUSH_ALL_TC;
	new_task->thread.sw_regs.tcd = E2K_GET_TCD();
#endif /* CONFIG_TC_STORAGE */
}
#else /* !CONFIG_SECONDARY_SPACE_SUPPORT: */
#define save_binco_regs(new_task)
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

static inline void
init_sw_regs(struct task_struct *new_task, e2k_stacks_t *new_stacks,
		e2k_mem_crs_t *new_crs, bool kernel)
{
	struct sw_regs *new_sw_regs = &new_task->thread.sw_regs;
	struct thread_info *new_ti = task_thread_info(new_task);

	/*
	 * Protect kernel part of hardware stacks from user.
	 *
	 * sw_regs contains the real value of psp.hi/pcsp.hi as
	 * opposed to pt_regs, so adjust "size" field explicitly.
	 */
	if (!kernel) {
		new_stacks->psp_hi.PSP_hi_size -= KERNEL_P_STACK_SIZE;
		new_stacks->pcsp_hi.PCSP_hi_size -= KERNEL_PC_STACK_SIZE;

		clear_ti_status_flag(new_ti, TS_HW_STACKS_EXPANDED);
	} else {
		set_ti_status_flag(new_ti, TS_HW_STACKS_EXPANDED);
	}

	new_sw_regs->sbr     = new_stacks->sbr;
	new_sw_regs->usd_lo  = new_stacks->usd_lo;
	new_sw_regs->usd_hi  = new_stacks->usd_hi;
	new_sw_regs->psp_lo  = new_stacks->psp_lo;
	new_sw_regs->psp_hi  = new_stacks->psp_hi;
	new_sw_regs->pcsp_lo = new_stacks->pcsp_lo;
	new_sw_regs->pcsp_hi = new_stacks->pcsp_hi;
	new_sw_regs->cr0_lo  = new_crs->cr0_lo;
	new_sw_regs->cr0_hi  = new_crs->cr0_hi;
	new_sw_regs->cr_wd   = new_crs->cr1_lo;
	new_sw_regs->cr_ussz = new_crs->cr1_hi;

	/*
	 * New process will start with interrupts disabled.
	 * They will be enabled in schedule_tail() (user's upsr
	 * is saved in pt_regs and does not need to be corrected).
	 */
	new_task->thread.sw_regs.upsr    = E2K_KERNEL_UPSR_DISABLED;

	AS_WORD(new_sw_regs->fpcr)  = E2K_GET_SREG_NV(fpcr);
	AS_WORD(new_sw_regs->fpsr)  = E2K_GET_SREG_NV(fpsr);
	AS_WORD(new_sw_regs->pfpfr) = E2K_GET_SREG_NV(pfpfr);
	AS_WORD(new_sw_regs->cutd)  = E2K_GET_DSREG_NV(cutd);

#ifdef CONFIG_GREGS_CONTEXT
	SAVE_GLOBAL_REGISTERS(new_task, true);
#endif /* CONFIG_GREGS_CONTEXT */

	save_binco_regs(new_task);

	DebugSWregs("finish", &new_task->thread.sw_regs);
}

long __ret_from_fork(struct task_struct *prev)
{
	BUG_ON(current->mm && sge_checking_enabled()
			|| !current->mm && !sge_checking_enabled());

	get_task_struct(current);
	schedule_tail(prev);

	return 0;
}

asmlinkage long e2k_sys_clone(unsigned long clone_flags, e2k_addr_t newsp,
			  struct pt_regs *regs, int __user *parent_tidptr,
			  int __user *child_tidptr, unsigned long tls)
{
	struct task_struct 	*current_fork = current;
	long rval;

	DebugCL("CPU #%d started for task %s (pid %d) with new "
		"SP 0x%lx\n",
		smp_processor_id(), current->comm, current->pid, newsp);
	DebugCpuR("sys_clone before");

        regs->tls = tls;
        rval = do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr);

        /* we should be here if parent only */
        if (current_fork != current)
        	/* we should return in ttable for new thread */
        	panic("sys_clone: current_fork != current");

	DebugCL("sys_clone exited with value %ld\n", rval);
        return rval;
}
asmlinkage pid_t sys_clone2(unsigned long clone_flags,
				long stack_base,
				unsigned long long stack_size,
				struct pt_regs * regs, 
	                        int __user *parent_tidptr,
                                int __user *child_tidptr,
                                unsigned long tls)
{
	long 			rval;
	long 			flags = clone_flags;
	struct task_struct 	*current_fork = current;

	DebugCL("start.\n");
	if (!access_ok(VERIFY_WRITE, stack_base, stack_size)) {
		return -ENOMEM;
	}
        //if (!flags) flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
        if (!flags) flags = SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES;
        regs->tls = tls;	
        rval = do_fork(flags, stack_base, stack_size,
		       parent_tidptr, child_tidptr);

        /* we should be here if parent only */
        if (current_fork != current)
        	/* we should return in ttable for new thread */
        	panic("sys_clone: current_fork != current");
	
	DebugCL("sys_clone2 exited with rval %ld\n", rval);

        return rval;
}

asmlinkage long sys_fork()
{
	long rval;
	unsigned long clone_flags = SIGCHLD;

	DebugF("CPU #%d: started for task %s (pid %d)\n",
		smp_processor_id(), current->comm, current->pid);

	rval = do_fork(clone_flags, 0, 0, NULL, NULL);
	DebugF("returned with child pid %ld\n", rval);

        return rval;
}

asmlinkage long e2k_sys_vfork(struct pt_regs *regs)
{
	long rval;

	DebugP("entered.\n");

	rval = do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, 0, NULL, NULL);

	DebugP("exited rval=%ld current=%p, current->pid =%d\n",
               rval, current, current->pid);

	return rval;
}

/*
 * Correct kernel pt_regs structure:
 * It needs remain state of stack registers as for parent stacks:
 * indexes and correct addresses and sizes of new process:
 * size & base of data stack and base & size of hardware stacks
 */

static inline void
fix_kernel_pt_regs(thread_info_t *new_ti, pt_regs_t *regs,
			e2k_size_t delta_sp, e2k_size_t delta_sz)
{
	e2k_stacks_t	*stacks = &regs->stacks;
	e2k_mem_crs_t	*crs = &regs->crs;
	e2k_addr_t	cur_base;
	e2k_addr_t	new_base;
	e2k_size_t	cur_size;
	e2k_size_t	new_size;
	e2k_cr1_hi_t 	cr1_hi;

	DebugKS("corrects SBR from 0x%lx "
		"to 0x%lx\n",
		stacks->sbr, new_ti->k_stk_base + new_ti->k_stk_sz);
	stacks->sbr = new_ti->k_stk_base + new_ti->k_stk_sz;

	cur_base = stacks->usd_lo.USD_lo_base;
	cur_size = stacks->usd_hi.USD_hi_size;
	new_base = cur_base + delta_sp;
	new_size = cur_size + delta_sz;
	DebugKS("corrects USD base from 0x%llx to 0x%lx, size from 0x%x to 0x%lx\n",
		stacks->usd_lo.USD_lo_base, new_base,
		stacks->usd_hi.USD_hi_size, new_size);
	stacks->usd_lo.USD_lo_base = new_base;
	stacks->usd_hi.USD_hi_size = new_size;

	if (delta_sz == 0) {
		/* Does not need correct cr1_hi.ussz field because of */
		/* size of data stack was not changed */
		return;
	}
	cr1_hi = crs->cr1_hi;
	AS_STRUCT(cr1_hi).ussz += (delta_sz >> 4);
	DebugKS("corrects CR1_hi ussz field "
		"from 0x%x to 0x%x\n",
		AS_STRUCT(crs->cr1_hi).ussz << 4,
		AS_STRUCT(cr1_hi).ussz << 4);
	crs->cr1_hi = cr1_hi;

	/* Update all pointers */
	if (regs->trap)
		regs->trap = (void *) regs->trap + delta_sp;
#ifdef CONFIG_USE_AAU
	if (regs->aau_context)
		regs->aau_context = (void *) regs->aau_context + delta_sp;
#endif
}

static inline void
fix_kernel_stacks_state(pt_regs_t *regs, e2k_size_t delta_sz)
{
	DebugKS("corrects kernel USD current "
		"size from 0x%lx to 0x%lx\n",
		regs->k_usd_size, regs->k_usd_size + delta_sz);
	regs->k_usd_size += delta_sz;
}


/*
 * fork() duplicates all user virtual space, including user local
 * data stack and hardware stacks, but creates new kernel stacks for
 * son process. These stacks have other addresses and can have other size.
 * It needs correct all stacks pointers and registers into the
 * thread/thread_info structure and pt_regs structures of new process
 */

static inline int
fix_all_kernel_stack_regs(thread_info_t *new_ti, e2k_size_t delta_sp)
{
	thread_info_t	*cur_ti = current_thread_info();
	pt_regs_t	*regs;
	e2k_addr_t	cur_base;
	e2k_addr_t	new_base;
	e2k_size_t	cur_size;
	e2k_size_t	new_size;
	e2k_size_t	delta_sz;
	int		regs_num = 0;

	DebugKS("started for thread 0x%p, "
		"delta sp 0x%lx\n",
		new_ti, delta_sp);
	/*
	 * thread_info structure created with empty state of stacks.
	 * We copied fully data from current stacks to new stacks, so
	 * it needs correct only current state of stack registers
	 * according to state of parent stacks:
	 * size & base of data stack and indexes of hardware stacks
	 */
	cur_base = cur_ti->k_usd_lo.USD_lo_base;
	cur_size = cur_ti->k_usd_hi.USD_hi_size;
	new_base = cur_base + delta_sp;
	new_size = new_base - new_ti->k_stk_base;
	delta_sz = new_size - cur_size;
	DebugKS("corrects USD base from 0x%llx to 0x%lx, size from 0x%x to 0x%lx\n",
		new_ti->k_usd_lo.USD_lo_base, new_base,
		new_ti->k_usd_hi.USD_hi_size, new_size);
	new_ti->k_usd_lo.USD_lo_base = new_base;
	new_ti->k_usd_hi.USD_hi_size = new_size;

	/*
	 * kernel pt_regs structures were copied from parent structures
	 * without any corrections, it needs remain state of stack
	 * registers as for parent stacks: indexes and correct addresses
	 * and sizes of new process: size & base of data stack
	 * and base & size of hardware stacks
	 */

	CHECK_PT_REGS_LOOP(new_ti->pt_regs);
	for (regs = new_ti->pt_regs; regs != NULL; regs = regs->next) {
		CHECK_PT_REGS_LOOP(regs);
		if (user_mode(regs)) {
			DebugKS("pt_regs 0x%p "
				"is user regs, miss its\n",
				regs);
			continue;
		}
		fix_kernel_pt_regs(new_ti, regs, delta_sp, delta_sz);
		regs_num ++;
	}
	return regs_num;
}

/*
 * To increment or decrease user data stack size it needs update
 * data stack size in the USD register and and in te chine regisres
 * (CR1_hi.ussz field) into all user pt_regs structures of the process
 */

int
fix_all_user_stack_regs(pt_regs_t *regs, e2k_size_t delta_sp)
{
	pt_regs_t	*user_regs;
	e2k_usd_hi_t 	usd_hi;
	e2k_cr1_hi_t 	cr1_hi;
	int		regs_num = 0;

	DebugES("started with pt_regs 0x%p, "
		"delta sp 0x%lx\n",
		regs, delta_sp);
	CHECK_PT_REGS_LOOP(regs);
	for (user_regs = regs; user_regs != NULL;
					user_regs = user_regs->next) {
		if (!user_mode(user_regs) &&
			user_regs->stacks.usd_lo.USD_lo_base >= TASK_SIZE) {
			DebugDS("pt_regs 0x%p "
				"is kernel regs, miss its\n",
				user_regs);
			continue;
		}
		usd_hi = user_regs->stacks.usd_hi;
		DebugES("pt_regs 0x%p is user regs, USD base 0x%llx, size 0x%x\n",
			user_regs, user_regs->stacks.usd_lo.USD_lo_base,
			usd_hi.USD_hi_size);
		usd_hi.USD_hi_size += delta_sp;
		user_regs->stacks.usd_hi = usd_hi;
		DebugES("USD new size 0x%x\n",
			usd_hi.USD_hi_size);
		cr1_hi = user_regs->crs.cr1_hi;
		DebugES("CR1_hi us size 0x%x\n",
			AS_STRUCT(cr1_hi).ussz << 4);
		AS_STRUCT(cr1_hi).ussz += (delta_sp >> 4);
		user_regs->crs.cr1_hi = cr1_hi;
		DebugES("CR1_hi new us size 0x%x\n",
			AS_STRUCT(cr1_hi).ussz << 4);
		regs_num ++;
	}
	return regs_num;
}

int
fix_all_stack_sz(e2k_addr_t base, long cr_ind,
			e2k_size_t delta_sp, long start_cr_ind,
			int user_stacks, int set_stack_sz)
{
	e2k_cr0_hi_t 	cr0_hi;
	e2k_cr1_hi_t 	cr1_hi;
	e2k_cr1_lo_t 	cr1_lo;
	e2k_pcsp_lo_t 	pcsp_lo;
	e2k_pcsp_hi_t 	pcsp_hi;
	long		flags = 0;
	int		current_pcs = 0;

	if (start_cr_ind <= 0)
		start_cr_ind = 0;
	DebugES("started with PCSP stack base "
		"0x%lx cr_ind 0x%lx, start cr_ind 0x%lx, delta sp 0x%lx\n",
		base, cr_ind, start_cr_ind, delta_sp);
	if (cr_ind == 0) {
		DebugES("stack is empty\n");
		return 0;
	}

	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_hi = READ_PCSP_HI_REG();
	if (base >= pcsp_lo.PCSP_lo_base &&
		base < pcsp_lo.PCSP_lo_base + pcsp_hi.PCSP_hi_size) {
		current_pcs = 1;
		raw_all_irq_save(flags);
		E2K_FLUSHC;
		E2K_FLUSH_WAIT;
	}

	for (cr_ind = cr_ind - SZ_OF_CR; cr_ind >= start_cr_ind;
						cr_ind -= SZ_OF_CR) {
		int err;
		e2k_psr_t psr;
		e2k_addr_t ip;

		err = get_cr0_hi(&cr0_hi, base, cr_ind, user_stacks);
		if (err != 0) {
			DebugES("get_cr0_hi() "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n",
				base, cr_ind, err);
			return err;
		}
		ip = (AS_STRUCT(cr0_hi).ip) << 3;
		DebugES("cr_ind 0x%lx : IP "
			"0x%lx\n", cr_ind, ip);
		err = get_cr1_lo(&cr1_lo, base, cr_ind, user_stacks);
		if (err != 0) {
			DebugES("get_cr1_lo() "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n", base, cr_ind, err);
			return err;
		}
		AS_WORD(psr) = AS_STRUCT(cr1_lo).psr;
		DebugES("cr_ind 0x%lx : psr "
			"0x%x\n", cr_ind, AS_WORD(psr));
		if ((user_stacks && (ip >= TASK_SIZE ||
						AS_STRUCT(psr).pm)) ||
			(!user_stacks && (ip < TASK_SIZE &&
						!AS_STRUCT(psr).pm))) {
			/*
			 * It is a kernel function in the user PC stack or
			 * user function in the kernel stack
			 * The data stack of this function is out of this
			 * stack and places in separate user or kernel
			 * space for each process.
			 * Do not correct this chain register
			 */
			DebugES("it is the "
				"chain of %s procedure, do not correct "
				"one\n",
				(!user_stacks) ? "user" : "kernel");
			continue;
		}
		err = get_cr1_hi(&cr1_hi, base, cr_ind, user_stacks);
		if (err != 0) {
			DebugES("get_cr1_hi() "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n", base, cr_ind, err);
			return err;
		}
		DebugES("cr_ind 0x%lx : ussz 0x%x\n",
			cr_ind, (AS_STRUCT(cr1_hi).ussz) << 4);
		if (set_stack_sz)
			(AS_STRUCT(cr1_hi).ussz) = (delta_sp >> 4);
		else
			(AS_STRUCT(cr1_hi).ussz) += (delta_sp >> 4);
		DebugES("new cr1_hi.ussz 0x%x\n",
			(AS_STRUCT(cr1_hi).ussz) << 4);
		err = put_cr1_hi(cr1_hi, base, cr_ind, user_stacks);
		if (err != 0) {
			DebugES("put_cr1_hi() "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n", base, cr_ind, err);
			return err;
		}
	}

	if (current_pcs)
		raw_all_irq_restore(flags);

	return 0;
}

static inline void
account_the_wd_psize(e2k_mem_crs_t *crs, long cr_ind, e2k_size_t *wd_psize)
{
	*wd_psize = AS_STRUCT(crs->cr1_lo).wpsz;
	DebugSD("cr_ind 0x%lx : WD.psize 0x%lx\n",
		cr_ind, *wd_psize);
}

static inline void
account_the_ps_frame(e2k_mem_crs_t *crs, long cr_ind, long *fp_ind)
{
	*fp_ind -= AS_STRUCT(crs->cr1_lo).wbs * EXT_4_NR_SZ;
	DebugST("cr_ind 0x%lx : wbs "
		"0x%x, procedure stack ind 0x%lx\n",
		cr_ind, AS_STRUCT(crs->cr1_lo).wbs * EXT_4_NR_SZ, *fp_ind);
}

static inline void
account_the_ds_frame(e2k_mem_crs_t *crs, long cr_ind,
			e2k_addr_t *cur_usd_sp, long *cur_usd_size)
{
	long cur_ussz;

	cur_ussz = AS_STRUCT(crs->cr1_hi).ussz << 4;
	*cur_usd_sp += (cur_ussz - *cur_usd_size);
	DebugST("cr_ind 0x%lx "
		": ussz 0x%lx, current SP 0x%lx\n",
		cr_ind, cur_ussz, *cur_usd_sp);
	*cur_usd_size = cur_ussz;
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

	E2K_FLUSH_WAIT;

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

int
go_hd_stk_down(e2k_psp_hi_t psp_hi,
		e2k_pcsp_lo_t pcsp_lo, e2k_pcsp_hi_t pcsp_hi,
		int down,
		long *psp_ind, long *pcsp_ind,
		e2k_size_t *wd_psize, int *sw_num_p,
		e2k_mem_crs_t *crs, int user_stacks)
{
	unsigned long	flags;
	u64		pcs_base;
	s64		cr_ind, end_cr_ind;
	long		fp_ind;
	e2k_size_t	psize = 0;
	int		sw_num = 0, user_frame = user_stacks;

	/*
	 * Dump chain stack contents to memory.
	 */
	raw_all_irq_save(flags);
	E2K_FLUSHC;
	E2K_FLUSH_WAIT;
	raw_all_irq_restore(flags);

	pcs_base = AS_STRUCT(pcsp_lo).base;
	cr_ind = AS_STRUCT(pcsp_hi).ind;
	end_cr_ind = cr_ind - SZ_OF_CR * down;
	fp_ind = AS_STRUCT(psp_hi).ind;
	DebugSD("started with base 0x%lx cr_ind 0x%lx : "
		"procedure stack ind 0x%lx, end cr_ind 0x%lx\n",
		pcs_base, cr_ind, fp_ind, end_cr_ind);

	while (1) {
		e2k_psr_t psr;
		int err;

		AS_WORD(psr) = AS_STRUCT(crs->cr1_lo).psr;
		if (user_frame == AS_STRUCT(psr).pm) {
			if (user_frame == user_stacks)
				sw_num ++;
			user_frame = !user_frame;
		}
		DebugSD("cr_ind 0x%lx : IP "
			"0x%lx , psr.pm 0x%x, frames switching # %d\n",
			cr_ind, (AS_STRUCT(crs->cr0_hi).ip) << 3,
			AS_STRUCT(psr).pm, sw_num);
		if (cr_ind <= end_cr_ind) {
			break;
		}

		/*
		 * Wd_psize should be accounted in any case
		 */
		account_the_wd_psize(crs, cr_ind, &psize);

		account_the_ps_frame(crs, cr_ind, &fp_ind);

		cr_ind -= SZ_OF_CR;

		err = get_crs(crs, pcs_base, cr_ind, user_stacks);
		if (err != 0) {
			DebugSD("get_crs() "
				"base 0x%lx cr_ind 0x%lx returned "
				"error %d\n",
				pcs_base, cr_ind, err);
			return err;
		}

		DebugSD("cr_ind 0x%lx : ussz 0x%x\n",
			cr_ind, (AS_STRUCT(crs->cr1_hi).ussz) << 4);

	}

	*psp_ind = fp_ind;
	*pcsp_ind = cr_ind;
	*wd_psize = psize;
	*sw_num_p = sw_num;
	DebugSD("returns with cr_ind 0x%lx fp_ind 0x%lx "
		"WD.psize 0x%lx, SW_num %d\n",
		cr_ind, fp_ind, psize, sw_num);
	return 0;
}

/*
 * Calculate hardware stacks indexes and sizes, kernel data stack bottom
 * and SP for specified frames number (level_num up or down).
 * Before (if it needs) miss some frames (down number).
 * Hardware stacks can be handled only within the bounds of current
 * active (resident) stack frame
 */
static inline int
get_n_stacks_frames_to_copy(e2k_stacks_t *cur_stacks, e2k_mem_crs_t *cur_crs,
		int down, int level_num,
		int copy_data_stack, int user_stacks,
		long *fp_ind_p, long *fp_size_p,
		long *cr_ind_p, long *cr_size_p, e2k_mem_crs_t *new_crs,
		long *usd_bottom_p, long *usd_sp_p, long *usd_size_p)
{
	thread_info_t	*cur_thr = current_thread_info();
	long		fp_ind;
	long		fp_end;
	e2k_addr_t	pcs_base;
	long		cr_ind;
	long		cr_end;
	e2k_mem_crs_t	crs;
	e2k_addr_t	cur_usd_sp = 0;
	e2k_addr_t	cur_usd_start = 0;
	long		cur_usd_size = 0;
	int		sp_is_not_set = 0;
	e2k_size_t	psize = 0;
	int		sw_num = 0;
	long		to_copy;
	e2k_psr_t	psr;
	int		level = 0;
	int		other_frame;
	int		err;

	DebugUS("entered for %s stacks "
		"level down %d, num %d\n",
		(user_stacks) ? "user" : "kernel",
		down, level_num);

	pcs_base = cur_stacks->pcsp_lo.PCSP_lo_base;

	/*
	 * cr1_lo has wbs (num of NR in window) of previouse func
	 * (copy_thread) and we can get needed fp_ind in go_hd_stk_down()
	 */

	go_hd_stk_down(cur_stacks->psp_hi,
			cur_stacks->pcsp_lo, cur_stacks->pcsp_hi,
			down,
			&fp_ind, &cr_ind,
			&psize, &sw_num,
			cur_crs, user_stacks);
	fp_end = fp_ind;
	DebugUS("current procedure stack: "
		"start 0x%lx, ind 0x%lx\n",
		cur_stacks->psp_lo.PSP_lo_base, fp_ind);

	cr_end = cr_ind;
	DebugUS("current procedure chain "
		"stack: start 0x%lx, ind 0x%lx\n",
		pcs_base, cr_ind);
	if (level_num > cr_end / SZ_OF_CR) {
		level_num = cr_end / SZ_OF_CR;
	}
	if (down == 0) {
		crs = *cur_crs;
	} else {
		err = get_crs(&crs, pcs_base, cr_ind, user_stacks);
		if (err != 0) {
			DebugUS("get_crs() "
				": base 0x%lx cr_ind 0x%lx returned error "
				"%d\n",
				pcs_base, cr_ind, err);
			return err;
		}
	}
	*new_crs = crs;

	if (copy_data_stack) {
		cur_usd_size = AS_STRUCT(crs.cr1_hi).ussz << 4;
		cur_usd_sp = cur_stacks->usd_lo.USD_lo_base +
				(cur_usd_size -
					cur_stacks->usd_hi.USD_hi_size);
		cur_usd_start = cur_usd_sp;
		DebugUS("current data stack: sp 0x%lx, size of free area 0x%lx USD_size 0x%x\n",
			cur_usd_sp, cur_usd_size,
			cur_stacks->usd_hi.USD_hi_size);
	}
	AS_WORD(psr) = AS_STRUCT(crs.cr1_lo).psr;
	DebugUS("end cr_ind 0x%lx : IP "
		"0x%lx, psr.pm 0x%x\n",
		cr_ind, (AS_STRUCT(crs.cr0_hi).ip) << 3, AS_STRUCT(psr).pm);
	for (level = 0; level < level_num; level ++) {

		/*
		 * Wd_psize should be accounted in any case
		 */
		account_the_wd_psize(&crs, cr_ind, &psize);

		account_the_ps_frame(&crs, cr_ind, &fp_ind);

		if (cr_ind <= 0) {
			DebugUS("procedure "
				"chain stack ind 0%lx <= 0\n",
				cr_ind);
			BUG();
			return -EINVAL;
		}
		cr_ind -= SZ_OF_CR;

		err = get_crs(&crs, pcs_base, cr_ind, user_stacks);
		if (err != 0) {
			DebugUS("get_crs() "
				"base 0x%lx cr_ind 0x%lx returned "
				"error %d\n",
				pcs_base, cr_ind, err);
			return err;
		}
		if (!copy_data_stack)
			continue;
		AS_WORD(psr) = AS_STRUCT(crs.cr1_lo).psr;
		other_frame = (user_stacks == AS_STRUCT(psr).pm);
		DebugUS("cr_ind 0x%lx : IP "
			"0x%lx, psr.pm 0x%x, other frame %d\n",
			cr_ind, (AS_STRUCT(crs.cr0_hi).ip) << 3,
			AS_STRUCT(psr).pm, other_frame);
		if (other_frame) {
			/*
			 * It is a kernel function in the user PC
			 * stack or user function in the kernel stack.
			 * The data stack frame of this function
			 * is out of this stack and places
			 * in own kernel or user space for each
			 * process. This chain has not frames in
			 * the procedure stack and data stack.
			 */
			DebugUS("cr_ind "
				"0x%lx : %s function: do not copy data "
				"stack frames\n",
				cr_ind,
				(!user_stacks) ? "user" : "kernel");
			sp_is_not_set = 1;
		} else {
			account_the_ds_frame(&crs, cr_ind, &cur_usd_sp,
								&cur_usd_size);
			sp_is_not_set = 0;
		}
	}

	to_copy = fp_end - fp_ind;
	*fp_ind_p = fp_ind;
	*fp_size_p = to_copy;
	DebugUS("procedure stack "
		"to copy ind: 0x%lx, size 0x%lx\n",
		fp_ind, to_copy);

	to_copy = cr_end - cr_ind;
	*cr_ind_p = cr_ind;
	*cr_size_p= to_copy;
	DebugUS("procedure chain stack "
		"to copy ind: 0x%lx, size 0x%lx\n",
		cr_ind, to_copy);

	if (!copy_data_stack) {
		DebugUS("user data stack "
			"should not be copied\n");
		return 0;
	}
	if (sp_is_not_set) {
		if (user_stacks) {
			cur_usd_size = cur_thr->pt_regs->
						stacks.usd_hi.USD_hi_size;
			cur_usd_sp = cur_thr->pt_regs->
						stacks.usd_lo.USD_lo_base;
		} else {
			cur_usd_size = cur_thr->k_usd_hi.USD_hi_size;
			cur_usd_sp = cur_thr->k_usd_lo.USD_lo_base;
		}
		DebugUS("top of data stack "
			"is reached, set empty stack state: "
			"current SP 0x%lx, size 0x%lx\n",
			cur_usd_sp, cur_usd_size);
	}
	if (cr_ind == 0 && fp_ind != 0) {
		panic("get_n_stacks_frames_to_copy() : bottom of "
			"procedure chain stack is reached, but "
			"is not reached bottom of procedure "
			"stack: fp_ind 0x%lx\n", fp_ind);
	}
	*usd_bottom_p = cur_usd_start;
	*usd_sp_p = cur_usd_sp;
	*usd_size_p = cur_usd_size;

	DebugUS("local data stack "
		"to copy: bootom 0x%lx, sp 0x%lx, size 0x%lx\n",
		cur_usd_start, cur_usd_sp, cur_usd_size);

	return 0;
}
/*
 * Calculate full hardware stacks indexes and sizes, local data stack bootom
 * and SP. Before (if it needs) miss some frames (down number).
 */
static inline int
get_all_stacks_frames_to_copy(e2k_stacks_t *cur_stacks, e2k_mem_crs_t *cur_crs,
		int down,
		int copy_data_stack, int user_stacks,
		long *fp_size_p, long *cr_size_p, e2k_mem_crs_t *new_crs,
		long *usd_bottom_p, long *usd_sp_p, long *usd_size_p)
{
	thread_info_t	*cur_thr = current_thread_info();
	long		fp_end;
	e2k_addr_t	pcs_base;
	long		cr_end;
	e2k_mem_crs_t	crs;
	e2k_addr_t	cur_usd_sp = 0;
	e2k_addr_t	cur_usd_start = 0;
	long		cur_usd_size = 0;
	e2k_size_t	psize = 0;
	int		sw_num = 0;
	int		err;

	DebugUS("entered for %s stacks "
		"level down %d\n",
		(user_stacks) ? "user" : "kernel",
		down);

	pcs_base = cur_stacks->pcsp_lo.PCSP_lo_base;

	/*
	 * cr1_lo has wbs (num of NR in window) of previouse func
	 * (copy_thread) and we can get needed fp_ind in go_hd_stk_down()
	 */

	go_hd_stk_down(cur_stacks->psp_hi,
			cur_stacks->pcsp_lo, cur_stacks->pcsp_hi,
			down,
			&fp_end, &cr_end,
			&psize, &sw_num,
			cur_crs, user_stacks);
	DebugUS("current procedure stack: "
		"start 0x%lx, ind 0x%lx\n",
		cur_stacks->psp_lo.PSP_lo_base, fp_end);

	DebugUS("current procedure chain "
		"stack: start 0x%lx, ind 0x%lx\n",
		pcs_base, cr_end);
	if (down == 0) {
		crs = *cur_crs;
	} else {
		err = get_crs(&crs, pcs_base, cr_end, user_stacks);
		if (err != 0) {
			DebugUS("get_crs() "
				": base 0x%lx cr_ind 0x%lx returned error "
				"%d\n",
				pcs_base, cr_end, err);
			return err;
		}
	}
	*new_crs = crs;

	*fp_size_p = fp_end;
	DebugUS("procedure stack "
		"to copy full size 0x%lx\n",
		fp_end);

	*cr_size_p= cr_end;
	DebugUS("procedure chain stack "
		"to copy full size 0x%lx\n",
		cr_end);

	if (!copy_data_stack) {
		DebugUS("user data stack "
			"should not be copied\n");
		return 0;
	}
	cur_usd_size = AS_STRUCT(crs.cr1_hi).ussz << 4;
	cur_usd_sp = cur_stacks->usd_lo.USD_lo_base +
				(cur_usd_size -
					cur_stacks->usd_hi.USD_hi_size);
	cur_usd_start = cur_usd_sp;
	DebugUS("current data stack: sp 0x%lx, size of free area 0x%lx USD_size 0x%x\n",
		cur_usd_sp, cur_usd_size,
		cur_stacks->usd_hi.USD_hi_size);
	if (user_stacks) {
		cur_usd_size = cur_thr->u_stk_sz;
		cur_usd_sp = cur_thr->u_stk_top;
	} else {
		cur_usd_size = cur_thr->k_stk_sz;
		cur_usd_sp = cur_stacks->sbr;
	}
	DebugUS("empty stack state: SP 0x%lx, size 0x%lx\n",
		cur_usd_sp, cur_usd_size);
	*usd_bottom_p = cur_usd_start;
	*usd_sp_p = cur_usd_sp;
	*usd_size_p = cur_usd_size;

	DebugUS("local data stack "
		"to copy: bootom 0x%lx, sp 0x%lx, size 0x%lx\n",
		cur_usd_start, cur_usd_sp, cur_usd_size);

	return 0;
}


/*
 * Copy data stack (if it needs) from current user stacks to
 * the new process of kernel or user.
 * Stack will be copied from current stack pointers and only
 * from specified stack indexes and sizes
 */
static int do_copy_data_stack(e2k_stacks_t *new_stacks,
		int copy_data_stack, int user_stacks,
		long usd_bottom, long usd_sp, long usd_size,
		e2k_addr_t *delta_sp, long *delta_sz_p)
{
	e2k_addr_t	new_usd_base = 0;
	long		new_usd_size = 0;
	long		delta_sz = 0;
	long		usd_to_copy;

	DebugUS("entered for %s stacks\n",
		(user_stacks) ? "user" : "kernel");

	new_usd_base = new_stacks->usd_lo.USD_lo_base;
	new_usd_size = new_stacks->usd_hi.USD_hi_size;
	DebugUS("new data stack: base "
		"0x%lx, size 0x%lx\n",
		new_usd_base, new_usd_size);

	if (copy_data_stack) {
		delta_sz = new_usd_size - usd_size;
		if (delta_sp != NULL)
			*delta_sp = new_usd_base - usd_sp;
	} else {
		delta_sz = new_usd_size;
		if (delta_sp != NULL)
			*delta_sp = 0;
	}
	if (delta_sz_p != NULL)
		*delta_sz_p = delta_sz;
	DebugUS("delta sz 0x%lx: new USD "
		"size 0x%lx current USD size 0x%lx, delta sp 0x%lx\n",
		delta_sz, new_usd_size, usd_size,
		(delta_sp != NULL) ? *delta_sp : 0);
	if (!copy_data_stack) {
		DebugUS("user data stack should "
			"not be copied\n");
		return 0;
	}
	usd_to_copy = usd_sp - usd_bottom;
	if (usd_to_copy < 0) {
		DebugUS("size of data "
			"stack frames to copy 0x%lx is negative\n",
			usd_to_copy);
		BUG();
		return -EINVAL;
	} else if (usd_to_copy > new_usd_size) {
		DebugUS("size of data "
			"stack frames to copy 0x%lx > size of free area "
			"in the new stack 0x%lx\n",
			usd_to_copy, new_usd_size);
		return -EINVAL;
	} else if (usd_to_copy != 0) {
		DebugUS("copy data stack "
			"frames: from addr 0x%lx size 0x%lx to new stack "
			"addr 0x%lx end 0x%lx\n",
			usd_bottom, usd_to_copy,
			new_usd_base - usd_to_copy, new_usd_base);
		tagged_memcpy_8((char *) (new_usd_base - usd_to_copy),
				(char *) usd_bottom, usd_to_copy);
		new_usd_base -= usd_to_copy;
		new_usd_size -= usd_to_copy;
		new_stacks->usd_lo.USD_lo_base = new_usd_base;
		new_stacks->usd_hi.USD_hi_size = new_usd_size;
		DebugUS("new user data stack: "
			"base 0x%lx, free area size 0x%lx\n",
			new_usd_base, new_usd_size);
	} else {
		DebugUS("nothing to copy for "
			"user data stack\n");
	}

	return 0;
}

/*
 * Copy hardware stacks and data stack (if it needs) from current
 * user stacks to the new process of kernel or user.
 * Stack will be copied from current stack pointers and only
 * from specified stack indexes and sizes
 * Hardware stacks can be copied only within the bounds of current
 * active (resident) stack frame
 */
static inline int
do_copy_all_stacks(e2k_stacks_t *cur_stacks, e2k_mem_crs_t *cur_crs,
		e2k_stacks_t *new_stacks, e2k_mem_crs_t *new_crs,
		int copy_data_stack, int user_stacks,
		long fp_ind, long fp_size,
		long cr_ind, long cr_size,
		long usd_bottom, long usd_sp, long usd_size,
		e2k_addr_t *delta_sp, e2k_size_t *delta_sz_p)
{
	e2k_addr_t	new_ps_base;
	long		new_ps_ind;
	long		new_ps_size;
	e2k_addr_t	new_pcs_base;
	long		new_pcs_ind;
	long		new_pcs_size;
	e2k_addr_t	cur_ps_stk;
	e2k_addr_t	cur_pcs_stk;
	long		delta_sz = 0;
	int		err;

#if DEBUG_US_MODE
	dump_stack();
#endif
	DebugUS("entered for %s stacks\n",
		(user_stacks) ? "user" : "kernel");
	new_ps_base = new_stacks->psp_lo.PSP_lo_base;
	new_ps_ind = new_stacks->psp_hi.PSP_hi_ind;
	new_ps_size = new_stacks->psp_hi.PSP_hi_size;
	DebugUS("new procedure stack: base "
		"0x%lx, ind 0x%lx, size 0x%lx\n",
		new_ps_base, new_ps_ind, new_ps_size);

	new_pcs_base = new_stacks->pcsp_lo.PCSP_lo_base;
	new_pcs_ind = new_stacks->pcsp_hi.PCSP_hi_ind;
	new_pcs_size = new_stacks->pcsp_hi.PCSP_hi_size;
	DebugUS("new procedure chain stack: base "
		"0x%lx, ind 0x%lx, size 0x%lx\n",
		new_pcs_base, new_pcs_ind, new_pcs_size);

	cur_ps_stk = cur_stacks->psp_lo.PSP_lo_base;
	cur_pcs_stk = cur_stacks->pcsp_lo.PCSP_lo_base;

	err = do_copy_data_stack(new_stacks, copy_data_stack, user_stacks,
				 usd_bottom, usd_sp, usd_size,
				 delta_sp, &delta_sz);
	if (err != 0) {
		DebugUS("do_copy_data_stack() "
			"returned error %d\n", err);
		return err;
	}
	if (delta_sz_p != NULL)
		*delta_sz_p = delta_sz;

	if (fp_size < 0) {
		DebugUS("size of procedure "
			"fstack rames to copy 0x%lx is negative\n",
			fp_size);
		BUG();
		return -EINVAL;
	} else if (fp_size > new_ps_size - new_ps_ind) {
		DebugUS("size of procedure "
			"stack frames to copy 0x%lx > size of free area "
			"in new stack 0x%lx\n",
			fp_size, new_ps_size - new_ps_ind);
		return -EINVAL;
	} else if (fp_size != 0) {
		DebugUS("copy procedure stack "
			"frames: from addr 0x%lx size 0x%lx to new stack "
			"addr 0x%lx\n",
			cur_ps_stk + fp_ind, fp_size,
			new_ps_base + new_ps_ind);
		tagged_memcpy_8((char *)(new_ps_base + new_ps_ind),
				(char *)(cur_ps_stk + fp_ind), fp_size);
		new_ps_ind += fp_size;
		new_stacks->psp_hi.PSP_hi_ind = new_ps_ind;
		DebugUS("new procedure stack "
			"frames: ind 0x%lx\n", new_ps_ind);
	} else {
		DebugUS("nothing to copy for "
			"procedure stack\n");
	}

	if (cr_size < 0) {
		DebugUS("size of procedure "
			"chain stack frames to copy 0x%lx is negative\n",
			cr_size);
		BUG();
		return -EINVAL;
	} else if (cr_size > new_pcs_size - new_pcs_ind) {
		DebugUS("size of procedure "
			"chain stack frames to copy 0x%lx > size of free "
			"area in new stack 0x%lx\n",
			cr_size, new_pcs_size - new_pcs_ind);
		return -EINVAL;
	} else if (cr_size != 0) {
		DebugUS("copy procedure chain "
			"stack frames : from addr 0x%lx size 0x%lx to "
			"new stack addr 0x%lx\n",
			cur_pcs_stk + cr_ind, cr_size,
			new_pcs_base + new_pcs_ind);
		memcpy((char *)(new_pcs_base + new_pcs_ind),
				(char *)(cur_pcs_stk + cr_ind),
				cr_size);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		fix_return_values_in_chain_stack(current->mm,
				new_pcs_base + new_pcs_ind,
				cur_pcs_stk + cr_ind, cr_size,
				new_crs);
#endif

		new_stacks->pcsp_hi.PCSP_hi_ind = new_pcs_ind + cr_size;
		DebugUS("new procedure chain stack frames: ind 0x%x\n",
			new_stacks->pcsp_hi.PCSP_hi_ind);
		if (delta_sz != 0) {
			e2k_size_t delta_ussz;

			err = fix_all_stack_sz(new_pcs_base,
					new_pcs_ind + cr_size,
					delta_sz, new_pcs_ind,
					user_stacks,
					(copy_data_stack) ? 0 : 1);
			if (err != 0) {
				DebugUS(""
					"fix_all_stack_sz() "
					"returned error %d\n", err);
				return err;
			}
			delta_ussz = delta_sz >> 4;
			if (copy_data_stack)
				AS_STRUCT(new_crs->cr1_hi).ussz +=
								delta_ussz;
			else
				AS_STRUCT(new_crs->cr1_hi).ussz =
								delta_ussz;
		}
		new_pcs_ind += cr_size;
		DebugUS("new cr_ind 0x%lx : "
			"cr1_hi.ussz 0x%x\n",
			new_pcs_ind,
			(AS_STRUCT(new_crs->cr1_hi).ussz) << 4);
	} else {
		DebugUS("nothing to copy for "
			"procedure chain stack\n");
	}

	return 0;
}

int
fix_all_stack_sz_for_gdb(e2k_addr_t base, long cr_ind,
			e2k_size_t delta_sp, long start_cr_ind,
			int user_stacks, int set_stack_sz,
                        struct task_struct *child)
{
	e2k_cr0_hi_t 	cr0_hi;
	e2k_cr1_hi_t 	cr1_hi;
	e2k_cr1_lo_t 	cr1_lo;

	if (start_cr_ind <= 0)
		start_cr_ind = 0;
	DebugES_GDB("started with PCSP stack base "
		"0x%lx cr_ind 0x%lx, start cr_ind 0x%lx, delta sp 0x%lx\n",
		base, cr_ind, start_cr_ind, delta_sp);
	if (cr_ind == 0) {
		DebugES_GDB("stack is empty\n");
		return 0;
	}

	for (cr_ind = cr_ind - SZ_OF_CR; cr_ind >= start_cr_ind;
						cr_ind -= SZ_OF_CR) {
		int err;
		e2k_psr_t psr;
		e2k_addr_t ip;

		if ((err= access_process_vm(child, base + cr_ind +CR0_HI_I,
                                            &cr0_hi, sizeof(cr0_hi), 0))
		     != sizeof(cr0_hi)) {
 			DebugES_GDB("get_cr0_hi() "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n",
				base, cr_ind, err);
			return -1;
                }
 		ip = (AS_STRUCT(cr0_hi).ip) << 3;
		DebugES_GDB("cr_ind 0x%lx : IP "
			"0x%lx\n", cr_ind, ip);
		if ((err= access_process_vm(child, base + cr_ind + CR1_LO_I,
                                            &cr1_lo, sizeof(cr1_lo), 0))
		     != sizeof(cr1_lo)) {
 			DebugES_GDB("get_cr0_lo() "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n",
				base, cr_ind, err);
			return -1;
                }
		AS_WORD(psr) = AS_STRUCT(cr1_lo).psr;
		DebugES_GDB("cr_ind 0x%lx : psr "
			"0x%x\n", cr_ind, AS_WORD(psr));
		if ((user_stacks && (ip >= TASK_SIZE ||
						AS_STRUCT(psr).pm)) ||
			(!user_stacks && (ip < TASK_SIZE &&
						!AS_STRUCT(psr).pm))) {
			/*
			 * It is a kernel function in the user PC stack or
			 * user function in the kernel stack
			 * The data stack of this function is out of this
			 * stack and places in separate user or kernel
			 * space for each process.
			 * Do not correct this chain register
			 */
			DebugES_GDB("it is the "
				"chain of %s procedure, do not correct "
				"one\n",
				(!user_stacks) ? "user" : "kernel");
			continue;
		}
		if ((err= access_process_vm(child, base + cr_ind + CR1_HI_I,
                                            &cr1_hi, sizeof(cr1_hi), 0))
		     != sizeof(cr1_hi)) {
 			DebugES_GDB("get_cr1_hi() "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n",
				base, cr_ind, err);
			return -1;
                }    
		DebugES_GDB("cr_ind 0x%lx : ussz 0x%x\n",
			cr_ind, (AS_STRUCT(cr1_hi).ussz) << 4);
		if (set_stack_sz)
			(AS_STRUCT(cr1_hi).ussz) = (delta_sp >> 4);
		else
			(AS_STRUCT(cr1_hi).ussz) += (delta_sp >> 4);

		if ((err= access_process_vm(child, base + cr_ind + CR1_HI_I,
                                            &cr1_hi, sizeof(cr1_hi), 1))
		     != sizeof(cr1_hi)) {
 			DebugES_GDB("put_cr1_hi "
				"base 0x%lx cr_ind 0x%lx returned error "
				"%d\n",
				base, cr_ind, err);
			return -1;
                }
	}
	return 0;
}


static int create_kernel_data_stack(struct task_struct *new_task,
				    e2k_stacks_t *new_stacks)
{
	thread_info_t *new_thread = task_thread_info(new_task);
	void	*c_stk;

	DebugKS("started on task 0x%p thread "
		"0x%p for new task 0x%p thread 0x%p\n",
		current, current_thread_info(),
		new_task, new_thread);

	/*
	 * Allocate memory for data stack of new thread or task
	 */

	c_stk = alloc_kernel_c_stack();
	if (c_stk == NULL) {
		DebugKS("could not allocate "
			"kernel local data stack\n");
		return -ENOMEM;
	}

	/*
	 * Create initial state of kernel local data stack
	 */

	new_thread->k_stk_base = (e2k_addr_t)c_stk;
	new_thread->k_stk_sz = KERNEL_C_STACK_SIZE;
	new_thread->k_usd_lo.USD_lo_base =
		((e2k_addr_t)c_stk + KERNEL_C_STACK_SIZE) &
					~E2K_ALIGN_USTACK_MASK;
	new_thread->k_usd_hi.USD_hi_size = KERNEL_C_STACK_SIZE;
	new_stacks->usd_lo = new_thread->k_usd_lo;
	new_stacks->usd_hi = new_thread->k_usd_hi;
	new_stacks->sbr = (e2k_addr_t)c_stk + KERNEL_C_STACK_SIZE;
	DebugKS("allocated kernel local data  "
		"stack 0x%lx, size 0x%lx, USD base 0x%lx SBR 0x%lx\n",
		new_thread->k_stk_base, new_thread->k_stk_sz,
		new_thread->k_usd_lo.USD_lo_base,
		new_stacks->sbr);
	return 0;
}

static inline int
create_kernel_stacks(struct task_struct *new_task,
			e2k_stacks_t *new_stacks)
{
	thread_info_t		*new_ti = task_thread_info(new_task);
	void			*psp_stk;
	void			*pcsp_stk;
	e2k_psp_lo_t		psp_lo;
	e2k_psp_hi_t		psp_hi;
	e2k_pcsp_lo_t		pcsp_lo;
	e2k_pcsp_hi_t		pcsp_hi;
	struct hw_stack_area	*u_ps;
	struct hw_stack_area	*u_pcs;
	int			ret;

	DebugKS("started for new task 0x%p\n",
		new_task);
	DebugKS("started on task 0x%p thread 0x%p for new task 0x%p thread 0x%p\n",
		current, current_thread_info(),
		new_task, new_ti);

	/*
	 * Create data stack of new thread or task
	 */
	ret = create_kernel_data_stack(new_task, new_stacks);
	if (ret != 0) {
		return ret;
	}

	/*
	 * Allocate memory for hardware stacks of new thread or task
	 */
	psp_stk = alloc_kernel_p_stack(new_ti);
	if (psp_stk == NULL) {
		DebugKS("could not allocate kernel procedure stack\n");
		goto out_free_kernel_c_stack;
	}
	pcsp_stk = alloc_kernel_pc_stack(new_ti);
	if (pcsp_stk == NULL) {
		DebugKS("could not allocate kernel procedure chain stack\n");
		goto out_free_p_stack;
	}

	/*
	 * Create initial state of kernel hardware stacks
	 */

	if (UHWS_PSEUDO_MODE) {
		u_ps = kmalloc(sizeof(struct hw_stack_area), GFP_KERNEL);
		if (u_ps == NULL) {
			DebugKS("could not kmalloc u_ps\n");
			goto out_free_pc_stack;
		}
		list_add_tail(&u_ps->list_entry, &new_ti->ps_list);
		new_ti->cur_ps = u_ps;

		u_pcs = kmalloc(sizeof(struct hw_stack_area), GFP_KERNEL);
		if (u_pcs == NULL) {
			DebugKS("could not kmalloc u_pcs\n");
			goto out_free_u_ps;
		}
		list_add_tail(&u_pcs->list_entry, &new_ti->pcs_list);
		new_ti->cur_pcs = u_pcs;
	}

	SET_PS_BASE(new_ti, psp_stk);
	SET_PS_SIZE(new_ti, KERNEL_P_STACK_SIZE);
	SET_PS_OFFSET(new_ti, 0);
	SET_PS_TOP(new_ti, KERNEL_P_STACK_SIZE);
	psp_lo.PSP_lo_base = (e2k_addr_t)psp_stk;
	psp_hi.PSP_hi_size = KERNEL_P_STACK_SIZE;
	psp_hi.PSP_hi_ind = 0;
	new_stacks->psp_lo = psp_lo;
	new_stacks->psp_hi = psp_hi;
	DebugKS("allocated kernel procedure stack 0x%llx, size 0x%x\n",
		new_stacks->psp_lo.PSP_lo_base,
		new_stacks->psp_hi.PSP_hi_size);

	SET_PCS_BASE(new_ti, pcsp_stk);
	SET_PCS_SIZE(new_ti, KERNEL_PC_STACK_SIZE);
	SET_PCS_OFFSET(new_ti, 0);
	SET_PCS_TOP(new_ti, KERNEL_PC_STACK_SIZE);
	pcsp_lo.PCSP_lo_base = (e2k_addr_t)pcsp_stk;
	pcsp_hi.PCSP_hi_size = KERNEL_PC_STACK_SIZE;
	pcsp_hi.PCSP_hi_ind = 0;
	new_stacks->pcsp_lo = pcsp_lo;
	new_stacks->pcsp_hi = pcsp_hi;
	DebugKS("allocated kernel procedure chain stack 0x%llx, size 0x%x\n",
		new_stacks->pcsp_lo.PCSP_lo_base,
		new_stacks->pcsp_hi.PCSP_hi_size);

	return 0;

out_free_u_ps:
	list_del(&u_ps->list_entry);
	new_ti->cur_ps = NULL;
	kfree(u_ps);

out_free_pc_stack:
	free_kernel_pc_stack(psp_stk);

out_free_p_stack:
	free_kernel_p_stack(psp_stk);

out_free_kernel_c_stack:
	free_kernel_c_stack((void *)new_ti->k_stk_base);
	new_ti->k_stk_base = 0;

	return -ENOMEM;
}

/**
 * get_hardware_stacks_frames_to_copy - calculate stacks areas to copy
 * @cur_stacks: structure to put current stack parameters in
 * @cur_crs: current CR8 registers values will be returned here
 * @down: number of frames to skip
 * @level_num: number of frames to copy (copy all if 0)
 * @copy_data_stack: whether to copy the kernel data stack
 * @fp_ind_p: procedure stack area start will be returned here
 * @fp_size_p: procedure stack area size will be returned here
 * @cr_ind_p: chain stack area start will be returned here
 * @cr_size_p: chain stack area size will be returned here
 * @new_crs: new CR* registers values will be returned here
 * @usd_bottom_p: kernel data stack area top byte will be returned here
 * @usd_sp_p: kernel data stack area top free byte will be returned here
 * @usd_size_p: kernel data stack area free size will be returned here
 *
 * Calculate hardware stacks indexes and sizes, kernel data stack bottom
 * and SP for specified frames number (level_num up or down).
 * Before (if it is needed) skip some frames (down number).
 * Hardware stacks can be handled only within the bounds of
 * current active (resident) stack frame
 */
static inline int
get_hardware_stacks_frames_to_copy(e2k_stacks_t *cur_stacks,
		e2k_mem_crs_t *cur_crs,
		int down, int level_num, int copy_data_stack,
		long *fp_ind_p, long *fp_size_p,
		long *cr_ind_p, long *cr_size_p, e2k_mem_crs_t *new_crs,
		long *usd_bottom_p, long *usd_sp_p, long *usd_size_p)
{
	unsigned long	flags;
	int		ret;

	/*
	 * Read current stack parameters
	 */
	raw_all_irq_save(flags);
	E2K_FLUSHCPU;
	cur_stacks->sbr = READ_SBR_REG_VALUE();
	cur_stacks->usd_hi = READ_USD_HI_REG();
	cur_stacks->usd_lo = READ_USD_LO_REG();
	AS_WORD(cur_crs->cr0_lo) = E2K_GET_DSREG_NV(cr0.lo);
	AS_WORD(cur_crs->cr0_hi) = E2K_GET_DSREG_NV(cr0.hi);
	AS_WORD(cur_crs->cr1_lo) = E2K_GET_DSREG_NV(cr1.lo);
	AS_WORD(cur_crs->cr1_hi) = E2K_GET_DSREG_NV(cr1.hi);
	cur_stacks->psp_hi = READ_PSP_HI_REG();
	cur_stacks->psp_lo = READ_PSP_LO_REG();
	cur_stacks->pcsp_hi = READ_PCSP_HI_REG();
	cur_stacks->pcsp_lo = READ_PCSP_LO_REG();
	raw_all_irq_restore(flags);

	/*
	 * Do not copy copy_user_stacks()'s kernel data stack frame
	 */
	AS_STRUCT(cur_stacks->usd_lo).base +=
		((AS_STRUCT(cur_crs->cr1_hi).ussz << 4) -
				AS_STRUCT(cur_stacks->usd_hi).size);
	cur_stacks->usd_hi.USD_hi_size =
		AS_STRUCT(cur_crs->cr1_hi).ussz << 4;

	DebugCT("current kernel data stack: top 0x%lx, base 0x%llx, size 0x%x\n",
		cur_stacks->sbr,
		AS_STRUCT(cur_stacks->usd_lo).base,
		AS_STRUCT(cur_stacks->usd_hi).size);
	DebugCT("current kernel procedure stack: base 0x%llx, size 0x%x, ind 0x%x\n",
		AS_STRUCT(cur_stacks->psp_lo).base,
		AS_STRUCT(cur_stacks->psp_hi).size,
		AS_STRUCT(cur_stacks->psp_hi).ind);
	DebugCT("current kernel procedure chain stack: base 0x%llx, size 0x%x, ind 0x%x\n",
		AS_STRUCT(cur_stacks->pcsp_lo).base,
		AS_STRUCT(cur_stacks->pcsp_hi).size,
		AS_STRUCT(cur_stacks->pcsp_hi).ind);
	DebugCT("current cr: IP 0x%llx ussz 0x%x wbs 0x%x\n",
		AS_STRUCT(cur_crs->cr0_hi).ip << 3,
		AS_STRUCT(cur_crs->cr1_hi).ussz << 4,
		AS_STRUCT(cur_crs->cr1_lo).wbs * EXT_4_NR_SZ);

	if (level_num) {
		ret = get_n_stacks_frames_to_copy(cur_stacks, cur_crs,
			down, level_num, copy_data_stack, 0, /* user_stacks */
			fp_ind_p, fp_size_p,
			cr_ind_p, cr_size_p, new_crs,
			usd_bottom_p, usd_sp_p, usd_size_p);
	} else {
		*fp_ind_p = 0;
		*cr_ind_p = 0;
		ret = get_all_stacks_frames_to_copy(cur_stacks, cur_crs,
			down, copy_data_stack, 0, /* user_stacks */
			fp_size_p, cr_size_p, new_crs,
			usd_bottom_p, usd_sp_p, usd_size_p);
	}

	if (ret != 0) {
		DebugCT("could not copy "
			"kernel stacks for  new process or task\n");
	}

	return ret;
}


/**
 * copy_hardware_stacks - copy current hardware and kernel data stacks
 * @new_stacks: new stacks parameters; they will be corrected as needed
 * @new_crs: new CR* registers will be returned here
 * @down: number of frames to skip
 * @level_num: number of frames to copy (copy all if 0)
 * @copy_data_stack: whether to copy the kernel data stack
 * @delta_sp: difference between new and old kernel stacks' bases
 *            will be returned here
 * @delta_sz: difference between new and old kernel stacks' sizes
 *            will be returned here
 * @disable_sge: disable overflow/underflow checking in copied
 *		 hardware stacks
 *
 * 'disable_sge' is used to ensure that child will start with
 * collapsed stacks
 */
static inline int
copy_hardware_stacks(e2k_stacks_t *new_stacks, e2k_mem_crs_t *new_crs,
		int down, int level_num, int copy_data_stack,
		e2k_addr_t *delta_sp, e2k_size_t *delta_sz)
{
	e2k_stacks_t	cur_stacks;
	e2k_mem_crs_t	cur_crs;
	int	error;
	long	fp_ind;
	long	fp_size;
	long	cr_ind;
	long	cr_size;
	long	usd_bottom;
	long	usd_sp;
	long	usd_size;

	error = get_hardware_stacks_frames_to_copy(&cur_stacks, &cur_crs,
			down, level_num, copy_data_stack,
			&fp_ind, &fp_size,
			&cr_ind, &cr_size, new_crs,
			&usd_bottom, &usd_sp, &usd_size);
	if (error)
		return error;

	error = do_copy_all_stacks(&cur_stacks, &cur_crs,
			new_stacks, new_crs,
			copy_data_stack, 0, /* user stacks */
			fp_ind, fp_size,
			cr_ind, cr_size,
			usd_bottom, usd_sp, usd_size,
			delta_sp, delta_sz);

	return error;
}

/**
 * prepare_kernel_frame - prepare for return to kernel function
 * @stacks - allocated stacks' parameters (will be corrected)
 * @crs - chain stack frame will be returned here
 * @fn - function to return to
 * @arg - function's argument
 *
 * Note that cr1_lo.psr value is taken from PSR register. This means
 * that interrupts and sge are expected to be enabled by caller.
 */
static void prepare_kernel_frame(e2k_stacks_t *stacks, e2k_mem_crs_t *crs,
				 unsigned long fn, unsigned long arg)
{
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_psr_t psr;
	unsigned long *frame;

	/*
	 * Prepare @fn's frame in chain stack.
	 */
	AS(cr0_lo).pf = -1ULL;

	AW(cr0_hi) = 0;
	AS(cr0_hi).ip = fn >> 3;

	AW(psr) = E2K_GET_DSREG_NV(psr);
	BUG_ON(AS(psr).sge == 0);
	AW(cr1_lo) = 0;
	AS(cr1_lo).psr = AW(psr);
	AS(cr1_lo).cuir = KERNEL_CODES_INDEX;
	AS(cr1_lo).wbs = 1;

	AW(cr1_hi) = 0;
	AS(cr1_hi).ussz = AS(stacks->usd_hi).size / 16;

	crs->cr0_lo = cr0_lo;
	crs->cr0_hi = cr0_hi;
	crs->cr1_lo = cr1_lo;
	crs->cr1_hi = cr1_hi;

	/*
	 * Reserve space in hardware stacks for @fn and @arg
	 */
	AS(stacks->pcsp_hi).ind = SZ_OF_CR;
	AS(stacks->psp_hi).ind = EXT_4_NR_SZ;

	/*
	 * Prepare function's argument
	 */
	frame = (unsigned long *) AS(stacks->psp_lo).base;
	*frame = arg;
}

noinline
static int copy_kernel_stacks(struct task_struct *new_task,
			      unsigned long fn, unsigned long arg)
{
	e2k_stacks_t	new_stacks;
	e2k_mem_crs_t	new_crs;
	e2k_addr_t	psp_stk, pcsp_stk;
	int		ret;

	/*
	 * How kernel thread creation works.
	 *
	 * 1) After schedule() to the new kthread we jump to __ret_from_fork().
	 * 2) __ret_from_fork() calls schedule_tail() to finish the things
	 * for scheduler.
	 * 3) When __ret_from_fork() returns @fn frame will be FILLed along
	 * with function's argument.
	 */

	/*
	 * Allocate stacks for new thread or task
	 */
	ret = create_kernel_stacks(new_task, &new_stacks);
	if (ret != 0) {
		DebugCT("could not create kernel "
			"stacks for new task or thread\n");
		return ret;
	}

	psp_stk = new_stacks.psp_lo.PSP_lo_base;
	pcsp_stk = new_stacks.pcsp_lo.PCSP_lo_base;
	DebugCT("hw stacks: p_stk 0x%lx pc_stk 0x%lx new_task 0x%p\n"
		"data stack: top 0x%lx, base 0x%llx, size 0x%x, pt_regs 0x%p\n",
			psp_stk, pcsp_stk, new_task, new_stacks.sbr,
			AS_STRUCT(new_stacks.usd_lo).base,
			AS_STRUCT(new_stacks.usd_hi).size,
			task_thread_info(new_task)->pt_regs);

	/*
	 * Put function IP and argument to chain and procedure stacks.
	 */
	prepare_kernel_frame(&new_stacks, &new_crs, fn, arg);

	/*
	 * Update sw_regs with new stacks' parameters.
	 */
	init_sw_regs(new_task, &new_stacks, &new_crs, true);

	return 0;
}

static inline int
init_u_data_stack(e2k_addr_t new_stk_base, s64 new_stk_size,
			struct task_struct *new_task)
{
	thread_info_t	 	*new_thr = task_thread_info(new_task);
	thread_info_t	 	*curr_thr = current_thread_info();
	struct vm_area_struct	*vma, *cur, *prev;
	u64			new_stk_top, new_usd_size, new_usd_base, delta;
	bool			is_growable;

	DebugUS("new user data stack: base 0x%lx size 0x%lx\n",
		new_stk_base, new_stk_size);
	DebugUS("current user data stack: bottom 0x%lx, top 0x%lx, max size 0x%lx\n",
		curr_thr->u_stk_base, curr_thr->u_stk_top, curr_thr->u_stk_sz);

	BUG_ON(!new_task->mm);

	if (new_stk_size) {
		DebugUS("clone2() case: new stack base and size passed as args\n");
		new_stk_top = new_stk_base + new_stk_size;
	} else {
		DebugUS("clone() case: only new stack SP passed as arg\n");
		new_stk_top = new_stk_base;
	}

	down_read(&new_task->mm->mmap_sem);
	vma = find_vma(new_task->mm, new_stk_top - 1);
	if (!vma) {
		DebugUS("find_vma() could not find VMA of stack area top\n");
		goto out_efault;
	}
	DebugUS("find_vma() returned VMA 0x%p, start 0x%lx, end 0x%lx, mm 0x%p\n",
		vma, vma->vm_start, vma->vm_end, new_task->mm);
	if (new_stk_top <= vma->vm_start) {
		DebugUS("new stack top address "
			"is out of VMA area  new_stk_top=%lx vma_start=%lx\n",
			new_stk_top, vma->vm_start);
		goto out_efault;
	}

	is_growable = !!(vma->vm_flags & VM_GROWSDOWN);

	cur = vma;
	prev = vma->vm_prev;

	if (new_stk_size) {
		/*
		 * Check passed area
		 */
		while (new_stk_base < cur->vm_start) {
			if (!prev || cur->vm_start != prev->vm_end ||
			    ((cur->vm_flags ^ prev->vm_flags) & VM_GROWSDOWN)) {
				DebugUS("Bad passed area (prev 0x%lx)\n", prev);
				goto out_efault;
			}

			cur = prev;
			prev = prev->vm_prev;
		}
	} else {
		/*
		 * We assume here that the stack area is contained
		 * in a single vma.
		 */
		new_stk_base = cur->vm_start;
		new_stk_size = new_stk_top - new_stk_base;
	}

	if (new_stk_size > MAX_USD_HI_SIZE) {
		u64 delta = new_stk_size - MAX_USD_HI_SIZE;

		new_stk_base += delta;
		new_stk_size -= delta;
	}

	/* Leave the guard page out of stack
	 * (see comment before expand_user_data_stack()) */
	if (is_growable && new_stk_base == cur->vm_start) {
		if (new_stk_size < PAGE_SIZE) {
			up_read(&new_task->mm->mmap_sem);
			DebugUS("stack size < PAGE_SIZE\n");
			return -EINVAL;
		}

		new_stk_base += PAGE_SIZE;
		new_stk_size -= PAGE_SIZE;
	}

	up_read(&new_task->mm->mmap_sem);

	/* Align the stack */

	delta = round_up(new_stk_base, E2K_ALIGN_STACK) - new_stk_base;
	new_stk_base += delta;
	new_stk_size -= delta;

	delta = new_stk_top - round_down(new_stk_top, E2K_ALIGN_STACK);
	new_stk_top -= delta;
	new_stk_size -= delta;

	if (new_stk_size < 0)
		return -EINVAL;

	/* Set registers in thread_info */

	new_usd_base = new_stk_top & ~E2K_ALIGN_USTACK_MASK;
	new_usd_size = new_stk_size;
	new_thr->u_stk_base = new_stk_base;
	new_thr->u_stk_sz = new_usd_size;
	new_thr->u_stk_top = new_stk_top;

	DebugUS("new user data stack: bottom 0x%lx, top 0x%lx, max size 0x%lx\n",
		new_thr->u_stk_base, new_thr->u_stk_top, new_thr->u_stk_sz);

	return 0;

out_efault:
	up_read(&new_task->mm->mmap_sem);
	return -EFAULT;
}


static int
create_user_stacks(unsigned long clone_flags, e2k_addr_t new_stk_base,
		   e2k_size_t new_stk_sz, struct task_struct *new_task,
		   e2k_stacks_t *new_stacks)
{
	thread_info_t	*new_thr = task_thread_info(new_task);
	e2k_size_t	u_ps_size;
	e2k_size_t	u_pcs_size;
	int		ret;

	DebugUS("entered for stack base 0x%lx, size 0x%lx\n",
		new_stk_base, new_stk_sz);

	/* init user data stack pointers and registers info */
	if (!(clone_flags & CLONE_VFORK)) {
		ret = init_u_data_stack(new_stk_base, new_stk_sz, new_task);
		if (ret != 0) {
			DebugUS("could not create user data stack\n");
			return ret;
		}
	}

	if (UHWS_PSEUDO_MODE) {
		u_ps_size = USER_P_STACK_AREA_SIZE;
		u_pcs_size = USER_PC_STACK_AREA_SIZE;
	} else {
		/* init user's pointers and registers info of ps & pcs stacks */
		u_ps_size = PAGE_ALIGN_DOWN(32 * new_thr->u_stk_sz);
		if (u_ps_size < USER_P_STACK_INIT_SIZE) {
			u_ps_size = USER_P_STACK_INIT_SIZE;
		} else if (u_ps_size > USER_P_STACK_SIZE) {
			u_ps_size = USER_P_STACK_SIZE;
		}

		/* create user's pcs stack == new procedure stack / 16 */
		u_pcs_size = PAGE_ALIGN_DOWN(u_ps_size / 16);
		if (u_pcs_size < USER_PC_STACK_INIT_SIZE) {
			u_pcs_size = USER_PC_STACK_INIT_SIZE;
		}
	}

	ret = create_user_hard_stacks(new_thr, new_stacks,
			u_ps_size, USER_P_STACK_INIT_SIZE,
			u_pcs_size, USER_PC_STACK_INIT_SIZE);
	if (ret != 0) {
		DebugUS("could not allocate user procedure or chain stack (PS or PCS)\n");
		return ret;
	}

	new_stacks->psp_hi.PSP_hi_size += KERNEL_P_STACK_SIZE;
	DebugUS("allocated procedure stack: base 0x%p, size: max 0x%lx init 0x%x\n",
		GET_PS_BASE(new_thr), GET_PS_SIZE(new_thr),
		new_stacks->psp_hi.PSP_hi_size);

	new_stacks->pcsp_hi.PCSP_hi_size += KERNEL_PC_STACK_SIZE;
	DebugUS("allocated procedure chain stack: base 0x%p, size: max 0x%lx init 0x%x\n",
		GET_PCS_BASE(new_thr), GET_PCS_SIZE(new_thr),
		new_stacks->pcsp_hi.PCSP_hi_size);

	return 0;
}

static noinline int
copy_user_stacks(unsigned long clone_flags, e2k_addr_t new_stk_base,
		 e2k_size_t new_stk_sz, struct task_struct *new_task,
		 pt_regs_t *regs)
{
	thread_info_t	*new_ti = task_thread_info(new_task);
	pt_regs_t	*new_regs;
	e2k_addr_t	delta_sp = 0;
	e2k_size_t	delta_sz = 0, wd_psize = 0;
	e2k_stacks_t	new_stacks;
	e2k_mem_crs_t	new_crs;
	long		fp_ind, cr_ind;
	int		down, level_num, ret, sw_num = 0;

	BUG_ON(sge_checking_enabled());

	DebugUS("entered for stack base 0x%lx, size 0x%lx\n",
		new_stk_base, new_stk_sz);

	ret = alloc_hw_stack_mappings(new_ti);
	if (ret)
		return ret;

	/*
	 * Create kernel data stack of new thread or task
	 */
	ret = create_kernel_data_stack(new_task, &new_stacks);
	if (ret) {
		DebugUS("could not create kernel data stack\n");
		goto out_free_mappings;
	}

	/*
	 * Create user hardware stacks and initialize user data stack
	 */
	ret = create_user_stacks(clone_flags, new_stk_base, new_stk_sz,
				 new_task, &new_stacks);
	if (ret) {
		DebugUS("could not create user hardware stack\n");
		goto out_free_kernel_c_stack;
	}

	/*
	 * Now cr_ind (pcsp_hi.ind) & fp_ind (psp_hi.ind) are here
	 *	create_user_thread -> ttable -> sys_clone -> do_fork ->
	 *	copy_process -> copy_thread -> copy_user_stacks
	 * We can't to do copy stacks and return on the new stack in do_fork()
	 * and copy_process() because do_fork() and copy_process() are
	 * arch-independed and we can't change do_fork() and copy_process().
	 * So on the new stack we want to return to ttable_entry() as
	 * from sys_clone after schedule -> __switch_to.
	 *
	 * We will change regs (psp, pcsp, usd, cr1, psr) in __switch_to.
	 * To get value of needed regs we should go to down 4 levels trough
	 * hard stacks.
	 *
	 * In this case cr_ind & fp_ind point to sys_clone. CR1 of sys_clone
	 * has IP of ttable_entry. If we change regs in __switch_to, then
	 * __switch_to will return straight to ttable_entry.
	 * (see comment before __switch_to for more info)
	 *
	 *
	 * Remember that:
	 *  ttable -> sys_clone -> do_fork -> copy_process-> copy_thread ->
	 *  copy_user_stacks -> go_hd_stk_down
	 *
	 * So cr_ind, fp_ind are for copy_user_stacks and start_cr1_lo
	 * has wbs of copy_thread(). So we should go 4 steps down:
	 *	i == 0	fp_ind = fp_ind - cr1_lo.wbs      for copy_thread()
	 *		cr_ind = cr_ind  - SZ_OF_CR       for copy_thread()
	 *		cr1_lo = base + cr_ind + CR1_LO_I wbs for copy_process()
	 *	i == 1	fp_ind = fp_ind - cr1_lo.wbs      for copy_process()
	 *		cr_ind = cr_ind  - SZ_OF_CR       for copy_process()
	 *		cr1_lo = base + cr_ind + CR1_LO_I has wbs for do_fork()
	 *	i == 2	fp_ind = fp_ind - cr1_lo.wbs      for do_fork()
	 *		cr_ind = cr_ind  - SZ_OF_CR       for do_fork()
	 *		cr1_lo = base + cr_ind + CR1_LO_I wbs for sys_clone()
	 *	i == 3	fp_ind = fp_ind - cr1_lo.wbs      for sys_clone()
	 *		cr_ind = cr_ind  - SZ_OF_CR       for sys_clone()
	 *		cr1_lo = base + cr_ind + CR1_LO_I wbs for ttable_entry()
	 */
	down = 4;
	if (clone_flags & CLONE_VFORK)
		level_num = 3;
	else
		level_num = 2;
	ret = copy_hardware_stacks(&new_stacks, &new_crs,
				down, level_num,
				1,  /* copy data stack */
				&delta_sp,
				&delta_sz);
	if (ret) {
		DebugUS("could not copy kernel stacksfor new user thread\n");
		goto out_free_kernel_c_stack;
	}

	/*
	 * New thread pt_regs structure should be only one:
	 * the same as pt_regs structure of the system call and
	 * this structure was copied while copying local data
	 * stack frames. So it needs correct all stacks registers into
	 * the new pt_regs structure to point to the new created stacks
	 * Correct pt_regs structue address because of new thread
	 * will run on the new kernel data stack
	 */
	new_regs = (pt_regs_t *)((e2k_addr_t)regs + delta_sp);
	DebugUS("pt_regs structure 0x%p "
		"for new thread was copied from old regs 0x%p, "
		"delta SP 0x%lx\n",
		new_regs, regs, delta_sp);
	CHECK_PT_REGS_LOOP(new_regs);
	new_regs->next = NULL;
	new_ti->pt_regs = new_regs;
	if (delta_sz != 0)
		fix_kernel_stacks_state(new_regs, delta_sz);

	/*
	 * Now cr_ind (pcsp_hi.ind) & fp_ind (psp_hi.ind) for new stacks
	 * are here
	 *	user -> create_thread -> ttable -> sys_clone
	 * pt_regs structure should point to thr state of stacks after
	 * system call to return to user. So it needs go down 2 levels
	 * to save this state in pt_regs structure
	 * User local data stack should be in empty state
	 */
	down = 1;
	new_regs->crs.cr0_lo = new_crs.cr0_lo;
	new_regs->crs.cr0_hi = new_crs.cr0_hi;
	new_regs->crs.cr1_lo = new_crs.cr1_lo;
	new_regs->crs.cr1_hi = new_crs.cr1_hi;
	go_hd_stk_down(new_stacks.psp_hi,
		new_stacks.pcsp_lo, new_stacks.pcsp_hi,
		down,
		&fp_ind, &cr_ind,
		&wd_psize, &sw_num,
		&new_regs->crs, 0 /* user_stacks */);

	if (!(clone_flags & CLONE_VFORK)) {
		new_regs->stacks.sbr = new_ti->u_stk_top;
#ifdef CONFIG_PROTECTED_MODE
		if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
			new_regs->stacks.usd_lo.USD_lo_base =
					(new_ti->u_stk_top & 0xFFFFFFFF) |
					(regs->stacks.usd_lo.USD_lo_half &
					 0xFFF00000000);
		} else
#endif
			new_regs->stacks.usd_lo.USD_lo_base = new_ti->u_stk_top;
		new_regs->stacks.usd_hi.USD_hi_size = new_ti->u_stk_sz;
		AS(new_regs->crs.cr1_hi).ussz = new_ti->u_stk_sz >> 4;
		DebugUS("new user local data stack: bottom 0x%lx, top 0x%lx, base 0x%llx, size 0x%x\n",
				new_ti->u_stk_base, new_regs->stacks.sbr,
				new_regs->stacks.usd_lo.USD_lo_base,
				new_regs->stacks.usd_hi.USD_hi_size);
	}

	init_sw_regs(new_task, &new_stacks, &new_crs, false);
	DebugCT("copy_user_stacks exited.\n");

	return 0;


out_free_kernel_c_stack:
	free_kernel_c_stack((void *) new_ti->k_stk_base);
	new_ti->k_stk_base = 0;

out_free_mappings:
	free_hw_stack_mappings(new_ti);

	return ret;
}

static inline int
clone_all_hardware_stacks(struct task_struct *new_task,
			e2k_stacks_t *cur_stacks, e2k_stacks_t *new_stacks,
			e2k_mem_crs_t *new_crs, long fp_ind, long fp_size,
			long cr_ind, long cr_size, unsigned long clone_flags)
{
	thread_info_t		*cur_ti = current_thread_info();
	thread_info_t		*new_ti = task_thread_info(new_task);
	struct hw_stack_area	*u_ps, *u_pcs, *u_ps_tmp, *u_pcs_tmp;
	e2k_addr_t		cur_ps_base, ps_base, cur_pcs_base, pcs_base;
	e2k_size_t		ps_size, pcs_size;
	int			ret;

	if (UHWS_PSEUDO_MODE) {
		u_ps_tmp = kmalloc(sizeof(struct hw_stack_area), GFP_KERNEL);
		if (u_ps_tmp == NULL) {
			ret = -ENOMEM;
			goto out_u_ps;
		}
		u_ps = list_last_entry(&cur_ti->ps_list,
				       struct hw_stack_area, list_entry);
		memcpy(u_ps_tmp, u_ps, sizeof(*u_ps));
		INIT_LIST_HEAD(&u_ps_tmp->list_entry);
		list_add_tail(&u_ps_tmp->list_entry, &new_ti->ps_list);
		new_ti->cur_ps = u_ps_tmp;

		u_pcs_tmp = kmalloc(sizeof(struct hw_stack_area), GFP_KERNEL);
		if (u_pcs_tmp == NULL) {
			ret = -ENOMEM;
			goto out_u_pcs;
		}
		u_pcs = list_last_entry(&cur_ti->pcs_list,
					struct hw_stack_area, list_entry);
		memcpy(u_pcs_tmp, u_pcs, sizeof(*u_pcs));
		INIT_LIST_HEAD(&u_pcs_tmp->list_entry);
		list_add_tail(&u_pcs_tmp->list_entry, &new_ti->pcs_list);
		new_ti->cur_pcs = u_pcs_tmp;
	} else {
		new_ti->ps_base = current_thread_info()->ps_base;
		new_ti->pcs_base = current_thread_info()->pcs_base;
	}

	ps_base = (e2k_addr_t)GET_PS_BASE(cur_ti);
	cur_ps_base = ps_base + GET_PS_OFFSET(cur_ti);
	ps_size = GET_PS_SIZE(cur_ti);
	DebugUS("procedure stack: start 0x%lx, current base 0x%lx, max size 0x%lx, kernel part size 0x%lx\n",
		ps_base, cur_ps_base, ps_size, KERNEL_P_STACK_SIZE);
	DebugUS("will clone procedure stack from ind 0x%lx, size 0x%lx\n",
		fp_ind, fp_size);

	pcs_base = (e2k_addr_t)GET_PCS_BASE(cur_ti);
	cur_pcs_base = pcs_base + GET_PCS_OFFSET(cur_ti);
	pcs_size = GET_PCS_SIZE(cur_ti);
	DebugUS("chain procedure stack: start 0x%lx, current base 0x%lx, max size 0x%lx, kernel part size 0x%lx\n",
		pcs_base, cur_pcs_base, pcs_size, KERNEL_PC_STACK_SIZE);
	DebugUS("will clone procedure stack from ind 0x%lx, size 0x%lx\n",
		cr_ind, cr_size);
	if (fp_ind != 0 || cr_ind != 0)
		panic("clone_all_hardware_stacks() start index to copy of PS 0x%lx or PCS 0x%lx is not zero\n",
				fp_ind, cr_ind);

	ret = do_clone_all_user_hard_stacks(new_task,
			cur_ps_base, fp_size,
			ps_base + ps_size + KERNEL_P_STACK_SIZE,
			cur_pcs_base, cr_size,
			pcs_base + pcs_size + KERNEL_PC_STACK_SIZE,
			clone_flags, new_crs);
	if (ret != 0) {
		DebugUS("could not clone hardware stacks, error %d\n",
			ret);
		goto out_u_pcs;
	}
	DebugUS("new procedure stack: base 0x%llx, size 0x%x, correct ind from 0x%x to 0x%lx\n",
		cur_stacks->psp_lo.PSP_lo_base,
		cur_stacks->psp_hi.PSP_hi_size,
		new_stacks->psp_hi.PSP_hi_ind, fp_size);
	new_stacks->psp_lo = cur_stacks->psp_lo;
	new_stacks->psp_hi = cur_stacks->psp_hi;
	new_stacks->psp_hi.PSP_hi_ind = fp_size;

	DebugUS("new chain procedure stack: base 0x%llx, size 0x%x, correct ind from 0x%x to 0x%lx\n",
		cur_stacks->pcsp_lo.PCSP_lo_base,
		cur_stacks->pcsp_hi.PCSP_hi_size,
		new_stacks->pcsp_hi.PCSP_hi_ind, cr_size);
	new_stacks->pcsp_lo = cur_stacks->pcsp_lo;
	new_stacks->pcsp_hi = cur_stacks->pcsp_hi;
	new_stacks->pcsp_hi.PCSP_hi_ind = cr_size;

	return 0;

out_u_pcs:
	kfree(new_ti->cur_pcs);
	new_ti->cur_pcs = NULL;
out_u_ps:
	kfree(new_ti->cur_ps);
	new_ti->cur_ps = NULL;
	return ret;
}

static noinline int
clone_user_stacks(struct task_struct *new_task, pt_regs_t *regs,
			unsigned long clone_flags)
{
	thread_info_t	*new_ti = task_thread_info(new_task);
	pt_regs_t	*cur_regs, *new_regs, *cur_new_regs;
	e2k_addr_t	delta_sp = 0;
	e2k_stacks_t	cur_stacks, new_stacks;
	e2k_mem_crs_t	cur_crs, new_crs;
	long		fp_ind, fp_size, cr_ind, cr_size, usd_bottom,
			usd_sp, usd_size;
	int		down, level_num, regs_num, ret;

	DebugUS("entered\n");

	ret = alloc_hw_stack_mappings(new_ti);
	if (ret)
		return ret;

	/*
	 * Create data stack of new thread or task
	 */
	ret = create_kernel_data_stack(new_task, &new_stacks);
	if (ret) {
		DebugUS("could not create kernel data stack\n");
		goto out_free_mappings;
	}

	/*
	 * Now cr_ind (pcsp_hi.ind) & fp_ind (psp_hi.ind) are here
	 *	user_fork() -> ttable -> sys_clone -> do_fork ->
	 *	copy_process -> copy_thread -> clone_user_stacks
	 * See comments for copy_user_stacks() about down value
	 *
	 * fork() duplicates process: it must copy full stacks
	 * and all frames of stacks
	 */
	down = 4;
	level_num = 0;
	ret = get_hardware_stacks_frames_to_copy(&cur_stacks, &cur_crs,
			down, level_num, 1, /* copy_data_stack */
			&fp_ind, &fp_size,
			&cr_ind, &cr_size, &new_crs,
			&usd_bottom, &usd_sp, &usd_size);
	if (ret) {
		DebugUS("could not get kernel stacks frames sizes to copy\n");
		goto out_free_kernel_c_stack;
	}

	ret = clone_all_hardware_stacks(new_task,
			&cur_stacks, &new_stacks, &new_crs,
			fp_ind, fp_size, cr_ind, cr_size,
			clone_flags);
	if (ret) {
		DebugUS("could not clone kernel hardware stacks\n");
		goto out_free_kernel_c_stack;
	}

	ret = do_copy_data_stack(&new_stacks,
				 1, /* copy_data_stack */ 0, /* user_stacks */
				 usd_bottom, usd_sp, usd_size,
				 &delta_sp, NULL);

	if (ret) {
		DebugUS("could not copy kernel data stack\n");
		goto out_free_kernel_c_stack;
	}

	new_regs = (pt_regs_t *)((e2k_addr_t)regs + delta_sp);
	DebugUS("pt_regs structure 0x%p for new thread was copied from old regs 0x%p, delta SP 0x%lx\n",
		new_regs, regs, delta_sp);

	/*
	 * pt_regs structure from parent task were copied while copying
	 * local data stack, It needs correct all stacks pointers and
	 * registers into the thread/thread_info structure and
	 * pt_regs structures of new process
	 */
	cur_regs = regs;
	cur_new_regs = new_regs;
	regs_num = 0;
	CHECK_PT_REGS_LOOP(regs);

	while ((cur_regs = cur_regs->next) != NULL) {
		CHECK_PT_REGS_LOOP(cur_regs);
		cur_new_regs->next = (pt_regs_t *)
				((e2k_addr_t)cur_regs + delta_sp);
		DebugUS("pt_regs structure 0x%p for new thread is previous for regs 0x%p, copied from old regs 0x%p\n",
			cur_new_regs->next, cur_new_regs, cur_regs);
		cur_new_regs = cur_new_regs->next;
		CHECK_PT_REGS_LOOP(cur_new_regs);
	}
	CHECK_PT_REGS_LOOP(new_regs);
	cur_new_regs->next = NULL;
	new_ti->pt_regs = new_regs;
	regs_num = fix_all_kernel_stack_regs(new_ti, delta_sp);
	DebugUS("corrected %d pt_regs structure for new process\n", regs_num);
	DebugUS("new kernel data stack: top 0x%lx, base 0x%llx, size 0x%x, pt_regs 0x%p\n",
		new_stacks.sbr, AS(new_stacks.usd_lo).base,
		AS(new_stacks.usd_hi).size, new_ti->pt_regs);

	init_sw_regs(new_task, &new_stacks, &new_crs, false);
	DebugUS("clone_user_stacks exited.\n");
	return 0;


out_free_kernel_c_stack:
	free_kernel_c_stack((void *) new_ti->k_stk_base);
	new_ti->k_stk_base = 0;

out_free_mappings:
	free_hw_stack_mappings(new_ti);

	return ret;
}

/*
 * Clear unallocated memory pointers which can be allocated for parent task
 */
static void clear_thread_struct(struct task_struct *task)
{
	struct thread_struct	*thread = &task->thread;
	thread_info_t		*thread_info = task_thread_info(task);

	DebugEX("started for task 0x%p CPU #%d\n", task, task_cpu(task));

#ifdef CONFIG_PROTECTED_MODE
        thread_info->user_stack_addr = 0;
        thread_info->user_stack_size = 0;
#endif
	thread_info->k_stk_base = 0;
	thread_info->k_stk_sz = 0;
	thread_info->k_usd_lo.USD_lo_half = 0;
	thread_info->k_usd_hi.USD_hi_half = 0;

	bitmap_zero(thread_info->need_tlb_flush, NR_CPUS);

	thread_info->mapped_p_stack = NULL;
	thread_info->mapped_pc_stack = NULL;

	memset(thread_info->mapped_p_pages, 0,
	       sizeof(thread_info->mapped_p_pages));
	memset(thread_info->mapped_pc_pages, 0,
	       sizeof(thread_info->mapped_pc_pages));

#ifdef CONFIG_TC_STORAGE
	thread->sw_regs.tcd = 0;
#endif

	thread->intr_counter = 0;

	thread_info->main_context_saved = false;
	thread_info->free_hw_context = false;
	thread_info->prev_ctx = NULL;
	thread_info->next_ctx = NULL;
	thread_info->hw_context_current = 0;

	thread_info->pt_regs = NULL;

	if (UHWS_PSEUDO_MODE) {
		thread_info->cur_ps = NULL;
		thread_info->cur_pcs = NULL;
	} else {
		thread_info->ps_base = NULL;
		thread_info->pcs_base = NULL;
	}

	INIT_LIST_HEAD(&thread_info->ps_list);
	INIT_LIST_HEAD(&thread_info->pcs_list);

	INIT_LIST_HEAD(&thread_info->old_u_pcs_list);

	thread_info->status = 0;

#if defined(CONFIG_SECONDARY_SPACE_SUPPORT)
	thread_info->sc_restart_ignore = 0;
	thread_info->rp_start = 0;
	thread_info->rp_end = 0;
#endif
}

void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
	*task_thread_info(p) = *task_thread_info(org);

	task_thread_info(p)->task = p;

	clear_thread_struct(p);
}

/*
 * thread local storage (TLS) pointer
 */
#define TLS_REG 13

int copy_thread(unsigned long 		clone_flags,
		unsigned long 		stack_base,
		unsigned long 		stack_size,
		struct task_struct 	*new_task)
{
	struct pt_regs  *regs = current_thread_info()->pt_regs;
	int		rval = 0;
	thread_info_t	*new_ti = task_thread_info(new_task);
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	int i;
	scall_times_t *new_scall_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	DebugCT("entered: pt_regs %p\n", regs);

	/* TODO FIXME on fork g_list should be copied, not zeroed */
	if (!(clone_flags & CLONE_VM))
		clear_g_list(task_thread_info(new_task));

	if (test_ts_flag(TS_IDLE_CLONE)) {
		DebugCT("idle clone\n");
		return 0;
	}

	set_ti_status_flag(new_ti, TS_FORK);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	for (i = 0; i < (sizeof(new_ti->times)) / sizeof(u16); i++)
		((u16 *)(new_ti->times))[i] = new_task->pid;
	new_ti->times_num = 1;
	new_ti->times_index = 1;
	new_scall_times = &(new_ti->times[0].of.syscall);
	new_ti->times[0].type = SYSTEM_CALL_TT;
	new_ti->fork_scall_times = new_scall_times;
	new_scall_times->syscall_num = regs->scall_times->syscall_num;
	new_scall_times->signals_num = 0;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	if (unlikely(current->flags & PF_KTHREAD)) {
		/* creation of a kernel thread */
		rval = copy_kernel_stacks(new_task, stack_base, stack_size);
	} else {
		if (clone_flags & CLONE_VM) {
			BUG_ON(context_ti_key(new_ti));

			/* For fork'ed and exec'ed threads this is done
			 * in init_new_context(). */
			set_context_ti_key(new_ti,
					   alloc_context_key(new_task->mm));

			/*
			 * Create a user thread or vfork()'ed process
			 */
			rval = copy_user_stacks(clone_flags, stack_base,
					stack_size, new_task, regs);
			DebugCT("copy_user_stacks() returned %d\n", rval);

			/*
			 * Set a new TLS for the child thread.
			 */
			if (clone_flags & CLONE_SETTLS) {
				new_task->thread.sw_regs.gbase[TLS_REG] =
						regs->tls;
				new_task->thread.sw_regs.gext[TLS_REG] = 0;
				new_task->thread.sw_regs.tag[TLS_REG] = 0;
			}
		} else {
			rval = clone_user_stacks(new_task, regs, clone_flags);
			DebugCT("exited with return value %d\n", rval);
#ifdef CONFIG_PROTECTED_MODE
			if (new_task->thread.flags & E2K_FLAG_PROTECTED_MODE &&
					!(clone_flags & CLONE_VM)) {
				/*
				 *  create new malloc pool
				 */
				DebugCT("init_pool_malloc\n");
				init_pool_malloc(current, new_task);
			}
#endif

			if (!rval && MONITORING_IS_ACTIVE)
				init_monitors(new_task);
		}
	}

	return rval;
}

void free_thread(struct task_struct *task)
{
	struct thread_info *ti = task_thread_info(task);

	/* We don't have to free virtual memory if this was
	 * a fork (and we'd have to switch mm to do it). */
	if (task->mm != current->mm) {
		if (UHWS_PSEUDO_MODE) {
			if (ti->cur_ps) {
				kfree(ti->cur_ps);
				ti->cur_ps = NULL;
			}
			if (ti->cur_pcs) {
				kfree(ti->cur_pcs);
				ti->cur_pcs = NULL;
			}
		}

		return;
	}

	BUG_ON(current->mm != current->active_mm);

	/* It is possible that copy_process() failed after
	 * allocating stacks in copy_thread(). In this case
	 * we must free the allocated stacks. */
	if (UHWS_PSEUDO_MODE) {
		if (ti->cur_ps) {
			free_user_p_stack(ti->cur_ps, true);
			ti->cur_ps = NULL;
		}

		if (ti->cur_pcs) {
			free_user_pc_stack(ti->cur_pcs, true);
			ti->cur_pcs = NULL;
		}

	} else {
		if (ti->ps_base) {
			free_user_pc_stack_cont(ti->ps_base, ti->ps_size,
						ti->ps_offset, ti->ps_top);
			ti->ps_base = NULL;
		}
		if (ti->pcs_base) {
			free_user_pc_stack_cont(ti->pcs_base, ti->pcs_size,
						ti->pcs_offset, ti->pcs_top);
			ti->pcs_base = NULL;
		}
	}
}

void deactivate_mm(struct task_struct *dead_task, struct mm_struct *mm)
{
	int ret;

	if (!mm)
		return;

	DebugEX("entered for task 0x%p %d [%s], mm 0x%lx\n",
		dead_task, dead_task->pid, dead_task->comm, mm);

#if defined(CONFIG_MLT_STORAGE)
	if (unlikely(MLT_NOT_EMPTY())) {
		WARN_ONCE(true, "MLT isn't empty\n");
		invalidate_MLT_context();
	}
#endif

	/*
	 * mm is going away, so we have to remap the stacks to the kernel space
	 */
	switch_to_kernel_hardware_stacks();

	/*
	 * Free user hardware stacks, as kernel created them and only kernel
	 * knows about them. We must free both physical and virtual memory.
	 */
	ret = free_user_hardware_stacks();
	if (ret) {
		pr_err("deactivate_mm(): Could not free user hardware stacks, error %d\n",
			ret);
		print_stack(current);
	}

	DebugEX("successfully finished\n");
}

/**
 * release_hw_stacks - clean up hardware stacks after the task has died
 * @thread_info: pointer to task's thread_info
 *
 * The dead task must have either mapped hardware stacks (for user
 * threads) or plain kernel hardware stacks (for kernel threads).
 */
static void release_hw_stacks(struct thread_info *thread_info)
{
	/*
	 * WARNING: DO NOT PRINT ANYTHING HERE
	 *
	 * This function is called asynchronously during boot-up,
	 * and if we access serial port while kernel_init() tries
	 * to configure it during PCI scan, the serial port will
	 * hang. We do not want that.
	 */

	BUG_ON(!list_empty(&thread_info->old_u_pcs_list));

	if (test_ti_status_flag(thread_info, TS_MAPPED_HW_STACKS))
		free_hw_stack_pages(thread_info);

	free_hw_stack_mappings(thread_info);

	if (UHWS_PSEUDO_MODE) {
		if (thread_info->cur_ps &&
		    (unsigned long) thread_info->cur_ps->base >= TASK_SIZE) {
			BUG_ON(!list_is_singular(&thread_info->ps_list));

			DebugEX("free kernel procedure stack list head 0x%p\n",
				&thread_info->ps_list);

			list_del(&thread_info->cur_ps->list_entry);

			free_kernel_p_stack(thread_info->cur_ps->base);

			kfree(thread_info->cur_ps);

			thread_info->cur_ps = NULL;
		}

		if (thread_info->cur_pcs &&
		    (unsigned long) thread_info->cur_pcs->base >= TASK_SIZE) {
			BUG_ON(!list_is_singular(&thread_info->pcs_list));

			DebugEX("free kernel chain stack list head 0x%p\n",
				&thread_info->pcs_list);

			list_del(&thread_info->cur_pcs->list_entry);

			free_kernel_pc_stack(thread_info->cur_pcs->base);

			kfree(thread_info->cur_pcs);

			thread_info->cur_pcs = NULL;
		}
	} else {
		if ((unsigned long) thread_info->ps_base >= TASK_SIZE) {
			DebugEX("free kernel procedure stack from 0x%p\n",
				thread_info->ps_base);

			free_kernel_p_stack(thread_info->ps_base);

			thread_info->ps_base = NULL;
		}
		if ((unsigned long) thread_info->pcs_base >= TASK_SIZE) {
			DebugEX("free kernel procedure chain stack from 0x%p\n",
				thread_info->pcs_base);

			free_kernel_pc_stack(thread_info->pcs_base);

			thread_info->pcs_base = NULL;
		}
	}
}

void release_thread(struct task_struct *dead_task)
{
	DebugP("is empty function for task %s pid %d\n",
		dead_task->comm, dead_task->pid);
}

/*
 * Free current thread data structures etc..
 */

extern void pthread_exit(void);

#ifdef CONFIG_MCST_RT
extern int unset_user_irq_thr(void);
#endif

void exit_thread(void)
{
	thread_info_t	*thread_info = current_thread_info();

	DebugP("CPU#%d : started for %s pid %d, u_stk_base 0x%lx\n",
		smp_processor_id(), current->comm, current->pid,
		thread_info->u_stk_base);

#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
	if (current->pobjs)
		pthread_exit();
#endif

#ifdef CONFIG_MCST_RT
	if (current->irq_to_be_proc != 0)
		unset_user_irq_thr();
#endif

#ifdef CONFIG_PROTECTED_MODE
	free_global_sp();
	if (thread_info->user_stack_addr)
		sys_munmap(thread_info->user_stack_addr,
				thread_info->user_stack_size);
#endif /* CONFIG_PROTECTED_MODE */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	if (debug_process_name != NULL &&
		(strncmp(current->comm, debug_process_name,
					debug_process_name_len) == 0)) {
		sys_e2k_print_kernel_times(current, thread_info->times,
			thread_info->times_num, thread_info->times_index);
	}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#ifdef CONFIG_MONITORS
	if (MONITORING_IS_ACTIVE) {
		process_monitors(current);
		add_dead_proc_events(current);
	}
#endif /* CONFIG_MONITORS */

	DebugP("exit_thread exited.\n");
}


/*
 * Makecontext/freecontext implementation for Elbrus architecture
 *
 * 1. Every context has a hardware stack associated with it. Those stacks
 * are organized in a hash table.
 *
 * 2. Contexts are a property of a process so the hash table is located
 * in 'mm_struct' structure.
 *
 * 3. There can be multiple contexts associated with the same hardware stack,
 * so we have to use some stack's property as a key for the hash table.
 * Keys are allocated from mm_context.hw_context_last and stored in
 * thread_info.hw_context_current. On the user side the keys are stored
 * in "sbr" field of struct uc_mcontext.
 *
 * 4. When we switch to a context that is on current hardware stack, we
 * do a longjmp to a saved location. The same limitations as for setjmp/longjmp
 * apply.
 *
 * 5. When we switch to a context that is on another hardware stack, we
 * save current context and then switch all registers.
 *
 * 6. Contexts created by makecontext() are always present in the hash table,
 * they are just marked if someone executes on them. This is needed for
 * freecontext() to distinguish between "bad pointer" and "busy context"
 * errors.
 *
 * 7. Since on e2k signal handlers take some space in kernel data stack,
 * it must be created for each new context too.
 *
 * 8. When context created by makecontext() exits it should return to
 * the kernel trampoline which will switch to kernel data stack and then
 * switch to the context mentioned in uc_link or call do_exit().
 *
 * 9. The original context is not in the hash table, but we have to put
 * it there on the first switch.
 */

static noinline int do_swapcontext_noinline(struct ucontext __user *oucp,
		const struct ucontext __user *ucp,
		bool save_prev_ctx, int format)
{
	return do_swapcontext(oucp, ucp, save_prev_ctx, format);
}

#define printk printk_fixed_args
#ifndef CONFIG_E2S_CPU_RF_BUG
__interrupt
#endif
static notrace __noreturn void makecontext_trampoline()
{
	int ret = 0;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	struct thread_info *ti;
	struct hw_context *ctx;
	void __user *uc_link = NULL;

	/*
	 * Switch to kernel stacks
	 */
	E2K_WAIT(_all_e);
	ti = (struct thread_info *) E2K_GET_DSREG_NV(osr0);
	E2K_SAVE_GREG(ti->gbase, ti->gext, ti->tag, 16, 17);
	E2K_SET_DGREG_NV(16, ti);
	E2K_SET_DGREG_NV(17, ti->task);
	E2K_SET_DGREG_NV(19, (u64) ti->cpu);
	SET_KERNEL_UPSR_WITH_DISABLED_NMI(0);
	AW(usd_lo) = AW(ti->k_usd_lo);
	AW(usd_hi) = AW(ti->k_usd_hi);
	DISABLE_US_CLW();
	WRITE_SBR_REG_VALUE(ti->k_stk_base + ti->k_stk_sz);
	WRITE_USD_REG(usd_hi, usd_lo);
	E2K_WAIT_ALL;
	set_my_cpu_offset(per_cpu_offset(raw_smp_processor_id()));
	raw_all_irq_enable();

	/*
	 * Call switchcontext if needed
	 */
	ctx = ti->next_ctx;

	/*
	 * Read uc_link from user
	 */
	if (ctx->ptr_format == CTX_32_BIT) {
		u32 ucontext_32;

		if (get_user(ucontext_32, (u32 *) ctx->p_uc_link)) {
			ret = -EFAULT;
			goto exit;
		}
		uc_link = (struct ucontext_32 *) (u64) ucontext_32;
	} else if (ctx->ptr_format == CTX_64_BIT) {
		u64 ucontext_64;

		if (get_user(ucontext_64, (u64 *) ctx->p_uc_link)) {
			ret = -EFAULT;
			goto exit;
		}
		uc_link = (struct ucontext *) ucontext_64;
	} else {
		/* CTX_128_BIT */
		e2k_ptr_t ptr;
		u64 lo_val, hi_val;
		int lo_tag, hi_tag;
		int tag;
		u32 size;

		BEGIN_USR_PFAULT("makecontext_pfault", "0f");
		E2K_LOAD_TAGGED_QWORD_AND_TAGS(ctx->p_uc_link,
				lo_val, hi_val, lo_tag, hi_tag);
		LBL_USR_PFAULT("makecontext_pfault", "0:");
		if (END_USR_PFAULT) {
			ret = -EFAULT;
			goto exit;
		}
		AW(ptr).lo = lo_val;
		AW(ptr).hi = hi_val;
		size = AS(ptr).size - AS(ptr).curptr;
		tag = (hi_tag << 4) | lo_tag;

		/*
		 * Check that the pointer is good.
		 * We must be able to access uc_mcontext.sbr field.
		 */
		if (!size)
			/* NULL pointer, just return */
			goto exit;
		if (tag != ETAGAPQ || size <
				offsetof(struct ucontext_prot,
						uc_mcontext.usd_lo)) {
			ret = -EFAULT;
			goto exit;
		}

		uc_link = (struct ucontext_prot *) E2K_PTR_PTR(ptr);
	}

	DebugCTX("ctx %lx, uc_link=%lx\n",
			ctx, uc_link);

	if (uc_link) {
		ti->free_hw_context = true;
		/*
		 * swapcontext() must not be inlined since current
		 * function has __interrupt attribute.
		 */
		ret = do_swapcontext_noinline(NULL, uc_link, false,
				ctx->ptr_format);

		DebugCTX("swapcontext failed with %d\n",
				ret);
	}

exit:
	if (test_thread_flag(TIF_NOHZ))
		user_exit();

	/* Convert to user codes */
	ret = -ret;

	DebugCTX("calling do_exit with %d\n", ret);
	do_exit((ret & 0xff) << 8);
}
#undef printk

static size_t get_ps_stack_size(size_t u_stk_size)
{
	size_t ps_size;

	ps_size = 32 * u_stk_size;
	if (ps_size < USER_P_STACK_INIT_SIZE)
		ps_size = USER_P_STACK_INIT_SIZE;
	else if (ps_size < USER_P_STACK_SIZE)
		ps_size = USER_P_STACK_SIZE;

	return ps_size;
}

static size_t get_pcs_stack_size(size_t ps_size)
{
	size_t pcs_size;

	pcs_size = ps_size / 16;
	if (pcs_size < USER_PC_STACK_INIT_SIZE)
		pcs_size = USER_PC_STACK_INIT_SIZE;

	return pcs_size;
}

/**
 * alloc_hw_context - allocate kernel stacks for a context
 * @main_context - is this main thread's context?
 * @u_stk_size - user data stack size
 *
 * For the main thread stacks are already allocated and we only
 * have to save their parameters.
 */
static struct hw_context *alloc_hw_context(bool main_context, size_t u_stk_size)
{
	size_t u_pcs_size, u_ps_size;
	struct hw_context *ctx;
	struct hw_stack_area	*user_psp_stk, *user_pcsp_stk;
	void *pcs_base, *ps_base;

	ctx = kmalloc(sizeof(*ctx), GFP_USER);
	if (!ctx)
		return NULL;

	/*
	 * Make sure sys_swapcontext() won't use this context in the window
	 * between allocating and initializing main context.
	 */
	ctx->in_use = true;

	if (main_context) {
		/*
		 * Stacks have been allocated already
		 */
		struct thread_info *ti = current_thread_info();

		ctx->ti.k_stk_base = ti->k_stk_base;
		ctx->ti.k_stk_sz = ti->k_stk_sz;
		ctx->ti.old_u_pcs_list = ti->old_u_pcs_list;
		ctx->ti.ps_list = ti->ps_list;
		ctx->ti.cur_ps = ti->cur_ps;
		ctx->ti.pcs_list = ti->pcs_list;
		ctx->ti.cur_pcs = ti->cur_pcs;
		ctx->ti.ps_base = ti->ps_base;
		ctx->ti.ps_size = ti->ps_size;
		ctx->ti.ps_offset = ti->ps_offset;
		ctx->ti.ps_top = ti->ps_top;
		ctx->ti.pcs_base = ti->pcs_base;
		ctx->ti.pcs_size = ti->pcs_size;
		ctx->ti.pcs_offset = ti->pcs_offset;
		ctx->ti.pcs_top = ti->pcs_top;

		set_context_key(ctx, context_ti_key(current_thread_info()));

		DebugCTX("ctx %lx allocated for main\n", ctx);
		return ctx;
	}

	INIT_LIST_HEAD(&ctx->ti.old_u_pcs_list);
	INIT_LIST_HEAD(&ctx->ti.ps_list);
	INIT_LIST_HEAD(&ctx->ti.pcs_list);

	if (UHWS_PSEUDO_MODE) {
		u_ps_size = get_max_psp_size(USER_P_STACK_AREA_SIZE);
		user_psp_stk = alloc_user_p_stack(u_ps_size, 0,
						  USER_P_STACK_INIT_SIZE);
		if (!user_psp_stk)
			goto free_context;

		u_pcs_size = get_max_pcsp_size(USER_PC_STACK_AREA_SIZE);
		user_pcsp_stk = alloc_user_pc_stack(u_pcs_size, 0,
						     USER_PC_STACK_INIT_SIZE);
		if (!user_pcsp_stk)
			goto free_p_stack;

		list_add(&user_psp_stk->list_entry, &ctx->ti.ps_list);
		list_add(&user_pcsp_stk->list_entry, &ctx->ti.pcs_list);

		ctx->ti.cur_pcs = user_pcsp_stk;
		ctx->ti.cur_ps = user_psp_stk;
	} else {
		u_ps_size = get_max_psp_size(get_ps_stack_size(u_stk_size));
		ps_base = alloc_user_p_stack_cont(u_ps_size,
						  USER_P_STACK_INIT_SIZE);
		if (!ps_base)
			goto free_context;

		u_pcs_size = get_max_pcsp_size(get_pcs_stack_size(u_ps_size));
		pcs_base = alloc_user_pc_stack_cont(u_pcs_size,
						    USER_PC_STACK_INIT_SIZE);
		if (!pcs_base)
			goto free_p_stack;

		ctx->ti.ps_base = ps_base;
		ctx->ti.ps_size = u_ps_size;
		ctx->ti.ps_offset = 0;
		ctx->ti.ps_top = USER_P_STACK_INIT_SIZE;

		ctx->ti.pcs_base = pcs_base;
		ctx->ti.pcs_size = u_pcs_size;
		ctx->ti.pcs_offset = 0;
		ctx->ti.pcs_top = USER_PC_STACK_INIT_SIZE;
	}

	ctx->ti.k_stk_base = (unsigned long) alloc_kernel_c_stack();
	if (!ctx->ti.k_stk_base)
		goto free_pc_stack;

	ctx->ti.k_stk_sz = KERNEL_C_STACK_SIZE;

	DebugCTX("allocated stacks p: 0x%lx, pc: 0x%lx, data: 0x%lx-0x%lx\n",
		GET_PS_BASE(&ctx->ti), GET_PCS_BASE(&ctx->ti),
		ctx->ti.k_stk_base, ctx->ti.k_stk_base + ctx->ti.k_stk_sz);

	set_context_key(ctx, alloc_context_key(current->mm));

	return ctx;

free_pc_stack:
	if (UHWS_PSEUDO_MODE) {
		free_user_pc_stack(user_pcsp_stk, true);
		ctx->ti.cur_pcs = NULL;
	} else {
		free_user_pc_stack_cont(pcs_base, u_pcs_size, 0,
					USER_PC_STACK_INIT_SIZE);
	}
free_p_stack:
	if (UHWS_PSEUDO_MODE) {
		free_user_p_stack(user_psp_stk, true);
		ctx->ti.cur_ps = NULL;
	} else {
		free_user_p_stack_cont(ps_base, u_ps_size, 0,
				       USER_P_STACK_INIT_SIZE);
	}
free_context:
	kfree(ctx);

	return NULL;
}

/**
 * free_hw_context - free kernel stacks
 * @ctx - context to free
 * @exit - set if the whole process exits
 */
static void free_hw_context(struct hw_context *ctx, bool ctx_in_use, bool exit)
{
	if (!ctx_in_use) {
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		kfree(ctx->task.ret_stack);
		ctx->task.ret_stack = NULL;
#endif

		if (UHWS_PSEUDO_MODE) {
			struct hw_stack_area *u_ps, *u_pcs;

			free_user_old_pc_stack_areas(&ctx->ti.old_u_pcs_list);

			BUG_ON(list_empty(&ctx->ti.ps_list) ||
			       list_empty(&ctx->ti.pcs_list));

#if DEBUG_CTX_MODE
			list_for_each_entry(u_ps, &ctx->ti.ps_list, list_entry)
				DebugCTX("register stack at 0x%lx\n",
						u_ps->base);

			list_for_each_entry(u_pcs, &ctx->ti.pcs_list,
					    list_entry)
				DebugCTX("chain stack at 0x%lx\n", u_pcs->base);
#endif

			/*
			 * If the whole process is exiting we do not free
			 * address space - it is neither needed nor possible
			 * because by the time of arch_exit_mmap() call
			 * current->mm pointer has been set to NULL already.
			 */
			if (exit) {
				list_for_each_entry(u_ps, &ctx->ti.ps_list,
						    list_entry)
					kfree(u_ps);
				INIT_LIST_HEAD(&ctx->ti.ps_list);

				list_for_each_entry(u_pcs, &ctx->ti.pcs_list,
						    list_entry)
					kfree(u_pcs);
				INIT_LIST_HEAD(&ctx->ti.pcs_list);
			} else {
				free_user_p_stack_areas(&ctx->ti.ps_list);
				free_user_pc_stack_areas(&ctx->ti.pcs_list);
			}

			ctx->ti.cur_ps = NULL;
			ctx->ti.cur_pcs = NULL;
		} else if (!exit) {
			free_user_p_stack_cont(ctx->ti.ps_base,
					       ctx->ti.ps_size,
					       ctx->ti.ps_offset,
					       ctx->ti.ps_top);

			free_user_pc_stack_cont(ctx->ti.pcs_base,
						ctx->ti.pcs_size,
						ctx->ti.pcs_offset,
						ctx->ti.pcs_top);
		}

		free_kernel_c_stack((void *) ctx->ti.k_stk_base);
	}

	DebugCTX("ctx %lx freed (%s stack areas, %d stack memory)\n",
			ctx, ctx_in_use ? "without" : "with",
			exit ? "without" : "with");

	kfree(ctx);
}

/**
 * free_hw_contexts - called on thread exit to free all contexts
 * @mm - mm that is being freed
 */
void free_hw_contexts(struct mm_struct *mm)
{
	mm_context_t *mm_context = &mm->context;
	int i;

	for (i = 0; i < (1 << HW_CONTEXT_HASHBITS); i++) {
		struct list_head *head = &mm_context->hw_contexts[i];

		while (!list_empty(head)) {
			struct hw_context *ctx;

			spin_lock(&mm_context->hw_context_lock);
			if (!list_empty(head)) {
				ctx = list_first_entry(head, struct hw_context,
						       list_entry);
				list_del(&ctx->list_entry);
			} else {
				ctx = NULL;
			}
			spin_unlock(&mm_context->hw_context_lock);

			/*
			 * Cannot free context's stacks if they are used
			 * by some thread in current process. They will
			 * be freed by exit_mm() instead.
			 */
			if (ctx)
				free_hw_context(ctx, ctx->in_use, true);
		}
	}
}

int set_user_ap(void __user *ptr, unsigned long addr, size_t len)
{
	int ret = 0;
	e2k_ptr_t qptr;

	qptr = MAKE_AP(addr, len);

	SAVE_USR_PFAULT;
	current_thread_info()->usr_pfault_jump = PG_JMP;
	DebugUA("will put to ptr 0x%p\n", ptr);
	E2K_CMD_SEPARATOR;
	E2K_SET_TAGS_AND_STORE_QUADRO(qptr, ptr);
	E2K_CMD_SEPARATOR;
	if (!current_thread_info()->usr_pfault_jump) {
		DebugUAF("set_user_ap interrupted %p\n", ptr);
		ret = -EFAULT;
	}
	END_USR_PFAULT;

	return ret;
}

void set_kernel_ap(void *ptr, unsigned long addr, size_t len)
{
	e2k_ptr_t qptr;

	qptr = MAKE_AP(addr, len);
	E2K_SET_TAGS_AND_STORE_QUADRO(qptr, ptr);
}

struct longjmp_regs {
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
};

/**
 * prepare_hw_context - set up all stacks for a user function execution
 * @ctx: hardware context
 * @func: user function
 * @args_size: size of all arguments
 * @args: pointer to arguments
 * @u_stk_base: user data stack base
 * @u_stk_size: user data stack size
 * @protected: protected mode execution
 *
 * The first frame in the context is set to point to a kernel function
 * which will handle return from @func, and the second frame points to
 * @func.
 */
noinline
static int prepare_hw_context(struct longjmp_regs *user_regs,
		struct hw_context *ctx, void (*func)(),
		u64 args_size, void __user *args,
		void *u_stk_base, size_t u_stk_size, bool protected)
{
	e2k_stacks_t stacks;
	e2k_mem_crs_t crs;
	e2k_sbr_t u_sbr;
	e2k_psr_t psr;
	e2k_usd_lo_t u_usd_lo;
	e2k_usd_hi_t u_usd_hi;
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_mem_crs_t *cs_frame;
	void *ps_frame;
	e2k_addr_t delta_sp;
	e2k_size_t delta_sz;
	u64 args_registers_size;
	u64 args_stack_size;
	u64 func_frame_size;
	unsigned long func_frame_ptr;
	int first_user_cui;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	struct ftrace_ret_stack *ret_stack;
#endif
	int i;

	if (ALIGN(args_size, 16) + (protected ? 16 : 0) > u_stk_size)
		return -EINVAL;

	INIT_LIST_HEAD(&ctx->list_entry);

	AW(stacks.pcsp_lo) = 0;
	AS(stacks.pcsp_lo).base = (u64) GET_PCS_BASE(&ctx->ti);
	AS(stacks.pcsp_lo).rw = 3;

	AW(stacks.psp_lo) = 0;
	AS(stacks.psp_lo).base = (u64) GET_PS_BASE(&ctx->ti);
	AS(stacks.psp_lo).rw = 3;

	/*
	 * Do not add kernel part size since we are executing
	 * under disabled PSR.sge.
	 */
	AS(stacks.pcsp_hi).size = USER_PC_STACK_INIT_SIZE;
	AS(stacks.psp_hi).size = USER_P_STACK_INIT_SIZE;

	/*
	 * Leave space for trampoline's frame so that there is space
	 * for the user function to return to.
	 */
	AS(stacks.pcsp_hi).ind = 2 * SZ_OF_CR;

	/*
	 * And this is space for user function
	 */
	AS(stacks.psp_hi).ind = 4 * EXT_4_NR_SZ;

	ps_frame = (void *) GET_PS_BASE(&ctx->ti);

	AW(stacks.usd_lo) = 0;
	AS(stacks.usd_lo).base = (u64) ctx->ti.k_stk_base + ctx->ti.k_stk_sz;
	AS(stacks.usd_lo).rw = 3;

	AS(stacks.usd_hi).ind = 0;
	AS(stacks.usd_hi).size = ctx->ti.k_stk_sz;

	/*
	 * Calculate user function frame's parameters.
	 */
	if (protected) {
		args_registers_size = min(args_size, (u64) 64 - 16);
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
	if (!access_ok(VERIFY_WRITE, func_frame_ptr, func_frame_size))
		return -EFAULT;
	DebugCTX("arguments: base 0x%lx, size %ld (regs %ld + stack %ld)\n",
			args, args_size, args_registers_size, args_stack_size);

	u_sbr = (u64) u_stk_base + u_stk_size;

	AW(u_usd_lo) = 0;
	AS(u_usd_lo).base = func_frame_ptr;
	AS(u_usd_lo).rw = 3;

	AS(u_usd_hi).ind = 0;
	AS(u_usd_hi).size = u_stk_size - func_frame_size;

	if (protected) {
		e2k_pusd_lo_t pusd_lo;

		/* Check that the stack does not cross 4Gb boundary */
		if (((u64) u_stk_base & ~0xffffffffULL)
				!= (u_sbr & ~0xffffffffULL)) {
			DebugCTX("stack crosses 4Gb boundary\n");
			return -EINVAL;
		}

		/*
		 * Set PSL to 2 (we must allow for two returns:
		 * first to user function and second to the trampoline)
		 */
		AW(pusd_lo) = AW(u_usd_lo);
		AS(pusd_lo).psl = 2;

		/*
		 * Set 'protected' bit
		 */
		AS(pusd_lo).p = 1;

		AW(u_usd_lo) = AW(pusd_lo);

		/*
		 * Put descriptor of user function frame in %qr0.
		 */
		set_kernel_ap(ps_frame, func_frame_ptr, args_size);
		ps_frame += EXT_4_NR_SZ;
	}

	/*
	 * Put arguments into registers and user data stack
	 */

	BEGIN_USR_PFAULT("lbl_prepare_hw_context", "1f");
	for (i = 0; i < args_registers_size / 16; i++) {
#if DEBUG_CTX_MODE
		u64 val_lo, val_hi;
		int tag_lo, tag_hi;
		E2K_LOAD_TAGGED_QWORD_AND_TAGS(args + 16 * i, val_lo, val_hi,
				tag_lo, tag_hi);
		DebugCTX("register arguments: 0x%llx 0x%llx\n", val_lo, val_hi);
#endif
		if (protected) {
			/* We have to check for SAP */
			u64 val_lo, val_hi;
			int tag_lo, tag_hi;
			e2k_sap_lo_t sap;
			e2k_ap_lo_t ap;

			E2K_LOAD_TAGGED_QWORD_AND_TAGS(args + 16 * i,
					val_lo, val_hi, tag_lo, tag_hi);
			if (((tag_hi << 4) | tag_lo) == ETAGAPQ &&
					((val_lo & AP_ITAG_MASK) >>
						AP_ITAG_SHIFT) == SAP_ITAG) {
				/* SAP was passed, convert to AP
				 * for the new context since it has
				 * separate data stack. */
				AW(sap) = val_lo;
				AW(ap) = 0;
				AS(ap).itag = AP_ITAG;
				AS(ap).rw = AS(sap).rw;
				AS(ap).base = AS(sap).base +
					(current_thread_info()->u_stk_base &
							0xFFFF00000000UL);
				val_lo = AW(ap);
				DebugCTX("\tfixed SAP: 0x%llx 0x%llx\n",
						val_lo, val_hi);
			}
			E2K_STORE_TAGGED_QWORD(ps_frame + EXT_4_NR_SZ * i,
					val_lo, val_hi, tag_lo, tag_hi);
		} else {
			E2K_MOVE_TAGGED_DWORD(args + 16 * i,
					ps_frame + EXT_4_NR_SZ * i);
			E2K_MOVE_TAGGED_DWORD(args + 16 * i + 8,
					ps_frame + EXT_4_NR_SZ * i + 8);
		}
	}

	if (2 * i < args_registers_size / 8) {
#if DEBUG_CTX_MODE
		u64 val;
		int tag;
		E2K_LOAD_VAL_AND_TAGD(args + 16 * i, val, tag);
		DebugCTX("register arguments: 0x%llx\n", val);
#endif
		E2K_MOVE_TAGGED_DWORD(args + 16 * i,
				ps_frame + EXT_4_NR_SZ * i);
	}

#if DEBUG_CTX_MODE
	for (i = 0; i + 1 < args_stack_size / 8; i += 2) {
		u64 val_lo, val_hi;
		int tag_lo, tag_hi;
		E2K_LOAD_TAGGED_QWORD_AND_TAGS(args +
				args_registers_size + 8 * i,
				val_lo, val_hi, tag_lo, tag_hi);
		DebugCTX("stack arguments: 0x%llx 0x%llx\n",
				val_lo, val_hi);
	}
#endif
	LBL_USR_PFAULT("lbl_prepare_hw_context", "1:");
	if (END_USR_PFAULT)
		return -EFAULT;

	if (args_stack_size) {
		DebugCTX("Copying stack arguments to 0x%lx\n",
				(void *) func_frame_ptr + 64);
		if (copy_in_user_with_tags((void *) func_frame_ptr + 64,
				args + args_registers_size, args_stack_size))
			return -EFAULT;
	}

	user_regs->pcsp_lo = stacks.pcsp_lo;
	user_regs->pcsp_hi = stacks.pcsp_hi;

	/*
	 * We are here:
	 *
	 * hard_sys_calls -> sys_makecontext -> prepare_hw_context
	 *
	 * We want to copy hard_sys_calls() frame.
	 */
	copy_hardware_stacks(&stacks, &crs, 1 /* down */,
			1 /* level_num */, 1 /* copy data stack */,
			&delta_sp, &delta_sz);

	DebugCTX("copied stack, delta_sp = 0x%lx\n",
			delta_sp);

	ctx->pcsp_lo = stacks.pcsp_lo;
	ctx->pcsp_hi = stacks.pcsp_hi;
	ctx->psp_lo = stacks.psp_lo;
	ctx->psp_hi = stacks.psp_hi;

	ctx->k_usd_lo = stacks.usd_lo;
	ctx->k_usd_hi = stacks.usd_hi;
	ctx->k_sbr = (u64) ctx->ti.k_stk_base + ctx->ti.k_stk_sz;

	ctx->u_stk_top = (unsigned long) u_stk_base + u_stk_size;

#ifdef CONFIG_GREGS_CONTEXT
	memset(ctx->gbase, 0, sizeof(ctx->gbase));
	memset(ctx->gext, 0, sizeof(ctx->gext));
	memset(ctx->tag, ETAGEWD, sizeof(ctx->tag));

	AS(ctx->bgr).cur = 0;
	AS(ctx->bgr).val = 0xff;
#endif

	/*
	 * Set chain stack for hard_sys_calls()
	 */
	ctx->cr0_lo = crs.cr0_lo;
	ctx->cr0_hi = crs.cr0_hi;
	ctx->cr1_lo = crs.cr1_lo;
	ctx->cr1_hi = crs.cr1_hi;

	/*
	 * Set chain stack for the user function
	 */
	cs_frame = (e2k_mem_crs_t *) (GET_PCS_BASE(&ctx->ti) + 2 * SZ_OF_CR);

	AS(cr0_lo).pf = -1ULL;

	AW(cr0_hi) = 0;
	AS(cr0_hi).ip = (unsigned long) func >> 3;

	AW(cr1_lo) = 0;
	AS(cr1_lo).psr = AW(E2K_USER_INITIAL_PSR);
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	first_user_cui = USER_CODES_32_INDEX;
#else
	first_user_cui = 1;
#endif
	AS(cr1_lo).cuir = first_user_cui;
	AS(cr1_lo).wbs = 4;

	AW(cr1_hi) = 0;
	AS(cr1_hi).ussz = AS(u_usd_hi).size / 16;

	cs_frame->cr0_lo = cr0_lo;
	cs_frame->cr0_hi = cr0_hi;
	cs_frame->cr1_lo = cr1_lo;
	cs_frame->cr1_hi = cr1_hi;

	user_regs->cr0_hi = cr0_hi;
	user_regs->cr1_lo = cr1_lo;
	user_regs->cr1_hi = cr1_hi;

	/*
	 * Set chain stack for the trampoline
	 */
	cs_frame = (e2k_mem_crs_t *) (GET_PCS_BASE(&ctx->ti) + SZ_OF_CR);

	AS(cr0_hi).ip = (u64) &makecontext_trampoline >> 3;
	AW(psr) = E2K_GET_DSREG_NV(psr);
	AS(psr).ie = 0;
	AS(psr).nmie = 0;
	AS(psr).sge = 0;
	AS(cr1_lo).psr = AW(psr);
	AS(cr1_lo).cuir = KERNEL_CODES_INDEX;
	AS(cr1_lo).wbs = 0;
	AS(cr1_hi).ussz = ctx->ti.k_stk_sz / 16;

	cs_frame->cr0_lo = cr0_lo;
	cs_frame->cr0_hi = cr0_hi;
	cs_frame->cr1_lo = cr1_lo;
	cs_frame->cr1_hi = cr1_hi;


	/*
	 * Initialize thread_info
	 */
	ctx->ti.pt_regs = (void *) current_thread_info()->pt_regs +
			delta_sp;
	DebugCTX("old pt_regs at 0x%lx, new at %lx\n",
			current_thread_info()->pt_regs,
			ctx->ti.pt_regs);
	DebugCTX("old pt_regs->ctpr1 is 0x%lx, new is %lx\n",
			current_thread_info()->pt_regs->ctpr1,
			ctx->ti.pt_regs->ctpr1);
	/* Only one pt_regs structure for the new context */
	ctx->ti.pt_regs->next = NULL;
	ctx->ti.k_usd_hi = ctx->k_usd_hi;
	ctx->ti.k_usd_lo = ctx->k_usd_lo;
	ctx->ti.upsr = E2K_USER_INITIAL_UPSR;
	ctx->ti.u_stk_base = (u64) u_stk_base;
	ctx->ti.u_stk_sz = u_stk_size;
	ctx->ti.u_stk_top = (u64) u_stk_base + u_stk_size;
	ctx->ti.pusd_pil = 0;
#ifdef CONFIG_PROTECTED_MODE
	ctx->ti.g_list = 0;
	ctx->ti.multithread_address = 0;
	ctx->ti.lock = NULL;
	ctx->ti.user_stack_addr = 0;
	ctx->ti.user_stack_size = 0;
#endif

	/*
	 * Initialize task_struct
	 */
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	ret_stack = kmalloc(FTRACE_RETFUNC_DEPTH
			* sizeof(struct ftrace_ret_stack), GFP_KERNEL);
	if (ret_stack) {
		atomic_set(&ctx->task.tracing_graph_pause, 0);
		atomic_set(&ctx->task.trace_overrun, 0);
		ctx->task.ftrace_timestamp = 0;
	}
	ctx->task.ret_stack = ret_stack;
	ctx->task.curr_ret_stack = -1;
	DebugFTRACE("ret_stack %p allocated\n", ret_stack);
#endif

	/*
	 * Set stack registers in new pt_regs
	 */
	cs_frame = (e2k_mem_crs_t *) (GET_PCS_BASE(&ctx->ti) + 2 * SZ_OF_CR);
	ctx->ti.pt_regs->crs = *cs_frame;
	ctx->ti.pt_regs->stacks.sbr = u_sbr;
	ctx->ti.pt_regs->stacks.usd_lo = u_usd_lo;
	ctx->ti.pt_regs->stacks.usd_hi = u_usd_hi;

	ctx->in_use = false;

	return 0;
}

static inline u64 key2index(u64 key)
{
	return jhash_1word((u32) key, (u32) (key >> 32))
			& ((1 << HW_CONTEXT_HASHBITS) - 1);
}

static inline struct hw_context *key2hw_context(u64 key, u64 index,
		mm_context_t *mm_context, bool used)
{
	struct hw_context *ctx;

	list_for_each_entry(ctx, &mm_context->hw_contexts[index],
			list_entry) {
		if (context_key_matches(key, ctx)) {
			if (unlikely(ctx->in_use && !used ||
					!ctx->in_use && used)) {
				DebugCTX("ucp %lx found by key %llx but in use == %d\n",
						ctx, key, used);
				break;
			}
			goto found;
		}
	}

	ctx = NULL;

found:
	DebugCTX("ucp %lx found by key %llx (index %lld)\n",
			ctx, key, index);

	return ctx;
}

int sys_makecontext(struct ucontext __user *ucp, void (*func)(),
		u64 args_size, void __user *args, int sigsetsize)
{
	void *u_stk_base;
	size_t u_stk_size;
	struct hw_context *ctx;
	struct list_head *hb;
	struct longjmp_regs user_regs;
	mm_context_t *mm_context = &current->mm->context;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	u32 index;
	int ret;

	DebugCTX("ucp %lx started\n", ucp);

	if (!access_ok(ACCESS_WRITE, ucp, sizeof(*ucp))) {
		ret = -EFAULT;
		goto out;
	}
	ret =  __get_user(u_stk_base, &ucp->uc_stack.ss_sp);
	ret |= __get_user(u_stk_size, &ucp->uc_stack.ss_size);
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	u_stk_size -= PTR_ALIGN(u_stk_base, 16) - u_stk_base;
	u_stk_base = PTR_ALIGN(u_stk_base, 16);
	u_stk_size = round_down(u_stk_size, 16);
	DebugCTX("user stack at %lx, size=%lx\n",
			u_stk_base, u_stk_size);

	if (sigsetsize != sizeof(sigset_t)) {
		ret = -EINVAL;
		goto out;
	}

	ctx = alloc_hw_context(false, u_stk_size);
	if (!ctx) {
		ret = -ENOMEM;
		goto out;
	}
	DebugCTX("ctx %lx allocated, key=%lx\n", ctx,
			context_key(ctx));

	ctx->p_uc_link = &ucp->uc_link;
	ctx->ptr_format = CTX_64_BIT;

	ret = prepare_hw_context(&user_regs, ctx, func, args_size, args,
			u_stk_base, u_stk_size, false);
	if (ret)
		goto out_free_ctx;

	/*
	 * Initialize user structure
	 */
	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr);
	ret = __clear_user(&ucp->uc_sigmask, sigsetsize);
	ret |= __put_user(context_key(ctx), &ucp->uc_mcontext.sbr);
	ret |= __put_user(AW(user_regs.cr0_hi), &ucp->uc_mcontext.cr0_hi);
	ret |= __put_user(AW(user_regs.cr1_lo), &ucp->uc_mcontext.cr1_lo);
	ret |= __put_user(AW(user_regs.cr1_hi), &ucp->uc_mcontext.cr1_hi);
	ret |= __put_user(AW(user_regs.pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	ret |= __put_user(AW(user_regs.pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	ret |= __put_user(AW(fpcr), &ucp->uc_extra.fpcr);
	ret |= __put_user(AW(fpsr), &ucp->uc_extra.fpsr);
	ret |= __put_user(AW(pfpfr), &ucp->uc_extra.pfpfr);
	if (ret) {
		ret = -EFAULT;
		goto out_free_ctx;
	}

	index = key2index(context_key(ctx));

	if (unlikely(key2hw_context(context_key(ctx), index, mm_context, true)
			|| key2hw_context(context_key(ctx), index, mm_context,
							false))) {
		/*
		 * This key is already in use.
		 */
		ret = -EBUSY;
		goto out_free_ctx;
	}

	spin_lock(&mm_context->hw_context_lock);
	DebugCTX("adding ctx %lx with key %llx and index %lld\n",
			ctx, context_key(ctx), index);
	hb = &mm_context->hw_contexts[index];
	list_add(&ctx->list_entry, hb);

	spin_unlock(&mm_context->hw_context_lock);

	return 0;

out_free_ctx:
	free_hw_context(ctx, false, false);

out:
	DebugCTX("failed with %d\n", ret);

	return ret;
}

#ifdef CONFIG_COMPAT
int compat_sys_makecontext(struct ucontext_32 __user *ucp,
		void (*func)(), u64 args_size, void __user *args,
		int sigsetsize)
{
	void *u_stk_base;
	u32 __u_stk_base;
	size_t u_stk_size;
	struct hw_context *ctx;
	struct list_head *hb;
	struct longjmp_regs user_regs;
	mm_context_t *mm_context = &current->mm->context;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	u32 index;
	int ret;

	DebugCTX("ucp %lx started\n", ucp);

	if (!access_ok(ACCESS_WRITE, ucp, sizeof(*ucp))) {
		ret = -EFAULT;
		goto out;
	}
	ret =  __get_user(__u_stk_base, &ucp->uc_stack.ss_sp);
	ret |= __get_user(u_stk_size, &ucp->uc_stack.ss_size);
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	u_stk_base = (void *) (unsigned long) __u_stk_base;

	u_stk_size -= PTR_ALIGN(u_stk_base, 16) - u_stk_base;
	u_stk_base = PTR_ALIGN(u_stk_base, 16);
	u_stk_size = round_down(u_stk_size, 16);
	DebugCTX("user stack at %lx, size=%lx\n",
			u_stk_base, u_stk_size);

	if (sigsetsize != sizeof(sigset_t)) {
		ret = -EINVAL;
		goto out;
	}

	ctx = alloc_hw_context(false, u_stk_size);
	if (!ctx) {
		ret = -ENOMEM;
		goto out;
	}
	DebugCTX("ctx %lx allocated, key=%lx\n", ctx,
			context_key(ctx));

	ctx->p_uc_link = &ucp->uc_link;
	ctx->ptr_format = CTX_32_BIT;

	ret = prepare_hw_context(&user_regs, ctx, func, args_size, args,
			u_stk_base, u_stk_size, false);
	if (ret)
		goto out_free_ctx;

	/*
	 * Initialize user structure
	 */
	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr);
	ret = __clear_user(&ucp->uc_sigmask, sigsetsize);
	ret |= __put_user(context_key(ctx), &ucp->uc_mcontext.sbr);
	ret |= __put_user(AW(user_regs.cr0_hi), &ucp->uc_mcontext.cr0_hi);
	ret |= __put_user(AW(user_regs.cr1_lo), &ucp->uc_mcontext.cr1_lo);
	ret |= __put_user(AW(user_regs.cr1_hi), &ucp->uc_mcontext.cr1_hi);
	ret |= __put_user(AW(user_regs.pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	ret |= __put_user(AW(user_regs.pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	ret |= __put_user(AW(fpcr), &ucp->uc_extra.fpcr);
	ret |= __put_user(AW(fpsr), &ucp->uc_extra.fpsr);
	ret |= __put_user(AW(pfpfr), &ucp->uc_extra.pfpfr);
	if (ret) {
		ret = -EFAULT;
		goto out_free_ctx;
	}

	index = key2index(context_key(ctx));

	spin_lock(&mm_context->hw_context_lock);
	DebugCTX("adding ctx %lx with key %llx and index %lld\n",
			ctx, context_key(ctx), index);
	hb = &mm_context->hw_contexts[index];
	list_add(&ctx->list_entry, hb);

	spin_unlock(&mm_context->hw_context_lock);

	return 0;

out_free_ctx:
	free_hw_context(ctx, false, false);

out:
	DebugCTX("failed with %d\n", ret);

	return ret;
}
#endif

#ifdef CONFIG_PROTECTED_MODE
int protected_sys_makecontext(struct ucontext_prot __user *ucp,
		void (*func)(), u64 args_size,
		void __user *args, int sigsetsize)
{
	e2k_ptr_t stack_ptr;
	void *u_stk_base;
	size_t u_stk_size;
	struct hw_context *ctx;
	struct list_head *hb;
	struct longjmp_regs user_regs;
	mm_context_t *mm_context = &current->mm->context;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	u32 index;
	int ret;

	DebugCTX("ucp %lx started\n", ucp);

	if (!access_ok(ACCESS_WRITE, ucp, sizeof(*ucp))) {
		ret = -EFAULT;
		goto out;
	}
	ret = __copy_from_user(&stack_ptr, &ucp->uc_stack.ss_sp, 16);
	ret |= __get_user(u_stk_size, &ucp->uc_stack.ss_size);
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	if (AS(stack_ptr).size < u_stk_size)
		return -EINVAL;

	u_stk_base = (void *) E2K_PTR_PTR(stack_ptr);

	u_stk_size -= PTR_ALIGN(u_stk_base, 16) - u_stk_base;
	u_stk_base = PTR_ALIGN(u_stk_base, 16);
	u_stk_size = round_down(u_stk_size, 16);
	DebugCTX("user stack at %lx, size=%lx\n",
			u_stk_base, u_stk_size);

	if (sigsetsize != sizeof(sigset_t)) {
		ret = -EINVAL;
		goto out;
	}

	ctx = alloc_hw_context(false, u_stk_size);
	if (!ctx) {
		ret = -ENOMEM;
		goto out;
	}
	DebugCTX("ctx %lx allocated, key=%lx\n", ctx,
			context_key(ctx));

	ctx->p_uc_link = &ucp->uc_link;
	ctx->ptr_format = CTX_128_BIT;

	ret = prepare_hw_context(&user_regs, ctx, func, args_size, args,
			u_stk_base, u_stk_size, true);
	if (ret)
		goto out_free_ctx;

	/*
	 * Initialize user structure
	 */
	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr);
	ret = __clear_user(&ucp->uc_sigmask, sigsetsize);
	ret |= __put_user(context_key(ctx), &ucp->uc_mcontext.sbr);
	ret |= __put_user(AW(user_regs.cr0_hi), &ucp->uc_mcontext.cr0_hi);
	ret |= __put_user(AW(user_regs.cr1_lo), &ucp->uc_mcontext.cr1_lo);
	ret |= __put_user(AW(user_regs.cr1_hi), &ucp->uc_mcontext.cr1_hi);
	ret |= __put_user(AW(user_regs.pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	ret |= __put_user(AW(user_regs.pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	ret |= __put_user(AW(fpcr), &ucp->uc_extra.fpcr);
	ret |= __put_user(AW(fpsr), &ucp->uc_extra.fpsr);
	ret |= __put_user(AW(pfpfr), &ucp->uc_extra.pfpfr);
	if (ret) {
		ret = -EFAULT;
		goto out_free_ctx;
	}

	index = key2index(context_key(ctx));

	/*
	 * Fix global pointers before making the context available
	 */
	mark_all_global_sp(current_thread_info()->pt_regs, current->pid);

	spin_lock(&mm_context->hw_context_lock);
	DebugCTX("adding ctx %lx with key %llx and index %lld\n",
			ctx, context_key(ctx), index);
	hb = &mm_context->hw_contexts[index];
	list_add(&ctx->list_entry, hb);

	spin_unlock(&mm_context->hw_context_lock);

	return 0;

out_free_ctx:
	free_hw_context(ctx, false, false);

out:
	DebugCTX("failed with %d\n", ret);

	return ret;
}
#endif

static int do_freecontext(u64 free_key)
{
	mm_context_t *mm_context = &current->mm->context;
	u64 free_index;
	struct hw_context *ctx;
	int ret = 0;

	free_index = key2index(free_key);

	spin_lock(&mm_context->hw_context_lock);
	ctx = key2hw_context(free_key, free_index, mm_context, false);
	if (!ctx) {
		ret = -EINVAL;
		goto out;
	}

	list_del(&ctx->list_entry);
out:
	spin_unlock(&mm_context->hw_context_lock);

	if (!ret)
		free_hw_context(ctx, ctx->in_use, false);

	return ret;
}


int sys_freecontext(struct ucontext __user *ucp)
{
	u64 free_key;

	DebugCTX("entered for ucp %lx\n", ucp);

	if (get_user(free_key, &ucp->uc_mcontext.sbr))
		return -EFAULT;

	return do_freecontext(free_key);
}

#ifdef CONFIG_COMPAT
int compat_sys_freecontext(struct ucontext_32 __user *ucp)
{
	u64 free_key;

	DebugCTX("entered for ucp %lx\n", ucp);

	if (get_user(free_key, &ucp->uc_mcontext.sbr))
		return -EFAULT;

	return do_freecontext(free_key);
}
#endif

#ifdef CONFIG_PROTECTED_MODE
int protected_sys_freecontext(struct ucontext_prot __user *ucp)
{
	u64 free_key;

	DebugCTX("entered for ucp %lx\n", ucp);

	if (get_user(free_key, &ucp->uc_mcontext.sbr))
		return -EFAULT;

	return do_freecontext(free_key);
}
#endif

/*
 * Actually do the switch to another hardware stack described by ucp.
 *
 * Called from sys_setcontext() or sys_swapcontext().
 */
#define printk printk_fixed_args
__interrupt
static noinline long switch_hw_contexts(
		struct hw_context *__restrict prev_ctx,
		struct hw_context *__restrict next_ctx,
		u32 fpcr, u32 fpsr, u32 pfpfr)
{
#if DEBUG_CTX_MODE
	struct hw_stack_area  *u_ps, *u_pcs;

	DebugCTX("Before switching (pt_regs 0x%lx):\n",
			current_thread_info()->pt_regs);
	print_stack_frames(current, 0, 0);

	list_for_each_entry(u_ps, &current_thread_info()->ps_list, list_entry)
		DebugCTX("register stack at 0x%lx\n", u_ps->base);

	list_for_each_entry(u_pcs, &current_thread_info()->pcs_list, list_entry)
		DebugCTX("chain stack at 0x%lx\n", u_pcs->base);
#endif

	next_ctx->in_use = true;

	/*
	 * Save thread_info
	 */
	prev_ctx->ti.hw_context_current =
			current_thread_info()->hw_context_current;
	prev_ctx->ti.pt_regs = current_thread_info()->pt_regs;
	prev_ctx->ti.k_usd_hi = current_thread_info()->k_usd_hi;
	prev_ctx->ti.k_usd_lo = current_thread_info()->k_usd_lo;
	prev_ctx->ti.k_stk_base = current_thread_info()->k_stk_base;
	prev_ctx->ti.k_stk_sz = current_thread_info()->k_stk_sz;
	prev_ctx->ti.upsr = current_thread_info()->upsr;
	prev_ctx->ti.u_stk_base = current_thread_info()->u_stk_base;
	prev_ctx->ti.u_stk_sz = current_thread_info()->u_stk_sz;
	prev_ctx->ti.u_stk_top = current_thread_info()->u_stk_top;
	/* We moved the lists so the pointers in them
	 * must be fixed to point to the new location. */
	if (list_empty(&current_thread_info()->old_u_pcs_list)) {
		INIT_LIST_HEAD(&prev_ctx->ti.old_u_pcs_list);
	} else {
		prev_ctx->ti.old_u_pcs_list =
				current_thread_info()->old_u_pcs_list;
		current_thread_info()->old_u_pcs_list.next->prev =
				&prev_ctx->ti.old_u_pcs_list;
		current_thread_info()->old_u_pcs_list.prev->next =
				&prev_ctx->ti.old_u_pcs_list;
	}
	if (list_empty(&current_thread_info()->ps_list)) {
		INIT_LIST_HEAD(&prev_ctx->ti.ps_list);
	} else {
		prev_ctx->ti.ps_list = current_thread_info()->ps_list;
		current_thread_info()->ps_list.next->prev =
				&prev_ctx->ti.ps_list;
		current_thread_info()->ps_list.prev->next =
				&prev_ctx->ti.ps_list;
	}
	if (list_empty(&current_thread_info()->pcs_list)) {
		INIT_LIST_HEAD(&prev_ctx->ti.pcs_list);
	} else {
		prev_ctx->ti.pcs_list = current_thread_info()->pcs_list;
		current_thread_info()->pcs_list.next->prev =
				&prev_ctx->ti.pcs_list;
		current_thread_info()->pcs_list.prev->next =
				&prev_ctx->ti.pcs_list;
	}
	prev_ctx->ti.cur_ps = current_thread_info()->cur_ps;
	prev_ctx->ti.cur_pcs = current_thread_info()->cur_pcs;
	prev_ctx->ti.ps_base = current_thread_info()->ps_base;
	prev_ctx->ti.ps_size = current_thread_info()->ps_size;
	prev_ctx->ti.ps_offset = current_thread_info()->ps_offset;
	prev_ctx->ti.ps_top = current_thread_info()->ps_top;
	prev_ctx->ti.pcs_base = current_thread_info()->pcs_base;
	prev_ctx->ti.pcs_size = current_thread_info()->pcs_size;
	prev_ctx->ti.pcs_offset = current_thread_info()->pcs_offset;
	prev_ctx->ti.pcs_top = current_thread_info()->pcs_top;
	prev_ctx->ti.pusd_pil = current_thread_info()->pusd_pil;
#ifdef CONFIG_PROTECTED_MODE
	prev_ctx->ti.g_list = current_thread_info()->g_list;
	prev_ctx->ti.user_stack_addr = current_thread_info()->user_stack_addr;
	prev_ctx->ti.user_stack_size = current_thread_info()->user_stack_size;
	prev_ctx->ti.multithread_address =
			current_thread_info()->multithread_address;
	prev_ctx->ti.lock = current_thread_info()->lock;
#endif

	/*
	 * Save task_struct
	 */
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	DebugFTRACE("ret_stack %p saved\n", current->ret_stack);
	prev_ctx->task.tracing_graph_pause = current->tracing_graph_pause;
	prev_ctx->task.trace_overrun = current->trace_overrun;
	prev_ctx->task.ftrace_timestamp = current->ftrace_timestamp;
	prev_ctx->task.ret_stack = current->ret_stack;
	prev_ctx->task.curr_ret_stack = current->curr_ret_stack;
#endif

	raw_all_irq_disable();

	E2K_FLUSHCPU;

	prev_ctx->k_sbr = READ_SBR_REG_VALUE();
	prev_ctx->k_usd_hi = READ_USD_HI_REG();
	prev_ctx->k_usd_lo = READ_USD_LO_REG();

	AW(prev_ctx->cr1_lo) = E2K_GET_DSREG_NV(cr1.lo);
	AW(prev_ctx->cr1_hi) = E2K_GET_DSREG_NV(cr1.hi);
	AW(prev_ctx->cr0_lo) = E2K_GET_DSREG_NV(cr0.lo);
	AW(prev_ctx->cr0_hi) = E2K_GET_DSREG_NV(cr0.hi);

#ifdef CONFIG_GREGS_CONTEXT
	DO_SAVE_GLOBAL_REGISTERS(prev_ctx, false, true);
#endif /* CONFIG_GREGS_CONTEXT */

	/* These will wait for the flush so we give
	 * the flush some time to finish. */
	prev_ctx->psp_hi = RAW_READ_PSP_HI_REG();
	prev_ctx->psp_lo = READ_PSP_LO_REG();
	prev_ctx->pcsp_hi = RAW_READ_PCSP_HI_REG();
	prev_ctx->pcsp_lo = READ_PCSP_LO_REG();

	WRITE_SBR_REG_VALUE(next_ctx->k_sbr);
	WRITE_USD_REG(next_ctx->k_usd_hi, next_ctx->k_usd_lo);
	RAW_WRITE_PSP_REG(next_ctx->psp_hi, next_ctx->psp_lo);
	RAW_WRITE_PCSP_REG(next_ctx->pcsp_hi, next_ctx->pcsp_lo);

	E2K_SET_DSREG_NV_NOIRQ(cr1.lo, AW(next_ctx->cr1_lo));
	E2K_SET_DSREG_NV_NOIRQ(cr1.hi, AW(next_ctx->cr1_hi));
	E2K_SET_DSREG_NV_NOIRQ(cr0.lo, AW(next_ctx->cr0_lo));
	E2K_SET_DSREG_NV_NOIRQ(cr0.hi, AW(next_ctx->cr0_hi));

	E2K_SET_SREG_NV(fpcr,  fpcr);
	E2K_SET_SREG_NV(fpsr,  fpsr);
	E2K_SET_SREG_NV(pfpfr, pfpfr);

#ifdef CONFIG_GREGS_CONTEXT
	DO_LOAD_GLOBAL_REGISTERS(next_ctx, false);
#endif /* CONFIG_GREGS_CONTEXT */

	CLEAR_DAM;

	/*
	 * Restore thread_info
	 */
	current_thread_info()->hw_context_current =
			next_ctx->ti.hw_context_current;
	current_thread_info()->pt_regs = next_ctx->ti.pt_regs;
	current_thread_info()->k_usd_hi = next_ctx->ti.k_usd_hi;
	current_thread_info()->k_usd_lo = next_ctx->ti.k_usd_lo;
	current_thread_info()->k_stk_base = next_ctx->ti.k_stk_base;
	current_thread_info()->k_stk_sz = next_ctx->ti.k_stk_sz;
	current_thread_info()->upsr = next_ctx->ti.upsr;
	current_thread_info()->u_stk_base = next_ctx->ti.u_stk_base;
	current_thread_info()->u_stk_sz = next_ctx->ti.u_stk_sz;
	current_thread_info()->u_stk_top = next_ctx->ti.u_stk_top;
	/* We moved the lists so the pointers in them
	 * must be fixed to point to the new location. */
	if (list_empty(&next_ctx->ti.old_u_pcs_list)) {
		INIT_LIST_HEAD(&current_thread_info()->old_u_pcs_list);
	} else {
		current_thread_info()->old_u_pcs_list =
				next_ctx->ti.old_u_pcs_list;
		next_ctx->ti.old_u_pcs_list.next->prev =
				&current_thread_info()->old_u_pcs_list;
		next_ctx->ti.old_u_pcs_list.prev->next =
				&current_thread_info()->old_u_pcs_list;
	}
	if (list_empty(&next_ctx->ti.ps_list)) {
		INIT_LIST_HEAD(&current_thread_info()->ps_list);
	} else {
		current_thread_info()->ps_list = next_ctx->ti.ps_list;
		next_ctx->ti.ps_list.next->prev =
				&current_thread_info()->ps_list;
		next_ctx->ti.ps_list.prev->next =
				&current_thread_info()->ps_list;
	}
	if (list_empty(&next_ctx->ti.pcs_list)) {
		INIT_LIST_HEAD(&current_thread_info()->pcs_list);
	} else {
		current_thread_info()->pcs_list = next_ctx->ti.pcs_list;
		next_ctx->ti.pcs_list.next->prev =
				&current_thread_info()->pcs_list;
		next_ctx->ti.pcs_list.prev->next =
				&current_thread_info()->pcs_list;
	}
	current_thread_info()->cur_ps = next_ctx->ti.cur_ps;
	current_thread_info()->cur_pcs = next_ctx->ti.cur_pcs;
	current_thread_info()->ps_base = next_ctx->ti.ps_base;
	current_thread_info()->ps_size = next_ctx->ti.ps_size;
	current_thread_info()->ps_offset = next_ctx->ti.ps_offset;
	current_thread_info()->ps_top = next_ctx->ti.ps_top;
	current_thread_info()->pcs_base = next_ctx->ti.pcs_base;
	current_thread_info()->pcs_size = next_ctx->ti.pcs_size;
	current_thread_info()->pcs_offset = next_ctx->ti.pcs_offset;
	current_thread_info()->pcs_top = next_ctx->ti.pcs_top;
	current_thread_info()->pusd_pil = next_ctx->ti.pusd_pil;
#ifdef CONFIG_PROTECTED_MODE
	current_thread_info()->g_list = next_ctx->ti.g_list;
	current_thread_info()->user_stack_addr = next_ctx->ti.user_stack_addr;
	current_thread_info()->user_stack_size = next_ctx->ti.user_stack_size;
	current_thread_info()->multithread_address =
			next_ctx->ti.multithread_address;
	current_thread_info()->lock = next_ctx->ti.lock;
#endif

	/*
	 * Restore task_struct
	 */
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	current->tracing_graph_pause = next_ctx->task.tracing_graph_pause;
	current->trace_overrun = next_ctx->task.trace_overrun;
	current->ftrace_timestamp = next_ctx->task.ftrace_timestamp;
	current->ret_stack = next_ctx->task.ret_stack;
	current->curr_ret_stack = next_ctx->task.curr_ret_stack;
	DebugFTRACE("ret_stack %p restored\n", current->ret_stack);
#endif

#if DEBUG_CTX_MODE
	DebugCTX("After switching (pt_regs 0x%lx):\n",
			current_thread_info()->pt_regs);
	print_stack_frames(current, 0, 0);

	list_for_each_entry(u_ps, &current_thread_info()->ps_list, list_entry)
		DebugCTX("register stack at 0x%lx\n", u_ps->base);

	list_for_each_entry(u_pcs, &current_thread_info()->pcs_list, list_entry)
		DebugCTX("chain stack at 0x%lx\n", u_pcs->base);
#endif
	raw_all_irq_enable();

	prev_ctx->in_use = false;

	return HW_CONTEXT_TAIL;
}
#undef printk

/**
 * hw_context_tail() - first thing a new hardware context must call
 */
void hw_context_tail()
{
	struct hw_context *prev_ctx, *next_ctx;

	prev_ctx = current_thread_info()->prev_ctx;
	next_ctx = current_thread_info()->next_ctx;
	DebugCTX("switching from ctx %lx to ctx %lx\n",
			prev_ctx, next_ctx);

	if (current_thread_info()->free_hw_context)
		list_del(&prev_ctx->list_entry);

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/*
	 * First switch always gets us here, so this check
	 * should not be done in do_swapcontext after the switch
	 * (since the check only applies to the first switch).
	 */
	if (unlikely(!current_thread_info()->main_context_saved)) {
		current_thread_info()->main_context_saved = true;

		DebugCTX("main context was saved (%d)\n",
			current_thread_info()->main_context_saved);

		if (!prev_ctx->task.ret_stack) {
			struct ftrace_ret_stack *ret_stack;

			ret_stack = kmalloc(FTRACE_RETFUNC_DEPTH
					* sizeof(struct ftrace_ret_stack),
					GFP_ATOMIC);
			if (ret_stack) {
				atomic_set(&prev_ctx->task.tracing_graph_pause,
						0);
				atomic_set(&prev_ctx->task.trace_overrun, 0);
				prev_ctx->task.ftrace_timestamp = 0;
			}
			prev_ctx->task.ret_stack = ret_stack;
			prev_ctx->task.curr_ret_stack = -1;
			DebugFTRACE("ret_stack %p allocated for main ctx\n",
					ret_stack);
		}
	}
#endif

	spin_unlock(&current->mm->context.hw_context_lock);

	if (current_thread_info()->free_hw_context) {
		current_thread_info()->free_hw_context = false;
		free_hw_context(prev_ctx, false, false);
	}
}

static int save_ctx_32_bit(struct ucontext_32 __user *oucp)
{
	struct pt_regs *regs;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	int ret = 0;

	regs = current_thread_info()->pt_regs;
	E2K_GET_FPU(AW(fpcr), AW(fpsr), AW(pfpfr));
	if (!access_ok(ACCESS_WRITE, oucp, sizeof(*oucp)))
		return -EFAULT;
	BEGIN_USR_PFAULT("lbl_save_ctx_32_bit", "2f");
	*((u64 *) &oucp->uc_sigmask) = current->blocked.sig[0];
	oucp->uc_mcontext.sbr = context_ti_key(current_thread_info());
	oucp->uc_mcontext.cr0_hi = AW(regs->crs.cr0_hi);
	oucp->uc_mcontext.cr1_lo = AW(regs->crs.cr1_lo);
	oucp->uc_mcontext.cr1_hi = AW(regs->crs.cr1_hi);
	oucp->uc_mcontext.pcsp_lo = AW(regs->stacks.pcsp_lo);
	oucp->uc_mcontext.pcsp_hi = AW(regs->stacks.pcsp_hi);
	oucp->uc_extra.fpcr = AW(fpcr);
	oucp->uc_extra.fpsr = AW(fpsr);
	oucp->uc_extra.pfpfr = AW(pfpfr);
	LBL_USR_PFAULT("lbl_save_ctx_32_bit", "2:");
	if (END_USR_PFAULT)
		ret = -EFAULT;

	return ret;
}

static int save_ctx_64_bit(struct ucontext __user *oucp)
{
	struct pt_regs *regs;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	int ret = 0;

	regs = current_thread_info()->pt_regs;
	E2K_GET_FPU(AW(fpcr), AW(fpsr), AW(pfpfr));
	if (!access_ok(ACCESS_WRITE, oucp, sizeof(*oucp)))
		return -EFAULT;
	BEGIN_USR_PFAULT("lbl_save_ctx_64_bit", "3f");
	*((u64 *) &oucp->uc_sigmask) = current->blocked.sig[0];
	oucp->uc_mcontext.sbr = context_ti_key(current_thread_info());
	oucp->uc_mcontext.cr0_hi = AW(regs->crs.cr0_hi);
	oucp->uc_mcontext.cr1_lo = AW(regs->crs.cr1_lo);
	oucp->uc_mcontext.cr1_hi = AW(regs->crs.cr1_hi);
	oucp->uc_mcontext.pcsp_lo = AW(regs->stacks.pcsp_lo);
	oucp->uc_mcontext.pcsp_hi = AW(regs->stacks.pcsp_hi);
	oucp->uc_extra.fpcr = AW(fpcr);
	oucp->uc_extra.fpsr = AW(fpsr);
	oucp->uc_extra.pfpfr = AW(pfpfr);
	LBL_USR_PFAULT("lbl_save_ctx_64_bit", "3:");
	if (END_USR_PFAULT)
		ret = -EFAULT;

	return ret;
}

static int save_ctx_128_bit(struct ucontext_prot __user *oucp)
{
	struct pt_regs *regs;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	int ret = 0;

	regs = current_thread_info()->pt_regs;
	E2K_GET_FPU(AW(fpcr), AW(fpsr), AW(pfpfr));
	if (!access_ok(ACCESS_WRITE, oucp, sizeof(*oucp)))
		return -EFAULT;
	BEGIN_USR_PFAULT("lbl_save_ctx_128_bit", "4f");
	*((u64 *) &oucp->uc_sigmask) = current->blocked.sig[0];
	oucp->uc_mcontext.sbr = context_ti_key(current_thread_info());
	oucp->uc_mcontext.cr0_hi = AW(regs->crs.cr0_hi);
	oucp->uc_mcontext.cr1_lo = AW(regs->crs.cr1_lo);
	oucp->uc_mcontext.cr1_hi = AW(regs->crs.cr1_hi);
	oucp->uc_mcontext.pcsp_lo = AW(regs->stacks.pcsp_lo);
	oucp->uc_mcontext.pcsp_hi = AW(regs->stacks.pcsp_hi);
	oucp->uc_extra.fpcr = AW(fpcr);
	oucp->uc_extra.fpsr = AW(fpsr);
	oucp->uc_extra.pfpfr = AW(pfpfr);
	LBL_USR_PFAULT("lbl_save_ctx_128_bit", "4:");
	if (END_USR_PFAULT)
		ret = -EFAULT;

	return ret;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
inline int do_swapcontext(void __user *oucp, const void __user *ucp,
		bool save_prev_ctx, int format)
{
	u64 next_key, prev_key, sigset;
	int next_index, prev_index;
	struct list_head *hb;
	struct hw_context *next_ctx, *prev_ctx;
	mm_context_t *mm_context = &current->mm->context;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	struct pt_regs *regs;
	int ret;

	DebugCTX("oucp=%lx ucp=%lx started\n", oucp, ucp);

	BUILD_BUG_ON(sizeof(current->blocked.sig[0]) != 8);
	if (save_prev_ctx) {
		if (format == CTX_32_BIT) {
			ret = save_ctx_32_bit(
					(struct ucontext_32 __user *) oucp);
		} else if (format == CTX_64_BIT) {
			ret = save_ctx_64_bit((struct ucontext __user *) oucp);
		} else {
			/* CTX_128_BIT */
			ret = save_ctx_128_bit(
					(struct ucontext_prot __user *) oucp);
		}
		if (ret)
			return -EFAULT;
	}

	if (format == CTX_32_BIT) {
		const struct ucontext_32 __user *_ucp = ucp;
		if (!access_ok(ACCESS_READ, _ucp, sizeof(*_ucp)))
			return -EFAULT;
		ret = __get_user(next_key, &_ucp->uc_mcontext.sbr);
		ret |= __get_user(AW(fpcr), &_ucp->uc_extra.fpcr);
		ret |= __get_user(AW(fpsr), &_ucp->uc_extra.fpsr);
		ret |= __get_user(AW(pfpfr), &_ucp->uc_extra.pfpfr);
	} else if (format == CTX_64_BIT) {
		const struct ucontext __user *_ucp = ucp;
		if (!access_ok(ACCESS_READ, _ucp, sizeof(*_ucp)))
			return -EFAULT;
		ret = __get_user(next_key, &_ucp->uc_mcontext.sbr);
		ret |= __get_user(AW(fpcr), &_ucp->uc_extra.fpcr);
		ret |= __get_user(AW(fpsr), &_ucp->uc_extra.fpsr);
		ret |= __get_user(AW(pfpfr), &_ucp->uc_extra.pfpfr);
	} else {
		/* CTX_128_BIT */
		const struct ucontext_prot __user *_ucp = ucp;
		if (!access_ok(ACCESS_READ, _ucp, sizeof(*_ucp)))
			return -EFAULT;
		ret = __get_user(next_key, &_ucp->uc_mcontext.sbr);
		ret |= __get_user(AW(fpcr), &_ucp->uc_extra.fpcr);
		ret |= __get_user(AW(fpsr), &_ucp->uc_extra.fpsr);
		ret |= __get_user(AW(pfpfr), &_ucp->uc_extra.pfpfr);
	}
	if (ret)
		return -EFAULT;

	prev_key = context_ti_key(current_thread_info());

	DebugCTX("prev_key %lx, next_key %lx\n",
			prev_key, next_key);

	next_index = key2index(next_key);
	prev_index = key2index(prev_key);

	/*
	 * If this is the first time this thread is changing contexts
	 * we'll have to allocate memory for the main context.
	 */
	if (likely(current_thread_info()->main_context_saved)) {
		prev_ctx = NULL;
	} else {
		DebugCTX("will save main context (%d)\n",
			current_thread_info()->main_context_saved);
		prev_ctx = alloc_hw_context(true,
				current_thread_info()->u_stk_sz);
		if (!prev_ctx)
			return -ENOMEM;

		if (save_prev_ctx) {
			if (format == CTX_32_BIT) {
				ret = put_user(prev_key,
					&((struct ucontext_32 __user *)
						oucp)->uc_mcontext.sbr);
			} else if (format == CTX_64_BIT) {
				ret = put_user(prev_key,
					&((struct ucontext __user *)
						oucp)->uc_mcontext.sbr);
			} else {
				/* CTX_128_BIT */
				ret = put_user(prev_key,
					&((struct ucontext_prot __user *)
						oucp)->uc_mcontext.sbr);
			}
			if (ret) {
				free_hw_context(prev_ctx, true, false);
				return -EFAULT;
			}
		}

		if (format == CTX_32_BIT) {
			prev_ctx->p_uc_link =
					&((struct ucontext_32 __user *)
							oucp)->uc_link;
			prev_ctx->ptr_format = CTX_32_BIT;
		} else if (format == CTX_64_BIT) {
			prev_ctx->p_uc_link = &((struct ucontext __user *)
							oucp)->uc_link;
			prev_ctx->ptr_format = CTX_64_BIT;
		} else {
			/* CTX_128_BIT */
			prev_ctx->p_uc_link =
					&((struct ucontext_prot __user *)
							oucp)->uc_link;
			prev_ctx->ptr_format = CTX_128_BIT;
		}
	}

	/*
	 * Do the switch
	 */
	spin_lock(&mm_context->hw_context_lock);

	hb = &mm_context->hw_contexts[prev_index];

	/*
	 * Find the next context
	 */
	next_ctx = key2hw_context(next_key, next_index, mm_context,
			false);
	if (!next_ctx) {
		spin_unlock(&mm_context->hw_context_lock);
		if (!current_thread_info()->main_context_saved)
			free_hw_context(prev_ctx, true, false);
		return -ESRCH;
	}

	if (likely(current_thread_info()->main_context_saved)) {
		prev_ctx = key2hw_context(prev_key, prev_index,
				mm_context, true);
		DebugCTX("ctx %lx found\n", prev_ctx);
		BUG_ON(!prev_ctx);
	} else {
		list_add(&prev_ctx->list_entry, hb);
#ifndef CONFIG_FUNCTION_GRAPH_TRACER
		current_thread_info()->main_context_saved = true;
#endif
	}

	DebugCTX("switching from ctx %lx to ctx %lx\n",
		prev_ctx, next_ctx);
	current_thread_info()->prev_ctx = prev_ctx;
	current_thread_info()->next_ctx = next_ctx;
	current_thread_info()->ucp = ucp;
	(void) switch_hw_contexts(prev_ctx, next_ctx,
			AW(fpcr), AW(fpsr), AW(pfpfr));
	prev_ctx = current_thread_info()->prev_ctx;
	next_ctx = current_thread_info()->next_ctx;
	ucp = current_thread_info()->ucp;

	if (current_thread_info()->free_hw_context)
		list_del(&prev_ctx->list_entry);

	spin_unlock(&mm_context->hw_context_lock);

	if (current_thread_info()->free_hw_context) {
		current_thread_info()->free_hw_context = false;
		free_hw_context(prev_ctx, false, false);
	}

	regs = current_thread_info()->pt_regs;

	/*
	 * Read sigmask and stack parameters
	 */
	if (format == CTX_32_BIT) {
		const struct ucontext_32 __user *_ucp = ucp;
		ret = __get_user(sigset, (u64 *) &_ucp->uc_sigmask);
		ret |= __get_user(AW(pcsp_lo),
				(u64 *) &_ucp->uc_mcontext.pcsp_lo);
		ret |= __get_user(AW(pcsp_hi),
				(u64 *) &_ucp->uc_mcontext.pcsp_hi);
		ret |= __get_user(AW(cr0_hi), &_ucp->uc_mcontext.cr0_hi);
	} else if (format == CTX_64_BIT) {
		const struct ucontext __user *_ucp = ucp;
		ret = __get_user(sigset, (u64 *) &_ucp->uc_sigmask);
		ret |= __get_user(AW(pcsp_lo),
				(u64 *) &_ucp->uc_mcontext.pcsp_lo);
		ret |= __get_user(AW(pcsp_hi),
				(u64 *) &_ucp->uc_mcontext.pcsp_hi);
		ret |= __get_user(AW(cr0_hi), &_ucp->uc_mcontext.cr0_hi);
	} else {
		/* CTX_128_BIT */
		const struct ucontext_prot __user *_ucp = ucp;
		ret = __get_user(sigset, (u64 *) &_ucp->uc_sigmask);
		ret |= __get_user(AW(pcsp_lo),
				(u64 *) &_ucp->uc_mcontext.pcsp_lo);
		ret |= __get_user(AW(pcsp_hi),
				(u64 *) &_ucp->uc_mcontext.pcsp_hi);
		ret |= __get_user(AW(cr0_hi), &_ucp->uc_mcontext.cr0_hi);
	}
	if (ret)
		return -EFAULT;

	/*
	 * Do we need to jump backwards in the new context?
	 */
	if (AS(regs->stacks.pcsp_lo).base + AS(regs->stacks.pcsp_hi).size
			!= AS(pcsp_lo).base + AS(pcsp_hi).size
			|| AW(cr0_hi) != AW(regs->crs.cr0_hi)) {
		e2k_cr1_lo_t cr1_lo;
		e2k_cr1_hi_t cr1_hi;

		if (format == CTX_32_BIT) {
			const struct ucontext_32 __user *_ucp = ucp;
			ret = __get_user(AW(cr1_lo),
					&_ucp->uc_mcontext.cr1_lo);
			ret |= __get_user(AW(cr1_hi),
					&_ucp->uc_mcontext.cr1_hi);
		} else if (format == CTX_64_BIT) {
			const struct ucontext __user *_ucp = ucp;
			ret = __get_user(AW(cr1_lo),
					&_ucp->uc_mcontext.cr1_lo);
			ret |= __get_user(AW(cr1_hi),
					&_ucp->uc_mcontext.cr1_hi);
		} else {
			/* CTX_128_BIT */
			const struct ucontext_prot __user *_ucp = ucp;
			ret = __get_user(AW(cr1_lo),
					&_ucp->uc_mcontext.cr1_lo);
			ret |= __get_user(AW(cr1_hi),
					&_ucp->uc_mcontext.cr1_hi);
		}
		if (ret)
			return -EFAULT;

		/* A hack to make do_longjmp() restore
		 * blocked signals mask */
		sigset |= sigmask(SIGKILL);

		DebugCTX("calling longjmp\n");
		do_longjmp(0, sigset, cr0_hi, cr1_lo, pcsp_lo, pcsp_hi,
				AS(cr1_hi).br,
				0, 0, 0, 0);

		return HW_CONTEXT_NEW_STACKS;
	}

	current->blocked.sig[0] = sigset & _BLOCKABLE;

	return 0;
}

int sys_swapcontext(struct ucontext __user *oucp,
		const struct ucontext __user *ucp,
		int sigsetsize)
{
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	return do_swapcontext(oucp, ucp, true, CTX_64_BIT);
}

#ifdef CONFIG_COMPAT
int compat_sys_swapcontext(struct ucontext_32 __user *oucp,
		const struct ucontext_32 __user *ucp, int sigsetsize)
{
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	return do_swapcontext(oucp, ucp, true, CTX_32_BIT);
}
#endif

#ifdef CONFIG_PROTECTED_MODE
int protected_sys_swapcontext(struct ucontext_prot __user *oucp,
		const struct ucontext_prot __user *ucp, int sigsetsize)
{
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	return do_swapcontext(oucp, ucp, true, CTX_128_BIT);
}
#endif

void machine_restart(char * __unused)
{
	DebugP("machine_restart entered.\n");
        
	if (machine.restart != NULL)
		machine.restart(__unused);

	DebugP("machine_restart exited.\n");
}

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
void default_idle(void)
{
	if (psr_and_upsr_irqs_disabled())
		local_irq_enable();

	/* loop is done by the caller */
	cpu_relax();
}
EXPORT_SYMBOL(default_idle);

#ifdef CONFIG_HOTPLUG_CPU
/* We take CLK off on CPU on ES2 due we have hw support for it,
 * on other e2k machines we don't actually take CPU down,
 * just spin without interrupts. */
void arch_cpu_idle_dead(void)
{
	unsigned int this_cpu = raw_smp_processor_id();

	raw_local_irq_disable();

	/* Ack it for __cpu_die() */
	__this_cpu_write(cpu_state, CPU_DEAD);

	/* idle_task_exit(); - we do not leave idle task,
	 * and do not create new one, as we use common hw stack.
	 */


	/* Busy loop inside, waiting for bit in callin_go mask.
	 * For ES2 there is opportunity to switch off the CLK also.
	 */
	e2k_up_secondary(this_cpu);

	/*
	 * We are here after __cpu_up. Now we are going back to cpu_idle.
	 */
	raw_local_irq_enable();
}
#endif /* CONFIG_HOTPLUG_CPU */

void arch_cpu_idle_enter()
{
	/* It works under CONFIG_PROFILING flag only */
	cpu_idle_time();
}

void arch_cpu_idle_exit()
{
	/* It works under CONFIG_PROFILING flag only */
	calculate_cpu_idle_time();
}

void arch_cpu_idle()
{
	if (cpuidle_idle_call())
		default_idle();
}

void flush_thread(void)
{
	DebugP("flush_thread entered.\n");
	DebugP("flush_thread exited.\n");
}

int dump_fpu( struct pt_regs *regs, void *fpu )
{
	DebugP("dump_fpu entered.\n");
	DebugP("dump_fpu exited.\n");

	return 0;
}

unsigned long
thread_saved_pc(struct task_struct *task)
{
	// ????
	return AS_STRUCT(task->thread.sw_regs.cr0_hi).ip << 3;
}

