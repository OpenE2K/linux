/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_MMU_H_
#define _E2K_MMU_H_

#include <linux/hash.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/kvm_types.h>
#include <linux/rwsem.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/nodemask.h>
#include <linux/refcount.h>
#include <linux/rhashtable-types.h>

#include <asm/mmu_types.h>
#include <asm/umalloc.h>
#include <asm/e2k_api.h>
#include <asm/secondary_space.h>
#include <asm/protected_diag_msg_ids.h>

/* hw_context_lifetime.state possible values.
 * Actual values are important because we use atomic_inc/dec to switch states.
 * "state" field helps to avoid double use, and "alive" field helps to avoid
 * double free. */
enum {
	HWC_STATE_READY = 0U, /* The context is free to take */
	HWC_STATE_BUSY = 1U, /* A thread is currently executing on the context */
	HWC_STATE_COPYING = 2U /* The context is being copied in fork() */
};
#define HWC_STATE_SHIFT 0
#define HWC_ALIVE_BIAS (1U << 16)
union hw_context_lifetime {
	refcount_t refcount;
	struct {
		u16 state;
		u16 alive;
	};
};

enum hw_context_fmt {
	CTX_32_BIT,
	CTX_64_BIT,
	CTX_128_BIT
};

struct coroutine {
	u64 key; /* For finding this context in the hash table */
	struct rhash_head hash_entry;
	union hw_context_lifetime lifetime;

	struct {
		typeof_member(struct pt_regs, stacks) stacks;
		typeof_member(struct pt_regs, crs) crs;
		typeof_member(struct pt_regs, wd) wd;
		typeof_member(struct pt_regs, kernel_entry) kernel_entry;
	} regs;

	/* After user_hw_stacks_copy_full() there is one user frame
	 * left in kernel chain stack, it's contents are saved here. */
	e2k_mem_crs_t prev_crs;

	/* Data from thread_info */
	struct {
		struct data_stack u_stack;	/* User data stack info */
		hw_stack_t	u_hw_stack;	/* User hardware stacks info */
		struct list_head	getsp_adj;
		struct list_head	old_u_pcs_list;
		struct signal_stack signal_stack;
#define TIF_COROUTINES_SPECIFIC (_TIF_USD_NOT_EXPANDED)
		u64 switched_flags;
	} ti;

	enum hw_context_fmt ptr_format;

	/* Used to free in a separate context (for better performance) */
	struct rcu_head rcu_head;
	struct work_struct work;
	struct mm_struct *mm;
} ____cacheline_aligned_in_smp;


typedef struct {
#ifdef CONFIG_NUMA
	/* In !CONFIG_NUMA case we use mm->pgd as other architectures.
	 *
	 * In CONFIG_NUMA case we have per-node _kernel_ page tables
	 * (because kernel code and rodata sections are duplicated
	 * across all nodes) and so we have MAX_NUMNODES versions of
	 * pgd for each user application. If some node does not have
	 * memory it will use memory of a node with neighboring number:
	 * 0<-1, 0->1<-2 ... (n-1)->n<-(n+1) ... (nr_node_ids-1)->nr_node_ids
	 *
	 * Thus every pgd modification has to modify all these pgds
	 * but that's OK as pgds are modified extremely rarely.
	 *
	 * Note that in !MMU_IS_SEPARATE_PT() case we copy kernel PGDs
	 * to user (see pgd_ctor()), so these node_pgds() are needed for
	 * user mm too. In MMU_IS_SEPARATE_PT() case no additional pgds
	 * will be allocated besides the one in mm->pgd for user mm, so
	 * pgds_nodemask will have just one corresponding bit set. */
	pgd_t *node_pgds[MAX_NUMNODES];
	/* Has one bit set for every distinct entry in 'node_pgds'
	 * array (no duplicates here) */
	nodemask_t pgds_nodemask;
	/* Shows which pgd in 'node_pgds' corresponds to mm->pgd. */
	int mm_pgd_node;
# define for_each_node_mm_pgdmask(node, mm) \
		for_each_node_mask((node), (mm)->context.pgds_nodemask)
# define mm_node_pgd(mm, node) ((MMU_IS_SEPARATE_PT() && (mm) != &init_mm) ? \
			(void) (node), (mm)->pgd : (mm)->context.node_pgds[node])
# define kernel_duplicated_nodes_num() nodes_weight(init_mm.context.pgds_nodemask)
#else
# define for_each_node_mm_pgdmask(node, mm) for_each_node(node)
# define mm_node_pgd(mm, node) ((void) (node), (mm)->pgd)
#endif

	u64		cpumsk[NR_CPUS];
	atomic_t	cur_cui;	/* first free cui */
	atomic_t	tstart;		/* first free type for TSD */
	int		tcount;

	/*
	 * Address of user area with trampolines for signals and coroutines
	 */
	unsigned long trampolines;

	/*
	 * Bit array for saving the information about
	 * busy and free entries in cut
	 */
	DECLARE_BITMAP(cut_mask, USER_CUT_AREA_SIZE/sizeof(e2k_cute_t));
	/*
	 * Semaphore lock for protecting of cut_mask
	 */
	struct rw_semaphore cut_mask_lock;

	/*
	 * For makecontext/swapcontext - a hash list of available contexts
	 */
	struct rhashtable hw_contexts;

	/*
	 *  for multithreads coredump
	 *
	 * e2k arch has 3 stacks (2 hardware_stacks)
	 * for core file needed all stacks
	 * The threads must free pc & p stacks after finish_coredump
	 * The below structure are needed to delay free hardware_stacks
	 */
	struct list_head delay_free_stacks;
	struct rw_semaphore core_lock;
#ifdef CONFIG_PROTECTED_MODE
	/* The fields below controls different debug/error output
	 * purposed to support porting libraries to protected mode:
	 */
	unsigned long		pm_sc_debug_mode;
	/* Bit mask to register messages already delivered: */
	DECLARE_BITMAP(pm_sc_warned_once_msgs, PMSCERRMSG_NUMBER);
	/* Controls extra info and issues identified by kernel to journal.
	 * Use command 'dmesg' to display these messages.
	 * For particular controls see:
	 *                      arch/e2k/include/uapi/asm/protected_mode.h
	 */
	unsigned int		pm_sc_check4tags_max_size;
	unsigned int		pm_sc_unsafe_uint64_to_ptr_mode; /* options to the syscall */
#if IS_ENABLED(CONFIG_SOFT_PM)
	unsigned int		pm_soft_options_mask;
#endif /* CONFIG_SOFT_PM */
#endif /* CONFIG_PROTECTED_MODE */

	/* List of cached user hardware stacks */
	struct list_head cached_stacks;
	spinlock_t cached_stacks_lock;
	size_t cached_stacks_size;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	bin_comp_info_t	bincomp_info;	/* bin comp info */
#endif
} mm_context_t;

#define for_each_used_cui(cui, context) \
	for ((cui) = 0; \
	     (cui) < CUI_SIZE; \
	     (cui) = find_next_bit(&(context)->cut_mask[0], CUI_SIZE, (cui) + 1))

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
# define INIT_BIN_COMP_MM_CONTEXT \
	.bincomp_info.lock = __RW_LOCK_UNLOCKED(&mm.context.bincomp_info.lock),
#else
# define INIT_BIN_COMP_MM_CONTEXT
#endif

#ifdef CONFIG_NUMA
/* Initially all nodes use the same pgd, later duplicate_kernel_image()
 * will allocate and initialize all pgds properly. */
# define INIT_MM_CONTEXT_NUMA(mm) \
	.node_pgds[0 ... MAX_NUMNODES-1] = swapper_pg_dir,
#else
# define INIT_MM_CONTEXT_NUMA(mm)
#endif

#define INIT_MM_CONTEXT(mm) \
	.context = { \
		.cut_mask_lock = __RWSEM_INITIALIZER(mm.context.cut_mask_lock), \
		INIT_BIN_COMP_MM_CONTEXT \
		INIT_MM_CONTEXT_NUMA(mm) \
	} \

/* Version for fast syscalls. Must be used only for current. */
#define context_ti_key_fast_syscall(returned_key, ti) \
({ \
	struct pt_regs __priv *u_regs = __signal_pt_regs_last(ti); \
	int ret = 0; \
 \
	if (u_regs) { \
		u64 st_top; \
 \
		ret = get_priv_switched_pt(st_top, &u_regs->stacks.top, ti); \
		if (likely(!ret)) { \
			returned_key = st_top; \
		} else { \
			/* Fix uninitialized warning */ \
			returned_key = 0; \
		} \
	} else { \
		returned_key = ti->u_stack.top; \
	} \
 \
	ret; \
})

extern long coroutine_switch_and_longjmp(unsigned long pcsp_base,
		struct jmp_info *jmp_info, u64 retval);
extern int hw_contexts_init(struct task_struct *p, mm_context_t *mm_context,
		bool is_fork);
extern void hw_contexts_destroy(mm_context_t *mm_context);
extern void hw_context_deactivate_mm(struct task_struct *dead_task);

struct vm_userfaultfd_ctx;
unsigned long mremap_to(unsigned long addr, unsigned long old_len,
		unsigned long new_addr, unsigned long new_len, bool *locked,
		unsigned long flags, struct vm_userfaultfd_ctx *uf,
		struct list_head *uf_unmap_early,
		struct list_head *uf_unmap);
extern struct vm_area_struct *vma_to_resize(unsigned long addr,
	unsigned long old_len, unsigned long new_len, unsigned long flags);

#ifdef CONFIG_SEMI_SPEC_LOADS_INJECTION
extern void debug_inject_semi_spec_loads(bool check);
#else
static inline void debug_inject_semi_spec_loads(bool check) { }
#endif

#ifdef CONFIG_CLW_ENABLE
DECLARE_PER_CPU(bool, clw_enabled);
#endif

#endif /* _E2K_MMU_H_ */
