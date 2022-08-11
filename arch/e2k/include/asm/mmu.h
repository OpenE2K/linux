/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

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
#include <linux/refcount.h>
#include <linux/rhashtable-types.h>
#include <linux/uaccess.h>

#include <asm/mmu_types.h>
#include <asm/umalloc.h>
#include <asm/e2k_api.h>
#include <asm/protected_mode.h>


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

struct hw_context {
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
		data_stack_t	u_stack;	/* User data stack info */
		hw_stack_t	u_hw_stack;	/* User hardware stacks info */
		struct list_head	getsp_adj;
		struct list_head	old_u_pcs_list;
#ifdef CONFIG_PROTECTED_MODE
		global_store_t	*g_list;
		e2k_addr_t      multithread_address;
		struct rw_semaphore *lock;
#endif /* CONFIG_PROTECTED_MODE */
		struct signal_stack signal_stack;
	} ti;

	/* Pointer to the corresponding user context */
	void __user *ucp;
	/* Pointer to the next context to run */
	void __user	*p_uc_link;
	enum hw_context_fmt ptr_format;

	/* Used to free in a separate context (for better performance) */
	struct rcu_head rcu_head;
	struct work_struct work;
	struct mm_struct *mm;
} ____cacheline_aligned_in_smp;

#ifdef CONFIG_PROTECTED_MODE
	/*
	 * The list below is used to restore descriptors from pointers
	 * when kernel needs to pass a descriptor back to user protected space.
	 * The list stores pointer/descriptor pairs with some extra info if any.
	 * When kernel need to pass a descriptor to a signal handler operating
	 * in the protected mode, it looks for the given pointer in the list,
	 * and gets the descriptor it correcponds to if available.
	 */
struct sival_ptr_list {
	struct list_head link; /* connects links into the list */
	void __user *kernel_ptr;
	unsigned long long int user_ptr_lo;
	unsigned long long int user_ptr_hi;
	unsigned char user_tags;
	unsigned int  signum;	/* mq_notify needs keeping a single pointer
				 * for a particular registered signal
				 */
};
#endif

typedef struct {
	unsigned long	cpumsk[NR_CPUS];
	atomic_t	cur_cui;	/* first free cui */
	atomic_t	tstart;		/* first free type for TSD */
	int		tcount;

	/*
	 * Bit array for saving the information about
	 * busy and free entries in cut
	 */
	DECLARE_BITMAP(cut_mask, USER_CUT_AREA_SIZE/sizeof(e2k_cute_t));
	/*
	 * Mutex lock for protecting of cut_mask
	 */
	struct mutex cut_mask_lock;

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
	allpools_t		umpools;
	struct list_head	sival_ptr_list_head;
	struct rw_semaphore	sival_ptr_list_sem;
	/* The field below controls different debug/error output
	 * purposed to support porting libraries to protected mode:
	 */
	unsigned long		pm_sc_debug_mode;
	/* Controls extra info and issues identified by kernel to journal.
	 * Use command 'dmesg' to display these messages.
	 * For particular controls see:
	 *                      arch/e2k/include/uapi/asm/protected_mode.h
	 */
#endif /* CONFIG_PROTECTED_MODE */

	/* List of cached user hardware stacks */
	struct list_head cached_stacks;
	spinlock_t cached_stacks_lock;
	size_t cached_stacks_size;
} mm_context_t;


/* Version for fast syscalls, so it must be inlined.
 * Must be used only for current. */
static inline u64 context_ti_key_fast_syscall(const struct thread_info *ti)
{
	struct pt_regs __user *u_regs = __signal_pt_regs_last(ti);

	if (u_regs)
		return u_regs->stacks.top;

	return ti->u_stack.top;
}

extern long hw_context_lookup_pcsp_and_switch(e2k_pcsp_lo_t pcsp_lo,
		e2k_usd_lo_t usd_lo);
extern int hw_contexts_init(struct task_struct *p, mm_context_t *mm_context,
		bool is_fork);
extern void hw_contexts_destroy(mm_context_t *mm_context);
extern long swapcontext(const void __user *ucp, int format);
extern void makecontext_trampoline(void);
extern void makecontext_trampoline_protected(void);
extern void makecontext_trampoline_continue(void);
extern void hw_context_deactivate_mm(struct task_struct *dead_task);

struct ucontext;
extern long sys_setcontext(const struct ucontext __user *ucp,
		int sigsetsize);
extern long sys_makecontext(struct ucontext __user *ucp, void (*func)(void),
		u64 args_size, void __user *args, int sigsetsize);
extern long sys_freecontext(struct ucontext __user *ucp);
extern long sys_swapcontext(struct ucontext __user *oucp,
		const struct ucontext __user *ucp, int sigsetsize);
#ifdef CONFIG_COMPAT
struct ucontext_32;
extern long compat_sys_setcontext(const struct ucontext_32 __user *ucp,
		int sigsetsize);
extern long compat_sys_makecontext(struct ucontext_32 __user *ucp,
		void (*func)(void), u64 args_size, void __user *args,
		int sigsetsize);
extern long compat_sys_freecontext(struct ucontext_32 __user *ucp);
extern long compat_sys_swapcontext(struct ucontext_32 __user *oucp,
		const struct ucontext_32 __user *ucp, int sigsetsize);
#endif
#ifdef CONFIG_PROTECTED_MODE
struct ucontext_prot;
extern long protected_sys_setcontext(
		const struct ucontext_prot __user *ucp,
		int sigsetsize);
extern long protected_sys_makecontext(struct ucontext_prot __user *ucp,
		void (*func)(void), u64 args_size, void __user *args,
		int sigsetsize);
extern long protected_sys_freecontext(struct ucontext_prot __user *ucp);
extern long protected_sys_swapcontext(struct ucontext_prot __user *oucp,
		const struct ucontext_prot __user *ucp, int sigsetsize);
#endif

struct vm_userfaultfd_ctx;
extern unsigned long mremap_to(unsigned long addr, unsigned long old_len,
		unsigned long new_addr, unsigned long new_len, bool *locked,
		struct vm_userfaultfd_ctx *uf, struct list_head *uf_unmap_early,
		struct list_head *uf_unmap);

#endif /* _E2K_MMU_H_ */
