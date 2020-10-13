#ifndef _E2K_MMU_H_
#define _E2K_MMU_H_

#include <linux/threads.h>
#include <linux/list.h>
#include <asm/mmu_types.h>
#include <asm/umalloc.h>
#include <asm/e2k_api.h>


/*
 * For new contexts we return from do_switchcontext() straight to
 * hard_sys_calls(). This return value indicates to hard_syscalls()
 * that it should unlock the spinlock.
 */
#define HW_CONTEXT_TAIL 1
#define HW_CONTEXT_NEW_STACKS 1

extern void hw_context_tail(void);

#define HW_CONTEXT_HASHBITS 6

struct hw_context {
	struct list_head list_entry;

	bool in_use;

	e2k_cr0_lo_t cr0_lo;		/* chain info to recover */
	e2k_cr0_hi_t cr0_hi;		/* chain info to recover */
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;

	e2k_psp_lo_t psp_lo;		/* Procedure stack pointer: */
	e2k_psp_hi_t psp_hi;		/* base & index & size */
	e2k_pcsp_lo_t pcsp_lo;		/* Procedure chain stack */
	e2k_pcsp_hi_t pcsp_hi;		/* pointer: base & index & size */

	e2k_sbr_t k_sbr;		/* Stack base register: top of */
					/* local data (kernel) stack */
	e2k_usd_lo_t k_usd_lo;		/* Local data (kernel) stack */
	e2k_usd_hi_t k_usd_hi;		/* descriptor: base & size */

	unsigned long u_stk_top;

#ifdef CONFIG_GREGS_CONTEXT
	u64 gbase[E2K_MAXGR_d];
	u16 gext[E2K_MAXGR_d];
	u8 tag[E2K_MAXGR_d];
	/* Global registers rotation base */
	e2k_bgr_t bgr;
#endif

	/* Data from thread_info */
	struct {
		u64 hw_context_current;
		struct pt_regs	*pt_regs;
		e2k_usd_hi_t	k_usd_hi;
		e2k_addr_t	k_stk_base;
		e2k_size_t	k_stk_sz;
		e2k_usd_lo_t	k_usd_lo;
		e2k_upsr_t	upsr;
		u64		u_stk_base;
		u64		u_stk_sz;
		u64		u_stk_top;
		struct list_head	old_u_pcs_list;
		struct list_head	ps_list;
		struct hw_stack_area	*cur_ps;
		struct list_head	pcs_list;
		struct hw_stack_area	*cur_pcs;
		void		*ps_base;
		long		ps_size;
		long		ps_offset;
		long		ps_top;
		void		*pcs_base;
		long		pcs_size;
		long		pcs_offset;
		long		pcs_top;
		long		pusd_pil;
#ifdef CONFIG_PROTECTED_MODE
		global_store_t  *g_list;
		unsigned long	user_stack_addr;
		size_t		user_stack_size;
		e2k_addr_t      multithread_address;
		struct rw_semaphore *lock;
#endif /* CONFIG_PROTECTED_MODE */
	} ti;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/* Data from task_struct */
	struct {
		/* Index of current stored adress in ret_stack */
		int curr_ret_stack;
		/* Stack of return addresses for return function tracing */
		struct ftrace_ret_stack	*ret_stack;
		/* time stamp for last schedule */
		unsigned long long ftrace_timestamp;
		/*
		 * Number of functions that haven't been traced
		 * because of depth overrun.
		 */
		atomic_t trace_overrun;
		/* Pause for the tracing */
		atomic_t tracing_graph_pause;
	} task;
#endif

	/* Pointer to the next context to run */
	void __user	*p_uc_link;
	int ptr_format;
};

typedef struct {
	unsigned long	cpumsk[NR_CPUS];
	unsigned long	mmap_position;
	allpools_t	umpools;
	atomic_t	cur_cui;	/* first free cui */
	atomic_t	tstart;		/* first free type for TSD */
	int		tcount;

	/*
	 * For makecontext/swapcontext - a hash list of available contexts
	 */
	struct spinlock hw_context_lock;
	struct list_head hw_contexts[1 << HW_CONTEXT_HASHBITS];
	atomic64_t hw_context_last;
} mm_context_t;


enum {
	CTX_32_BIT,
	CTX_64_BIT,
	CTX_128_BIT
};

static inline u64 context_key(struct hw_context *ctx)
{
	return ctx->ti.hw_context_current;
}

/* NOTE: context_ti_key() is used from
 * fast syscalls so it must be inlined. */
static inline u64 context_ti_key(struct thread_info *ti)
{
	return ti->hw_context_current;
}

static inline void set_context_key(struct hw_context *ctx, u64 key)
{
	ctx->ti.hw_context_current = key;
}

static inline void set_context_ti_key(struct thread_info *ti, u64 key)
{
	ti->hw_context_current = key;
}

#define alloc_context_key(mm) \
	(atomic64_inc_return(&(mm)->context.hw_context_last))

static inline bool context_key_matches(u64 key, struct hw_context *ctx)
{
	return key == context_key(ctx);
}

static inline bool context_keys_equal(u64 key1, u64 key2)
{
	return key1 == key2;
}

extern inline int do_swapcontext(void __user *oucp, const void __user *ucp,
		bool save_prev_ctx, int format);

struct ucontext;
extern long sys_setcontext(const struct ucontext __user *ucp,
		int sigsetsize);
extern int sys_makecontext(struct ucontext __user *ucp, void (*func)(),
		u64 args_size, void __user *args, int sigsetsize);
extern int sys_freecontext(struct ucontext __user *ucp);
extern int sys_swapcontext(struct ucontext __user *oucp,
		const struct ucontext __user *ucp, int sigsetsize);
#ifdef CONFIG_COMPAT
struct ucontext_32;
extern long compat_sys_setcontext(const struct ucontext_32 __user *ucp,
		int sigsetsize);
extern int compat_sys_makecontext(struct ucontext_32 __user *ucp,
		void (*func)(), u64 args_size, void __user *args,
		int sigsetsize);
extern int compat_sys_freecontext(struct ucontext_32 __user *ucp);
extern int compat_sys_swapcontext(struct ucontext_32 __user *oucp,
		const struct ucontext_32 __user *ucp, int sigsetsize);
#endif
#ifdef CONFIG_PROTECTED_MODE
struct ucontext_prot;
extern long protected_sys_setcontext(
		const struct ucontext_prot __user *ucp,
		int sigsetsize);
extern int protected_sys_makecontext(struct ucontext_prot __user *ucp,
		void (*func)(), u64 args_size, void __user *args,
		int sigsetsize);
extern int protected_sys_freecontext(struct ucontext_prot __user *ucp);
extern int protected_sys_swapcontext(struct ucontext_prot __user *oucp,
		const struct ucontext_prot __user *ucp, int sigsetsize);
#endif

#endif /* _E2K_MMU_H_ */
