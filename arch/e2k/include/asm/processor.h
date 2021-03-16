/*
 * include/asm-e2k/processor.h
 *
 * Copyright (C) 2001 MCST 
 */

#ifndef _E2K_PROCESSOR_H_
#define _E2K_PROCESSOR_H_
#ifndef __ASSEMBLY__

#include <linux/threads.h>
#include <linux/init.h>

#include <asm/atomic.h>
#include <asm/hw_breakpoint.h>
#include <asm/cpu_regs_types.h>
#include <asm/types.h>
#include <asm/ptrace.h>
#include <asm/pv_info.h>


/* We want to use OSGD for fast access to task_struct */
#define ARCH_MIN_TASKALIGN E2K_ALIGN_GLOBALS_SZ

/*
 * CPU type, hardware bug flags, and per-CPU state.
 */
typedef struct cpuinfo_e2k {
	__u8 family;
	__u8 model;
	__u8 revision;
	char vendor[16];
	__u64 proc_freq;	/* frequency of processor */
#ifdef CONFIG_SMP
	int cpu;
	__u64 mmu_last_context;
	__u64 ipi_count;
#endif
} cpuinfo_e2k_t;

extern	cpuinfo_e2k_t	cpu_data[NR_CPUS];

#define my_cpu_data1(num_cpu) cpu_data[num_cpu]

#define my_cpu_data	cpu_data[smp_processor_id()]
#define raw_my_cpu_data	cpu_data[raw_smp_processor_id()]

#define STACK_TOP (current->thread.flags & E2K_FLAG_32BIT ? \
		   USER32_STACK_TOP : USER64_STACK_TOP)
#define STACK_TOP_MAX		USER64_STACK_TOP

#define HAVE_ARCH_PICK_MMAP_LAYOUT
#define	HAVE_ARCH_UNMAPPED_AREA

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE \
	PAGE_ALIGN((current->thread.flags & \
		    (E2K_FLAG_32BIT | E2K_FLAG_PROTECTED_MODE)) ? \
				(TASK32_SIZE / 3) : (TASK_SIZE / 3))

/*
 * Size of io_bitmap in longwords: 32 is ports 0-0x3ff.
 */
#define IO_BITMAP_SIZE	32
#define IO_BITMAP_OFFSET offsetof(struct tss_struct,io_bitmap)
#define INVALID_IO_BITMAP_OFFSET 0x8000

typedef struct thread_struct {
#ifndef CONFIG_CPU_HAS_FILL_INSTRUCTION
	/* Used as a temporary area */
	struct {
		e2k_cr0_hi_t cr0_hi;
		e2k_cr1_lo_t cr1_lo;
		e2k_cr1_hi_t cr1_hi;
		e2k_psp_lo_t u_psp_lo;
		e2k_psp_hi_t u_psp_hi;
		e2k_pcsp_lo_t u_pcsp_lo;
		e2k_pcsp_hi_t u_pcsp_hi;
		int from;
		bool return_to_user;
# if defined(CONFIG_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
		bool from_paravirt_guest;
# endif
	} fill;
#endif
	u32		context;	/* context of running process	     */
	struct sw_regs	sw_regs;	/* switch regs                       */

	struct {
		struct {
			e2k_dibcr_t	dibcr;
			u64		dibar0;
			u64		dibar1;
			u64		dibar2;
			u64		dibar3;
			e2k_ddbcr_t	ddbcr;
			u64		ddbar0;
			u64		ddbar1;
			u64		ddbar2;
			u64		ddbar3;
		} regs;
		/* user breakpoints set via ptrace */
		struct perf_event *hbp_data[HBP_NUM];
		struct perf_event *hbp_instr[HBP_NUM];
	} debug;

	/* Used by an old implementation of C3 sleep state */
	struct {
		e2k_dibcr_t dibcr;
		e2k_ddbcr_t ddbcr;
		e2k_dimcr_t dimcr;
		e2k_ddmcr_t ddmcr;
	} C3;

	unsigned long	flags;		/* various flags (e.g. for mmap)     */
} thread_t;
#endif /* !__ASSEMBLY__ */

/*
 * Thread flags
 */
#define E2K_FLAG_32BIT		0x01	/* task is older 32-bit binary       */
#define E2K_FLAG_PROTECTED_MODE	0x02	/* task is running in protected mode */
#define E2K_FLAG_BIN_COMP_CODE	0x04	/* task is binary compiler code      */
#define PRINT_FUNCY_STACK_WORKS_BIT 3	/* do print_stack		     */
#define PRINT_FUNCY_STACK_WORKS	\
	(1UL << PRINT_FUNCY_STACK_WORKS_BIT) /* 0x08 */
#define E2K_FLAG_PRINT_ALL_TASK	0x10	/* do print_stack		     */
#define PRINT_STACK_WORKS	0x20	/* do print_stack		     */
#define E2K_FLAG_64BIT_BINCO	0x40	/* 32-bit binco is running 64-bit x86 */
#define E2K_FLAG_3P_ELF32	0x80	/* can be removed when only elf64 3P */
					/* is supported                      */

/*
 * Various task info flags (is common for host and guest task)
 * See last 'flags' argument of function switch_to_new_user() and
 * same as field 'flags' of structure kvm_task_info_t (asm/kvm/hypervisor.h)
 */
#define	BIN_32_CODE_TASK_FLAG_BIT	2	/* task is 32-bit binary */
						/* application */
#define	PROTECTED_CODE_TASK_FLAG_BIT	3	/* task is running in */
						/* protected mode */
#define	BIN_COMP_CODE_TASK_FLAG_BIT	4	/* task is binary application */
						/* compiler code */
#define	DO_PRESENT_HW_STACKS_TASK_FLAG_BIT 8	/* hardware stacks should be */
						/* made present (populated) */
#define	DO_LOCK_HW_STACKS_TASK_FLAG_BIT	9	/* hardware stacks should be */
						/* locked */
#define	PS_HAS_NOT_GUARD_PAGE_TASK_BIT	12	/* hardware procedure stack */
						/* has not extra guard page */
#define	PCS_HAS_NOT_GUARD_PAGE_TASK_BIT	13	/* hardware chain stack */
						/* has not extra guard page */
#define SWITCH_TO_COMPLETE_TASK_BIT	14	/* switch to kernel hardware */
						/* stacks to complete task */
						/* else to change user stacks */
						/* and return to them */
#define	RETURN_TO_USER_STACKS_TASK_BIT	15	/* return to user hardware */
						/* stacks, else switch to */
						/* kernel stacks */

#define BIN_32_CODE_TASK_FLAG		(1UL << BIN_32_CODE_TASK_FLAG_BIT)
#define BIN_COMP_CODE_TASK_FLAG		(1UL << BIN_COMP_CODE_TASK_FLAG_BIT)
#define PROTECTED_CODE_TASK_FLAG	(1UL << PROTECTED_CODE_TASK_FLAG_BIT)
#define DO_PRESENT_HW_STACKS_TASK_FLAG	\
		(1UL << DO_PRESENT_HW_STACKS_TASK_FLAG_BIT)
#define DO_LOCK_HW_STACKS_TASK_FLAG	\
		(1UL << DO_LOCK_HW_STACKS_TASK_FLAG_BIT)
#define	PS_HAS_NOT_GUARD_PAGE_TASK_FLAG	\
		(1UL << PS_HAS_NOT_GUARD_PAGE_TASK_BIT)
#define	PCS_HAS_NOT_GUARD_PAGE_TASK_FLAG	\
		(1UL << PCS_HAS_NOT_GUARD_PAGE_TASK_BIT)
#define SWITCH_TO_COMPLETE_TASK_FLAG	(1UL << SWITCH_TO_COMPLETE_TASK_BIT)
#define	RETURN_TO_USER_STACKS_TASK_FLAG	(1UL << RETURN_TO_USER_STACKS_TASK_BIT)

#ifndef __ASSEMBLY__

#define K_STK_BASE(thr)		((thr)->k_stk_base)
#define K_STK_TOP(thr)		((thr)->k_stk_base + KERNEL_C_STACK_SIZE)


#define INIT_THREAD { 0 }

#define INIT_MMAP \
{ &init_mm, 0, 0, NULL, PAGE_SHARED, VM_READ | VM_WRITE | VM_EXEC, 1, NULL, NULL }

extern void start_thread(struct pt_regs *regs,
			unsigned long entry, unsigned long sp);
extern int native_do_prepare_start_thread_frames(unsigned long entry,
							unsigned long sp);
extern long do_sys_execve(unsigned long entry, unsigned long sp, int kernel);

/* Forward declaration, a strange C thing */
struct task_struct;
struct mm_struct;

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);
/*
 * create a kernel thread without removing it from tasklists
 */
extern int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags);

extern void thread_init(void);

/*
 * Prepare to copy thread state - unlazy all lazy status
 */
#define prepare_to_copy(tsk)	do { } while (0)

/* Copy and release all segment info associated with a VM */

#define copy_segments(tsk, mm)		do { } while (0)  /* We don't have   */
#define release_segments(mm)		do { } while (0)  /* segments on E2K */

extern unsigned long	boot_option_idle_override;
extern unsigned long	idle_halt;
extern void		native_default_idle(void);
extern bool		idle_nomwait;

unsigned long get_wchan(struct task_struct *p);
#define	KSTK_EIP(tsk)							\
({									\
	struct pt_regs *pt_regs = task_thread_info(tsk)->pt_regs;	\
	(pt_regs) ?							\
		(unsigned long)AS_STRUCT(pt_regs->crs.cr0_hi).ip << 3 :	\
		0UL;							\
})
#define	KSTK_ESP(tsk)							\
({									\
	struct pt_regs *pt_regs = task_thread_info(tsk)->pt_regs;	\
	(pt_regs) ? AS_STRUCT(pt_regs->stacks.usd_lo).base :		\
				task_thread_info(tsk)->u_stack.top;	\
})

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
# define TASK_IS_BINCO(tsk)	(tsk->thread.flags & E2K_FLAG_BIN_COMP_CODE)
#else
# define TASK_IS_BINCO(tsk)	0UL
#endif

#ifdef CONFIG_PROTECTED_MODE
# define TASK_IS_PROTECTED(tsk)	(tsk->thread.flags & E2K_FLAG_PROTECTED_MODE)
#else
# define TASK_IS_PROTECTED(tsk)	0UL
#endif

#define native_cpu_relax() \
	__asm__ __volatile__("{nop 7}" ::: "memory", PREEMPTION_CLOBBERS)
#define cpu_relax_lowlatency()		cpu_relax()
#define	native_cpu_relax_no_resched()	native_cpu_relax()

#define ARCH_HAS_PREFETCH
static inline void prefetch(const void *ptr)
{
	/* Use fully speculative load since ptr could be bad */
	E2K_PREFETCH_L1_SPEC(ptr);
}

#define ARCH_HAS_PREFETCHW
static inline void prefetchw(const void *ptr)
{
	/* prefetchw() is used when ptr is good, thus
	 * we can use half-speculative load */
	E2K_PREFETCH_L1(ptr);
}

#define prefetch_offset(ptr, offset) \
do { \
	/* Use fully speculative load since ptr could be bad */ \
	E2K_PREFETCH_L1_SPEC_OFFSET((ptr), (offset)); \
} while (0)

#define prefetchw_offset(ptr, offset) \
do { \
	E2K_PREFETCH_L2_OFFSET((ptr), (offset)); \
} while (0)

/*  Use L2 cache line size since we are prefetching to L2 */
#define PREFETCH_STRIDE 64

static __always_inline void prefetchw_range(const void *addr, size_t len)
{
#ifdef ARCH_HAS_PREFETCHW
	s64 i, rem, prefetched;

	if (__builtin_constant_p(len) && len < 24 * PREFETCH_STRIDE) {
		if (len > 0)
			prefetchw(addr);
		if (len > PREFETCH_STRIDE)
			prefetchw_offset(addr, PREFETCH_STRIDE);
		if (len > 2 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 2 * PREFETCH_STRIDE);
		if (len > 3 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 3 * PREFETCH_STRIDE);
		if (len > 4 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 4 * PREFETCH_STRIDE);
		if (len > 5 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 5 * PREFETCH_STRIDE);
		if (len > 6 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 6 * PREFETCH_STRIDE);
		if (len > 7 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 7 * PREFETCH_STRIDE);
		if (len > 8 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 8 * PREFETCH_STRIDE);
		if (len > 9 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 9 * PREFETCH_STRIDE);
		if (len > 10 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 10 * PREFETCH_STRIDE);
		if (len > 11 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 11 * PREFETCH_STRIDE);
		if (len > 12 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 12 * PREFETCH_STRIDE);
		if (len > 13 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 13 * PREFETCH_STRIDE);
		if (len > 14 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 14 * PREFETCH_STRIDE);
		if (len > 15 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 15 * PREFETCH_STRIDE);
		if (len > 16 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 16 * PREFETCH_STRIDE);
		if (len > 17 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 17 * PREFETCH_STRIDE);
		if (len > 18 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 18 * PREFETCH_STRIDE);
		if (len > 19 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 19 * PREFETCH_STRIDE);
		if (len > 20 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 20 * PREFETCH_STRIDE);
		if (len > 21 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 21 * PREFETCH_STRIDE);
		if (len > 22 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 22 * PREFETCH_STRIDE);
		if (len > 23 * PREFETCH_STRIDE)
			prefetchw_offset(addr, 23 * PREFETCH_STRIDE);

		return;
	}

	rem = len % (4 * PREFETCH_STRIDE);
	prefetched = len / (4 * PREFETCH_STRIDE);

	for (i = 0; i <= (s64) len - 256; i += 256)
		E2K_PREFETCH_L2_256(addr + i);

	if (rem > 0)
		prefetchw(addr + prefetched);
	if (rem > PREFETCH_STRIDE)
		prefetchw_offset(addr + prefetched, PREFETCH_STRIDE);
	if (rem > 2 * PREFETCH_STRIDE)
		prefetchw_offset(addr + prefetched, 2 * PREFETCH_STRIDE);
	if (rem > 3 * PREFETCH_STRIDE)
		prefetchw_offset(addr + prefetched, 3 * PREFETCH_STRIDE);
#endif
}

extern u64 cacheinfo_get_l1d_line_size(void);
extern void show_cacheinfo(struct seq_file *m);
extern int get_cpuinfo(char *buffer);
extern void native_print_machine_type_info(void);

#ifdef CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/processor.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* pure guest kernel (not paravirtualized) */
#include <asm/kvm/guest/processor.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */

#define	prepare_start_thread_frames(entry, sp)	\
		native_prepare_start_thread_frames(entry, sp)

#define	default_idle()		native_default_idle()
#define cpu_relax()		native_cpu_relax()
#define	cpu_relax_no_resched()	native_cpu_relax_no_resched()

static inline void
print_machine_type_info(void)
{
	native_print_machine_type_info();
}

#ifdef	CONFIG_VIRTUALIZATION
/* it is host kernel with virtualization support */
static inline void
paravirt_banner(void)
{
	printk(KERN_INFO "Booting host kernel with virtualization support\n");
}
#else	/* ! CONFIG_VIRTUALIZATION */
/* it is native kernel without any virtualization */
static inline void
paravirt_banner(void)
{
	printk(KERN_INFO "Booting native kernel without any virtualization "
		"support\n");
}
#endif	/* CONFIG_VIRTUALIZATION */
#endif	/* CONFIG_PARAVIRT */

#endif /* !__ASSEMBLY__ */

/*
 * If there are user pt_regs, return them.
 * Return the first kernel pt_regs otherwise.
 *
 * This way it should be compatible with all other architectures
 * which always return the first pt_regs structure.
 */
#define current_pt_regs() \
({ \
	struct pt_regs *__cpr_pt_regs = current_thread_info()->pt_regs; \
	if (__cpr_pt_regs) \
		__cpr_pt_regs = find_entry_regs(__cpr_pt_regs); \
	__cpr_pt_regs; \
})

#define task_pt_regs(task) \
({ \
	struct pt_regs *__tpr_pt_regs = task_thread_info(task)->pt_regs; \
	if (__tpr_pt_regs) \
		__tpr_pt_regs = find_entry_regs(__tpr_pt_regs); \
	__tpr_pt_regs; \
})

static inline int cpu_max_cores_num(void)
{
	if (IS_MACHINE_E1CP)
		return 1;
	else if (IS_MACHINE_ES2 || IS_MACHINE_E2C3)
		return 2;
	else if (IS_MACHINE_E2S)
		return 4;
	else if (IS_MACHINE_E8C || IS_MACHINE_E8C2)
		return 8;
	else if (IS_MACHINE_E12C)
		return 12;
	else if (IS_MACHINE_E16C)
		return 16;
	else
		BUG();
}

static inline bool range_includes(unsigned long addr1, size_t size1,
		unsigned long addr2, size_t size2)
{
	return addr2 >= addr1 && addr2 + size2 <= addr1 + size1;
}

static inline bool range_intersects(unsigned long addr1, size_t size1,
		unsigned long addr2, size_t size2)
{
	return addr1 + size1 > addr2 && addr2 + size2 > addr1;
}

#endif /* _E2K_PROCESSOR_H_ */
