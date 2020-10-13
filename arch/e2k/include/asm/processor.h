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
#include <asm/segment.h>
#include <asm/cpu_regs.h>
#include <asm/types.h>
#include <asm/ptrace.h>

/*
 * CPU type, hardware bug flags, and per-CPU state.
 */
typedef struct cpuinfo_e2k {
	e2k_addr_t *pgd_quick;
	e2k_addr_t *pud_quick;
	e2k_addr_t *pmd_quick;
	e2k_addr_t *pte_quick;
	__u32 pgtable_cache_sz;
	/* CPUID-derived information: */
	__u64 ppn;
	__u8 family;
	__u8 model;
	__u8 revision;
	char vendor[16];
	__u32 L1_size;
	__u32 L1_bytes;
	__u32 L2_size;
	__u32 L2_bytes;
	__u32 L3_size;
	__u32 L3_bytes;
	__u64 proc_freq;	/* frequency of processor */
#ifdef CONFIG_SMP
	int   cpu;
	__u64 loops_per_jiffy;
	__u64 mmu_last_context;
	__u64 ipi_count;
	__u64 prof_counter;
	__u64 prof_multiplier;
#endif
} cpuinfo_e2k_t;

extern	cpuinfo_e2k_t	cpu_data[NR_CPUS];

#ifdef CONFIG_L_LOCAL_APIC
/* Boot cpu frequency measured when calibrating LAPIC timer. */
extern u64 lapic_calibration_result_ticks;
#endif

#define my_cpu_data1(num_cpu) cpu_data[num_cpu]

#define my_cpu_data	cpu_data[smp_processor_id()]
#define raw_my_cpu_data	cpu_data[raw_smp_processor_id()]

/*
 * Default implementation of macro that returns current
 * instruction pointer ("program counter").
 */
#define current_text_addr() ({ __label__ __here; __here: &&__here; })

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
	u32		context;	/* context of running process	     */
	u32		intr_counter;	/* to check                          */
	struct sw_regs	sw_regs;	/* switch regs                       */
	u64		flags;		/* various flags (e.g. for mmap)     */
} thread_t;
#endif /* !__ASSEMBLY__ */

/*
 * Thread flags
 */
#define E_MMU_OP		0x01	/* execute_mmu_operations is working */
#define E_MMU_NESTED_OP		0x02	/* nested exception appeared while   */
					/* execute_mmu_operations is working */
#define E2K_FLAG_32BIT		0x04	/* task is older 32-bit binary       */
#define E2K_FLAG_PROTECTED_MODE	0x08	/* task is running in protected mode */
#define E2K_FLAG_BIN_COMP_CODE	0x10	/* task is binary compiler code      */
#define E2K_FLAG_PRINT_ALL_TASK	0x40	/* do print_stack          	     */
#define PRINT_FUNCY_STACK_WORKS	0x80	/* do print_stack          	     */
#define PRINT_STACK_WORKS	0x100	/* do print_stack          	     */
#define E2K_FLAG_64BIT_BINCO	0x200	/* 32-bit binco is running 64-bit x86 */
#define E2K_FLAG_3P_ELF32	0x800	/* can be removed when only elf64 3P */
					/* is supported                      */

#ifndef __ASSEMBLY__

#define K_STK_BASE(thr)		((thr)->k_stk_base)
#define K_STK_TOP(thr)		((thr)->k_stk_base + (thr)->k_stk_sz)


#define INIT_THREAD { 0 }

#define INIT_MMAP \
{ &init_mm, 0, 0, NULL, PAGE_SHARED, VM_READ | VM_WRITE | VM_EXEC, 1, NULL, NULL }

extern void start_thread(struct pt_regs * regs, unsigned long entry,
		unsigned long sp);

/* Forward declaration, a strange C thing */
struct task_struct;
struct mm_struct;

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);
/*
 * create a kernel thread without removing it from tasklists
 */
extern int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags);

extern void __init_recv thread_init(void);

/*
 * Prepare to copy thread state - unlazy all lazy status
 */
#define prepare_to_copy(tsk)	do { } while (0)

/* Copy and release all segment info associated with a VM */

#define copy_segments(tsk, mm)		do { } while (0)  /* We don't have   */
#define release_segments(mm)		do { } while (0)  /* segments on E2K */

/*
 * Return saved PC of a blocked thread.
 */
extern unsigned long thread_saved_pc(struct task_struct *t);

extern unsigned long	boot_option_idle_override;
extern unsigned long	idle_halt;
extern unsigned long	idle_nomwait;

unsigned long get_wchan(struct task_struct *p);
#define	KSTK_EIP(tsk)							\
({									\
	struct pt_regs *pt_regs = task_thread_info(tsk)->pt_regs;		\
	(pt_regs) ? AS_STRUCT(pt_regs->crs.cr0_hi).ip << 3 : 0;		\
})
#define	KSTK_ESP(tsk)							\
({									\
	struct pt_regs *pt_regs = task_thread_info(tsk)->pt_regs;		\
	(pt_regs) ? AS_STRUCT(pt_regs->stacks.usd_lo).base :		\
				task_thread_info(tsk)->u_stk_top;		\
})

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
# define TASK_IS_BINCO(tsk)	(tsk->thread.flags & E2K_FLAG_BIN_COMP_CODE)
#else
# define TASK_IS_BINCO(tsk)	false
#endif

#define cpu_relax() __asm__ __volatile__("{nop 7}" ::: IRQ_BARRIER_CLOBBERS)

#define ARCH_HAS_PREFETCH
static inline void prefetch(const void *ptr)
{
	/* Cannot use __builtin_prefetch() here since ptr could be NULL */
	E2K_PREFETCH_L2_SPEC(ptr);
}

#define ARCH_HAS_PREFETCHW
static inline void prefetchw(const void *ptr)
{
	__builtin_prefetch(ptr);
}

/*  Use L2 cache line size since we are prefetching to L2 */
#define PREFETCH_STRIDE 64

static __always_inline void prefetchw_range(void *addr, size_t len)
{
#ifdef ARCH_HAS_PREFETCHW
	size_t i, rem, prefetched;

	if (__builtin_constant_p(len) && len < 24 * PREFETCH_STRIDE) {
		if (len > 0)
			prefetchw(addr);
		if (len > PREFETCH_STRIDE)
			prefetchw(addr + PREFETCH_STRIDE);
		if (len > 2 * PREFETCH_STRIDE)
			prefetchw(addr + 2 * PREFETCH_STRIDE);
		if (len > 3 * PREFETCH_STRIDE)
			prefetchw(addr + 3 * PREFETCH_STRIDE);
		if (len > 4 * PREFETCH_STRIDE)
			prefetchw(addr + 4 * PREFETCH_STRIDE);
		if (len > 5 * PREFETCH_STRIDE)
			prefetchw(addr + 5 * PREFETCH_STRIDE);
		if (len > 6 * PREFETCH_STRIDE)
			prefetchw(addr + 6 * PREFETCH_STRIDE);
		if (len > 7 * PREFETCH_STRIDE)
			prefetchw(addr + 7 * PREFETCH_STRIDE);
		if (len > 8 * PREFETCH_STRIDE)
			prefetchw(addr + 8 * PREFETCH_STRIDE);
		if (len > 9 * PREFETCH_STRIDE)
			prefetchw(addr + 9 * PREFETCH_STRIDE);
		if (len > 10 * PREFETCH_STRIDE)
			prefetchw(addr + 10 * PREFETCH_STRIDE);
		if (len > 11 * PREFETCH_STRIDE)
			prefetchw(addr + 11 * PREFETCH_STRIDE);
		if (len > 12 * PREFETCH_STRIDE)
			prefetchw(addr + 12 * PREFETCH_STRIDE);
		if (len > 13 * PREFETCH_STRIDE)
			prefetchw(addr + 13 * PREFETCH_STRIDE);
		if (len > 14 * PREFETCH_STRIDE)
			prefetchw(addr + 14 * PREFETCH_STRIDE);
		if (len > 15 * PREFETCH_STRIDE)
			prefetchw(addr + 15 * PREFETCH_STRIDE);
		if (len > 16 * PREFETCH_STRIDE)
			prefetchw(addr + 16 * PREFETCH_STRIDE);
		if (len > 17 * PREFETCH_STRIDE)
			prefetchw(addr + 17 * PREFETCH_STRIDE);
		if (len > 18 * PREFETCH_STRIDE)
			prefetchw(addr + 18 * PREFETCH_STRIDE);
		if (len > 19 * PREFETCH_STRIDE)
			prefetchw(addr + 19 * PREFETCH_STRIDE);
		if (len > 20 * PREFETCH_STRIDE)
			prefetchw(addr + 20 * PREFETCH_STRIDE);
		if (len > 21 * PREFETCH_STRIDE)
			prefetchw(addr + 21 * PREFETCH_STRIDE);
		if (len > 22 * PREFETCH_STRIDE)
			prefetchw(addr + 22 * PREFETCH_STRIDE);
		if (len > 23 * PREFETCH_STRIDE)
			prefetchw(addr + 23 * PREFETCH_STRIDE);

		return;
	}

	for (i = 0; i <= len - 4 * PREFETCH_STRIDE; i += 4 * PREFETCH_STRIDE) {
		prefetchw(addr + i);
		prefetchw(addr + i + PREFETCH_STRIDE);
		prefetchw(addr + i + 2 * PREFETCH_STRIDE);
		prefetchw(addr + i + 3 * PREFETCH_STRIDE);
	}

	rem = len % (4 * PREFETCH_STRIDE);
	prefetched = len / (4 * PREFETCH_STRIDE);

	if (rem > 0)
		prefetchw(addr + prefetched);
	if (rem > PREFETCH_STRIDE)
		prefetchw(addr + prefetched + PREFETCH_STRIDE);
	if (rem > 2 * PREFETCH_STRIDE)
		prefetchw(addr + prefetched + 2 * PREFETCH_STRIDE);
	if (rem > 3 * PREFETCH_STRIDE)
		prefetchw(addr + prefetched + 3 * PREFETCH_STRIDE);
#endif
}



extern void print_cpu_info(cpuinfo_e2k_t *cpu_data);
extern int get_cpuinfo(char *buffer);
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

#endif /* _E2K_PROCESSOR_H_ */
