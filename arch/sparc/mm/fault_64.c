/*
 * arch/sparc64/mm/fault.c: Page fault handlers for the 64-bit Sparc.
 *
 * Copyright (C) 1996, 2008 David S. Miller (davem@davemloft.net)
 * Copyright (C) 1997, 1999 Jakub Jelinek (jj@ultra.linux.cz)
 */

#include <asm/head.h>

#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/interrupt.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/percpu.h>
#include <linux/context_tracking.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/openprom.h>
#include <asm/oplib.h>
#include <asm/uaccess.h>
#include <asm/asi.h>
#include <asm/lsu.h>
#include <asm/sections.h>
#include <asm/mmu_context.h>
#include <asm/irq.h>
#ifdef CONFIG_MCST_RT
#include <linux/sched/rt.h>
#endif

int show_unhandled_signals = 1;

static inline __kprobes int notify_page_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (kprobes_built_in() && !user_mode(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, 0))
			ret = 1;
		preempt_enable();
	}
	return ret;
}

static void __kprobes unhandled_fault(unsigned long address,
				      struct task_struct *tsk,
				      struct pt_regs *regs)
{
	if ((unsigned long) address < PAGE_SIZE) {
		printk(KERN_ALERT "Unable to handle kernel NULL "
		       "pointer dereference\n");
	} else {
		printk(KERN_ALERT "Unable to handle kernel paging request "
		       "at virtual address %016lx\n", (unsigned long)address);
	}
	printk(KERN_ALERT "tsk->{mm,active_mm}->context = %016lx\n",
	       (tsk->mm ?
		CTX_HWBITS(tsk->mm->context) :
		CTX_HWBITS(tsk->active_mm->context)));
	printk(KERN_ALERT "tsk->{mm,active_mm}->pgd = %016lx\n",
	       (tsk->mm ? (unsigned long) tsk->mm->pgd :
		          (unsigned long) tsk->active_mm->pgd));
	die_if_kernel("Oops", regs);
}

static void __kprobes bad_kernel_pc(struct pt_regs *regs, unsigned long vaddr)
{
	printk(KERN_CRIT "OOPS: Bogus kernel PC [%016lx] in fault handler\n",
	       regs->tpc);
	printk(KERN_CRIT "OOPS: RPC [%016lx]\n", regs->u_regs[15]);
	printk("OOPS: RPC <%pS>\n", (void *) regs->u_regs[15]);
	printk(KERN_CRIT "OOPS: Fault was to vaddr[%lx]\n", vaddr);
	dump_stack();
	unhandled_fault(regs->tpc, current, regs);
}

/*
 * We now make sure that mmap_sem is held in all paths that call 
 * this. Additionally, to prevent kswapd from ripping ptes from
 * under us, raise interrupts around the time that we look at the
 * pte, kswapd will have to wait to get his smp ipi response from
 * us. vmtruncate likewise. This saves us having to get pte lock.
 */
static unsigned int get_user_insn(unsigned long tpc)
{
	pgd_t *pgdp = pgd_offset(current->mm, tpc);
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep, pte;
	unsigned long pa;
	u32 insn = 0;

	if (pgd_none(*pgdp) || unlikely(pgd_bad(*pgdp)))
		goto out;
	pudp = pud_offset(pgdp, tpc);
	if (pud_none(*pudp) || unlikely(pud_bad(*pudp)))
		goto out;

	/* This disables preemption for us as well. */
	local_irq_disable();

	pmdp = pmd_offset(pudp, tpc);
	if (pmd_none(*pmdp) || unlikely(pmd_bad(*pmdp)))
		goto out_irq_enable;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (pmd_trans_huge(*pmdp)) {
		if (pmd_trans_splitting(*pmdp))
			goto out_irq_enable;

		pa  = pmd_pfn(*pmdp) << PAGE_SHIFT;
		pa += tpc & ~HPAGE_MASK;

		/* Use phys bypass so we don't pollute dtlb/dcache. */
		__asm__ __volatile__("lduwa [%1] %2, %0"
				     : "=r" (insn)
				     : "r" (pa), "i" (ASI_PHYS_USE_EC));
	} else
#endif
	{
		ptep = pte_offset_map(pmdp, tpc);
		pte = *ptep;
		if (pte_present(pte)) {
			pa  = (pte_pfn(pte) << PAGE_SHIFT);
			pa += (tpc & ~PAGE_MASK);

			/* Use phys bypass so we don't pollute dtlb/dcache. */
			__asm__ __volatile__("lduwa [%1] %2, %0"
					     : "=r" (insn)
					     : "r" (pa), "i" (ASI_PHYS_USE_EC));
		}
		pte_unmap(ptep);
	}
out_irq_enable:
	local_irq_enable();
out:
	return insn;
}

static inline void
show_signal_msg(struct pt_regs *regs, int sig, int code,
		unsigned long address, struct task_struct *tsk)
{
	if (!unhandled_signal(tsk, sig))
		return;

	if (!printk_ratelimit())
		return;

	printk("%s%s[%d]: segfault at %lx ip %p (rpc %p) sp %p error %x",
	       task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
	       tsk->comm, task_pid_nr(tsk), address,
	       (void *)regs->tpc, (void *)regs->u_regs[UREG_I7],
	       (void *)regs->u_regs[UREG_FP], code);

	print_vma_addr(KERN_CONT " in ", regs->tpc);

	printk(KERN_CONT "\n");
}

static void do_fault_siginfo(int code, int sig, struct pt_regs *regs,
			     unsigned long fault_addr, unsigned int insn,
			     int fault_code)
{
	unsigned long addr;
	siginfo_t info;

	info.si_code = code;
	info.si_signo = sig;
	info.si_errno = 0;
	if (fault_code & FAULT_CODE_ITLB) {
		addr = regs->tpc;
	} else {
		/* If we were able to probe the faulting instruction, use it
		 * to compute a precise fault address.  Otherwise use the fault
		 * time provided address which may only have page granularity.
		 */
		if (insn)
			addr = compute_effective_address(regs, insn, 0);
		else
			addr = fault_addr;
	}
	info.si_addr = (void __user *) addr;
	info.si_trapno = 0;

	if (unlikely(show_unhandled_signals))
		show_signal_msg(regs, sig, code, addr, current);

	force_sig_info(sig, &info, current);
}

extern int handle_ldf_stq(u32, struct pt_regs *);
extern int handle_ld_nf(u32, struct pt_regs *);

static unsigned int get_fault_insn(struct pt_regs *regs, unsigned int insn)
{
	if (!insn) {
		if (!regs->tpc || (regs->tpc & 0x3))
			return 0;
		if (regs->tstate & TSTATE_PRIV) {
			insn = *(unsigned int *) regs->tpc;
		} else {
			insn = get_user_insn(regs->tpc);
		}
	}
	return insn;
}

static void __kprobes do_kernel_fault(struct pt_regs *regs, int si_code,
				      int fault_code, unsigned int insn,
				      unsigned long address)
{
	unsigned char asi = ASI_P;
 
	if ((!insn) && (regs->tstate & TSTATE_PRIV))
		goto cannot_handle;

	/* If user insn could be read (thus insn is zero), that
	 * is fine.  We will just gun down the process with a signal
	 * in that case.
	 */

	if (!(fault_code & (FAULT_CODE_WRITE|FAULT_CODE_ITLB)) &&
	    (insn & 0xc0800000) == 0xc0800000) {
		if (insn & 0x2000)
			asi = (regs->tstate >> 24);
		else
			asi = (insn >> 5);
		if ((asi & 0xf2) == 0x82) {
			if (insn & 0x1000000) {
				handle_ldf_stq(insn, regs);
			} else {
				/* This was a non-faulting load. Just clear the
				 * destination register(s) and continue with the next
				 * instruction. -jj
				 */
				handle_ld_nf(insn, regs);
			}
			return;
		}
	}
		
	/* Is this in ex_table? */
	if (regs->tstate & TSTATE_PRIV) {
		const struct exception_table_entry *entry;

		entry = search_exception_tables(regs->tpc);
		if (entry) {
			regs->tpc = entry->fixup;
			regs->tnpc = regs->tpc + 4;
			return;
		}
	} else {
		/* The si_code was set to make clear whether
		 * this was a SEGV_MAPERR or SEGV_ACCERR fault.
		 */
		do_fault_siginfo(si_code, SIGSEGV, regs, address, insn, fault_code);
		return;
	}

cannot_handle:
	unhandled_fault (address, current, regs);
}

static void noinline __kprobes bogus_32bit_fault_tpc(struct pt_regs *regs)
{
	static int times;

	if (times++ < 10)
		printk(KERN_ERR "FAULT[%s:%d]: 32-bit process reports "
		       "64-bit TPC [%lx]\n",
		       current->comm, current->pid,
		       regs->tpc);
	show_regs(regs);
}

asmlinkage void __kprobes do_sparc64_fault(struct pt_regs *regs)
{
	enum ctx_state prev_state = exception_enter();
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned int insn = 0;
	int si_code, fault_code, fault;
	unsigned long address, mm_rss;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

#ifdef CONFIG_MCST_RT
	if (my_rt_cpu_data->modes & RTCPUM_NO_PG_FAULT ||
		((rts_act_mask & RTS_PGFLT_RTWRN && rt_task(current)) ||
			rts_act_mask & RTS_PGFLT_WRN)) {
		pr_err("page fault on cpu #%d. pid = %d (%s)\n",
			raw_smp_processor_id(), current->pid, current->comm);
	}
#endif
	fault_code = get_thread_fault_code();

	if (notify_page_fault(regs))
		goto exit_exception;

	si_code = SEGV_MAPERR;
	address = current_thread_info()->fault_address;

	if ((fault_code & FAULT_CODE_ITLB) &&
	    (fault_code & FAULT_CODE_DTLB))
		BUG();

	if (test_thread_flag(TIF_32BIT)) {
		if (!(regs->tstate & TSTATE_PRIV)) {
			if (unlikely((regs->tpc >> 32) != 0)) {
				bogus_32bit_fault_tpc(regs);
				goto intr_or_no_mm;
			}
		}
		if (unlikely((address >> 32) != 0))
			goto intr_or_no_mm;
	}

	if (regs->tstate & TSTATE_PRIV) {
		unsigned long tpc = regs->tpc;

		/* Sanity check the PC. */
		if ((tpc >= KERNBASE && tpc < (unsigned long) __init_end) ||
		    (tpc >= MODULES_VADDR && tpc < MODULES_END)) {
			/* Valid, no problems... */
		} else {
			bad_kernel_pc(regs, address);
			goto exit_exception;
		}
	} else
		flags |= FAULT_FLAG_USER;

	/*
	 * If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (!mm || pagefault_disabled())
		goto intr_or_no_mm;

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (!down_read_trylock(&mm->mmap_sem)) {
		if ((regs->tstate & TSTATE_PRIV) &&
		    !search_exception_tables(regs->tpc)) {
			insn = get_fault_insn(regs, insn);
			goto handle_kernel_fault;
		}

retry:
		down_read(&mm->mmap_sem);
	}

	if (fault_code & FAULT_CODE_BAD_RA)
		goto do_sigbus;

	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;

	/* Pure DTLB misses do not tell us whether the fault causing
	 * load/store/atomic was a write or not, it only says that there
	 * was no match.  So in such a case we (carefully) read the
	 * instruction to try and figure this out.  It's an optimization
	 * so it's ok if we can't do this.
	 *
	 * Special hack, window spill/fill knows the exact fault type.
	 */
	if (((fault_code &
	      (FAULT_CODE_DTLB | FAULT_CODE_WRITE | FAULT_CODE_WINFIXUP)) == FAULT_CODE_DTLB) &&
	    (vma->vm_flags & VM_WRITE) != 0) {
		insn = get_fault_insn(regs, 0);
		if (!insn)
			goto continue_fault;
		/* All loads, stores and atomics have bits 30 and 31 both set
		 * in the instruction.  Bit 21 is set in all stores, but we
		 * have to avoid prefetches which also have bit 21 set.
		 */
		if ((insn & 0xc0200000) == 0xc0200000 &&
		    (insn & 0x01780000) != 0x01680000) {
			/* Don't bother updating thread struct value,
			 * because update_mmu_cache only cares which tlb
			 * the access came from.
			 */
			fault_code |= FAULT_CODE_WRITE;
		}
	}
continue_fault:

	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (!(fault_code & FAULT_CODE_WRITE)) {
		/* Non-faulting loads shouldn't expand stack. */
		insn = get_fault_insn(regs, insn);
		if ((insn & 0xc0800000) == 0xc0800000) {
			unsigned char asi;

			if (insn & 0x2000)
				asi = (regs->tstate >> 24);
			else
				asi = (insn >> 5);
			if ((asi & 0xf2) == 0x82)
				goto bad_area;
		}
	}
	if (expand_stack(vma, address))
		goto bad_area;
	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
good_area:
	si_code = SEGV_ACCERR;

	/* If we took a ITLB miss on a non-executable page, catch
	 * that here.
	 */
	if ((fault_code & FAULT_CODE_ITLB) && !(vma->vm_flags & VM_EXEC)) {
		BUG_ON(address != regs->tpc);
		BUG_ON(regs->tstate & TSTATE_PRIV);
		goto bad_area;
	}

	if (fault_code & FAULT_CODE_WRITE) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;

		/* Spitfire has an icache which does not snoop
		 * processor stores.  Later processors do...
		 */
		if (tlb_type == spitfire &&
		    (vma->vm_flags & VM_EXEC) != 0 &&
		    vma->vm_file != NULL)
			set_thread_fault_code(fault_code |
					      FAULT_CODE_BLKCOMMIT);

		flags |= FAULT_FLAG_WRITE;
	} else {
		/* Allow reads even for write-only mappings */
		if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
			goto bad_area;
	}

	fault = handle_mm_fault(mm, vma, address, flags);

	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		goto exit_exception;

	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGSEGV)
			goto bad_area;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}

	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			current->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ,
				      1, regs, address);
		} else {
			current->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN,
				      1, regs, address);
		}
		if (fault & VM_FAULT_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;

			/* No need to up_read(&mm->mmap_sem) as we would
			 * have already released it in __lock_page_or_retry
			 * in mm/filemap.c.
			 */

			goto retry;
		}
	}
	up_read(&mm->mmap_sem);

	mm_rss = get_mm_rss(mm);
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	mm_rss -= (mm->context.huge_pte_count * (HPAGE_SIZE / PAGE_SIZE));
#endif
	if (unlikely(mm_rss >
		     mm->context.tsb_block[MM_TSB_BASE].tsb_rss_limit))
		tsb_grow(mm, MM_TSB_BASE, mm_rss);
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	mm_rss = mm->context.huge_pte_count;
	if (unlikely(mm_rss >
		     mm->context.tsb_block[MM_TSB_HUGE].tsb_rss_limit)) {
		if (mm->context.tsb_block[MM_TSB_HUGE].tsb)
			tsb_grow(mm, MM_TSB_HUGE, mm_rss);
		else
			hugetlb_setup(regs);

	}
#endif
exit_exception:
	exception_exit(prev_state);
	return;

	/*
	 * Something tried to access memory that isn't in our memory map..
	 * Fix it, but check if it's kernel or user first..
	 */
bad_area:
	insn = get_fault_insn(regs, insn);
	up_read(&mm->mmap_sem);

handle_kernel_fault:
	do_kernel_fault(regs, si_code, fault_code, insn, address);
	goto exit_exception;

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	insn = get_fault_insn(regs, insn);
	up_read(&mm->mmap_sem);
	if (!(regs->tstate & TSTATE_PRIV)) {
		pagefault_out_of_memory();
		goto exit_exception;
	}
	goto handle_kernel_fault;

intr_or_no_mm:
	insn = get_fault_insn(regs, 0);
	goto handle_kernel_fault;

do_sigbus:
	insn = get_fault_insn(regs, insn);
	up_read(&mm->mmap_sem);

	/*
	 * Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	do_fault_siginfo(BUS_ADRERR, SIGBUS, regs, address, insn, fault_code);

	/* Kernel mode? Handle exceptions or die */
	if (regs->tstate & TSTATE_PRIV)
		goto handle_kernel_fault;
}

#ifdef CONFIG_E90S
#include <asm/io.h>
#include <asm/e90s.h>

/*	Регистр AFSR*/
/* Биты 	 Название 	 Режим доступа 	 Reset 	 Описание*/
/*63:32 	Резерв 				RO 	X 	Резерв*/
#define	AFSR_L1_WAY 		(F << 28) 	/*RW 	X 	L1 way mask ? Столбцы в L1, в которых случилась ошибка*/
/*27:25 	Резерв 				RO 	X 	Резерв*/
#define AFSR_L2_ERR 		(3 << 23)	/*RW 	X 	L2 error code ? Код ошибки L2:*/
		/*
		* 00 ? Нет ошибки	
		* 01 ? Ошибка данных
		* 10 ? Не существующий адрес
		* 11 ? Ошибка протокола 
		*/
#define AFSR_L2_SIZE 		(3 << 21)	/*RW 	X 	L2 size - Размер для размерных обращений в L2*/
#define AFSR_L2_CFG 		(1 << 20)	/*RW 	X 	L2 configuration access - Конфиграционный доступ в L2*/
#define	AFSR_L2_OP		(F << 16) 	/*RW 	X 	L2 operation code - Опкод, с которым обращались в L2*/
/*14:15 	Резерв			 	RO 	0 	Резерв*/
#define	AFSR_ERR_IOCC		(1 << 13) 	/*RW 	X 	Error in IOCC - Неисправимая ошибка в IOCC.*/
#define	AFSR_ERR_SC		(1 << 12) 	/*RW 	X 	 Error in SC - Неисправимая ошибка в SC.*/
#define	AFSR_ERR_IOMMU 		(1 << 11) 	/*RW 	X 	Error in IOMMU - Неисправимая ошибка в IOMMU.*/
#define	AFSR_ERR_IC_SNOOP_MULTIHIT	(1 << 10) 	/*RW 	X 	IC snoop multihit - Multihit при снупировании IC.*/
#define	AFSR_ERR_IC_SNOOP	(1 << 9) 	/*RW 	X 	Error IC snoop - Неисправимая ошибка при снупировании IC.*/
#define	AFSR_ERR_RB_DATA 	(1 << 8) 	/*RW 	X 	Error L1 repeat data read - Неисправимая ошибка при чтении данных при повторе запроса из repeat buff.*/
#define AFSR_ERR_RB_TAG 	(1 << 7)	/*RW 	X 	Error L1 repeat tag read - Неисправимая ошибка при чтении тегов при повторе запроса из repeat buff.*/
#define AFSR_ERR_SNOOP_DATA 	(1 << 6)	/*RW 	X 	Error L1 snoop data read - Неисправимая ошибка при чтении данных для снупинга*/
#define AFSR_ERR_SNOOP_TAG 	(1 << 5)	/*RW 	X 	Error L1 snoop tag read - Неисправимая ошибка при чтении тегов для снупинга*/
#define	AFSR_ERR_CWB		(1 << 4) 	/*RW 	X 	Error L1 write-back - Неисправимая ошибка при чтении данных для вытеснения из L1*/
#define AFSR_ERR_L2_WR		(1 << 3)	/*RW 	X 	Error L2 write - Неисправимая ошибка при записи L2*/
#define	AFSR_ERR_L2_RD		(1 << 2)	/*RW 	X 	Error L2 read - Неисправимая ошибка при чтении L2*/
#define	AFSR_OW 		(1 << 1) 	/*RW 	X 	Overwrite - Устанавливается при исключении если бит FV уже установлен.*/
#define	AFSR_FV 		(1 << 0) 	/*RW 	0 	Fault Valid - Значимость содержимого регистра. НЕ устанавливается при исключении fast_data_access_MMU_miss*/


#define	L2_FAR	((2UL << 32) | (3 << 8))
#define	L2_FSR	((2UL << 32) | (4 << 8))

asmlinkage void do_async_data_error(int irq, struct pt_regs *regs)
{
	unsigned long asfr = readq_asi(0, ASI_AFSR);
	unsigned long afar = readq_asi(0, ASI_AFAR);
	unsigned long l2_fsr = readq_asi(L2_FSR, ASI_CONFIG);
	unsigned long l2_far = readq_asi(L2_FAR, ASI_CONFIG);
	char s[128];
	int len;
	int cpu = smp_processor_id();
		
	char *err =
	  asfr & AFSR_ERR_IOCC		? "Error in IOCC"
	: asfr & AFSR_ERR_SC		? "Error in SC"
	: asfr & AFSR_ERR_IOMMU 		? "Error in IOMMU"
	: asfr & AFSR_ERR_IC_SNOOP_MULTIHIT	? "IC snoop multihit"
	: asfr & AFSR_ERR_IC_SNOOP	? "Error IC snoop"
	: asfr & AFSR_ERR_RB_DATA 	? "Error L1 repeat data read"
	: asfr & AFSR_ERR_RB_TAG 	? "Error L1 repeat tag read"
	: asfr & AFSR_ERR_SNOOP_DATA 	? "Error L1 snoop data read"
	: asfr & AFSR_ERR_SNOOP_TAG 	? "Error L1 snoop tag read"
	: asfr & AFSR_ERR_RB_DATA	? "Error L1 repeat data read" 
	: asfr & AFSR_ERR_RB_TAG 	? "Error L1 repeat tag read" 
	: asfr & AFSR_ERR_SNOOP_DATA 	? "Error L1 snoop data read" 
	: asfr & AFSR_ERR_SNOOP_TAG 	? "Error L1 snoop tag read" 
	: asfr & AFSR_ERR_CWB		? "Error L1 write-back" 
	: asfr & AFSR_ERR_L2_WR		? "Error L2 write" 
	: asfr & AFSR_ERR_L2_RD		? "Error L2 read"
		: "Unknown error";

	clear_softint(1 << irq);
	len = snprintf(s, sizeof(s), "cpu %d:async data error: %s "
			"(afsr: 0x%lx) at address 0x%lx.\n"
			"\tpc: %lx, L2 fsr: 0x%lx, far: 0x%lx",
			cpu, err, asfr, afar,
			regs->tpc, l2_fsr, l2_far);

	if(asfr & AFSR_ERR_IOMMU) {
		char *str;
		unsigned fsr = _raw_readl(BASE_NODE0 + NBSR_IOMMU_FSR);
 		afar = _raw_readl(BASE_NODE0 + NBSR_IOMMU_FAH);	
		afar = (afar << 32) | 
				_raw_readl(BASE_NODE0 + NBSR_IOMMU_FAL);
		err =  
		fsr & IOMMU_FSR_MULTIHIT 		? "Multihit"
		: fsr & IOMMU_FSR_WRITE_PROTECTION	? "Write protection error"
		: fsr & IOMMU_FSR_PAGE_MISS 		? "Page miss"
		: fsr & IOMMU_FSR_ADDR_RNG_VIOLATION 	? "Address range violation"
			: "Unknown error";
		str = fsr & IOMMU_FSR_MUTIPLE_ERR ? " (Mutiple error)" :"";

		snprintf(s + len, sizeof(s) - len,
			 "\n\t\tIOMMU %s%s (afsr: 0x%lx iommu sfr: 0x%x)"
				" at address 0x%lx",
				err, str, asfr, fsr,  afar);
	}

	panic(s);
}

asmlinkage void do_e90s_data_access_error(struct pt_regs *regs)
{
	int cpu = smp_processor_id();
	char s[128];
	unsigned long fsr = readq_asi(TLB_SFSR, ASI_DMMU);
	unsigned long far = readq_asi(DMMU_SFAR, ASI_DMMU);
	sprintf(s, "cpu %d: data access error: dsfsr: 0x%lx dfar: 0x%lx",
		 cpu, fsr, far);
	panic(s);
}

asmlinkage void do_e90s_insn_access_error(struct pt_regs *regs)
{
	int cpu = smp_processor_id();
	char s[128];
	unsigned long fsr = readq_asi(TLB_SFSR, ASI_IMMU);
	sprintf(s, "cpu %d: instruction access error: isfsr: 0x%lx",
		 cpu, fsr);
	panic(s);
}

#endif /*CONFIG_E90S*/
