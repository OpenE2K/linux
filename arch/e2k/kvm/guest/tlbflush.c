/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * TLB flushing support on paravirt guest kernel
 *
 * Memroy access of paravirt guest is also cached in tlb, therefore guest
 * needs to flush tlb when editing page tables.
 * But guest kernel manages its own gest page tables, whereas hardware
 * uses shadow page tables for real memery access. Therefore, wee need
 * to synchronize guest and shadow page tables when flushing tlb.
 * Syncronization is provided by host.
 */

#include <linux/mm.h>
#include <linux/pgtable.h>

#include <asm/mmu_regs.h>
#include <asm/kvm/hypercall.h>
#include <asm/debug_print.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

#define CREATE_TRACE_POINTS
#include "trace-tlb-flush.h"

#undef	DEBUG_TLB_MODE
#undef	DebugTLB
#define	DEBUG_TLB_MODE		0	/* TLB FLUSHES */
#define DebugTLB(...)		DebugPrint(DEBUG_TLB_MODE, ##__VA_ARGS__)

static long pv_flush_tlb_range(struct mm_struct *mm, mmu_flush_tlb_op_t opc,
				e2k_addr_t start_gva, e2k_addr_t end_gva,
				unsigned long stride, u32 levels_mask)
{
	mmu_spt_flush_t flush_info;
	unsigned long flags;
	bool fl_c_needed = cpu_has(CPU_HWBUG_TLB_FLUSH_L1D);
	e2k_addr_t start, end;
	long ret;

	flush_info.opc = opc;
	flush_info.gmm_id = mm->gmmid_nr;
	if (unlikely(mm->gmmid_nr < 0)) {
		/* mm has been already released and has not own agent on a host */
		/* so flushing on the host should be ignored */
		return 0;
	}

	switch (opc) {
	case flush_all_tlb_op:
		/* such flushing should not be here */
		BUG_ON(true);
		ret = -EINVAL;
		break;
	case flush_mm_tlb_op:
		start = 0;
		end = GUEST_TASK_SIZE;
		break;
	case flush_mm_page_tlb_op:
		start = round_down(start_gva, PAGE_SIZE);
		end = start;
		break;
	case flush_tlb_range_tlb_op:
	case flush_pmd_range_tlb_op:
	case flush_pt_range_tlb_op:
	case flush_kernel_range_tlb_op:
	case flush_mm_range_tlb_op:
		start = round_down(start_gva, stride);
		end = round_up(end_gva, stride);
		if (start > end) {
			pr_err("%s(): start addres of range 0x%lx > 0x%lx end\n",
				__func__, start, end);
			return -EINVAL;
		}
		break;
	default:
		pr_err("%s()^ unknown type of flush TLB operation %d\n",
			__func__, opc);
		return -EINVAL;
	}
	flush_info.start = start;
	flush_info.end = end;
	flush_info.stride = stride;
	flush_info.levels_mask = levels_mask;

	if (IS_ENABLED(CONFIG_KVM_PARAVIRT_TLB_FLUSH)) {
		trace_guest_flush_tlb_range(mm, opc, start, end);
		flush_TLB_page_begin();
		raw_all_irq_save(flags);
		ret = HYPERVISOR_mmu_pv_flush_tlb(&flush_info);
		if (fl_c_needed)
			__E2K_WAIT(_fl_c);
		raw_all_irq_restore(flags);
		flush_TLB_page_end();
	} else {
		BUG_ON(true);
		ret = -EINVAL;
	}
	if (unlikely(ret != 0)) {
		if (likely(mm->gmmid_nr == -1)) {
			/* gmm is dropping while host flush TLB */
			ret = 0;
		} else {
			trace_guest_flush_tlb_failed(mm, opc, start, end, ret);
		}
	}
	return ret;
}

/*
 * Flush all processes TLBs
 */
void kvm_pv_flush_tlb_all(void)
{
	long ret;

	DebugTLB("Flush all mm address space CPU #%d\n",
		raw_smp_processor_id());

	pr_err("%s(): CPU #%d\n",
		__func__, smp_processor_id());
	WARN_ON(true);
	return;

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_tlb_all();
#endif
	ret = pv_flush_tlb_range(NULL, flush_all_tlb_op, 0, GUEST_TASK_SIZE,
				 PAGE_SIZE, FLUSH_TLB_LEVELS_ALL);

	preempt_enable();

	if (unlikely(ret != 0)) {
		pr_err("%s(): failed to flush all TLB, error %ld\n",
			__func__, ret);
	}
}

/*
 * Flush a specified user mapping
 */
void kvm_pv_flush_tlb_mm(struct mm_struct *mm)
{
	long ret;

	DebugTLB("Flush all mm address space context 0x%llx CPU #%d\n",
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_tlb_mm(mm);
#endif
	if (likely(mm->gmmid_nr < 0)) {
		/* gmm agent on host has been already dropped and flushed */
		ret = 0;
	} else {
		/* it seems this should not be */
		WARN_ON(!IS_ENABLED(CONFIG_SMP));
		ret = pv_flush_tlb_range(mm, flush_mm_tlb_op, 0, GUEST_TASK_SIZE,
					 PAGE_SIZE, FLUSH_TLB_LEVELS_ALL);
	}

	preempt_enable();

	if (unlikely(ret != 0)) {
		pr_err("%s(): failed to flush mm id #%d, error %ld\n",
			__func__, mm->gmmid_nr, ret);
	}
}

/*
 * Flush a single page from TLB
 */
void kvm_pv_flush_tlb_page(struct mm_struct *mm, e2k_addr_t addr)
{
	long ret;

	DebugTLB("Flush address 0x%lx context 0x%llx CPU #%d\n",
		PAGE_ALIGN_UP(addr),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_tlb_page(mm, addr);
#endif
	ret = pv_flush_tlb_range(mm, flush_mm_page_tlb_op, addr, addr,
				 PAGE_SIZE, FLUSH_TLB_LEVELS_ALL);

	preempt_enable();

	if (unlikely(ret != 0)) {
		pr_err("%s(): failed to flush mm id #%d addr 0x%lx, error %ld\n",
			__func__, mm->gmmid_nr, addr, ret);
	}
}

/*
 * Flush a range of pages
 */
void kvm_pv_flush_tlb_range(struct mm_struct *const mm,
			e2k_addr_t start, e2k_addr_t end)
{
	long ret;

	E2K_KVM_BUG_ON(start > end);
	DebugTLB("Flush address range start 0x%lx end 0x%lx context 0x%llx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	start = round_down(start, PAGE_SIZE);
	end = round_up(end, PAGE_SIZE);
	(end == start) ? end += PAGE_SIZE : end;

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_tlb_range(mm, start, end);
#endif
	ret = pv_flush_tlb_range(mm, flush_tlb_range_tlb_op, start, end,
				 PAGE_SIZE, FLUSH_TLB_LEVELS_ALL);

	preempt_enable();

	if (unlikely(ret != 0)) {
		pr_err("%s(): failed to flush mm id #%d range from addr 0x%lx "
			"to 0x%lx, error %ld\n",
			__func__, mm->gmmid_nr, start, end, ret);
	}
}

/*
 * As flush_tlb_range() but for pmd's
 */
void kvm_pv_flush_pmd_tlb_range(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end)
{
	long ret;

	E2K_KVM_BUG_ON(start > end);

	/*
	 * Do not need real flush here for paravirt kernel.
	 * Page tables are synchronized automatically and full tlb flush
	 * occures when guest tries to edit pmd level of guest pts.
	 */
	WARN(!IS_ENABLED(CONFIG_SMP), "%s(): CPU #%d range from 0x%lx to 0x%lx\n",
		__func__, smp_processor_id(), start, end);

	start = round_down(start, PMD_SIZE);
	end = round_up(end, PMD_SIZE);
	(end == start) ? end += PMD_SIZE : end;

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_pmd_tlb_range(mm, start, end);
#endif
	ret = pv_flush_tlb_range(mm, flush_pmd_range_tlb_op, start, end,
				 PMD_SIZE, FLUSH_TLB_LEVELS_LAST);

	preempt_enable();

	if (unlikely(ret != 0)) {
		pr_err("%s(): failed to flush mm id #%d range from addr 0x%lx "
			"to 0x%lx, error %ld\n",
			__func__, mm->gmmid_nr, start, end, ret);
	}
}

/*
 * Flush a range of pages and page tables.
 */
void kvm_pv_flush_tlb_range_and_pgtables(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end)
{
	long ret;

	E2K_KVM_BUG_ON(start > end);
	DebugTLB("Flush PTs address range start 0x%lx end 0x%lx context 0x%llx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	start = round_down(start, PAGE_SIZE);
	end = round_up(end, PAGE_SIZE);
	(end == start) ? end += PAGE_SIZE : end;

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_tlb_range_and_pgtables(mm, start, end);
#endif
	ret = pv_flush_tlb_range(mm, flush_pt_range_tlb_op, start, end,
				 PAGE_SIZE, FLUSH_TLB_LEVELS_ALL);

	preempt_enable();

	if (unlikely(ret != 0)) {
		pr_err("%s(): failed to flush mm id #%d range from addr 0x%lx "
			"to 0x%lx, error %ld\n",
			__func__, mm->gmmid_nr, start, end, ret);
	}
}

/*
 * Flush a range of pages and page tables.
 */
void kvm_pv_flush_tlb_mm_range(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end,
				unsigned long stride, u32 levels_mask)
{
	long ret;

	E2K_KVM_BUG_ON(start > end);
	DebugTLB("Flush PTs address range start 0x%lx end 0x%lx context 0x%llx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	start = round_down(start, stride);
	end = round_up(end, stride);
	(end == start) ? end += stride : end;

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_tlb_mm_range(mm, start, end, stride, levels_mask);
#endif
	ret = pv_flush_tlb_range(mm, flush_mm_range_tlb_op, start, end,
				 stride, levels_mask);

	preempt_enable();

	if (unlikely(ret != 0)) {
		pr_err("%s(): failed to flush mm id #%d range from addr 0x%lx "
			"to 0x%lx, error %ld\n",
			__func__, mm->gmmid_nr, start, end, ret);
	}
}

void kvm_pv_flush_tlb_kernel_range(e2k_addr_t start, e2k_addr_t end)
{
	long ret;

	E2K_KVM_BUG_ON(start > end);
	DebugTLB("Flush kernel address range start 0x%lx end 0x%lx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		raw_smp_processor_id());

	start = round_down(start, PAGE_SIZE);
	end = round_up(end, PAGE_SIZE);
	(end == start) ? end += PAGE_SIZE : end;

	preempt_disable();

#ifdef CONFIG_SMP
	native_flush_tlb_all();
#endif
	ret = pv_flush_tlb_range(&init_mm, flush_kernel_range_tlb_op, start, end,
				 PAGE_SIZE, FLUSH_TLB_LEVELS_ALL);

	preempt_enable();

	if (unlikely(ret != 0)) {
		panic("%s(): failed to flush kernel range from addr 0x%lx "
			"to 0x%lx, error %ld\n",
			__func__, start, end, ret);
	}
}
