/*
 * TLB flushing support on paravirt guest kernel
 *
 * Memroy access of paravirt guest is also cached in tlb, therefore guest
 * needs to flush tlb when editing page tables.
 * But guest kernel manages its own gest page tables, whereas hardware
 * uses shadow page tables for real memery access. Therefore, wee need
 * to synchronize guest and shadow page tables when flushing tlb.
 * Syncronization is provided by host.
 *
 * Copyright 2020 Andrey A. Alekhin (alekhin_a@mcst.ru)
 */

#include <linux/mm.h>
#include <asm/mmu_regs.h>
#include <asm/kvm/hypercall.h>
#include <asm/debug_print.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#undef	DEBUG_TLB_MODE
#undef	DebugTLB
#define	DEBUG_TLB_MODE		0	/* TLB FLUSHES */
#define DebugTLB(...)		DebugPrint(DEBUG_TLB_MODE, ##__VA_ARGS__)

static void pv_flush_tlb_range(e2k_addr_t start_gva, e2k_addr_t end_gva)
{
	unsigned long flags;
	bool fl_c_needed = cpu_has(CPU_HWBUG_TLB_FLUSH_L1D);

	if (IS_ENABLED(CONFIG_KVM_PARAVIRT_TLB_FLUSH)) {
		flush_TLB_page_begin();
		raw_all_irq_save(flags);
		HYPERVISOR_flush_tlb_range(start_gva, end_gva);
		if (fl_c_needed)
			__E2K_WAIT(_fl_c);
		raw_all_irq_restore(flags);
		flush_TLB_page_end();
	}
}

void kvm_pv_flush_tlb_all(void)
{
	DebugTLB("Flush all mm address space CPU #%d\n",
		raw_smp_processor_id());

	preempt_disable();

	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
	pv_flush_tlb_range(0, E2K_VA_SIZE);

	preempt_enable();
}

void kvm_pv_flush_tlb_mm(struct mm_struct *mm)
{
	DebugTLB("Flush all mm address space context 0x%lx CPU #%d\n",
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	preempt_disable();

	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
	pv_flush_tlb_range(0, E2K_VA_SIZE);

	preempt_enable();
}

void kvm_pv_flush_tlb_page(struct mm_struct *mm, e2k_addr_t addr)
{
	DebugTLB("Flush address 0x%lx context 0x%lx CPU #%d\n",
		PAGE_ALIGN_UP(addr),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	preempt_disable();

	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ONE);
	pv_flush_tlb_range(addr, addr);

	preempt_enable();
}

void kvm_pv_flush_tlb_range(struct mm_struct *mm, e2k_addr_t start,
				e2k_addr_t end)
{
	const long pages_num = (PAGE_ALIGN_DOWN(end) - PAGE_ALIGN_UP(start))
			/ PAGE_SIZE;
	KVM_BUG_ON(start > end);
	DebugTLB("Flush address range start 0x%lx end 0x%lx context 0x%lx "
		"CPU #%d\n", PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		raw_smp_processor_id());

	preempt_disable();

	count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, pages_num);
	pv_flush_tlb_range(start, end);

	preempt_enable();
}

void kvm_pv_flush_tlb_kernel_range(e2k_addr_t start, e2k_addr_t end)
{
	const long pages_num = (PAGE_ALIGN_DOWN(end) - PAGE_ALIGN_UP(start))
			/ PAGE_SIZE;
	KVM_BUG_ON(start > end);
	DebugTLB("Flush kernel address range start 0x%lx end 0x%lx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		raw_smp_processor_id());

	preempt_disable();

	count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, pages_num);
	pv_flush_tlb_range(start, end);

	preempt_enable();
}

void kvm_pv_flush_pmd_tlb_range(struct mm_struct *mm, e2k_addr_t start,
				e2k_addr_t end)
{
	KVM_BUG_ON(start > end);

	/*
	 * Do not need real flush here for paravirt kernel.
	 * Page tables are synchronized automatically and full tlb flush
	 * occures when guest tries to edit pmd level of guest pts.
	 */
}

void kvm_pv_flush_tlb_range_and_pgtables(struct mm_struct *mm,
					e2k_addr_t start,
					e2k_addr_t end)
{
	const long pages_num = (PAGE_ALIGN_DOWN(end) - PAGE_ALIGN_UP(start))
			/ PAGE_SIZE;
	KVM_BUG_ON(start > end);
	DebugTLB("Flush kernel address range start 0x%lx end 0x%lx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		raw_smp_processor_id());

	preempt_disable();

	count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, pages_num);
	pv_flush_tlb_range(start, end);

	preempt_enable();
}
