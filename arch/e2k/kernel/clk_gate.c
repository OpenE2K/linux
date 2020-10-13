/*
 * Clock gating support for e2s and e8c.
 *
 * Copyright (C) 2014 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <asm/tlbflush.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/mmu_regs_access.h>
#include <asm/e2k_api.h>
#include <asm/irqflags.h>
#include <asm/clk_gate.h>

/* This guy is to be called from cpu_idle only,
 * after do_clk_on */
void e2k_clk_resume()
{
	unsigned long mmu_cr;
	unsigned int cu_hw0_reg;

	/*
	 * 1) snooping on in cu_hw0
	 * 2) prefetch on (ipd = 2) in mmu_cr,
	 */
	cu_hw0_reg = E2K_GET_SREG(cu_hw0);
	cu_hw0_reg &= ~_CU_HW0_IB_SNOOP_DISABLE_MASK;
	E2K_SET_SREG(cu_hw0, cu_hw0_reg);
	E2K_WAIT_ALL;

	mmu_cr = READ_MMU_CR();
	mmu_cr |= _MMU_CR_IPD_MASK;
	E2K_WAIT_ALL;
	WRITE_MMU_CR(__mmu_reg(mmu_cr));
	E2K_WAIT_ALL;

	return;
}
EXPORT_SYMBOL(e2k_clk_resume);

static inline void clk_suspend()
{

	unsigned long mmu_cr;
	unsigned int cu_hw0_reg;

	/* 1) prefetch off (ipd = 0) in mmu_cr,
	 * 2) snooping off in cu_hw0
	 */
	mmu_cr = READ_MMU_CR();
	mmu_cr &= ~_MMU_CR_IPD_MASK;
	E2K_WAIT_ALL;
	WRITE_MMU_CR(__mmu_reg(mmu_cr));
	E2K_WAIT_ALL;

	cu_hw0_reg = E2K_GET_SREG(cu_hw0);
	cu_hw0_reg |= _CU_HW0_IB_SNOOP_DISABLE_MASK;
	E2K_SET_SREG(cu_hw0, cu_hw0_reg);

	return;
}

void do_e8c_clk_on(int cpuid)
{
	int nid;
	e8c_st_core_struct_t pwr_mgr;

	nid = cpu_to_node(cpuid);
	if ((cpuid & 0x7) == 0) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core0);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core0,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x7) == 1) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core1);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core1,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x7) == 2) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core2);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core2,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x7) == 3) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core3);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core3,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x7) == 4) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core4);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core4,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x7) == 5) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core5);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core5,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x7) == 6) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core6);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core6,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x7) == 7) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core7);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core7,
					E2K_ST_CORE_reg(pwr_mgr));
	}
	return;
}
EXPORT_SYMBOL(do_e8c_clk_on);

void do_e8c_clk_off(int cpuid)
{

	int nid;
	e8c_st_core_struct_t pwr_mgr;

	nid = cpu_to_node(cpuid);

	if ((cpuid & 0x7) == 0) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core0);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core0,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x7) == 1) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core1);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core1,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x7) == 2) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core2);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core2,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x7) == 3) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core3);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core3,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x7) == 4) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core4);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core4,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x7) == 5) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core5);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core5,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x7) == 6) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core6);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core6,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x7) == 7) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core7);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core7,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	}
	return;
}
EXPORT_SYMBOL(do_e8c_clk_off);

void do_e2s_clk_on(int cpuid)
{
	int nid;
	e2s_st_core_struct_t pwr_mgr;

	nid = cpu_to_node(cpuid);
	if ((cpuid & 0x3) == 0) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core0);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core0,
				E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x3) == 1) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core1);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core1,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x3) == 2) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core2);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core2,
					E2K_ST_CORE_reg(pwr_mgr));
	} else if ((cpuid & 0x3) == 3) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core3);

		E2K_ST_CORE_val(pwr_mgr) = 1;

		sic_write_node_nbsr_reg(nid, SIC_st_core3,
					E2K_ST_CORE_reg(pwr_mgr));
	}
	return;
}
EXPORT_SYMBOL(do_e2s_clk_on);

void do_e2s_clk_off(int cpuid)
{
	int nid;
	e2s_st_core_struct_t pwr_mgr;

	nid = cpu_to_node(cpuid);
	if ((cpuid & 0x3) == 0) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core0);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core0,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x3) == 1) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core1);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core1,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x3) == 2) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core2);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core2,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	} else if ((cpuid & 0x3) == 3) {
		E2K_ST_CORE_reg(pwr_mgr) =
			sic_read_node_nbsr_reg(nid, SIC_st_core3);

		E2K_ST_CORE_val(pwr_mgr) = 0;
		clk_suspend();
		write_back_CACHE_all();
		flush_TLB_all();

		sic_write_node_nbsr_reg(nid, SIC_st_core3,
					E2K_ST_CORE_reg(pwr_mgr));
		/* wait until clk off */
		wmb();
	}
	return;
}
EXPORT_SYMBOL(do_e2s_clk_off);
