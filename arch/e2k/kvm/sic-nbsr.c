/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * North Bridge registers emulation for guest VM
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/smp.h>

#include <asm/sic_regs.h>
#include <asm/e2k-iommu.h>
#include <asm/pic.h>
#include <uapi/asm/iset_ver.h>

#include <asm-generic/tlb.h>

#include "sic-nbsr.h"
#include "mmu.h"
#include "pic.h"
#include "irq.h"
# ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include "paravirt_sw/gaccess.h"
# endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#if 0
#define nbsr_debug(fmt, arg...)		pr_warn(fmt, ##arg)
#else
#define nbsr_debug(fmt, arg...)
#endif

#if 0
#define nbsr_warn(fmt, arg...)		pr_warn(fmt, ##arg)
#else
#define nbsr_warn(fmt, arg...)
#endif

#define	NBSR_PCI_BOUND			(1UL << 32)
#define	NBSR_LOW_MEMORY_BOUND		(0x80000000)
#define	NBSR_HI_MEMORY_BOUND		(1UL << 48)	/* physical memory size */

#define NBSR_ADDR64(hi, lo)		((((u64)hi) << 32) + ((u64)lo))

#define BC_MP_T_CORR_ADDR(hreg, reg) \
		((((u64)hreg.addr) << 32) + (((u64)reg.addr) << PAGE_SHIFT))

static inline struct kvm_nbsr *to_nbsr(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_nbsr, dev);
}

/* Max number of nodes is now 4, so link can be from 1 to 3 */
static inline int nbsr_get_node_to_node_link(int node_on, int node_to)
{
	int link = 0;

	if (node_on == 0) {
		if (node_to == 1) {
			link = 1;
		} else if (node_to == 2) {
			link = 2;
		} else if (node_to == 3) {
			link = 3;
		} else {
			ASSERT(false);
		}
	} else if (node_on == 1) {
		if (node_to == 2) {
			link = 1;
		} else if (node_to == 3) {
			link = 2;
		} else if (node_to == 0) {
			link = 3;
		} else {
			ASSERT(false);
		}
	} else if (node_on == 2) {
		if (node_to == 3) {
			link = 1;
		} else if (node_to == 0) {
			link = 2;
		} else if (node_to == 1) {
			link = 3;
		} else {
			ASSERT(false);
		}
	} else if (node_on == 3) {
		if (node_to == 0) {
			link = 1;
		} else if (node_to == 1) {
			link = 2;
		} else if (node_to == 2) {
			link = 3;
		} else {
			ASSERT(false);
		}
	} else {
		ASSERT(false);
	}
	ASSERT(link >= 1 && link <= 3);
	return link;
}

static inline bool nbsr_is_node_online(struct kvm_nbsr *nbsr, int node_id)
{
	return !!(nbsr->nodes_online & (1 << node_id));
}

static inline void nbsr_set_node_online(struct kvm_nbsr *nbsr, int node_id)
{
	nbsr->nodes_online |= (1 << node_id);
}

static inline int nbsr_in_range(struct kvm_nbsr *nbsr, gpa_t addr)
{
	return (addr >= nbsr->base) && (addr < nbsr->base + nbsr->size);
}

static inline int nbsr_addr_to_node(struct kvm_nbsr *nbsr, gpa_t addr)
{
	int node_id;

	if (!nbsr_in_range(nbsr, addr)) {
		pr_err("%s(): address 0x%llx is out of North Bridge registers space from 0x%llx to 0x%llx\n",
		       __func__, addr, nbsr->base, nbsr->base + nbsr->size);
		BUG_ON(true);
	}
	node_id = (addr - nbsr->base) / nbsr->node_size;
	return node_id;
}

static inline unsigned nbsr_addr_to_reg_offset(struct kvm_nbsr *nbsr,
					       gpa_t addr)
{
	unsigned reg_offset;

	if (!nbsr_in_range(nbsr, addr)) {
		pr_err("%s(): address 0x%llx is out of North Bridge registers space from 0x%llx to 0x%llx\n",
		       __func__, addr, nbsr->base, nbsr->base + nbsr->size);
		BUG_ON(true);
	}
	reg_offset = addr & (nbsr->node_size - 1);
	return reg_offset;
}

static inline bool nbsr_bc_reg_in_range(unsigned int reg_offset)
{
	return reg_offset >= BC_MM_REG_BASE && reg_offset < BC_MM_REG_END;
}

static inline unsigned int nbsr_bc_reg_offset_to_no(unsigned int reg_offset)
{
	if (!nbsr_bc_reg_in_range(reg_offset)) {
		pr_err("%s(): offset 0x%x is out of North Bridge BC registers space from 0x%04x to 0x%04x\n",
		       __func__, reg_offset, BC_MM_REG_BASE, BC_MM_REG_END);
		BUG_ON(true);
	}
	return (reg_offset - BC_MM_REG_BASE) / 4;
}

static inline unsigned int nbsr_get_rt_mlo_offset(int node_id)
{
	if (node_id == 0)
		return SIC_rt_mlo0;
	else if (node_id == 1)
		return SIC_rt_mlo1;
	else if (node_id == 2)
		return SIC_rt_mlo2;
	else if (node_id == 3)
		return SIC_rt_mlo3;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_mhi_offset(int node_id)
{
	if (node_id == 0)
		return SIC_rt_mhi0;
	else if (node_id == 1)
		return SIC_rt_mhi1;
	else if (node_id == 2)
		return SIC_rt_mhi2;
	else if (node_id == 3)
		return SIC_rt_mhi3;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pcim_offset(int node_id)
{
	if (node_id == 0)
		return SIC_rt_pcim0;
	else if (node_id == 1)
		return SIC_rt_pcim1;
	else if (node_id == 2)
		return SIC_rt_pcim2;
	else if (node_id == 3)
		return SIC_rt_pcim3;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pcim_xmu_offset(char xmu_k)
{
	if (likely(xmu_k == RT_XMU_l))
		return SIC_rt_pcim0_xmu_l;
	else if (xmu_k == RT_XMU_a)
		return SIC_rt_pcim0_xmu_a;
	else if (xmu_k == RT_XMU_b)
		return SIC_rt_pcim0_xmu_b;
	else if (xmu_k == RT_XMU_c)
		return SIC_rt_pcim0_xmu_c;
	else if (xmu_k == RT_XMU_d)
		return SIC_rt_pcim0_xmu_d;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pciio_offset(int node_id)
{
	if (node_id == 0)
		return SIC_rt_pciio0;
	else if (node_id == 1)
		return SIC_rt_pciio1;
	else if (node_id == 2)
		return SIC_rt_pciio2;
	else if (node_id == 3)
		return SIC_rt_pciio3;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pciio_xmu_offset(char xmu_k)
{
	if (likely(xmu_k == RT_XMU_l))
		return SIC_rt_pciio0_xmu_l;
	else if (xmu_k == RT_XMU_a)
		return SIC_rt_pciio0_xmu_a;
	else if (xmu_k == RT_XMU_b)
		return SIC_rt_pciio0_xmu_b;
	else if (xmu_k == RT_XMU_c)
		return SIC_rt_pciio0_xmu_c;
	else if (xmu_k == RT_XMU_d)
		return SIC_rt_pciio0_xmu_d;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pcimp_b_offset(int node_id)
{
	if (node_id == 0)
		return SIC_rt_pcimp_b0;
	else if (node_id == 1)
		return SIC_rt_pcimp_b1;
	else if (node_id == 2)
		return SIC_rt_pcimp_b2;
	else if (node_id == 3)
		return SIC_rt_pcimp_b3;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pcimp_e_offset(int node_id)
{
	if (node_id == 0)
		return SIC_rt_pcimp_e0;
	else if (node_id == 1)
		return SIC_rt_pcimp_e1;
	else if (node_id == 2)
		return SIC_rt_pcimp_e2;
	else if (node_id == 3)
		return SIC_rt_pcimp_e3;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pcimp_b_xmu_offset(char xmu_k)
{
	if (likely(xmu_k == RT_XMU_l))
		return SIC_rt_pcimp0_xmu_l_bgn;
	else if (xmu_k == RT_XMU_a)
		return SIC_rt_pcimp0_xmu_a_bgn;
	else if (xmu_k == RT_XMU_b)
		return SIC_rt_pcimp0_xmu_b_bgn;
	else if (xmu_k == RT_XMU_c)
		return SIC_rt_pcimp0_xmu_c_bgn;
	else if (xmu_k == RT_XMU_d)
		return SIC_rt_pcimp0_xmu_d_bgn;
	else
		ASSERT(false);
	return -1;
}

static inline unsigned int nbsr_get_rt_pcimp_e_xmu_offset(char xmu_k)
{
	if (likely(xmu_k == RT_XMU_l))
		return SIC_rt_pcimp0_xmu_l_end;
	else if (xmu_k == RT_XMU_a)
		return SIC_rt_pcimp0_xmu_a_end;
	else if (xmu_k == RT_XMU_b)
		return SIC_rt_pcimp0_xmu_b_end;
	else if (xmu_k == RT_XMU_c)
		return SIC_rt_pcimp0_xmu_c_end;
	else if (xmu_k == RT_XMU_d)
		return SIC_rt_pcimp0_xmu_d_end;
	else
		ASSERT(false);
	return -1;
}

static inline void
nbsr_debug_dump_rt_mlo(int node_id, unsigned int reg_offset, bool write,
		       unsigned int reg_value, char *reg_name)
{
	e2k_rt_mlo_t rt_mlo;

	AW(rt_mlo) = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset,
		   (rt_mlo.bgn << E2K_SIC_ALIGN_RT_MLO),
		   (rt_mlo.end << E2K_SIC_ALIGN_RT_MLO) | (E2K_SIC_SIZE_RT_MLO - 1));
}

static inline void
nbsr_debug_dump_rt_mhi(int node_id, unsigned int reg_offset, bool write,
		       unsigned int reg_value, char *reg_name)
{
	e2k_rt_mhi_t rt_mhi;

	AW(rt_mhi) = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%016llx:%016llx]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset,
		   ((u64) rt_mhi.bgn << E2K_SIC_ALIGN_RT_MHI),
		   ((u64) rt_mhi.end << E2K_SIC_ALIGN_RT_MHI) |
		   (E2K_SIC_SIZE_RT_MHI - 1));
}

static inline void
nbsr_debug_dump_rt_lcfg(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_lcfg_t rt_lcfg;
	int pn;

	AW(rt_lcfg) = reg_value;
	pn = rt_lcfg.pln;
	nbsr_debug("%s(): node #%d %s %s 0x%04x link to node #%d %s boot %s\n"
		   "IO link %s intercluster %s\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset, pn,
		   rt_lcfg.vp ? "ON" : "OFF",
		   rt_lcfg.vb ? "ON" : "OFF",
		   rt_lcfg.vio ? "ON" : "OFF", rt_lcfg.vics ? "ON" : "OFF");
}

static inline unsigned int
nbsr_get_rt_pcim_bgn(unsigned int reg_value)
{
	e2k_rt_pcim_t rt_pcim;

	AW(rt_pcim) = reg_value;
	return rt_pcim.bgn << E2K_SIC_ALIGN_RT_PCIM;
}

static inline unsigned int
nbsr_get_rt_pcim_end(unsigned int reg_value)
{
	e2k_rt_pcim_t rt_pcim;

	AW(rt_pcim) = reg_value;
	return rt_pcim.end << E2K_SIC_ALIGN_RT_PCIM;
}

static inline void
nbsr_debug_dump_rt_pcim(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset,
		   nbsr_get_rt_pcim_bgn(reg_value),
		   nbsr_get_rt_pcim_end(reg_value) |
		   (E2K_SIC_SIZE_RT_PCIM - 1));
}

static inline void
nbsr_debug_dump_rt_pcim_xmu(int node_id, unsigned int reg_offset, bool write,
			    unsigned int reg_value, char *reg_name)
{
	nbsr_debug_dump_rt_pcim(node_id, reg_offset, write, reg_value, reg_name);
}

static inline unsigned int
nbsr_get_rt_pciio_bgn_v7(unsigned int reg_value)
{
	e2k_rt_pciio_v7_t rt_pciio;

	AW(rt_pciio) = reg_value;
	return rt_pciio.bgn << E2K_SIC_ALIGN_RT_PCIIO;
}

static inline unsigned int
nbsr_get_rt_pciio_end_v7(unsigned int reg_value)
{
	e2k_rt_pciio_v7_t rt_pciio;

	AW(rt_pciio) = reg_value;
	return rt_pciio.end << E2K_SIC_ALIGN_RT_PCIIO;
}

static inline unsigned int
nbsr_get_rt_pciio_bgn_v6(unsigned int reg_value)
{
	e2k_rt_pciio_t rt_pciio;

	AW(rt_pciio) = reg_value;
	return rt_pciio.bgn << E2K_SIC_ALIGN_RT_PCIIO;
}

static inline unsigned int
nbsr_get_rt_pciio_end_v6(unsigned int reg_value)
{
	e2k_rt_pciio_t rt_pciio;

	AW(rt_pciio) = reg_value;
	return rt_pciio.end << E2K_SIC_ALIGN_RT_PCIIO;
}

static inline unsigned int
nbsr_get_rt_pciio_bgn(unsigned int reg_value, e2k_iset_ver_t iset_no)
{
	if (iset_no >= E2K_ISET_V7) {
		return nbsr_get_rt_pciio_bgn_v7(reg_value);
	} else {
		return nbsr_get_rt_pciio_bgn_v6(reg_value);
	}
}

static inline unsigned int
nbsr_get_rt_pciio_end(unsigned int reg_value, e2k_iset_ver_t iset_no)
{
	if (iset_no >= E2K_ISET_V7) {
		return nbsr_get_rt_pciio_end_v7(reg_value);
	} else {
		return nbsr_get_rt_pciio_end_v6(reg_value);
	}
}

static inline unsigned int
nbsr_set_rt_pciio_reg_v7(unsigned int start, unsigned int end)
{
	e2k_rt_pciio_v7_t rt_pciio;

	AW(rt_pciio) = 0;
	rt_pciio.bgn = (start >> E2K_SIC_ALIGN_RT_PCIIO) & 0xff;
	rt_pciio.end = (end >> E2K_SIC_ALIGN_RT_PCIIO) &0xff;
	return AW(rt_pciio);
}

static inline unsigned int
nbsr_set_rt_pciio_reg_v6(unsigned int start, unsigned int end)
{
	e2k_rt_pciio_t rt_pciio;

	AW(rt_pciio) = 0;
	rt_pciio.bgn = (start >> E2K_SIC_ALIGN_RT_PCIIO) & 0xf;
	rt_pciio.end = (end >> E2K_SIC_ALIGN_RT_PCIIO) & 0xf;
	return AW(rt_pciio);
}

static inline unsigned int
nbsr_set_rt_pciio_reg(unsigned int start, unsigned int end, e2k_iset_ver_t iset_no)
{
	if (iset_no >= E2K_ISET_V7) {
		return nbsr_set_rt_pciio_reg_v7(start, end);
	} else {
		return nbsr_set_rt_pciio_reg_v6(start, end);
	}
}

static inline void
nbsr_debug_dump_rt_pciio(int node_id, unsigned int reg_offset, bool write,
			 unsigned int reg_value, char *reg_name,
			 e2k_iset_ver_t iset_no)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset,
		   nbsr_get_rt_pciio_bgn(reg_value, iset_no),
		   nbsr_get_rt_pciio_end(reg_value, iset_no) |
		   (E2K_SIC_SIZE_RT_PCIIO - 1));
}

static inline void
nbsr_debug_dump_rt_pciio_xmu(int node_id, unsigned int reg_offset, bool write,
			     unsigned int reg_value, char *reg_name)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset,
		   nbsr_get_rt_pciio_bgn_v7(reg_value),
		   nbsr_get_rt_pciio_end_v7(reg_value) | (E2K_SIC_SIZE_RT_PCIIO - 1));
}

static inline unsigned int
nbsr_get_rt_pcimp_bgn(unsigned int reg_value)
{
	e2k_rt_pcimp_t rt_pcimp;

	AW(rt_pcimp) = reg_value;
	return rt_pcimp.bgn << E2K_SIC_ALIGN_RT_PCIMP;
}

static inline unsigned int
nbsr_get_rt_pcimp_end(unsigned int reg_value)
{
	e2k_rt_pcimp_t rt_pcimp;

	AW(rt_pcimp) = reg_value;
	return rt_pcimp.end << E2K_SIC_ALIGN_RT_PCIMP;
}

static inline unsigned int
nbsr_set_rt_pcimp_bgn_reg(unsigned int start)
{
	e2k_rt_pcimp_t rt_pcimp;

	AW(rt_pcimp) = 0;
	rt_pcimp.bgn = start >> E2K_SIC_ALIGN_RT_PCIMP;
	return AW(rt_pcimp);
}

static inline unsigned int
nbsr_set_rt_pcimp_end_reg(unsigned int end)
{
	e2k_rt_pcimp_t rt_pcimp;

	AW(rt_pcimp) = 0;
	rt_pcimp.end = end >> E2K_SIC_ALIGN_RT_PCIMP;
	return AW(rt_pcimp);
}

static inline void
nbsr_debug_dump_rt_pcimp(int node_id, unsigned int reg_offset, bool write,
			 unsigned int reg_value, char *reg_name, bool end)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x %s : %08x\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset,
		   (end) ? "end " : "base",
		   (!end) ? nbsr_get_rt_pcimp_bgn(reg_value)
		   : nbsr_get_rt_pcimp_end(reg_value) |
		   (E2K_SIC_SIZE_RT_PCIMP - 1));
}

static inline void
nbsr_debug_dump_rt_pcimp_xmu(int node_id, unsigned int reg_offset, bool write,
			    unsigned int reg_value, char *reg_name, bool end)
{
	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, write, reg_value, reg_name, end);
}

static inline void
nbsr_debug_dump_rt_pcicfgb(int node_id, unsigned int reg_offset, bool write,
			   unsigned int reg_value, char *reg_name)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x : %08x\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset, reg_value);
}

static inline void
nbsr_debug_dump_rt_ioapic(int node_id, unsigned int reg_offset, bool write,
			  unsigned int reg_value, char *reg_name)
{
	e2k_rt_ioapic_t rt_ioapic;
	u32 start, end;

	AW(rt_ioapic) = reg_value;
	start = (rt_ioapic.bgn << E2K_SIC_ALIGN_RT_IOAPIC) |
	    (IO_EPIC_DEFAULT_PHYS_BASE & E2K_SIC_IOAPIC_FIX_ADDR_MASK);
	end = start + (E2K_SIC_IOAPIC_SIZE - 1);
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset, start, end);
}

static inline void
nbsr_debug_dump_rt_msi(int node_id, unsigned int reg_offset, bool write,
		       unsigned int reg_value, char *reg_name)
{
	e2k_rt_msi_t rt_msi;

	AW(rt_msi) = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset,
		   (rt_msi.bgn << E2K_SIC_ALIGN_RT_MSI));
}

static inline void
nbsr_debug_dump_rt_msi_h(int node_id, unsigned int reg_offset, bool write,
			 unsigned int reg_value, char *reg_name)
{
	e2k_rt_msi_h_t rt_msi_h;

	AW(rt_msi_h) = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x]\n",
		   __func__, node_id, (write) ? "write" : "read",
		   reg_name, reg_offset, rt_msi_h.bgn);
}

static inline void
nbsr_debug_dump_iommu(int node_id, unsigned int reg_offset, unsigned long val,
		      bool write, char *reg_name, bool dword)
{
	nbsr_debug("%s(): node #%d %svalue 0x%lx %s %s 0x%04x\n",
		   __func__, node_id, (dword) ? "64-bit " : "", val,
		   (write) ? "write to" : "read from", reg_name, reg_offset);
}

static inline void
nbsr_debug_dump_pmc(int node_id, unsigned int reg_offset, bool write,
		    unsigned int reg_value, char *reg_name)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x\n",
		   __func__, node_id, (write) ? "write" : "read", reg_name,
		   reg_offset);
}

static inline void
nbsr_debug_dump_l3(int node_id, unsigned int reg_offset, bool write,
		   unsigned int reg_value, char *reg_name)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x\n",
		   __func__, node_id, (write) ? "write" : "read", reg_name,
		   reg_offset);
}

static inline void
nbsr_debug_dump_prepic(int node_id, unsigned int reg_offset,
		       unsigned int val, bool write, char *reg_name)
{
	nbsr_debug("%s(): node #%d 32-bit value 0x%x %s %s 0x%04x\n",
		   __func__, node_id, val, (write) ? "write to" : "read from",
		   reg_name, reg_offset);
}

static inline int
node_nbsr_reg_get(struct kvm_nbsr *nbsr, int node_id, unsigned int reg_offset,
				u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[node_id];

	*reg_val = node_nbsr->regs[offset_to_no(reg_offset)];

	return 0;
}

static inline int
node_nbsr_reg_set(struct kvm_nbsr *nbsr, int node, unsigned int reg_offset,
				u32 reg_val)
{
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[node];

	node_nbsr->regs[offset_to_no(reg_offset)] = reg_val;

	return 0;
}

static inline int
node_nbsr_reg_set_writemask(struct kvm_nbsr *nbsr, int node_id, unsigned int reg_offset,
				u32 mask_val)
{
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[node_id];

	node_nbsr->write_mask[offset_to_no(reg_offset)] = mask_val;
	return 0;
}

static inline int
node_nbsr_reg_read(struct kvm_nbsr *nbsr, int node_id, unsigned int reg_offset,
				u32 *reg_val)
{
	return node_nbsr_reg_get(nbsr, node_id, reg_offset, reg_val);
}

static inline int
node_nbsr_reg_write(struct kvm_nbsr *nbsr, int node_id, unsigned int reg_offset,
				u32 reg_val)
{
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[node_id];
	u32 write_mask = node_nbsr->write_mask[offset_to_no(reg_offset)];

	return node_nbsr_reg_set(nbsr, node_id, reg_offset, reg_val & write_mask);
}

static int node_nbsr_read_rt_mem(struct kvm_nbsr *nbsr, int node_id,
				 unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";
	bool is_rt_mhi = false;

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_mlo0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mlo0, reg_val);
		reg_name = "rt_mlo0";
		break;
	case SIC_rt_mlo1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mlo1, reg_val);
		reg_name = "rt_mlo1";
		break;
	case SIC_rt_mlo2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mlo2, reg_val);
		reg_name = "rt_mlo2";
		break;
	case SIC_rt_mlo3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mlo3, reg_val);
		reg_name = "rt_mlo3";
		break;
	case SIC_rt_mhi0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mhi0, reg_val);
		reg_name = "rt_mhi0";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mhi1, reg_val);
		reg_name = "rt_mhi1";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mhi2, reg_val);
		reg_name = "rt_mhi2";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_mhi3, reg_val);
		reg_name = "rt_mhi3";
		is_rt_mhi = true;
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	if (is_rt_mhi) {
		nbsr_debug_dump_rt_mhi(node_id, reg_offset, false, *reg_val, reg_name);
	} else {
		nbsr_debug_dump_rt_mlo(node_id, reg_offset, false, *reg_val, reg_name);
	}

	return 0;
}

static int node_nbsr_write_rt_mem(struct kvm_nbsr *nbsr, int node_id,
				   unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";
	bool is_rt_mhi = false;

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_mlo0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mlo0, reg_value);
		reg_name = "rt_mlo0";
		break;
	case SIC_rt_mlo1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mlo1, reg_value);
		reg_name = "rt_mlo1";
		break;
	case SIC_rt_mlo2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mlo2, reg_value);
		reg_name = "rt_mlo2";
		break;
	case SIC_rt_mlo3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mlo3, reg_value);
		reg_name = "rt_mlo3";
		break;
	case SIC_rt_mhi0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mhi0, reg_value);
		reg_name = "rt_mhi0";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mhi1, reg_value);
		reg_name = "rt_mhi1";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mhi2, reg_value);
		reg_name = "rt_mhi2";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_mhi3, reg_value);
		reg_name = "rt_mhi3";
		is_rt_mhi = true;
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	if (is_rt_mhi) {
		nbsr_debug_dump_rt_mhi(node_id, reg_offset, true, reg_value, reg_name);
	} else {
		nbsr_debug_dump_rt_mlo(node_id, reg_offset, true, reg_value, reg_name);
	}
	return 0;
}

static int node_nbsr_read_rt_lcfg(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_lcfg0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_lcfg0, reg_val);
		reg_name = "rt_lcfg0";
		break;
	case SIC_rt_lcfg1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_lcfg1, reg_val);
		reg_name = "rt_lcfg1";
		break;
	case SIC_rt_lcfg2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_lcfg2, reg_val);
		reg_name = "rt_lcfg2";
		break;
	case SIC_rt_lcfg3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_lcfg3, reg_val);
		reg_name = "rt_lcfg3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_lcfg(node_id, reg_offset, false, *reg_val, reg_name);
	return 0;
}

static int node_nbsr_write_rt_lcfg(struct kvm_nbsr *nbsr, int node_id,
				    unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_lcfg0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_lcfg0, reg_value);
		reg_name = "rt_lcfg0";
		break;
	case SIC_rt_lcfg1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_lcfg1, reg_value);
		reg_name = "rt_lcfg1";
		break;
	case SIC_rt_lcfg2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_lcfg2, reg_value);
		reg_name = "rt_lcfg2";
		break;
	case SIC_rt_lcfg3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_lcfg3, reg_value);
		reg_name = "rt_lcfg3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_lcfg(node_id, reg_offset, true, reg_value, reg_name);
	return 0;
}

static int node_nbsr_read_rt_pcim(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcim0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim0, reg_val);
		reg_name = "rt_pcim0";
		break;
	case SIC_rt_pcim1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim1, reg_val);
		reg_name = "rt_pcim1";
		break;
	case SIC_rt_pcim2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim2, reg_val);
		reg_name = "rt_pcim2";
		break;
	case SIC_rt_pcim3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim3, reg_val);
		reg_name = "rt_pcim3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcim(node_id, reg_offset, false, *reg_val, reg_name);
	return 0;
}

static int node_nbsr_write_rt_pcim(struct kvm_nbsr *nbsr, int node_id,
				    unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcim0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0, reg_value);
		reg_name = "rt_pcim0";
		break;
	case SIC_rt_pcim1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim1, reg_value);
		reg_name = "rt_pcim1";
		break;
	case SIC_rt_pcim2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim2, reg_value);
		reg_name = "rt_pcim2";
		break;
	case SIC_rt_pcim3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim3, reg_value);
		reg_name = "rt_pcim3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcim(node_id, reg_offset, true, reg_value, reg_name);
	return -EOPNOTSUPP;
}

static int node_nbsr_read_rt_pciio(struct kvm_nbsr *nbsr, int node_id,
				   unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pciio0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio0, reg_val);
		reg_name = "rt_pciio0";
		break;
	case SIC_rt_pciio1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio1, reg_val);
		reg_name = "rt_pciio1";
		break;
	case SIC_rt_pciio2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio2, reg_val);
		reg_name = "rt_pciio2";
		break;
	case SIC_rt_pciio3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio3, reg_val);
		reg_name = "rt_pciio3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pciio(node_id, reg_offset, false, *reg_val, reg_name,
				 nbsr->iset_no);
	return 0;
}

static int node_nbsr_write_rt_pciio(struct kvm_nbsr *nbsr, int node_id,
				     unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pciio0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pciio0, reg_value);
		reg_name = "rt_pciio0";
		break;
	case SIC_rt_pciio1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pciio1, reg_value);
		reg_name = "rt_pciio1";
		break;
	case SIC_rt_pciio2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pciio2, reg_value);
		reg_name = "rt_pciio2";
		break;
	case SIC_rt_pciio3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pciio3, reg_value);
		reg_name = "rt_pciio3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pciio(node_id, reg_offset, true, reg_value, reg_name,
				 nbsr->iset_no);
	return -EOPNOTSUPP;
}

static int node_nbsr_read_rt_pcim_xmu(struct kvm_nbsr *nbsr, int node_id,
				      char xmu_k, u32 *reg_val)
{
	unsigned int reg_offset;
	char *reg_name;

	mutex_lock(&nbsr->lock);
	switch (xmu_k) {
	case RT_XMU_l:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim0_xmu_l, reg_val);
		reg_offset = SIC_rt_pcim0_xmu_l;
		reg_name = "SIC_rt_pcim0_xmu_l";
		break;
	case RT_XMU_a:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim0_xmu_a, reg_val);
		reg_offset = SIC_rt_pcim0_xmu_a;
		reg_name = "SIC_rt_pcim0_xmu_a";
		break;
	case RT_XMU_b:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim0_xmu_b, reg_val);
		reg_offset = SIC_rt_pcim0_xmu_b;
		reg_name = "SIC_rt_pcim0_xmu_b";
		break;
	case RT_XMU_c:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim0_xmu_c, reg_val);
		reg_offset = SIC_rt_pcim0_xmu_c;
		reg_name = "SIC_rt_pcim0_xmu_c";
		break;
	case RT_XMU_d:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcim0_xmu_d, reg_val);
		reg_offset = SIC_rt_pcim0_xmu_d;
		reg_name = "SIC_rt_pcim0_xmu_d";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with XMU_%c 0x%x is not yet supported, so return 0x%x\n",
		       __func__, node_id, xmu_k, xmu_k, *reg_val);
		reg_offset = xmu_k;
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcim_xmu(node_id, reg_offset, false, *reg_val, reg_name);

	return 0;
}


static int node_nbsr_write_rt_pcim_xmu(struct kvm_nbsr *nbsr, int node_id,
					char xmu_k, u32 reg_value)
{
	unsigned int reg_offset;
	char *reg_name;

	mutex_lock(&nbsr->lock);
	switch (xmu_k) {
	case RT_XMU_l:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_l, reg_value);
		reg_offset = SIC_rt_pcim0_xmu_l;
		reg_name = "rt_pcim0_xmu_l";
		break;
	case RT_XMU_a:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_a, reg_value);
		reg_offset = SIC_rt_pcim0_xmu_a;
		reg_name = "rt_pcim0_xmu_a";
		break;
	case RT_XMU_b:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_b, reg_value);
		reg_offset = SIC_rt_pcim0_xmu_b;
		reg_name = "rt_pcim0_xmu_b";
		break;
	case RT_XMU_c:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_c, reg_value);
		reg_offset = SIC_rt_pcim0_xmu_c;
		reg_name = "rt_pcim0_xmu_c";
		break;
	case RT_XMU_d:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_d, reg_value);
		reg_offset = SIC_rt_pcim0_xmu_d;
		reg_name = "rt_pcim0_xmu_d";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with XMU_%c 0x%x is not yet supported, so ignore write\n",
		       __func__, node_id, xmu_k, xmu_k);
		reg_offset = xmu_k;
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcim_xmu(node_id, reg_offset, true, reg_value, reg_name);
	return -EOPNOTSUPP;
}

static int node_nbsr_read_rt_pciio_xmu(struct kvm_nbsr *nbsr, int node_id,
				       char xmu_k, u32 *reg_val)
{
	unsigned int reg_offset;
	char *reg_name;

	mutex_lock(&nbsr->lock);
	switch (xmu_k) {
	case RT_XMU_l:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio0_xmu_l, reg_val);
		reg_offset = SIC_rt_pciio0_xmu_l;
		reg_name = "rt_pciio0_xmu_l";
		break;
	case RT_XMU_a:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio0_xmu_a, reg_val);
		reg_offset = SIC_rt_pciio0_xmu_a;
		reg_name = "rt_pciio0_xmu_a";
		break;
	case RT_XMU_b:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio0_xmu_b, reg_val);
		reg_offset = SIC_rt_pciio0_xmu_b;
		reg_name = "rt_pciio0_xmu_b";
		break;
	case RT_XMU_c:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio0_xmu_c, reg_val);
		reg_offset = SIC_rt_pciio0_xmu_c;
		reg_name = "rt_pciio0_xmu_c";
		break;
	case RT_XMU_d:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pciio0_xmu_d, reg_val);
		reg_offset = SIC_rt_pciio0_xmu_d;
		reg_name = "rt_pciio0_xmu_d";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with XMU_%c 0x%x is not yet supported, so return 0x%x\n",
		       __func__, node_id, xmu_k, xmu_k, *reg_val);
		reg_offset = xmu_k;
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pciio_xmu(node_id, reg_offset, false, *reg_val, reg_name);

	return 0;
}

static int node_nbsr_write_rt_pciio_xmu(struct kvm_nbsr *nbsr, int node_id,
					 char xmu_k, u32 reg_value)
{
	unsigned int reg_offset;
	char *reg_name;

	mutex_lock(&nbsr->lock);
	switch (xmu_k) {
	case RT_XMU_l:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_l, reg_value);
		reg_offset = SIC_rt_pciio0_xmu_l;
		reg_name = "rt_pciio0_xmu_l";
		break;
	case RT_XMU_a:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_a, reg_value);
		reg_offset = SIC_rt_pciio0_xmu_a;
		reg_name = "rt_pciio0_xmu_a";
		break;
	case RT_XMU_b:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_b, reg_value);
		reg_offset = SIC_rt_pciio0_xmu_b;
		reg_name = "rt_pciio0_xmu_b";
		break;
	case RT_XMU_c:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_c, reg_value);
		reg_offset = SIC_rt_pciio0_xmu_b;
		reg_name = "rt_pciio0_xmu_c";
		break;
	case RT_XMU_d:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcim0_xmu_d, reg_value);
		reg_offset = SIC_rt_pciio0_xmu_b;
		reg_name = "rt_pciio0_xmu_d";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with XMU_%c 0x%x is not yet supported, so ignore write\n",
		       __func__, node_id, xmu_k, xmu_k);
		reg_offset = xmu_k;
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pciio_xmu(node_id, reg_offset, true, reg_value, reg_name);
	return -EOPNOTSUPP;
}

static int node_nbsr_read_rt_pcimp_b(struct kvm_nbsr *nbsr, int node_id,
				     unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_b0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_b0, reg_val);
		reg_name = "rt_pcimp_b0";
		break;
	case SIC_rt_pcimp_b1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_b1, reg_val);
		reg_name = "rt_pcimp_b1";
		break;
	case SIC_rt_pcimp_b2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_b2, reg_val);
		reg_name = "rt_pcimp_b2";
		break;
	case SIC_rt_pcimp_b3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_b3, reg_val);
		reg_name = "rt_pcimp_b3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, false, *reg_val, reg_name, false);
	return 0;
}

static int node_nbsr_read_rt_pcimp_e(struct kvm_nbsr *nbsr, int node_id,
				     unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_e0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_e0, reg_val);
		reg_name = "rt_pcimp_e0";
		break;
	case SIC_rt_pcimp_e1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_e1, reg_val);
		reg_name = "rt_pcimp_e1";
		break;
	case SIC_rt_pcimp_e2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_e2, reg_val);
		reg_name = "rt_pcimp_e2";
		break;
	case SIC_rt_pcimp_e3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp_e3, reg_val);
		reg_name = "rt_pcimp_e3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, false, *reg_val, reg_name, true);
	return 0;
}

static int node_nbsr_read_rt_pcimp_b_xmu(struct kvm_nbsr *nbsr, int node_id,
					 char xmu_k, u32 *reg_val)
{
	unsigned int reg_offset;
	char *reg_name;

	mutex_lock(&nbsr->lock);
	switch (xmu_k) {
	case RT_XMU_l:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_l_bgn, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_l_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_l_bgn";
		break;
	case RT_XMU_a:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_a_bgn, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_a_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_a_bgn";
		break;
	case RT_XMU_b:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_b_bgn, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_b_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_b_bgn";
		break;
	case RT_XMU_c:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_c_bgn, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_c_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_c_bgn";
		break;
	case RT_XMU_d:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_d_bgn, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_d_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_d_bgn";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with XMU_%c 0x%x is not yet supported, so return 0x%x\n",
		       __func__, node_id, xmu_k, xmu_k, *reg_val);
		reg_offset = xmu_k;
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp_xmu(node_id, reg_offset, false, *reg_val, reg_name, false);

	return 0;
}

static int node_nbsr_write_rt_pcimp_b_xmu(struct kvm_nbsr *nbsr, int node_id,
					   char xmu_k, u32 reg_value)
{
	unsigned int reg_offset;
	char *reg_name;

	mutex_lock(&nbsr->lock);
	switch (xmu_k) {
	case RT_XMU_l:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp0_xmu_l_bgn, reg_value);
		reg_offset = SIC_rt_pcimp0_xmu_l_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_l_bgn";
		break;
	case RT_XMU_a:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp0_xmu_a_bgn, reg_value);
		reg_offset = SIC_rt_pcimp0_xmu_a_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_a_bgn";
		break;
	case RT_XMU_b:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp0_xmu_b_bgn, reg_value);
		reg_offset = SIC_rt_pcimp0_xmu_b_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_b_bgn";
		break;
	case RT_XMU_c:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp0_xmu_c_bgn, reg_value);
		reg_offset = SIC_rt_pcimp0_xmu_c_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_c_bgn";
		break;
	case RT_XMU_d:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp0_xmu_d_bgn, reg_value);
		reg_offset = SIC_rt_pcimp0_xmu_d_bgn;
		reg_name = "SIC_rt_pcimp0_xmu_d_bgn";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with XMU_%c 0x%x is not yet supported, so ignore write\n",
		       __func__, node_id, xmu_k, xmu_k);
		reg_offset = xmu_k;
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp_xmu(node_id, reg_offset, true, reg_value, reg_name, false);
	return -EOPNOTSUPP;
}

static int node_nbsr_read_rt_pcimp_e_xmu(struct kvm_nbsr *nbsr, int node_id,
					 char xmu_k, u32 *reg_val)
{
	unsigned int reg_offset;
	char *reg_name;

	mutex_lock(&nbsr->lock);
	switch (xmu_k) {
	case RT_XMU_l:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_l_end, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_l_end;
		reg_name = "SIC_rt_pcimp0_xmu_l_end";
		break;
	case RT_XMU_a:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_a_end, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_a_end;
		reg_name = "SIC_rt_pcimp0_xmu_a_end";
		break;
	case RT_XMU_b:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_b_end, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_b_end;
		reg_name = "SIC_rt_pcimp0_xmu_b_end";
		break;
	case RT_XMU_c:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_c_end, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_c_end;
		reg_name = "SIC_rt_pcimp0_xmu_c_end";
		break;
	case RT_XMU_d:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcimp0_xmu_d_end, reg_val);
		reg_offset = SIC_rt_pcimp0_xmu_d_end;
		reg_name = "SIC_rt_pcimp0_xmu_d_end";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with XMU_%c 0x%x is not yet supported, so return 0x%x\n",
		       __func__, node_id, xmu_k, xmu_k, *reg_val);
		reg_offset = xmu_k;
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp_xmu(node_id, reg_offset, false, *reg_val, reg_name, true);

	return 0;
}

static int node_nbsr_write_rt_pcimp_e_xmu(struct kvm_nbsr *nbsr, int node_id,
					   char xmu_k, u32 reg_value)
{
	nbsr_debug("%s(): node #%d write SIC_esclkr value 0x%x ignored\n",
		   __func__, node_id, reg_value);
	return -EOPNOTSUPP;
}

static int node_nbsr_write_esclkr(struct kvm_nbsr *nbsr, int node_id,
					   u32 reg_value)
{
	nbsr_debug("%s(): node #%d write SIC_esclkr value 0x%x ignored\n",
		   __func__, node_id, reg_value);
	return 0;
}

static int node_nbsr_read_rt_pcicfgb(struct kvm_nbsr *nbsr, int node_id,
				     unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name;

	mutex_lock(&nbsr->lock);
	node_nbsr_reg_read(nbsr, node_id, SIC_rt_pcicfgb, reg_val);
	if (nbsr->iset_no >= E2K_ISET_V7) {
		reg_name = "rt_pcicfg_bgn";
	} else {
		reg_name = "rt_pcicfgb";
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcicfgb(node_id, reg_offset, false, *reg_val, reg_name);
	return 0;
}

static int node_nbsr_write_rt_pcimp_b(struct kvm_nbsr *nbsr, int node_id,
				       unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_b0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_b0, reg_value);
		reg_name = "rt_pcimp_b0";
		break;
	case SIC_rt_pcimp_b1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_b1, reg_value);
		reg_name = "rt_pcimp_b1";
		break;
	case SIC_rt_pcimp_b2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_b2, reg_value);
		reg_name = "rt_pcimp_b2";
		break;
	case SIC_rt_pcimp_b3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_b3, reg_value);
		reg_name = "rt_pcimp_b3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, true, reg_value, reg_name, false);
	return -EOPNOTSUPP;
}

static int node_nbsr_write_rt_pcimp_e(struct kvm_nbsr *nbsr, int node_id,
				       unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_e0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_e0, reg_value);
		reg_name = "rt_pcimp_e0";
		break;
	case SIC_rt_pcimp_e1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_e1, reg_value);
		reg_name = "rt_pcimp_e1";
		break;
	case SIC_rt_pcimp_e2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_e2, reg_value);
		reg_name = "rt_pcimp_e2";
		break;
	case SIC_rt_pcimp_e3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcimp_e3, reg_value);
		reg_name = "rt_pcimp_e3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, true, reg_value, reg_name, true);
	return -EOPNOTSUPP;
}

static int node_nbsr_write_rt_pcicfgb(struct kvm_nbsr *nbsr, int node_id,
				       unsigned int reg_offset, u32 reg_value)
{
	char *reg_name;

	mutex_lock(&nbsr->lock);
	node_nbsr_reg_write(nbsr, node_id, SIC_rt_pcicfgb, reg_value);
	if (nbsr->iset_no >= E2K_ISET_V7) {
		reg_name = "rt_pcicfg_bgn";
	} else {
		reg_name = "rt_pcicfgb";
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcicfgb(node_id, reg_offset, true, reg_value, reg_name);
	return -EOPNOTSUPP;
}

static int node_nbsr_read_rt_ioapic(struct kvm_nbsr *nbsr, int node_id,
				    unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_ioapic0:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_ioapic0, reg_val);
		reg_name = "rt_ioapic0";
		break;
	case SIC_rt_ioapic1:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_ioapic1, reg_val);
		reg_name = "rt_ioapic1";
		break;
	case SIC_rt_ioapic2:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_ioapic2, reg_val);
		reg_name = "rt_ioapic2";
		break;
	case SIC_rt_ioapic3:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_ioapic3, reg_val);
		reg_name = "rt_ioapic3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_ioapic(node_id, reg_offset, false, *reg_val, reg_name);
	return 0;
}

static int node_nbsr_write_rt_ioapic(struct kvm_nbsr *nbsr, int node_id,
				      unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_ioapic0:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_ioapic0, reg_value);
		reg_name = "rt_ioapic0";
		break;
	case SIC_rt_ioapic1:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_ioapic1, reg_value);
		reg_name = "rt_ioapic1";
		break;
	case SIC_rt_ioapic2:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_ioapic2, reg_value);
		reg_name = "rt_ioapic2";
		break;
	case SIC_rt_ioapic3:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_ioapic3, reg_value);
		reg_name = "rt_ioapic3";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_ioapic(node_id, reg_offset, true, reg_value, reg_name);
	return 0;
}

static int node_nbsr_read_rt_msi(struct kvm_nbsr *nbsr, int node_id,
				 unsigned int reg_offset, u32 *reg_val)
{
	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_msi:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_msi, reg_val);
		nbsr_debug_dump_rt_msi(node_id, reg_offset, false, *reg_val, "rt_msi");
		break;
	case SIC_rt_msi_h:
		node_nbsr_reg_read(nbsr, node_id, SIC_rt_msi_h, reg_val);
		nbsr_debug_dump_rt_msi_h(node_id, reg_offset, false, *reg_val, "rt_msi_h");
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	return 0;
}

static int node_nbsr_read_pmc_info(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	e2k_idr_t idr = read_IDR_reg();
	u8 mdl = idr.mdl;
	u8 rev = idr.rev;

	*reg_val = rev << 8 | mdl;

	return 0;
}

static int node_nbsr_read_pmc(struct kvm_nbsr *nbsr, int node_id,
			      unsigned int reg_offset, u32 *reg_val)
{
	mutex_lock(&nbsr->lock);
	node_nbsr_reg_read(nbsr, node_id, reg_offset, reg_val);
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_pmc(node_id, reg_offset, false, *reg_val, "pmc_sleep");

	return 0;
}

static int node_nbsr_read_l3(struct kvm_nbsr *nbsr, int node_id,
			     unsigned int reg_offset, u32 *reg_val)
{
	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_l3_ctrl:
		node_nbsr_reg_read(nbsr, node_id, SIC_l3_ctrl, reg_val);
		nbsr_debug_dump_l3(node_id, reg_offset, false, *reg_val, "l3_ctrl");
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	return 0;
}

static int node_nbsr_read_iommu(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";
	int ret;

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	/* SIC_iommu_err is emulated only in qemu */
	case SIC_iommu_err:
		ret = -EOPNOTSUPP;
		reg_name = "iommu_err";
		break;
	/* SIC_iommu_err_info_hi is emulated only in qemu */
	case SIC_iommu_err_info_lo:
		ret = -EOPNOTSUPP;
		reg_name = "iommu_err_info";
		break;
	case SIC_iommu_mcr:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mcr, reg_val);
		reg_name = "iommu_mcr";
		break;
	case SIC_iommu_mid:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mid, reg_val);
		reg_name = "iommu_mid";
		break;
	case SIC_iommu_mar0_lo:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar0_lo, reg_val);
		reg_name = "iommu_mar0_lo";
		break;
	case SIC_iommu_mar0_hi:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar0_hi, reg_val);
		reg_name = "iommu_mar0_hi";
		break;
	case SIC_iommu_mar1_lo:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar1_lo, reg_val);
		reg_name = "iommu_mar1_lo";
		break;
	case SIC_iommu_mar1_hi:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar1_hi, reg_val);
		reg_name = "iommu_mar1_hi";
		break;
	default:
		WARN_ON_ONCE(1);
		ret = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_iommu(node_id, reg_offset, false, *reg_val, reg_name, false);
	return ret;
}

static int node_nbsr_readll_iommu(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u64 *reg_val)
{
	char *reg_name = "???";
	int ret;
	u32 reg_lo, reg_hi;

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_iommu_ba_lo:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_ba_lo, &reg_lo);
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_ba_hi, &reg_hi);
		*reg_val = reg_lo | ((u64)reg_hi << 32);
		reg_name = "iommu_ba";
		break;
	case SIC_iommu_dtba_lo:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_dtba_lo, &reg_lo);
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_dtba_hi, &reg_hi);
		*reg_val = reg_lo | ((u64)reg_hi << 32);
		reg_name = "iommu_dtba";
		break;
		/* SIC_iommu_err is emulated only in qemu */
	case SIC_iommu_err:
		ret = -EOPNOTSUPP;
		reg_name = "iommu_err";
		break;
		/* SIC_iommu_err_info_hi is emulated only in qemu */
	case SIC_iommu_err_info_lo:
		ret = -EOPNOTSUPP;
		reg_name = "iommu_err_info";
		break;
	case SIC_iommu_mcr:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mcr, &reg_lo);
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mid, &reg_hi);
		*reg_val = reg_lo | ((u64)reg_hi << 32);
		reg_name = "iommu_mcr";
		break;
	case SIC_iommu_mar0_lo:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar0_lo, &reg_lo);
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar0_hi, &reg_hi);
		*reg_val = reg_lo | ((u64)reg_hi << 32);
		reg_name = "iommu_mar0";
		break;
	case SIC_iommu_mar1_lo:
		ret = 0;
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar1_lo, &reg_lo);
		node_nbsr_reg_read(nbsr, node_id, SIC_iommu_mar1_hi, &reg_hi);
		*reg_val = reg_lo | ((u64)reg_hi << 32);
		reg_name = "iommu_mar1";
		break;
	default:
		WARN_ON_ONCE(1);
		ret = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_iommu(node_id, reg_offset, false, *reg_val, reg_name, true);
	return ret;
}

static int node_nbsr_read_prepic(struct kvm_nbsr *nbsr, int node_id,
				 unsigned int reg_offset, u32 *reg_val)
{
	char *reg_name = "???";
	int ret = 0;

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_prepic_ctrl2:
		node_nbsr_reg_read(nbsr, node_id, SIC_prepic_ctrl2, reg_val);
		reg_name = "prepic_ctrl2";
		break;
		/* Registers SIC_prepic_err_stat is emulated only in qemu */
	case SIC_prepic_err_stat:
		ret = -EOPNOTSUPP;
		reg_name = "prepic_err_stat";
		break;
		/* Registers SIC_prepic_err_int is emulated only in qemu */
	case SIC_prepic_err_int:
		ret = -EOPNOTSUPP;
		reg_name = "prepic_err_int";
		break;
	case SIC_prepic_linp0:
		node_nbsr_reg_read(nbsr, node_id, SIC_prepic_linp0, reg_val);
		reg_name = "prepic_linp0";
		break;
	case SIC_prepic_linp1:
		node_nbsr_reg_read(nbsr, node_id, SIC_prepic_linp1, reg_val);
		reg_name = "prepic_linp1";
		break;
	case SIC_prepic_linp2:
		node_nbsr_reg_read(nbsr, node_id, SIC_prepic_linp2, reg_val);
		reg_name = "prepic_linp2";
		break;
	case SIC_prepic_linp3:
		node_nbsr_reg_read(nbsr, node_id, SIC_prepic_linp3, reg_val);
		reg_name = "prepic_linp3";
		break;
	case SIC_prepic_linp4:
		node_nbsr_reg_read(nbsr, node_id, SIC_prepic_linp4, reg_val);
		reg_name = "prepic_linp4";
		break;
	case SIC_prepic_linp5:
		node_nbsr_reg_read(nbsr, node_id, SIC_prepic_linp5, reg_val);
		reg_name = "prepic_linp5";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_prepic(node_id, reg_offset, false, *reg_val, reg_name);
	return ret;
}

static int node_nbsr_read_mc_ecc(const struct kvm_vcpu *vcpu, u32 *reg_val)
{
	/* Return ECC with disabled checking */
	*reg_val = AW(E2K_MC_ECC_DISABLED);
	return 0;
}

static int node_nbsr_read_stp(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 *reg_val)
{
	e2k_idr_t idr = read_IDR_reg();
	u8 type = 0x2;
	u8 id = idr.mdl;
	e2k_rt_lcfg_t rt_lcfg0;
	node_nbsr_reg_read(nbsr, node_id, SIC_rt_lcfg0, &AW(rt_lcfg0));
	u8 pn = rt_lcfg0.pln;
	u8 pl_val = 0x7;
	u8 mlc = 0x0;
	u8 mlp = 0x0;
	u8 coh_on = 0x0;

	*reg_val = type | id << 4 | pn << 12 | coh_on << 20 | pl_val << 23 | mlc << 24 | mlp << 25;

	return 0;
}

static int node_nbsr_write_stp(struct kvm_nbsr *nbsr, int node_id,
				   unsigned int reg_offset, u32 reg_value)
{
	return 0;
}

static int node_nbsr_read_efuse(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[node_id];
	u32 efuse_addr;

	mutex_lock(&nbsr->lock);
	node_nbsr_reg_read(nbsr, node_id, EFUSE_RAM_ADDR, &efuse_addr);
	*reg_val = node_nbsr->efuse_ram[offset_to_no(efuse_addr & 0xff)];
	mutex_unlock(&nbsr->lock);

	return 0;
}

static int node_nbsr_write_efuse(struct kvm_nbsr *nbsr, int node_id,
				   unsigned int reg_offset, u32 reg_value)
{
	return 0;
}

static int node_nbsr_read_generic(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 *reg_val)
{
	mutex_lock(&nbsr->lock);
	node_nbsr_reg_read(nbsr, node_id, reg_offset, reg_val);
	mutex_unlock(&nbsr->lock);

	return 0;
}


static int node_nbsr_write_generic(struct kvm_nbsr *nbsr, int node_id,
				   unsigned int reg_offset, u32 reg_value)
{
	mutex_lock(&nbsr->lock);
	node_nbsr_reg_write(nbsr, node_id, reg_offset, reg_value);
	mutex_unlock(&nbsr->lock);

	return 0;
}

static int node_nbsr_write_rt_msi(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 reg_value)
{
	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_msi:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_msi, reg_value);
		nbsr_debug_dump_rt_msi(node_id, reg_offset, true, reg_value, "rt_msi");
		break;
	case SIC_rt_msi_h:
		node_nbsr_reg_write(nbsr, node_id, SIC_rt_msi_h, reg_value);
		nbsr_debug_dump_rt_msi_h(node_id, reg_offset, true, reg_value, "rt_msi_h");
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	return -EOPNOTSUPP;
}

static void nbsr_update_iommu_tdp(struct kvm *kvm, struct kvm_nbsr *nbsr, int node_id)
{
	u32 ctrl, ba_hi, ba_lo;
	u64 ptbar;

	node_nbsr_reg_read(nbsr, node_id, SIC_iommu_ctrl, &ctrl);
	node_nbsr_reg_read(nbsr, node_id, SIC_iommu_ba_hi, &ba_hi);
	node_nbsr_reg_read(nbsr, node_id, SIC_iommu_ba_lo, &ba_lo);

	ptbar = (u64) ba_hi << 32 | ba_lo;

	kvm_iommu_write_ctrl_ptbar(kvm, ctrl, ptbar);
}

static int node_nbsr_write_iommu(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = NULL;
	int ret = 0;

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_iommu_ctrl:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_ctrl, reg_value);
		nbsr_update_iommu_tdp(nbsr->kvm, nbsr, node_id);
		reg_name = "iommu_ctrl";
		ret = -EOPNOTSUPP;
		break;
	/* SIC_iommu_err is emulated only in qemu */
	case SIC_iommu_err:
	case SIC_iommu_err1:
		ret = -EOPNOTSUPP;
		reg_name = "iommu_err";
		break;
	/* SIC_iommu_err_info_hi is emulated only in qemu */
	case SIC_iommu_err_info_lo:
	case SIC_iommu_err_info_hi:
		ret = -EOPNOTSUPP;
		reg_name = "iommu_err_info";
		break;
	case SIC_iommu_mcr:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mcr, reg_value);
		reg_name = "iommu_mcr";
		break;
	case SIC_iommu_mid:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mid, reg_value);
		reg_name = "iommu_mid";
		break;
	case SIC_iommu_mar0_lo:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar0_lo, reg_value);
		reg_name = "iommu_mar0_lo";
		break;
	case SIC_iommu_mar0_hi:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar0_hi, reg_value);
		reg_name = "iommu_mar0_hi";
		break;
	case SIC_iommu_mar1_lo:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar1_lo, reg_value);
		reg_name = "iommu_mar0_lo";
		break;
	case SIC_iommu_mar1_hi:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar1_hi, reg_value);
		reg_name = "iommu_mar0_hi";
		break;
	default:
		pr_err_ratelimited("%s(): node #%d IOMMU reg with offset 0x%04x does not support 32-bit writes, so ignore it\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_iommu(node_id, reg_offset, reg_value, true, reg_name, false);
	return ret;
}

static u32 kvm_write_pmc_sleep(u32 reg_value)
{
	freq_core_sleep_t fr_state;

	AW(fr_state) = reg_value;
	fr_state.status = 0;	/* Stay in C0 state */

	return AW(fr_state);
}

static int node_nbsr_write_pmc_info(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	return 0;
}

static int node_nbsr_write_pmc(struct kvm_nbsr *nbsr, int node_id,
			       unsigned int reg_offset, u32 reg_value)
{
	mutex_lock(&nbsr->lock);
	node_nbsr_reg_write(nbsr, node_id, reg_offset, kvm_write_pmc_sleep(reg_value));
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_pmc(node_id, reg_offset, reg_value, true, "pmc_sleep");
	return 0;
}

static u32 kvm_write_l3_ctrl(struct kvm_nbsr *nbsr, u32 reg_value)
{
	l3_ctrl_t l3_ctrl;

	AW(l3_ctrl) = reg_value;
	l3_ctrl.fl = 0;		/* No need for L3 flush */

	return AW(l3_ctrl);
}

static int node_nbsr_write_l3(struct kvm_nbsr *nbsr, int node_id,
			      unsigned int reg_offset, u32 reg_value)
{
	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_l3_ctrl:
		node_nbsr_reg_write(nbsr, node_id, SIC_l3_ctrl, kvm_write_l3_ctrl(nbsr, reg_value));
		nbsr_debug_dump_l3(node_id, reg_offset, reg_value, true, "l3_ctrl");
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	return 0;
}

static int node_nbsr_write_prepic(struct kvm_nbsr *nbsr, int node_id,
				  unsigned int reg_offset, u32 reg_value)
{
	char *reg_name = "???";

	mutex_lock(&nbsr->lock);
	/*
	 * TODO: Additional actions when writing to
	 * ctrl2, err_start, err_int ?
	 */
	switch (reg_offset) {
	case SIC_prepic_ctrl2:
		node_nbsr_reg_write(nbsr, node_id, SIC_prepic_ctrl2, reg_value);
		reg_name = "prepic_ctrl2";
		break;
		/* SIC_prepic_err_stat is emulated only in qemu */
	case SIC_prepic_err_stat:
		reg_name = "prepic_err_stat";
		break;
		/* SIC_prepic_err_int is emulated only in qemu */
	case SIC_prepic_err_int:
		reg_name = "prepic_err_int";
		break;
	case SIC_prepic_linp0:
		node_nbsr_reg_write(nbsr, node_id, SIC_prepic_linp0, reg_value);
		reg_name = "prepic_linp0";
		break;
	case SIC_prepic_linp1:
		node_nbsr_reg_write(nbsr, node_id, SIC_prepic_linp1, reg_value);
		reg_name = "prepic_linp1";
		break;
	case SIC_prepic_linp2:
		node_nbsr_reg_write(nbsr, node_id, SIC_prepic_linp2, reg_value);
		reg_name = "prepic_linp2";
		break;
	case SIC_prepic_linp3:
		node_nbsr_reg_write(nbsr, node_id, SIC_prepic_linp3, reg_value);
		reg_name = "prepic_linp3";
		break;
	case SIC_prepic_linp4:
		node_nbsr_reg_write(nbsr, node_id, SIC_prepic_linp4, reg_value);
		reg_name = "prepic_linp4";
		break;
	case SIC_prepic_linp5:
		node_nbsr_reg_write(nbsr, node_id, SIC_prepic_linp5, reg_value);
		reg_name = "prepic_linp5";
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_prepic(node_id, reg_offset, reg_value, true, reg_name);
	return -EOPNOTSUPP;
}

static int node_nbsr_writell_iommu(struct kvm_nbsr *nbsr, int node_id,
				   unsigned int reg_offset, u64 reg_value)
{
	char *reg_name;
	int ret = 0;
	u32 reg_hi, reg_lo;

	reg_lo = reg_value & 0xffffffff;
	reg_hi = reg_value >> 32;

	mutex_lock(&nbsr->lock);
	/* Only *_lo halves 64-bit accesses are supported */
	switch (reg_offset) {
	case SIC_iommu_ba_lo:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_ba_lo, reg_lo);
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_ba_hi, reg_hi);
		nbsr_update_iommu_tdp(nbsr->kvm, nbsr, node_id);
		reg_name = "iommu_ba_lo";
		ret = -EOPNOTSUPP;
		break;
	case SIC_iommu_dtba_lo:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_dtba_lo, reg_lo);
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_dtba_hi, reg_hi);
		reg_name = "iommu_dtba_lo";
		ret = -EOPNOTSUPP;
		break;
	/* No need to forward flushes to qemu */
	case SIC_iommu_flush:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_flush, reg_lo);
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_flushP, reg_hi);
		kvm_iommu_flush(nbsr->kvm, reg_value);
		reg_name = "iommu_flush";
		break;
		/* SIC_iommu_err is emulated only in qemu */
	case SIC_iommu_err:
		reg_name = "iommu_err";
		ret = -EOPNOTSUPP;
		break;
		/* SIC_iommu_err_info is emulated only in qemu */
	case SIC_iommu_err_info_lo:
		reg_name = "iommu_err_info_lo";
		ret = -EOPNOTSUPP;
		break;
	case SIC_iommu_mcr:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mcr, reg_lo);
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mid, reg_lo);
		reg_name = "iommu_mcr";
		break;
	case SIC_iommu_mar0_lo:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar0_lo, reg_lo);
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar0_hi, reg_lo);
		reg_name = "iommu_mar0";
		break;
	case SIC_iommu_mar1_lo:
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar1_lo, reg_lo);
		node_nbsr_reg_write(nbsr, node_id, SIC_iommu_mar1_hi, reg_lo);
		reg_name = "iommu_mar0";
		break;
	default:
		pr_err("%s(): node #%d IOMMU reg with offset 0x%04x does not support 64-bit writes, so ignore it\n",
		       __func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_iommu(node_id, reg_offset, reg_value, true, reg_name, true);

	return ret;
}

static __cold int unsupported_reg_read(char *ver, int node_id, unsigned int reg_offset, u32 *reg_val)
{
	*reg_val = -1;
	pr_err_ratelimited("%s: node #%d NBSR reg with offset 0x%04x is not supported so return 0x%x\n",
			ver, node_id, reg_offset, *reg_val);
	return -EOPNOTSUPP;
}

static int node_nbsr_sic_read_v3(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			      int node_id, unsigned int reg_offset, u32 *reg_val)
{
	switch (reg_offset) {
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		return node_nbsr_read_rt_ioapic(nbsr, node_id, reg_offset, reg_val);
	case SIC_mc0_ecc:
	case SIC_mc1_ecc:
	case SIC_mc2_ecc:
		return node_nbsr_read_mc_ecc(vcpu, reg_val);
	case SIC_hw1:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	default:
		return unsupported_reg_read("v3", node_id, reg_offset, reg_val);
	}
}

static int node_nbsr_sic_read_v4_v5(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			      int node_id, unsigned int reg_offset, u32 *reg_val)
{
	switch (reg_offset) {
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		return node_nbsr_read_rt_ioapic(nbsr, node_id, reg_offset, reg_val);
	case SIC_mc0_ecc:
	case SIC_mc1_ecc:
	case SIC_mc2_ecc:
	case SIC_mc3_ecc:
		return node_nbsr_read_mc_ecc(vcpu, reg_val);
	case SIC_hw1:
	case SIC_pcs_ctrl0:
	case SIC_pcs_ctrl1:
	case SIC_pcs_ctrl2:
	case SIC_pcs_ctrl3:
	case SIC_pcs_ctrl4:
	case SIC_pcs_ctrl5:
	case SIC_pcs_ctrl6:
	case SIC_pcs_ctrl7:
	case SIC_pcs_ctrl8:
	case SIC_pcs_ctrl9:
	case SIC_iol_csr:
	case SIC_io_csr:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	default:
		return unsupported_reg_read("v5", node_id, reg_offset, reg_val);
	}
}

/* Now implement access just for guest of same arch and only one node */
static void  node_nbsr_read_mc_v6_v7(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
				     int node_id, unsigned int reg_offset, u32 *reg_val)
{
	u32 mc_ch;

	if (node_id != 0) {
		*reg_val = 0xffffffff;
		return;
	}
	if (machine.native_id != vcpu->kvm->arch.guest_info.cpu_mdl) {
		*reg_val = 0xffffffff;
		return;
	}
	node_nbsr_read_generic(nbsr, node_id, MC_CH, &mc_ch);
	if (mc_enabled_mask[node_id] & (1 << mc_ch))
		*reg_val = sic_read_node_v7_mc_nbsr_reg(node_id, mc_ch, reg_offset);
	else
		*reg_val = 0;
}

static int node_nbsr_sic_read_v6(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			      int node_id, unsigned int reg_offset, u32 *reg_val)
{
	if (is_pmc_freq_core_mon(reg_offset, false) ||
	    is_pmc_freq_core_ctrl(reg_offset, false) ||
	    is_pmc_freq_graphic_mon(reg_offset, false) ||
	    is_pmc_freq_graphic_ctrl(reg_offset, false))
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);

	if (is_pmc_freq_core_sleep(reg_offset, false))
		return node_nbsr_read_pmc(nbsr, node_id, reg_offset, reg_val);

	switch (reg_offset) {
	case PMC_INFO:
		return node_nbsr_read_pmc_info(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		return node_nbsr_read_rt_ioapic(nbsr, node_id, reg_offset, reg_val);
	case PMC_TERM_CTRL:
	case PMC_TERM_CONV:
	case PMC_TERM_TS0:
	case PMC_TERM_TS1:
	case PMC_TERM_TS2:
	case PMC_TERM_TS3:
	case PMC_TERM_TS4:
	case PMC_TERM_TS5:
	case PMC_TERM_TS6:
	case PMC_TERM_TS7:
	case PMC_FREQ_CFG:
	case PMC_FREQ_STEPS:
	case PMC_FREQ_C2:
	case PMC_FREQ_BND:
	case PMC_FREQ_CORE_FLOAT:
	case PMC_FREQ_OCN_FLOAT:
	case PMC_FREQ_CORE_TABLE0:
	case PMC_FREQ_CORE_TABLE1:
	case PMC_FREQ_CORE_TABLE2:
	case PMC_FREQ_CORE_TABLE3:
	case PMC_FREQ_CORE_TABLE4:
	case PMC_FREQ_CORE_TABLE5:
	case PMC_FREQ_CORE_TABLE6:
	case PMC_FREQ_CORE_TABLE7:
	case PMC_FREQ_OCN_TABLE0:
	case PMC_FREQ_OCN_TABLE1:
	case PMC_FREQ_OCN_TABLE2:
	case PMC_FREQ_OCN_TABLE3:
	case PMC_FREQ_OCN_TABLE4:
	case PMC_FREQ_OCN_TABLE5:
	case PMC_FREQ_OCN_TABLE6:
	case PMC_FREQ_OCN_TABLE7:
	case PMC_FREQ_OCN_MON:
	case PMC_FREQ_OCN_CTRL:
	case PMC_SYS_MON_1:
	case PMC_FAN_CFG:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	case MC_ECC:
		return node_nbsr_read_mc_ecc(vcpu, reg_val);
	case HC_CTRL:
	case MC_CH:
	case HMU_MIC:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	case SIC_st_p:
		return node_nbsr_read_stp(nbsr, node_id, reg_offset, reg_val);
	case SIC_st_core0:
	case SIC_st_core1:
	case SIC_st_core2:
	case SIC_st_core3:
	case SIC_st_core4:
	case SIC_st_core5:
	case SIC_st_core6:
	case SIC_st_core7:
	case SIC_st_core8:
	case SIC_st_core9:
	case SIC_st_core10:
	case SIC_st_core11:
	case SIC_st_core12:
	case SIC_st_core13:
	case SIC_st_core14:
	case SIC_st_core15:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_ln:
	case SIC_rt_pcicfged:
	case SIC_rt_vgamemed:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	case EFUSE_RAM_ADDR:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	case EFUSE_RAM_DATA:
		return node_nbsr_read_efuse(nbsr, node_id, reg_offset, reg_val);
	case MC_CTL :
		node_nbsr_read_mc_v6_v7(vcpu, nbsr, node_id, MC_CTL, reg_val);
		return 0;
	default:
		return unsupported_reg_read("v6", node_id, reg_offset, reg_val);
	}
}

static int node_nbsr_sic_read_v7(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			      int node_id, unsigned int reg_offset, u32 *reg_val)
{
	if (is_pmc_freq_core_mon(reg_offset, true) ||
	    is_pmc_freq_core_ctrl(reg_offset, true) ||
	    is_pmc_freq_graphic_mon(reg_offset, true) ||
	    is_pmc_freq_graphic_ctrl(reg_offset, true))
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);

	if (is_pmc_freq_core_sleep(reg_offset, true))
		return node_nbsr_read_pmc(nbsr, node_id, reg_offset, reg_val);

	switch (reg_offset) {
	case PMC_TERM_CTRL:
	case PMC_TERM_CONV:
	case PMC_TERM_TS0:
	case PMC_TERM_TS1:
	case PMC_TERM_TS2:
	case PMC_TERM_TS3:
	case PMC_TERM_TS4:
	case PMC_TERM_TS5:
	case PMC_TERM_TS6:
	case PMC_TERM_TS7:
	case PMC_FREQ_CFG:
	case PMC_FREQ_STEPS:
	case PMC_FREQ_C2:
	case PMC_FREQ_BND:
	case PMC_FREQ_CORE_FLOAT:
	case PMC_FREQ_OCN_FLOAT:
	case PMC_FREQ_CORE_TABLE0:
	case PMC_FREQ_CORE_TABLE1:
	case PMC_FREQ_CORE_TABLE2:
	case PMC_FREQ_CORE_TABLE3:
	case PMC_FREQ_CORE_TABLE4:
	case PMC_FREQ_CORE_TABLE5:
	case PMC_FREQ_CORE_TABLE6:
	case PMC_FREQ_CORE_TABLE7:
	case PMC_FREQ_OCN_TABLE0:
	case PMC_FREQ_OCN_TABLE1:
	case PMC_FREQ_OCN_TABLE2:
	case PMC_FREQ_OCN_TABLE3:
	case PMC_FREQ_OCN_TABLE4:
	case PMC_FREQ_OCN_TABLE5:
	case PMC_FREQ_OCN_TABLE6:
	case PMC_FREQ_OCN_TABLE7:
	case PMC_FREQ_OCN_MON:
	case PMC_FREQ_OCN_CTRL:
	case PMC_SYS_MON_1:
	case PMC_FAN_CFG:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	case MC_ECC:
		return node_nbsr_read_mc_ecc(vcpu, reg_val);
	case SIC_rt_pcim0_xmu_l:
		return node_nbsr_read_rt_pcim_xmu(nbsr, node_id, RT_XMU_l, reg_val);
	case SIC_rt_pcim0_xmu_a:
		return node_nbsr_read_rt_pcim_xmu(nbsr, node_id, RT_XMU_a, reg_val);
	case SIC_rt_pcim0_xmu_b:
		return node_nbsr_read_rt_pcim_xmu(nbsr, node_id, RT_XMU_b, reg_val);
	case SIC_rt_pcim0_xmu_c:
		return node_nbsr_read_rt_pcim_xmu(nbsr, node_id, RT_XMU_c, reg_val);
	case SIC_rt_pcim0_xmu_d:
		return node_nbsr_read_rt_pcim_xmu(nbsr, node_id, RT_XMU_d, reg_val);
	case SIC_rt_pciio0_xmu_l:
		return node_nbsr_read_rt_pciio_xmu(nbsr, node_id, RT_XMU_l, reg_val);
	case SIC_rt_pciio0_xmu_a:
		return node_nbsr_read_rt_pciio_xmu(nbsr, node_id, RT_XMU_a, reg_val);
	case SIC_rt_pciio0_xmu_b:
		return node_nbsr_read_rt_pciio_xmu(nbsr, node_id, RT_XMU_b, reg_val);
	case SIC_rt_pciio0_xmu_c:
		return node_nbsr_read_rt_pciio_xmu(nbsr, node_id, RT_XMU_c, reg_val);
	case SIC_rt_pciio0_xmu_d:
		return node_nbsr_read_rt_pciio_xmu(nbsr, node_id, RT_XMU_d, reg_val);
	case SIC_rt_pcimp0_xmu_l_bgn:
		return node_nbsr_read_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_l, reg_val);
	case SIC_rt_pcimp0_xmu_a_bgn:
		return node_nbsr_read_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_a, reg_val);
	case SIC_rt_pcimp0_xmu_b_bgn:
		return node_nbsr_read_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_b, reg_val);
	case SIC_rt_pcimp0_xmu_c_bgn:
		return node_nbsr_read_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_c, reg_val);
	case SIC_rt_pcimp0_xmu_d_bgn:
		return node_nbsr_read_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_d, reg_val);
	case SIC_rt_pcimp0_xmu_l_end:
		return node_nbsr_read_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_l, reg_val);
	case SIC_rt_pcimp0_xmu_a_end:
		return node_nbsr_read_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_a, reg_val);
	case SIC_rt_pcimp0_xmu_b_end:
		return node_nbsr_read_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_b, reg_val);
	case SIC_rt_pcimp0_xmu_c_end:
		return node_nbsr_read_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_c, reg_val);
	case SIC_rt_pcimp0_xmu_d_end:
		return node_nbsr_read_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_d, reg_val);
	case HC_CTRL:
	case MC_CH:
	case HMU_MIC:
		return node_nbsr_read_generic(nbsr, node_id, reg_offset, reg_val);
	case MC_CTL :
		node_nbsr_read_mc_v6_v7(vcpu, nbsr, node_id, MC_CTL, reg_val);
		return 0;
	default:
		return unsupported_reg_read("v7", node_id, reg_offset, reg_val);
	}
}



static int node_nbsr_sic_read(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			      int node_id, unsigned int reg_offset, u32 *reg_val)
{
	ASSERT(reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET);

	switch (reg_offset) {
	case SIC_rt_mlo0:
	case SIC_rt_mlo1:
	case SIC_rt_mlo2:
	case SIC_rt_mlo3:
	case SIC_rt_mhi0:
	case SIC_rt_mhi1:
	case SIC_rt_mhi2:
	case SIC_rt_mhi3:
		return node_nbsr_read_rt_mem(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_lcfg0:
	case SIC_rt_lcfg1:
	case SIC_rt_lcfg2:
	case SIC_rt_lcfg3:
		return node_nbsr_read_rt_lcfg(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_pcim0:
	case SIC_rt_pcim1:
	case SIC_rt_pcim2:
	case SIC_rt_pcim3:
		return node_nbsr_read_rt_pcim(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_pciio0:
	case SIC_rt_pciio1:
	case SIC_rt_pciio2:
	case SIC_rt_pciio3:
		return node_nbsr_read_rt_pciio(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_pcimp_b0:
	case SIC_rt_pcimp_b1:
	case SIC_rt_pcimp_b2:
	case SIC_rt_pcimp_b3:
		return node_nbsr_read_rt_pcimp_b(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_pcimp_e0:
	case SIC_rt_pcimp_e1:
	case SIC_rt_pcimp_e2:
	case SIC_rt_pcimp_e3:
		return node_nbsr_read_rt_pcimp_e(nbsr, node_id, reg_offset, reg_val);
	case SIC_rt_pcicfgb:
		return node_nbsr_read_rt_pcicfgb(nbsr, node_id, reg_offset, reg_val);
	case SIC_l3_ctrl:
		return node_nbsr_read_l3(nbsr, node_id, reg_offset, reg_val);
	case SIC_prepic_ctrl2:
	case SIC_prepic_err_stat:
	case SIC_prepic_err_int:
	case SIC_prepic_linp0:
	case SIC_prepic_linp1:
	case SIC_prepic_linp2:
	case SIC_prepic_linp3:
	case SIC_prepic_linp4:
	case SIC_prepic_linp5:
		return node_nbsr_read_prepic(nbsr, node_id, reg_offset, reg_val);
	case SIC_iommu_err:
	case SIC_iommu_err1:
	case SIC_iommu_err_info_lo:
	case SIC_iommu_err_info_hi:
	case SIC_iommu_mcr:
	case SIC_iommu_mid:
	case SIC_iommu_mar0_lo:
	case SIC_iommu_mar0_hi:
	case SIC_iommu_mar1_lo:
	case SIC_iommu_mar1_hi:
		return node_nbsr_read_iommu(nbsr, node_id, reg_offset, reg_val);
	/* These registers are missing on hardware v3-v5, but in virtual CPU
	 * they always exist to provide guest with MSI addresses */
	case SIC_rt_msi:
	case SIC_rt_msi_h:
		return node_nbsr_read_rt_msi(nbsr, node_id, reg_offset, reg_val);
	default:
		/* Not a common register, now try iset-specific ones */
		switch (vcpu->kvm->arch.guest_info.cpu_iset) {
		case 1 ... 3:
			return node_nbsr_sic_read_v3(vcpu, nbsr, node_id, reg_offset, reg_val);
		case 4 ... 5:
			return node_nbsr_sic_read_v4_v5(vcpu, nbsr, node_id, reg_offset, reg_val);
		case 6:
			return node_nbsr_sic_read_v6(vcpu, nbsr, node_id, reg_offset, reg_val);
		case 7:
			return node_nbsr_sic_read_v7(vcpu, nbsr, node_id, reg_offset, reg_val);
		default:
			return unsupported_reg_read("v?", node_id, reg_offset, reg_val);
		}
	}
}

static int node_nbsr_sic_readll(struct kvm_nbsr *nbsr, int node_id,
				unsigned int reg_offset, u64 *reg_val)
{
	ASSERT(reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET);

	switch (reg_offset) {
	case SIC_iommu_ba_lo:
	case SIC_iommu_dtba_lo:
	case SIC_iommu_err:
	case SIC_iommu_err_info_lo:
	case SIC_iommu_mcr:
	case SIC_iommu_mar0_lo:
	case SIC_iommu_mar1_lo:
		return node_nbsr_readll_iommu(nbsr, node_id, reg_offset, reg_val);
	default:
		*reg_val = -1;
		pr_err_ratelimited("%s(): node #%d NBSR reg with offset 0x%04x is not yet supported, so return 0x%llx\n",
			__func__, node_id, reg_offset, *reg_val);
		break;
	}

	return 0;
}


static inline void
nbsr_debug_dump_bc_reg(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value)
{
	nbsr_debug("%s(): node #%d %s BC memory protection register %04x "
		"value %08x\n",
		__func__, node_id, (write) ? "write" : "read ",
		reg_offset, reg_value);
}

static int mpdma_fixup_page_prot(u64 hva, u32 value)
{
	struct vm_area_struct	*vma, *prev;
	struct mm_struct	*mm = current->mm;
	unsigned long		vm_flags;
	struct mmu_gather	tlb;
	int			err = 0;

	mmap_write_lock(mm);

	vma = find_vma_prev(mm, hva, &prev);
	if (!vma || vma->vm_start > hva) {
		mmap_write_unlock(mm);
		return -EINVAL;
	}
	if (hva > vma->vm_start)
		prev = vma;

	if (value) {
		nbsr_warn("%s(): page hva 0x%llx isn't protected\n",
			  __func__, hva);
		vm_flags = (vma->vm_flags & ~VM_MPDMA) | VM_WRITE;
	} else {
		nbsr_warn("%s(): page hva 0x%llx is already protected\n",
			  __func__, hva);
		vm_flags = (vma->vm_flags & ~VM_WRITE) | VM_MPDMA;
	}

	tlb_gather_mmu(&tlb, mm);
	err = mprotect_fixup(&tlb, vma, &prev, hva, hva + PAGE_SIZE, vm_flags);
	tlb_finish_mmu(&tlb);

	mmap_write_unlock(mm);

	return err;
}

static void node_nbsr_write_bc_mp_t_corr(struct kvm_vcpu *vcpu,
					 struct kvm_nbsr *nbsr, int node_id,
					 unsigned int reg_no, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[node_id];
	bc_mp_t_corr_t reg;
	bc_mp_t_corr_h_t hreg;
	u64 gpa, hva;
	u32 value;

	AW(reg) = reg_value;

	if (!reg.corr)
		return;

	AW(hreg) = node_nbsr->bc_regs[reg_no + 1];

	value = reg.value;
	gpa = BC_MP_T_CORR_ADDR(hreg, reg);
	hva = kvm_vcpu_gfn_to_hva(vcpu, gpa_to_gfn(gpa));

	nbsr_debug("%s(): node #%d perform correction for gpa 0x%llx hva 0x%llx to value %d\n",
		__func__, node_id, gpa, hva, value);

	BUG_ON(mpdma_fixup_page_prot(hva, value));

	reg.corr = 0;
	node_nbsr->bc_regs[reg_no] = AW(reg);
}

static void node_nbsr_write_bc_mp_stat(struct kvm_nbsr *nbsr, int node_id,
				       unsigned int reg_no, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[node_id];
	bc_mp_stat_t reg;

	AW(reg) = reg_value;

	if (reg.b_ne)
		reg.b_ne = 0;

	if (reg.b_of)
		reg.b_of = 0;

	node_nbsr->bc_regs[reg_no] = AW(reg);

	nbsr_debug("%s(): node #%d BC_MP_STAT register changed to value 0x%x\n",
		   __func__, node_id, AW(reg));
}

static int node_nbsr_bc_write(struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			       int node_id, unsigned int reg_offset,
			       u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	unsigned int reg_no;

	nbsr_debug_dump_bc_reg(node_id, reg_offset, true, reg_value);

	if (WARN_ON_ONCE(!vcpu || !nbsr_bc_reg_in_range(reg_offset)))
		return -EINVAL;

	reg_no = nbsr_bc_reg_offset_to_no(reg_offset);
	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);

	switch (reg_offset) {
	case BC_MP_T_CORR:
		node_nbsr_write_bc_mp_t_corr(vcpu, nbsr, node_id, reg_no, reg_value);
		break;
	case BC_MP_STAT:
		node_nbsr_write_bc_mp_stat(nbsr, node_id, reg_no, reg_value);
		break;
	default:
		node_nbsr->bc_regs[reg_no] = reg_value;
		break;
	}

	mutex_unlock(&nbsr->lock);

	return 0;
}

static int node_nbsr_bc_read(struct kvm_nbsr *nbsr, int node_id,
			     unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	unsigned int reg_no;

	if (WARN_ON_ONCE(!nbsr_bc_reg_in_range(reg_offset)))
		return -EINVAL;

	reg_no = nbsr_bc_reg_offset_to_no(reg_offset);
	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	*reg_val = node_nbsr->bc_regs[reg_no];
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_bc_reg(node_id, reg_offset, false, *reg_val);

	return 0;
}

static int node_nbsr_read(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			  int node_id, unsigned int reg_offset, u32 *reg_val)
{
	if (!nbsr_is_node_online(nbsr, node_id)) {
		*reg_val = -1;
		pr_err_ratelimited("%s(): node #%d is not online, so return 0x%x for reg offset 0x%04x\n",
			__func__, node_id, *reg_val, reg_offset);
		return 0;
	}

	if (nbsr_bc_reg_in_range(reg_offset)) {
		return node_nbsr_bc_read(nbsr, node_id, reg_offset, reg_val);
	} else if (reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET) {
		return node_nbsr_sic_read(vcpu, nbsr, node_id, reg_offset, reg_val);
	} else {
		*reg_val = -1;
		pr_err_ratelimited("%s(): node #%d NBSR reg with offset 0x%04x is not yet supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
	}

	return 0;
}

static int node_nbsr_readll(struct kvm_nbsr *nbsr, int node_id,
			    unsigned int reg_offset, u64 *reg_val)
{
	if (!nbsr_is_node_online(nbsr, node_id)) {
		*reg_val = -1;
		pr_err_ratelimited("%s(): node #%d is not online, so return 0x%llx for reg offset 0x%04x\n",
			__func__, node_id, *reg_val, reg_offset);
		return 0;
	}

	if (reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET) {
		return node_nbsr_sic_readll(nbsr, node_id, reg_offset, reg_val);
	} else {
		*reg_val = -1;
		pr_err_ratelimited("%s(): node #%d NBSR reg with offset 0x%04x does not support 64-bit reads, so return 0x%llx\n",
			__func__, node_id, reg_offset, *reg_val);
	}

	return 0;
}

static int node_nbsr_write_ignore(int node_id, unsigned int reg_offset, u32 reg_value)
{
	nbsr_debug("node #%d NBSR reg with offset 0x%04x write value 0x%x ignored\n",
			node_id, reg_offset, reg_value);
	return 0;
}

static __cold int unsupported_reg_write(char *ver, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	pr_err_ratelimited("%s: node %02d: write 0x%08x to NBSR reg with offset 0x%04x not supported\n",
			ver, node_id, reg_value, reg_offset);
	return -EOPNOTSUPP;
}

static int node_nbsr_sic_write_v3(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			       int node_id, unsigned int reg_offset, u32 reg_value)
{
	switch (reg_offset) {
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		return node_nbsr_write_rt_ioapic(nbsr, node_id, reg_offset, reg_value);
	case SIC_mc0_ecc:
	case SIC_mc1_ecc:
	case SIC_mc2_ecc:
		return node_nbsr_write_ignore(node_id, reg_offset, reg_value);
	case SIC_hw1:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	default:
		return unsupported_reg_write("v3", node_id, reg_offset, reg_value);
	}
}

static int node_nbsr_sic_write_v4_v5(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			       int node_id, unsigned int reg_offset, u32 reg_value)
{
	switch (reg_offset) {
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		return node_nbsr_write_rt_ioapic(nbsr, node_id, reg_offset, reg_value);
	case SIC_mc0_ecc:
	case SIC_mc1_ecc:
	case SIC_mc2_ecc:
	case SIC_mc3_ecc:
		return node_nbsr_write_ignore(node_id, reg_offset, reg_value);
	case SIC_hw1:
	case SIC_pcs_ctrl0:
	case SIC_pcs_ctrl1:
	case SIC_pcs_ctrl2:
	case SIC_pcs_ctrl3:
	case SIC_pcs_ctrl4:
	case SIC_pcs_ctrl5:
	case SIC_pcs_ctrl6:
	case SIC_pcs_ctrl7:
	case SIC_pcs_ctrl8:
	case SIC_pcs_ctrl9:
	case SIC_iol_csr:
	case SIC_io_csr:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	default:
		return unsupported_reg_write("v4-5", node_id, reg_offset, reg_value);
	}
}

static int node_nbsr_sic_write_v6(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			       int node_id, unsigned int reg_offset, u32 reg_value)
{
	if (is_pmc_freq_core_mon(reg_offset, false) ||
	    is_pmc_freq_core_ctrl(reg_offset, false) ||
	    is_pmc_freq_graphic_mon(reg_offset, false) ||
	    is_pmc_freq_graphic_ctrl(reg_offset, false))
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);

	if (is_pmc_freq_core_sleep(reg_offset, false))
		return node_nbsr_write_pmc(nbsr, node_id, reg_offset, reg_value);

	switch (reg_offset) {
	case PMC_INFO:
		return node_nbsr_write_pmc_info(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		return node_nbsr_write_rt_ioapic(nbsr, node_id, reg_offset, reg_value);
	case PMC_TERM_CTRL:
	case PMC_TERM_CONV:
	case PMC_TERM_TS0:
	case PMC_TERM_TS1:
	case PMC_TERM_TS2:
	case PMC_TERM_TS3:
	case PMC_TERM_TS4:
	case PMC_TERM_TS5:
	case PMC_TERM_TS6:
	case PMC_TERM_TS7:
	case PMC_FREQ_CFG:
	case PMC_FREQ_STEPS:
	case PMC_FREQ_C2:
	case PMC_FREQ_BND:
	case PMC_FREQ_CORE_FLOAT:
	case PMC_FREQ_OCN_FLOAT:
	case PMC_FREQ_CORE_TABLE0:
	case PMC_FREQ_CORE_TABLE1:
	case PMC_FREQ_CORE_TABLE2:
	case PMC_FREQ_CORE_TABLE3:
	case PMC_FREQ_CORE_TABLE4:
	case PMC_FREQ_CORE_TABLE5:
	case PMC_FREQ_CORE_TABLE6:
	case PMC_FREQ_CORE_TABLE7:
	case PMC_FREQ_OCN_TABLE0:
	case PMC_FREQ_OCN_TABLE1:
	case PMC_FREQ_OCN_TABLE2:
	case PMC_FREQ_OCN_TABLE3:
	case PMC_FREQ_OCN_TABLE4:
	case PMC_FREQ_OCN_TABLE5:
	case PMC_FREQ_OCN_TABLE6:
	case PMC_FREQ_OCN_TABLE7:
	case PMC_FREQ_OCN_MON:
	case PMC_FREQ_OCN_CTRL:
	case PMC_SYS_MON_1:
	case PMC_FAN_CFG:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	case MC_ECC:
		return node_nbsr_write_ignore(node_id, reg_offset, reg_value);
	case HC_CTRL:
	case MC_CH:
	case EDBC_IOMMU_CTRL ... EDBC_IOMMU_ERR_INFO_HI:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	case SIC_st_p:
		return node_nbsr_write_stp(nbsr, node_id, reg_offset, reg_value);
	case SIC_st_core0:
	case SIC_st_core1:
	case SIC_st_core2:
	case SIC_st_core3:
	case SIC_st_core4:
	case SIC_st_core5:
	case SIC_st_core6:
	case SIC_st_core7:
	case SIC_st_core8:
	case SIC_st_core9:
	case SIC_st_core10:
	case SIC_st_core11:
	case SIC_st_core12:
	case SIC_st_core13:
	case SIC_st_core14:
	case SIC_st_core15:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_ln:
	case SIC_rt_pcicfged:
	case SIC_rt_vgamemed:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	case EFUSE_RAM_ADDR:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	case EFUSE_RAM_DATA:
		return node_nbsr_write_efuse(nbsr, node_id, reg_offset, reg_value);
	default:
		return unsupported_reg_write("v6", node_id, reg_offset, reg_value);
	}
}

static int node_nbsr_sic_write_v7(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			       int node_id, unsigned int reg_offset, u32 reg_value)
{
	if (is_pmc_freq_core_mon(reg_offset, true) ||
	    is_pmc_freq_core_ctrl(reg_offset, true) ||
	    is_pmc_freq_graphic_mon(reg_offset, true) ||
	    is_pmc_freq_graphic_ctrl(reg_offset, true))
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);

	if (is_pmc_freq_core_sleep(reg_offset, true))
		return node_nbsr_write_pmc(nbsr, node_id, reg_offset, reg_value);

	switch (reg_offset) {
	case PMC_TERM_CTRL:
	case PMC_TERM_CONV:
	case PMC_TERM_TS0:
	case PMC_TERM_TS1:
	case PMC_TERM_TS2:
	case PMC_TERM_TS3:
	case PMC_TERM_TS4:
	case PMC_TERM_TS5:
	case PMC_TERM_TS6:
	case PMC_TERM_TS7:
	case PMC_FREQ_CFG:
	case PMC_FREQ_STEPS:
	case PMC_FREQ_C2:
	case PMC_FREQ_BND:
	case PMC_FREQ_CORE_FLOAT:
	case PMC_FREQ_OCN_FLOAT:
	case PMC_FREQ_CORE_TABLE0:
	case PMC_FREQ_CORE_TABLE1:
	case PMC_FREQ_CORE_TABLE2:
	case PMC_FREQ_CORE_TABLE3:
	case PMC_FREQ_CORE_TABLE4:
	case PMC_FREQ_CORE_TABLE5:
	case PMC_FREQ_CORE_TABLE6:
	case PMC_FREQ_CORE_TABLE7:
	case PMC_FREQ_OCN_TABLE0:
	case PMC_FREQ_OCN_TABLE1:
	case PMC_FREQ_OCN_TABLE2:
	case PMC_FREQ_OCN_TABLE3:
	case PMC_FREQ_OCN_TABLE4:
	case PMC_FREQ_OCN_TABLE5:
	case PMC_FREQ_OCN_TABLE6:
	case PMC_FREQ_OCN_TABLE7:
	case PMC_FREQ_OCN_MON:
	case PMC_FREQ_OCN_CTRL:
	case PMC_SYS_MON_1:
	case PMC_FAN_CFG:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_pcim0_xmu_l:
		return node_nbsr_write_rt_pcim_xmu(nbsr, node_id, RT_XMU_l, reg_value);
	case SIC_rt_pcim0_xmu_a:
		return node_nbsr_write_rt_pcim_xmu(nbsr, node_id, RT_XMU_a, reg_value);
	case SIC_rt_pcim0_xmu_b:
		return node_nbsr_write_rt_pcim_xmu(nbsr, node_id, RT_XMU_b, reg_value);
	case SIC_rt_pcim0_xmu_c:
		return node_nbsr_write_rt_pcim_xmu(nbsr, node_id, RT_XMU_c, reg_value);
	case SIC_rt_pcim0_xmu_d:
		return node_nbsr_write_rt_pcim_xmu(nbsr, node_id, RT_XMU_d, reg_value);
	case SIC_rt_pciio0_xmu_l:
		return node_nbsr_write_rt_pciio_xmu(nbsr, node_id, RT_XMU_l, reg_value);
	case SIC_rt_pciio0_xmu_a:
		return node_nbsr_write_rt_pciio_xmu(nbsr, node_id, RT_XMU_a, reg_value);
	case SIC_rt_pciio0_xmu_b:
		return node_nbsr_write_rt_pciio_xmu(nbsr, node_id, RT_XMU_b, reg_value);
	case SIC_rt_pciio0_xmu_c:
		return node_nbsr_write_rt_pciio_xmu(nbsr, node_id, RT_XMU_c, reg_value);
	case SIC_rt_pciio0_xmu_d:
		return node_nbsr_write_rt_pciio_xmu(nbsr, node_id, RT_XMU_d, reg_value);
	case SIC_rt_pcimp0_xmu_l_bgn:
		return node_nbsr_write_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_l, reg_value);
	case SIC_rt_pcimp0_xmu_a_bgn:
		return node_nbsr_write_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_a, reg_value);
	case SIC_rt_pcimp0_xmu_b_bgn:
		return node_nbsr_write_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_b, reg_value);
	case SIC_rt_pcimp0_xmu_c_bgn:
		return node_nbsr_write_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_c, reg_value);
	case SIC_rt_pcimp0_xmu_d_bgn:
		return node_nbsr_write_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_d, reg_value);
	case SIC_rt_pcimp0_xmu_l_end:
		return node_nbsr_write_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_l, reg_value);
	case SIC_rt_pcimp0_xmu_a_end:
		return node_nbsr_write_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_a, reg_value);
	case SIC_rt_pcimp0_xmu_b_end:
		return node_nbsr_write_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_b, reg_value);
	case SIC_rt_pcimp0_xmu_c_end:
		return node_nbsr_write_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_c, reg_value);
	case SIC_rt_pcimp0_xmu_d_end:
		return node_nbsr_write_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_d, reg_value);
	case SIC_esclkr:
		return node_nbsr_write_esclkr(nbsr, node_id, reg_value);
	case MC_ECC:
		return node_nbsr_write_ignore(node_id, reg_offset, reg_value);
	case HC_CTRL:
	case MC_CH:
	case EDBC_IOMMU_CTRL ... EDBC_IOMMU_ERR_INFO_HI:
		return node_nbsr_write_generic(nbsr, node_id, reg_offset, reg_value);
	default:
		return unsupported_reg_write("v7", node_id, reg_offset, reg_value);
	}
}

static int node_nbsr_sic_write(const struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			       int node_id, unsigned int reg_offset, u32 reg_value)
{
	ASSERT(reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET);

	switch (reg_offset) {
	case SIC_rt_mlo0:
	case SIC_rt_mlo1:
	case SIC_rt_mlo2:
	case SIC_rt_mlo3:
	case SIC_rt_mhi0:
	case SIC_rt_mhi1:
	case SIC_rt_mhi2:
	case SIC_rt_mhi3:
		return node_nbsr_write_rt_mem(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_lcfg0:
	case SIC_rt_lcfg1:
	case SIC_rt_lcfg2:
	case SIC_rt_lcfg3:
		return node_nbsr_write_rt_lcfg(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_pcim0:
	case SIC_rt_pcim1:
	case SIC_rt_pcim2:
	case SIC_rt_pcim3:
		return node_nbsr_write_rt_pcim(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_pciio0:
	case SIC_rt_pciio1:
	case SIC_rt_pciio2:
	case SIC_rt_pciio3:
		return node_nbsr_write_rt_pciio(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_pcimp_b0:
	case SIC_rt_pcimp_b1:
	case SIC_rt_pcimp_b2:
	case SIC_rt_pcimp_b3:
		return node_nbsr_write_rt_pcimp_b(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_pcimp_e0:
	case SIC_rt_pcimp_e1:
	case SIC_rt_pcimp_e2:
	case SIC_rt_pcimp_e3:
		return node_nbsr_write_rt_pcimp_e(nbsr, node_id, reg_offset, reg_value);
	case SIC_rt_pcicfgb:
		return node_nbsr_write_rt_pcicfgb(nbsr, node_id, reg_offset, reg_value);
	case SIC_iommu_ctrl:
	case SIC_iommu_ba_lo:
	case SIC_iommu_ba_hi:
	case SIC_iommu_dtba_lo:
	case SIC_iommu_dtba_hi:
	case SIC_iommu_flush:
	case SIC_iommu_flushP:
	case SIC_iommu_err:
	case SIC_iommu_err1:
	case SIC_iommu_err_info_lo:
	case SIC_iommu_err_info_hi:
	case SIC_iommu_mcr:
	case SIC_iommu_mid:
	case SIC_iommu_mar0_lo:
	case SIC_iommu_mar0_hi:
	case SIC_iommu_mar1_lo:
	case SIC_iommu_mar1_hi:
		return node_nbsr_write_iommu(nbsr, node_id, reg_offset, reg_value);
	case SIC_l3_ctrl:
		return node_nbsr_write_l3(nbsr, node_id, reg_offset, reg_value);
	case SIC_prepic_ctrl2:
	case SIC_prepic_err_stat:
	case SIC_prepic_err_int:
	case SIC_prepic_linp0:
	case SIC_prepic_linp1:
	case SIC_prepic_linp2:
	case SIC_prepic_linp3:
	case SIC_prepic_linp4:
	case SIC_prepic_linp5:
		return node_nbsr_write_prepic(nbsr, node_id, reg_offset, reg_value);
	/* These registers are missing on hardware v3-v5, but in virtual CPU
	 * they always exist to provide guest with MSI addresses */
	case SIC_rt_msi:
	case SIC_rt_msi_h:
		return node_nbsr_write_rt_msi(nbsr, node_id, reg_offset, reg_value);
	default:
		/* Not a common register, now try iset-specific ones */
		switch ((vcpu) ? vcpu->kvm->arch.guest_info.cpu_iset : -1) {
		case 1 ... 3:
			return node_nbsr_sic_write_v3(vcpu, nbsr, node_id, reg_offset, reg_value);
		case 4 ... 5:
			return node_nbsr_sic_write_v4_v5(vcpu, nbsr, node_id,
							 reg_offset, reg_value);
		case 6:
			return node_nbsr_sic_write_v6(vcpu, nbsr, node_id, reg_offset, reg_value);
		case 7:
			return node_nbsr_sic_write_v7(vcpu, nbsr, node_id, reg_offset, reg_value);
		default:
			return unsupported_reg_write("v?", node_id, reg_offset, reg_value);
		}
	}
}

static int node_nbsr_write(struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			   int node_id, unsigned int reg_offset, u32 reg_value)
{
	int ret = 0;

	if (!nbsr_is_node_online(nbsr, node_id)) {
		pr_err("%s(): node #%d is not online, so ignore write to reg with offset 0x%04x\n",
		       __func__, node_id, reg_offset);
		return ret;
	}

	if (nbsr_bc_reg_in_range(reg_offset)) {
		ret = node_nbsr_bc_write(vcpu, nbsr, node_id, reg_offset, reg_value);
	} else if (reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET) {
		ret = node_nbsr_sic_write(vcpu, nbsr, node_id, reg_offset, reg_value);
	} else {
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet supported, so ignore write\n",
		       __func__, node_id, reg_offset);
	}

	return ret;
}

static int node_nbsr_writell(struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			     int node_id, unsigned int reg_offset,
			     u64 reg_value)
{
	int ret = 0;

	if (!nbsr_is_node_online(nbsr, node_id)) {
		pr_err("%s(): node #%d is not online, so ignore write to reg with offset 0x%04x\n",
		       __func__, node_id, reg_offset);
		return ret;
	}

	/* Fail silently for writes to IOMMU for embedded devices */
	if (reg_offset >= SIC_iommu_ctrl && reg_offset < SIC_iommu_mar1_hi) {
		ret = node_nbsr_writell_iommu(nbsr, node_id, reg_offset, reg_value);
	} else if (!(reg_offset >= EDBC_IOMMU_CTRL && reg_offset <= EDBC_IOMMU_ERR_INFO_HI)) {
		pr_err_ratelimited("%s(): node #%d NBSR reg with offset 0x%04x does not support 64-bit writes, so ignore it\n",
			__func__, node_id, reg_offset);
	}

	return ret;
}

static void nbsr_setup_lo_mem_region(struct kvm_nbsr *nbsr, int node_id,
				     gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value;
	e2k_rt_mlo_t rt_mlo;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_LOW_MEMORY_BOUND &&
	       base + size <= NBSR_LOW_MEMORY_BOUND);

	start = round_down(base, E2K_SIC_SIZE_RT_MLO);
	end = round_up(base + size, E2K_SIC_SIZE_RT_MLO) - 1;
	AW(rt_mlo) = 0;
	rt_mlo.bgn = start >> E2K_SIC_ALIGN_RT_MLO;
	rt_mlo.end = end >> E2K_SIC_ALIGN_RT_MLO;
	reg_value = AW(rt_mlo);

	node_nbsr_write(NULL, nbsr, node_id, SIC_rt_mlo0, reg_value);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_mlo_offset(link);
		node_nbsr_write(NULL, nbsr, node, reg_off, reg_value);
	}
}

static void nbsr_setup_hi_mem_region(struct kvm_nbsr *nbsr, int node_id,
				     gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	u32 reg_value;
	e2k_rt_mhi_t rt_mhi;
	gpa_t start, end;
	int node, link;

	ASSERT(base >= NBSR_LOW_MEMORY_BOUND &&
	       base + size > NBSR_LOW_MEMORY_BOUND);

	start = round_down(base, E2K_SIC_SIZE_RT_MHI);
	end = round_up(base + size, E2K_SIC_SIZE_RT_MHI) - 1;
	AW(rt_mhi) = 0;
	rt_mhi.bgn = start >> E2K_SIC_ALIGN_RT_MHI;
	rt_mhi.end = end >> E2K_SIC_ALIGN_RT_MHI;
	reg_value = AW(rt_mhi);

	node_nbsr_write(NULL, nbsr, node_id, SIC_rt_mhi0, reg_value);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_mhi_offset(link);
		node_nbsr_write(NULL, nbsr, node, reg_off, reg_value);
	}
}

int nbsr_setup_memory_region(struct kvm_nbsr *nbsr, int node_id,
			     gpa_t base, gpa_t size)
{
	if (base < NBSR_LOW_MEMORY_BOUND) {
		ASSERT(base + size <= NBSR_LOW_MEMORY_BOUND);
		nbsr->lo_mem_base = base;
		nbsr->lo_mem_size = size;
		nbsr_setup_lo_mem_region(nbsr, node_id, base, size);
	} else {
		ASSERT(base + size > NBSR_LOW_MEMORY_BOUND);
		nbsr->hi_mem_base = base;
		nbsr->hi_mem_size = size;
		nbsr_setup_hi_mem_region(nbsr, node_id, base, size);
	}
	return 0;
}

int nbsr_setup_mmio_region(struct kvm_nbsr *nbsr, int node_id,
			   gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value;
	e2k_rt_pcim_t rt_pcim;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_PCI_BOUND &&
	       base + size <= NBSR_PCI_BOUND);

	start = round_down(base, E2K_SIC_SIZE_RT_PCIM);
	end = round_up(base + size, E2K_SIC_SIZE_RT_PCIM) - 1;
	AW(rt_pcim) = 0;
	rt_pcim.bgn = start >> E2K_SIC_ALIGN_RT_PCIM;
	rt_pcim.end = end >> E2K_SIC_ALIGN_RT_PCIM;
	reg_value = AW(rt_pcim);

	node_nbsr_write_rt_pcim(nbsr, node_id, SIC_rt_pcim0, reg_value);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_pcim_offset(link);
		node_nbsr_write_rt_pcim(nbsr, node, reg_off, reg_value);
	}
	if (nbsr->iset_no >= E2K_ISET_V7) {
		/* it is currently assumed that eXternal Memory Units */
		/* are not used by guest and all memory must be set as XMU_l */
		node_nbsr_write_rt_pcim_xmu(nbsr, node_id, RT_XMU_l, reg_value);
	}
	return 0;
}

static int nbsr_setup_io_region(struct kvm_nbsr *nbsr, int node_id,
				gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_LOW_MEMORY_BOUND &&
	       base + size <= NBSR_LOW_MEMORY_BOUND);

	start = round_down(base, E2K_SIC_SIZE_RT_PCIIO);
	end = round_up(base + size, E2K_SIC_SIZE_RT_PCIIO) - 1;
	reg_value = nbsr_set_rt_pciio_reg(start, end, nbsr->iset_no);

	node_nbsr_write_rt_pciio(nbsr, node_id, SIC_rt_pciio0, reg_value);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_pciio_offset(link);
		node_nbsr_write_rt_pciio(nbsr, node, reg_off, reg_value);
	}
	if (nbsr->iset_no >= E2K_ISET_V7) {
		/* it is currently assumed that eXternal Memory Units */
		/* are not used by guest and all memory must be set as XMU_l */
		node_nbsr_write_rt_pciio_xmu(nbsr, node_id, RT_XMU_l, reg_value);
	}
	return 0;
}

int nbsr_setup_pref_mmio_region(struct kvm_nbsr *nbsr, int node_id,
				gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value_b, reg_value_e;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_HI_MEMORY_BOUND &&
	       base + size <= NBSR_HI_MEMORY_BOUND);

	start = round_down(base, E2K_SIC_SIZE_RT_PCIMP);
	end = round_up(base + size, E2K_SIC_SIZE_RT_PCIMP) - 1;

	reg_value_b = nbsr_set_rt_pcimp_bgn_reg(start);
	node_nbsr_write_rt_pcimp_b(nbsr, node_id, SIC_rt_pcimp_b0, reg_value_b);

	reg_value_e = nbsr_set_rt_pcimp_end_reg(end);
	node_nbsr_write_rt_pcimp_e(nbsr, node_id, SIC_rt_pcimp_e0, reg_value_e);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_pcimp_b_offset(link);
		node_nbsr_write_rt_pcimp_b(nbsr, node, reg_off, reg_value_b);
		reg_off = nbsr_get_rt_pcimp_e_offset(link);
		node_nbsr_write_rt_pcimp_e(nbsr, node, reg_off, reg_value_e);
	}
	if (nbsr->iset_no >= E2K_ISET_V7) {
		/* it is currently assumed that eXternal Memory Units */
		/* are not used by guest and all memory must be set as XMU_l */
		node_nbsr_write_rt_pcimp_b_xmu(nbsr, node_id, RT_XMU_l, reg_value_b);
		node_nbsr_write_rt_pcimp_e_xmu(nbsr, node_id, RT_XMU_l, reg_value_e);
	}
	return 0;
}

int nbsr_setup_pci_region(struct kvm *kvm, kvm_pci_region_t *pci_region)
{
	struct kvm_nbsr *nbsr = kvm->arch.nbsr;
	unsigned long base, size;
	int node_id;

	if (nbsr == NULL)
		return -ENXIO;

	/* FIXME: only node #0 is now supported */
	node_id = 0;

	base = pci_region->base;
	size = pci_region->size;

	switch (pci_region->type) {
	case kvm_pci_io_type:
		if (unlikely(base < KVM_PCI_IO_RANGE_START ||
			     base + size > KVM_PCI_IO_RANGE_END)) {
			return -EINVAL;
		}
		return nbsr_setup_io_region(nbsr, node_id, base, size);
	case kvm_pci_mem_type:
		if (unlikely(base < KVM_PCI_MEM_RANGE_START ||
			     base + size > KVM_PCI_MEM_RANGE_END)) {
			return -EINVAL;
		}
		return nbsr_setup_mmio_region(nbsr, node_id, base, size);
	case kvm_pci_pref_mem_type:
		if (unlikely(base < KVM_PCI_PREF_MEM_RANGE_START ||
			     base + size > KVM_PCI_PREF_MEM_RANGE_END)) {
			return -EINVAL;
		}
		return nbsr_setup_pref_mmio_region(nbsr, node_id, base, size);
	default:
		pr_err("%s(): invalid PCI memory region type %d\n",
		       __func__, pci_region->type);
		break;
	}

	return -EINVAL;
}

static int nbsr_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
			  gpa_t addr, int len, void *val)
{
	struct kvm_nbsr *nbsr = to_nbsr(this);
	unsigned int reg_offset;
	int node_id;

	if (!nbsr_in_range(nbsr, addr))
		return -EOPNOTSUPP;

	/* 8 bytes access is only for IOMMU */
	if (unlikely(len != 4 && len != 8)) {
		pr_err_ratelimited("KVM: invalid guest NBSR read of %d bytes\n", len);
		return -EOPNOTSUPP;
	}

	node_id = nbsr_addr_to_node(nbsr, addr);
	reg_offset = nbsr_addr_to_reg_offset(nbsr, addr);

	if (len == 4)
		return node_nbsr_read(vcpu, nbsr, node_id, reg_offset, (u32 *)val);
	else
		return node_nbsr_readll(nbsr, node_id, reg_offset, (u64 *) val);
}

static int nbsr_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
			   gpa_t addr, int len, const void *val)
{
	struct kvm_nbsr *nbsr = to_nbsr(this);
	unsigned int reg_offset;
	int node_id;
	int ret = 0;

	if (!nbsr_in_range(nbsr, addr))
		return -EOPNOTSUPP;

	/* 8 bytes access is only for IOMMU */
	if (unlikely(len != 4 && len != 8)) {
		pr_err_ratelimited("KVM: invalid guest NBSR write of %d bytes\n", len);
		return -EOPNOTSUPP;
	}

	node_id = nbsr_addr_to_node(nbsr, addr);
	reg_offset = nbsr_addr_to_reg_offset(nbsr, addr);
	if (len == 4) {
		u32 reg_value = *(u32 *) val;

		ret = node_nbsr_write(vcpu, nbsr, node_id, reg_offset, reg_value);
	} else {
		u64 reg_value = *(u64 *) val;

		ret = node_nbsr_writell(vcpu, nbsr, node_id, reg_offset, reg_value);
	}

	return ret;
}

void kvm_nbsr_reset(struct kvm *kvm, struct kvm_nbsr *nbsr)
{
	e2k_rt_mhi_t rt_mhi;
	e2k_rt_mlo_t rt_mlo;
	e2k_rt_lcfg_t rt_lcfg0, rt_lcfg;
	e2k_rt_pcim_t rt_pcim;
	e2k_rt_pcimp_t rt_pcimp_b, rt_pcimp_e;
	kvm_nbsr_regs_t *node_nbsr;
	u32 mlo_value, mhi_value;
	u32 pcim_value, pciio_value;
	u32 pcimp_b_value, pcimp_e_value;
	u32 pcicfgb_value;
	int node, i;

	memset(nbsr->nodes, 0x00, sizeof(nbsr->nodes));

	AW(rt_mhi) = 0;
	rt_mhi.bgn = 0xff;
	rt_mhi.end = 0x00;
	mhi_value = AW(rt_mhi);
	AW(rt_mlo) = 0;
	rt_mlo.bgn = 0x1f;
	rt_mlo.end = 0x00;
	mlo_value = AW(rt_mlo);
	AW(rt_pcim) = 0;
	rt_pcim.bgn = 0x1f;
	rt_pcim.end = 0x00;
	pcim_value = AW(rt_pcim);
	pciio_value = nbsr_set_rt_pciio_reg(-1, 0, nbsr->iset_no);
	AW(rt_pcimp_b) = 0;
	rt_pcimp_b.bgn = 0xfffff;
	AW(rt_pcimp_e) = 0;
	rt_pcimp_e.end = 0x00000;
	pcimp_b_value = AW(rt_pcimp_b);
	pcimp_e_value = AW(rt_pcimp_e);
	if (nbsr->iset_no >= E2K_ISET_V7) {
		e2k_rt_pcicfg_bgn_t rt_pcicfg_bgn;
		rt_pcicfg_bgn.bgn = 0x2;	/* 0x0002 0000 0000 */
		pcicfgb_value = AW(rt_pcicfg_bgn);
	} else {
		e2k_rt_pcicfgb_t rt_pcicfgb;
		rt_pcicfgb.bgn = 0x8;	/* 0x0002 0000 0000 */
		pcicfgb_value = AW(rt_pcicfgb);
	}
	for (node = 0; node < MAX_NUMNODES; node++) {
		u32 rt_msi_lo = E2K_RT_MSI_DEFAULT_BASE & 0xffffffff;
		u32 rt_msi_hi = E2K_RT_MSI_DEFAULT_BASE >> 32;

		/*
		 * Bug 129111 workaround: set guest's RT_MSI the same as on host
		 * We trust guest to never change this, and write this value
		 * to IOEPIC/PCI_MSI
		 */
		if (kvm_ioepic_unsafe_direct_map)
			get_io_pic_msi(0, &rt_msi_lo, &rt_msi_hi);

		node_nbsr = &nbsr->nodes[node];
		/*
		 * Set write mask of each register to 0xff by default to enable
		 * write. Need to redefine for specific registers later.
		 */
		memset(node_nbsr->write_mask, 0xff, sizeof(node_nbsr->write_mask));

		node_nbsr_reg_set(nbsr, node, SIC_rt_mhi0, mhi_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_mhi1, mhi_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_mhi2, mhi_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_mhi3, mhi_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_mlo0, mlo_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_mlo1, mlo_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_mlo2, mlo_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_mlo3, mlo_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim0, pcim_value);
		node_nbsr_reg_set_writemask(nbsr, node, SIC_rt_pcim0, 0xf800f800);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim1, pcim_value);
		node_nbsr_reg_set_writemask(nbsr, node, SIC_rt_pcim1, 0xf800f800);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim2, pcim_value);
		node_nbsr_reg_set_writemask(nbsr, node, SIC_rt_pcim2, 0xf800f800);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim3, pcim_value);
		node_nbsr_reg_set_writemask(nbsr, node, SIC_rt_pcim3, 0xf800f800);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim0_xmu_l, pcim_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim0_xmu_a, pcim_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim0_xmu_b, pcim_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim0_xmu_c, pcim_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcim0_xmu_d, pcim_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio0, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio1, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio2, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio3, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio0_xmu_l, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio0_xmu_a, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio0_xmu_b, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio0_xmu_c, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pciio0_xmu_d, pciio_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_b0, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_b1, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_b2, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_b3, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_e0, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_e1, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_e2, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp_e3, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_l_bgn, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_a_bgn, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_b_bgn, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_c_bgn, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_d_bgn, pcimp_b_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_l_end, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_a_end, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_b_end, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_c_end, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcimp0_xmu_d_end, pcimp_e_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcicfgb, pcicfgb_value);
		node_nbsr_reg_set(nbsr, node, SIC_rt_msi, rt_msi_lo);
		node_nbsr_reg_set(nbsr, node, SIC_rt_msi_h, rt_msi_hi);
		node_nbsr_reg_set(nbsr, node, SIC_l3_ctrl, 0x3f00f8);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl0, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl1, 0x04136590);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl2, 0x01684641);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl3, 0x00040910);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl4, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl5, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl6, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl7, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl8, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_pcs_ctrl9, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_iol_csr, 0x3);
		node_nbsr_reg_set(nbsr, node, SIC_io_csr, 0x80000000);
		node_nbsr_reg_set(nbsr, node, SIC_rt_ln, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_rt_pcicfged, 0x0);
		node_nbsr_reg_set(nbsr, node, SIC_rt_vgamemed, 0x0);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_CTRL, 0x86e00fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_CONV, 0x8067a18b);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS0, 0x80440fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS1, 0x80480fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS2, 0x804c0fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS3, 0x80500fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS4, 0x80540fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS5, 0x80580fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS6, 0x805c0fff);
		node_nbsr_reg_set(nbsr, node, PMC_TERM_TS7, 0x80600fff);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CFG, 0x87070707);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_STEPS, 0xe0504540);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_C2, 0x00000010);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_BND, 0x80242424);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_FLOAT, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_FLOAT, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE0, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE1, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE2, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE3, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE4, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE5, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE6, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_CORE_TABLE7, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE0, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE1, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE2, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE3, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE4, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE5, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE6, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_TABLE7, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_MON, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FREQ_OCN_CTRL, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_SYS_MON_1, 0x00000000);
		node_nbsr_reg_set(nbsr, node, PMC_FAN_CFG, 0x00000000);
		node_nbsr_reg_set(nbsr, node, EFUSE_RAM_ADDR, 0x00000000);
		for (i = 0; i < 16; i++)
			node_nbsr_reg_set(nbsr, node, SIC_st_core(i), 0x00000001);

		bool is_v7 = (nbsr->iset_no >= E2K_ISET_V7);
		for (i = 0; i < ((is_v7) ? 64 : 16); i++) {
			node_nbsr_reg_set(nbsr, node,
					PMC_FREQ_CORE_MON(i, is_v7), 0);
			node_nbsr_reg_set(nbsr, node,
					PMC_FREQ_CORE_CTRL(i, is_v7), 0);
			node_nbsr_reg_set(nbsr, node,
					PMC_FREQ_CORE_SLEEP(i, is_v7), 0);
		}

		for (i = 0; i < 4; i++) {
			node_nbsr_reg_set(nbsr, node,
					PMC_FREQ_GRAPHIC_MON(i, is_v7), 0);
			node_nbsr_reg_set(nbsr, node,
					PMC_FREQ_GRAPHIC_CTRL(i, is_v7), 0);
		}

		for (i = 0; i < EFUSE_RAM_LINES; i++)
			node_nbsr->efuse_ram[offset_to_no(i)] = 0x00000000;

		switch (nbsr->iset_no) {
		case 1 ... 3:
			node_nbsr_reg_set(nbsr, node, SIC_hw1, 0x76);
			break;
		case 4:
			node_nbsr_reg_set(nbsr, node, SIC_hw1, 0xd6);
			break;
		case 5:
			node_nbsr_reg_set(nbsr, node, SIC_hw1, 0x580d6);
			break;
		}
	}

	/* BSP node, now it should be #0 */
	AW(rt_lcfg0) = 0;
	rt_lcfg0.pln = 0;
	rt_lcfg0.vp = 1;
	rt_lcfg0.vb = 1;
	rt_lcfg0.vio = 1;
	/* links to other nodes */
	AW(rt_lcfg) = 0;
	rt_lcfg.pln = 0x3;
	rt_lcfg.vp = 0;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	node_nbsr_reg_set(nbsr, 0, SIC_rt_lcfg0, AW(rt_lcfg0));
	node_nbsr_reg_set(nbsr, 0, SIC_rt_lcfg1, AW(rt_lcfg));
	node_nbsr_reg_set(nbsr, 0, SIC_rt_lcfg2, AW(rt_lcfg));
	node_nbsr_reg_set(nbsr, 0, SIC_rt_lcfg3, AW(rt_lcfg));
	/* APP nodes links to other nodes */
	AW(rt_lcfg) = 0;
	rt_lcfg.pln = 0x3;
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	for (node = 1; node < MAX_NUMNODES; node++) {
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		node_nbsr_reg_set(nbsr, node, SIC_rt_lcfg0, AW(rt_lcfg));
		node_nbsr_reg_set(nbsr, node, SIC_rt_lcfg1, AW(rt_lcfg));
		node_nbsr_reg_set(nbsr, node, SIC_rt_lcfg2, AW(rt_lcfg));
		node_nbsr_reg_set(nbsr, node, SIC_rt_lcfg3, AW(rt_lcfg));
	}
	for (node = 1; node < MAX_NUMNODES; node++) {
		node_nbsr_reg_set(nbsr, node, SIC_iommu_mcr, 0x00000000);
		node_nbsr_reg_set(nbsr, node, SIC_iommu_mid, 0x00000000);
		node_nbsr_reg_set(nbsr, node, SIC_iommu_mar0_lo, 0x00000000);
		node_nbsr_reg_set(nbsr, node, SIC_iommu_mar0_hi, 0x00000000);
		node_nbsr_reg_set(nbsr, node, SIC_iommu_mar1_lo, 0x00000000);
		node_nbsr_reg_set(nbsr, node, SIC_iommu_mar1_hi, 0x00000000);
	}

	/* *FIXME* setup memory regions after reset only for node #0
	 * Need to update after NUMA support will be implemented */
	if (nbsr->lo_mem_size != 0)
		nbsr_setup_lo_mem_region(nbsr, 0, nbsr->lo_mem_base, nbsr->lo_mem_size);
	if (nbsr->hi_mem_size != 0)
		nbsr_setup_hi_mem_region(nbsr, 0, nbsr->hi_mem_base, nbsr->hi_mem_size);
}

static const struct kvm_io_device_ops nbsr_mmio_ops = {
	.read = nbsr_mmio_read,
	.write = nbsr_mmio_write,
};

int kvm_nbsr_init(struct kvm *kvm, unsigned long cpu_iset)
{
	struct kvm_nbsr *nbsr;
	int ret;

	nbsr = kzalloc(sizeof(struct kvm_nbsr), GFP_KERNEL);
	if (!nbsr) {
		pr_err("%s(): could not allocated NBSR structure\n", __func__);
		return -ENOMEM;
	}
	mutex_init(&nbsr->lock);
	kvm->arch.nbsr = nbsr;

	/* NBSR address and size are equal on all machines */
	/* so can be set same as on host */
	nbsr->base = (unsigned long) THE_NODE_NBSR_PHYS_BASE(0);
	nbsr->size = NODE_NBSR_SIZE * MAX_NUMNODES;
	nbsr->node_size = NODE_NBSR_SIZE;

	nbsr->iset_no = cpu_iset;

	/* FIXME: now only one node #0 is allowed */
	nbsr_set_node_online(nbsr, 0);

	kvm_nbsr_reset(kvm, nbsr);
	kvm_iodevice_init(&nbsr->dev, &nbsr_mmio_ops);
	nbsr->kvm = kvm;
	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, nbsr->base, nbsr->size, &nbsr->dev);
	mutex_unlock(&kvm->slots_lock);
	if (ret < 0) {
		pr_err("%s(); could not created NBSR emulation device, error %d\n",
			__func__, ret);
		kfree(nbsr);
	}

	return ret;
}

void kvm_nbsr_destroy(struct kvm *kvm)
{
	struct kvm_nbsr *nbsr = kvm->arch.nbsr;

	if (!nbsr)
		return;

	mutex_lock(&kvm->slots_lock);
	kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &nbsr->dev);
	mutex_unlock(&kvm->slots_lock);
	kvm->arch.nbsr = NULL;
	kfree(nbsr);
}

static int handle_mpdma_request(struct kvm *kvm, u32 *regs, u64 gpa)
{
	bc_mp_stat_t stat;
	bc_mp_ctrl_t ctrl;
	u32 b_put_off, stat_off;
	u32 b_put, b_get, b_hb, b_base, b_base_h, t_hb,
	    t_base, t_base_h, t_h_base, t_h_base_h, t_h_lb,
	    t_h_lb_h, t_h_hb, t_h_hb_h;
	u64 b_base_64, t_base_64, t_h_base_64, t_h_lb_64, t_h_hb_64;
	u64 t_base_gpa, t_h_base_gpa, b_base_gpa;
	u64 gpa_page, t_hb_page, t_h_lb_page, t_h_hb_page;
	u64 t_h_base_id;
	u8 t_base_val, t_h_base_val;
	int ret;

	AW(ctrl) = regs[nbsr_bc_reg_offset_to_no(BC_MP_CTRL)];

	nbsr_debug("%s(): ctrl 0x%x\n", __func__, AW(ctrl));

	if (!ctrl.mp_en)
		return 0;

	t_hb = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_HB)];
	t_base = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_BASE)];
	t_base_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_BASE_H)];

	t_base_64 = NBSR_ADDR64(t_base_h, t_base);

	gpa_page = gpa >> PAGE_SHIFT;
	t_hb_page = t_hb >> PAGE_SHIFT;

	t_base_gpa = t_base_64 + gpa_page;

	ret = kvm_read_guest(kvm, t_base_gpa, &t_base_val, 1);
	if (ret)
		return ret;

	nbsr_debug("%s(): gpa 0x%llx t_hb_page 0x%llx t_base_gpa 0x%llx t_base_val 0x%x\n",
		   __func__, gpa, t_hb_page, t_base_gpa, t_base_val);

	if (gpa < (1UL << 32) && gpa_page <= t_hb_page && t_base_val == 0) {
		nbsr_debug("%s(): set 1 to MPT 0x%llx\n", __func__, t_base_gpa);

		t_base_val = 1;

		ret = kvm_write_guest(kvm, t_base_gpa, &t_base_val, 1);
		if (ret)
			return ret;
	} else {
		t_h_lb = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_LB)];
		t_h_lb_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_LB_H)];
		t_h_hb = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_HB)];
		t_h_hb_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_HB_H)];
		t_h_base = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_BASE)];
		t_h_base_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_BASE_H)];

		t_h_lb_64 = NBSR_ADDR64(t_h_lb_h, t_h_lb);
		t_h_hb_64 = NBSR_ADDR64(t_h_hb_h, t_h_hb);
		t_h_base_64 = NBSR_ADDR64(t_h_base_h, t_h_base);

		t_h_lb_page = t_h_lb_64 >> PAGE_SHIFT;
		t_h_hb_page = t_h_hb_64 >> PAGE_SHIFT;

		t_h_base_id = (gpa - t_h_lb_64) >> PAGE_SHIFT;

		t_h_base_gpa = t_h_base_64 + t_h_base_id;

		ret = kvm_read_guest(kvm, t_h_base_gpa, &t_h_base_val, 1);
		if (ret)
			return ret;

		nbsr_debug("%s(): gpa_page 0x%llx t_h_lb_page 0x%llx\n"
			   "t_h_hb_page 0x%llx t_h_base_gpa 0x%llx\n"
			   "t_h_base_val 0x%x\n",
			   __func__, gpa_page, t_h_lb_page, t_h_hb_page,
			   t_h_base_gpa, t_h_base_val);

		if (gpa_page >= t_h_lb_page && gpa_page <= t_h_hb_page && t_h_base_val == 0) {
			nbsr_debug("%s(): set 1 to MPT HI 0x%llx\n",
				   __func__, t_h_base_gpa);

			t_h_base_val = 1;

			ret = kvm_write_guest(kvm, t_h_base_gpa, &t_h_base_val, 1);
			if (ret)
				return ret;
		} else {
			return 0;
		}
	}

	stat_off = nbsr_bc_reg_offset_to_no(BC_MP_STAT);
	AW(stat) = regs[stat_off];

	nbsr_debug("%s(): stat 0x%x\n", __func__, AW(stat));

	if (ctrl.b_en && !stat.b_of) {
		b_put_off = nbsr_bc_reg_offset_to_no(BC_MP_B_PUT);

		b_put = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_PUT)];
		b_get = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_GET)];
		b_hb = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_HB)];
		b_base = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_BASE)];
		b_base_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_BASE_H)];

		b_base_64 = NBSR_ADDR64(b_base_h, b_base);

		b_base_gpa = b_base_64 + b_put;

		nbsr_debug("%s(): set page 0x%llx to BUF 0x%llx\n",
			   __func__, gpa_page, b_base_gpa);

		ret = kvm_write_guest(kvm, b_base_gpa, &gpa_page, 8);
		if (ret)
			return ret;

		nbsr_debug("%s(): b_put 0x%x b_get 0x%x b_hb 0x%x\n",
			   __func__, b_put, b_get, b_hb);

		if (b_put == b_hb)
			b_put = 0;
		else
			b_put += 8;

		nbsr_debug("%s(): set BC_MP_B_PUT 0x%llx to 0x%x\n",
			   __func__, &regs[b_put_off], b_put);
		regs[b_put_off] = b_put;

		if (b_put == b_get) {
			stat.b_of = 1;

			nbsr_debug("%s(): set BC_MP_STAT 0x%llx to 0x%x\n",
				   __func__, &regs[stat_off], AW(stat));

			regs[stat_off] = AW(stat);

			kvm_int_violat_delivery_to_hw_epic(kvm);
		}
	}

	if (!stat.b_ne) {
		stat.b_ne = 1;

		nbsr_debug("%s(): set BC_MP_STAT 0x%llx to 0x%x\n",
			   __func__, &regs[stat_off], AW(stat));

		regs[stat_off] = AW(stat);

		kvm_int_violat_delivery_to_hw_epic(kvm);
	}

	return 0;
}

int native_handle_mpdma_fault(e2k_addr_t hva, struct pt_regs *ptregs)
{
	struct kvm *kvm = current_thread_info()->virt_machine;
	struct kvm_nbsr *nbsr;
	u32 *regs;
	gpa_t gpa;

	nbsr_debug("%s(): started for hva 0x%lx\n", __func__, hva);

	if (mpdma_fixup_page_prot(PAGE_ALIGN_DOWN(hva), 1))
		goto err;

	BUG_ON(!kvm);

	nbsr = kvm->arch.nbsr;
	if (!nbsr)
		goto err;

	/* FIXME: now only one node #0 is allowed */
	regs = nbsr->nodes[0].bc_regs;

	gpa = kvm_hva_to_gpa(kvm, hva);
	BUG_ON(gpa == INVALID_GPA);

	mutex_lock(&nbsr->lock);
	if (handle_mpdma_request(kvm, regs, gpa)) {
		mutex_unlock(&nbsr->lock);
		goto err;
	}
	mutex_unlock(&nbsr->lock);

	return PFR_SUCCESS;

err:
	return pf_force_sig_info("handle MPDMA", SIGBUS, BUS_ADRERR, hva, ptregs);
}

int kvm_get_nbsr_state(struct kvm *kvm, struct kvm_guest_nbsr_state *nbsr)
{
	struct kvm_nbsr *nbsr_kvm = kvm->arch.nbsr;
	u32 reg_lo, reg_hi;

	nbsr->cpu_iset = kvm->arch.nbsr->iset_no;

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcim0, &nbsr->rt_pcim0);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcim1, &nbsr->rt_pcim1);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcim2, &nbsr->rt_pcim2);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcim3, &nbsr->rt_pcim3);

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pciio0, &nbsr->rt_pciio0);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pciio1, &nbsr->rt_pciio1);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pciio2, &nbsr->rt_pciio2);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pciio3, &nbsr->rt_pciio3);

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_b0, &nbsr->rt_pcimp_b0);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_b1, &nbsr->rt_pcimp_b1);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_b2, &nbsr->rt_pcimp_b2);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_b3, &nbsr->rt_pcimp_b3);

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_e0, &nbsr->rt_pcimp_e0);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_e1, &nbsr->rt_pcimp_e1);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_e2, &nbsr->rt_pcimp_e2);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcimp_e3, &nbsr->rt_pcimp_e3);

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_pcicfgb, &nbsr->rt_pcicfgb);

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_msi, &reg_lo);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_rt_msi_h, &reg_hi);
	nbsr->rt_msi = (u64)reg_hi << 32 | reg_lo;

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_iommu_ctrl, &nbsr->iommu_ctrl);

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_iommu_ba_lo, &reg_lo);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_iommu_ba_hi, &reg_hi);
	nbsr->iommu_ptbar = (u64)reg_hi << 32 | reg_lo;

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_iommu_dtba_lo, &reg_lo);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_iommu_dtba_hi, &reg_hi);
	nbsr->iommu_dtbar = (u64)reg_hi << 32 | reg_lo;

	node_nbsr_reg_read(nbsr_kvm, 0, SIC_prepic_ctrl2, &nbsr->prepic_ctrl2);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_prepic_linp0, &nbsr->prepic_linp0);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_prepic_linp1, &nbsr->prepic_linp1);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_prepic_linp2, &nbsr->prepic_linp2);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_prepic_linp3, &nbsr->prepic_linp3);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_prepic_linp4, &nbsr->prepic_linp4);
	node_nbsr_reg_read(nbsr_kvm, 0, SIC_prepic_linp5, &nbsr->prepic_linp5);

	return 0;
}
