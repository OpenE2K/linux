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

#include "sic-nbsr.h"
#include "mmu.h"
#include "gaccess.h"
#include "pic.h"
#include "irq.h"

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

#define	ALIGN_DOWN_TO_MASK(addr, mask)	((addr) & ~(mask))
#define	ALIGN_UP_TO_MASK(addr, mask)	(((addr) + (mask)) & ~(mask))
#define	ALIGN_DOWN_TO_SIZE(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_DOWN_TO_MASK(addr, ((size)-1)))
#define	ALIGN_UP_TO_SIZE(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_UP_TO_MASK(addr, ((size)-1)))

#define	NBSR_LOW_MEMORY_BOUND		(1UL << 32)
#define	NBSR_HI_MEMORY_BOUND		(1UL << 48) /* physical memory size */

#define NBSR_ADDR64(hi, lo)		((((u64)hi) << 32) + ((u64)lo))

#define BC_MP_T_CORR_ADDR(hreg, reg) \
		((((u64)hreg.E2K_MP_T_CORR_H_addr) << 32) + \
		(((u64)reg.E2K_MP_T_CORR_addr) << PAGE_SHIFT))

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
		pr_err("%s(): address 0x%llx is out of North Bridge "
			"registers space from 0x%llx to 0x%llx\n",
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
		pr_err("%s(): address 0x%llx is out of North Bridge "
			"registers space from 0x%llx to 0x%llx\n",
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
		pr_err("%s(): offset 0x%x is out of North Bridge "
			"BC registers space from 0x%04x to 0x%04x\n",
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

static inline void
nbsr_debug_dump_rt_mlo(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_mlo_struct_t rt_mlo;

	rt_mlo.E2K_RT_MLO_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		(rt_mlo.E2K_RT_MLO_bgn << E2K_SIC_ALIGN_RT_MLO),
		(rt_mlo.E2K_RT_MLO_end << E2K_SIC_ALIGN_RT_MLO) |
			(E2K_SIC_SIZE_RT_MLO - 1));
}

static inline void
nbsr_debug_dump_rt_mhi(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_mhi_struct_t rt_mhi;

	rt_mhi.E2K_RT_MHI_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%016llx:%016llx]\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		((u64)rt_mhi.E2K_RT_MHI_bgn << E2K_SIC_ALIGN_RT_MHI),
		((u64)rt_mhi.E2K_RT_MHI_end << E2K_SIC_ALIGN_RT_MHI) |
			(E2K_SIC_SIZE_RT_MHI - 1));
}

static inline void
nbsr_debug_dump_rt_lcfg(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_lcfg_struct_t rt_lcfg;
	int pn;

	E2K_RT_LCFG_reg(rt_lcfg) = reg_value;
	pn = E8C_RT_LCFG_pln(rt_lcfg);
	nbsr_debug("%s(): node #%d %s %s 0x%04x link to node #%d %s boot %s "
		"IO link %s intercluster %s\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset, pn,
		(E2K_RT_LCFG_vp(rt_lcfg)) ? "ON" : "OFF",
		(E2K_RT_LCFG_vb(rt_lcfg)) ? "ON" : "OFF",
		(E2K_RT_LCFG_vio(rt_lcfg)) ? "ON" : "OFF",
		(E2K_RT_LCFG_vics(rt_lcfg)) ? "ON" : "OFF");
}

static inline void
nbsr_debug_dump_rt_pcim(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_pcim_struct_t rt_pcim;

	rt_pcim.E2K_RT_PCIM_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		(rt_pcim.E2K_RT_PCIM_bgn << E2K_SIC_ALIGN_RT_PCIM),
		(rt_pcim.E2K_RT_PCIM_end << E2K_SIC_ALIGN_RT_PCIM) |
			(E2K_SIC_SIZE_RT_PCIM - 1));
}

static inline void
nbsr_debug_dump_rt_pciio(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_pciio_struct_t rt_pciio;

	rt_pciio.E2K_RT_PCIIO_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		(rt_pciio.E2K_RT_PCIIO_bgn << E2K_SIC_ALIGN_RT_PCIIO),
		(rt_pciio.E2K_RT_PCIIO_end << E2K_SIC_ALIGN_RT_PCIIO) |
			(E2K_SIC_SIZE_RT_PCIIO - 1));
}

static inline void
nbsr_debug_dump_rt_pcimp(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name, bool end)
{
	e2k_rt_pcimp_struct_t rt_pcimp;

	rt_pcimp.E2K_RT_PCIMP_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x %s : %08x\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		(end) ? "end " : "base",
		(!end) ? (rt_pcimp.E2K_RT_PCIMP_bgn << E2K_SIC_ALIGN_RT_PCIMP)
			:
			(rt_pcimp.E2K_RT_PCIMP_end << E2K_SIC_ALIGN_RT_PCIMP) |
				(E2K_SIC_SIZE_RT_PCIMP - 1));
}

static inline void
nbsr_debug_dump_rt_pcicfgb(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_pcicfgb_struct_t rt_pcicfgb;

	rt_pcicfgb.E2K_RT_PCICFGB_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x : %08x\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		rt_pcicfgb.E2K_RT_PCICFGB_bgn << E2K_SIC_ALIGN_RT_PCICFGB);
}

static inline void
nbsr_debug_dump_rt_ioapic(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_ioapic_struct_t rt_ioapic;
	u32 start, end;

	rt_ioapic.E2K_RT_IOAPIC_reg = reg_value;
	start = (rt_ioapic.E2K_RT_IOAPIC_bgn << E2K_SIC_ALIGN_RT_IOAPIC) |
			(IO_EPIC_DEFAULT_PHYS_BASE &
				E2K_SIC_IOAPIC_FIX_ADDR_MASK);
	end = start + (E2K_SIC_IOAPIC_SIZE- 1);
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset, start, end);
}

static inline void
nbsr_debug_dump_rt_msi(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_msi_struct_t rt_msi;

	rt_msi.E2K_RT_MSI_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		(rt_msi.E2K_RT_MSI_bgn << E2K_SIC_ALIGN_RT_MSI),
		(rt_msi.E2K_RT_MSI_end << E2K_SIC_ALIGN_RT_MSI) |
			(E2K_SIC_SIZE_RT_MSI - 1));
}

static inline void
nbsr_debug_dump_rt_msi_h(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	e2k_rt_msi_h_struct_t rt_msi_h;

	rt_msi_h.E2K_RT_MSI_H_reg = reg_value;
	nbsr_debug("%s(): node #%d %s %s 0x%04x [%08x:%08x]\n",
		__func__, node_id, (write) ? "write" : "read",
		reg_name, reg_offset,
		rt_msi_h.E2K_RT_MSI_H_bgn, rt_msi_h.E2K_RT_MSI_H_end);
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
		__func__, node_id, (write) ? "write" : "read", reg_name, reg_offset);
}

static inline void
nbsr_debug_dump_l3(int node_id, unsigned int reg_offset, bool write,
			unsigned int reg_value, char *reg_name)
{
	nbsr_debug("%s(): node #%d %s %s 0x%04x\n",
		__func__, node_id, (write) ? "write" : "read", reg_name, reg_offset);
}

static inline void
nbsr_debug_dump_prepic(int node_id, unsigned int reg_offset,
			unsigned int val, bool write,
			char *reg_name)
{
	nbsr_debug("%s(): node #%d 32-bit value 0x%x %s %s 0x%04x\n",
		__func__, node_id, val, (write) ? "write to" : "read from",
		reg_name, reg_offset);
}

static int node_nbsr_read_rt_mem(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;
	bool is_rt_mlo = false;
	bool is_rt_mhi = false;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_mlo0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mlo0)];
		reg_name = "rt_mlo0";
		is_rt_mlo = true;
		break;
	case SIC_rt_mlo1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mlo1)];
		reg_name = "rt_mlo1";
		is_rt_mlo = true;
		break;
	case SIC_rt_mlo2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mlo2)];
		reg_name = "rt_mlo2";
		is_rt_mlo = true;
		break;
	case SIC_rt_mlo3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mlo3)];
		reg_name = "rt_mlo3";
		is_rt_mlo = true;
		break;
	case SIC_rt_mhi0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mhi0)];
		reg_name = "rt_mhi0";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mhi1)];
		reg_name = "rt_mhi1";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mhi2)];
		reg_name = "rt_mhi2";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_mhi3)];
		reg_name = "rt_mhi3";
		is_rt_mhi = true;
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	if (is_rt_mhi) {
		nbsr_debug_dump_rt_mhi(node_id, reg_offset, false, *reg_val,
					reg_name);
	} else if (is_rt_mlo) {
		nbsr_debug_dump_rt_mlo(node_id, reg_offset, false, *reg_val,
					reg_name);
	} else {
		nbsr_debug("%s(): node #%d %s offset 0x%04x value 0x%x\n",
			__func__, node_id, reg_name, reg_offset, *reg_val);
	}

	return 0;
}

static void node_nbsr_write_rt_mem(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;
	bool is_rt_mlo = false;
	bool is_rt_mhi = false;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_mlo0:
		node_nbsr->regs[offset_to_no(SIC_rt_mlo0)] = reg_value;
		reg_name = "rt_mlo0";
		is_rt_mlo = true;
		break;
	case SIC_rt_mlo1:
		node_nbsr->regs[offset_to_no(SIC_rt_mlo1)] = reg_value;
		reg_name = "rt_mlo1";
		is_rt_mlo = true;
		break;
	case SIC_rt_mlo2:
		node_nbsr->regs[offset_to_no(SIC_rt_mlo2)] = reg_value;
		reg_name = "rt_mlo2";
		is_rt_mlo = true;
		break;
	case SIC_rt_mlo3:
		node_nbsr->regs[offset_to_no(SIC_rt_mlo3)] = reg_value;
		reg_name = "rt_mlo3";
		is_rt_mlo = true;
		break;
	case SIC_rt_mhi0:
		node_nbsr->regs[offset_to_no(SIC_rt_mhi0)] = reg_value;
		reg_name = "rt_mhi0";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi1:
		node_nbsr->regs[offset_to_no(SIC_rt_mhi1)] = reg_value;
		reg_name = "rt_mhi1";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi2:
		node_nbsr->regs[offset_to_no(SIC_rt_mhi2)] = reg_value;
		reg_name = "rt_mhi2";
		is_rt_mhi = true;
		break;
	case SIC_rt_mhi3:
		node_nbsr->regs[offset_to_no(SIC_rt_mhi3)] = reg_value;
		reg_name = "rt_mhi3";
		is_rt_mhi = true;
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	if (is_rt_mhi) {
		nbsr_debug_dump_rt_mhi(node_id, reg_offset, true, reg_value,
					reg_name);
	} else if (is_rt_mlo) {
		nbsr_debug_dump_rt_mlo(node_id, reg_offset, true, reg_value,
					reg_name);
	} else {
		nbsr_debug("%s(): node #%d %s offset 0x%04x value 0x%x\n",
			__func__, node_id, reg_name, reg_offset, reg_value);
	}
}

static int node_nbsr_read_rt_lcfg(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_lcfg0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_lcfg0)];
		reg_name = "rt_lcfg0";
		break;
	case SIC_rt_lcfg1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_lcfg1)];
		reg_name = "rt_lcfg1";
		break;
	case SIC_rt_lcfg2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_lcfg2)];
		reg_name = "rt_lcfg2";
		break;
	case SIC_rt_lcfg3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_lcfg3)];
		reg_name = "rt_lcfg3";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_lcfg(node_id, reg_offset, false, *reg_val,
				reg_name);

	return 0;
}

static void node_nbsr_write_rt_lcfg(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_lcfg0:
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg0)] = reg_value;
		reg_name = "rt_lcfg0";
		break;
	case SIC_rt_lcfg1:
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg1)] = reg_value;
		reg_name = "rt_lcfg1";
		break;
	case SIC_rt_lcfg2:
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg2)] = reg_value;
		reg_name = "rt_lcfg2";
		break;
	case SIC_rt_lcfg3:
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg3)] = reg_value;
		reg_name = "rt_lcfg3";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_lcfg(node_id, reg_offset, true, reg_value,
				reg_name);
}

static int node_nbsr_read_rt_pcim(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcim0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcim0)];
		reg_name = "rt_pcim0";
		break;
	case SIC_rt_pcim1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcim1)];
		reg_name = "rt_pcim1";
		break;
	case SIC_rt_pcim2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcim2)];
		reg_name = "rt_pcim2";
		break;
	case SIC_rt_pcim3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcim3)];
		reg_name = "rt_pcim3";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcim(node_id, reg_offset, false, *reg_val,
				reg_name);

	return 0;
}

static void node_nbsr_write_rt_pcim(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcim0:
		node_nbsr->regs[offset_to_no(SIC_rt_pcim0)] = reg_value;
		reg_name = "rt_pcim0";
		break;
	case SIC_rt_pcim1:
		node_nbsr->regs[offset_to_no(SIC_rt_pcim1)] = reg_value;
		reg_name = "rt_pcim1";
		break;
	case SIC_rt_pcim2:
		node_nbsr->regs[offset_to_no(SIC_rt_pcim2)] = reg_value;
		reg_name = "rt_pcim2";
		break;
	case SIC_rt_pcim3:
		node_nbsr->regs[offset_to_no(SIC_rt_pcim3)] = reg_value;
		reg_name = "rt_pcim3";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcim(node_id, reg_offset, true, reg_value,
				reg_name);
}

static int node_nbsr_read_rt_pciio(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pciio0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pciio0)];
		reg_name = "rt_pciio0";
		break;
	case SIC_rt_pciio1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pciio1)];
		reg_name = "rt_pciio1";
		break;
	case SIC_rt_pciio2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pciio2)];
		reg_name = "rt_pciio2";
		break;
	case SIC_rt_pciio3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pciio3)];
		reg_name = "rt_pciio3";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pciio(node_id, reg_offset, false, *reg_val,
				reg_name);

	return 0;
}

static void node_nbsr_write_rt_pciio(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pciio0:
		node_nbsr->regs[offset_to_no(SIC_rt_pciio0)] = reg_value;
		reg_name = "rt_pciio0";
		break;
	case SIC_rt_pciio1:
		node_nbsr->regs[offset_to_no(SIC_rt_pciio1)] = reg_value;
		reg_name = "rt_pciio1";
		break;
	case SIC_rt_pciio2:
		node_nbsr->regs[offset_to_no(SIC_rt_pciio2)] = reg_value;
		reg_name = "rt_pciio2";
		break;
	case SIC_rt_pciio3:
		node_nbsr->regs[offset_to_no(SIC_rt_pciio3)] = reg_value;
		reg_name = "rt_pciio3";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pciio(node_id, reg_offset, true, reg_value,
				reg_name);
}

static int node_nbsr_read_rt_pcimp_b(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_b0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b0)];
		reg_name = "rt_pcimp_b0";
		break;
	case SIC_rt_pcimp_b1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b1)];
		reg_name = "rt_pcimp_b1";
		break;
	case SIC_rt_pcimp_b2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b2)];
		reg_name = "rt_pcimp_b2";
		break;
	case SIC_rt_pcimp_b3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b3)];
		reg_name = "rt_pcimp_b3";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, false, *reg_val,
				reg_name, false);

	return 0;
}

static int node_nbsr_read_rt_pcimp_e(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_e0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e0)];
		reg_name = "rt_pcimp_e0";
		break;
	case SIC_rt_pcimp_e1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e1)];
		reg_name = "rt_pcimp_e1";
		break;
	case SIC_rt_pcimp_e2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e2)];
		reg_name = "rt_pcimp_e2";
		break;
	case SIC_rt_pcimp_e3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e3)];
		reg_name = "rt_pcimp_e3";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, false, *reg_val,
				reg_name, true);

	return 0;
}

static int node_nbsr_read_rt_pcicfgb(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_pcicfgb)];
	reg_name = "rt_pcicfgb";
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcicfgb(node_id, reg_offset, false, *reg_val, reg_name);

	return 0;
}

static void node_nbsr_write_rt_pcimp_b(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_b0:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b0)] = reg_value;
		reg_name = "rt_pcimp_b0";
		break;
	case SIC_rt_pcimp_b1:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b1)] = reg_value;
		reg_name = "rt_pcimp_b1";
		break;
	case SIC_rt_pcimp_b2:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b2)] = reg_value;
		reg_name = "rt_pcimp_b2";
		break;
	case SIC_rt_pcimp_b3:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b3)] = reg_value;
		reg_name = "rt_pcimp_b3";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, true, reg_value,
				reg_name, false);
}

static void node_nbsr_write_rt_pcimp_e(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_pcimp_e0:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e0)] = reg_value;
		reg_name = "rt_pcimp_e0";
		break;
	case SIC_rt_pcimp_e1:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e1)] = reg_value;
		reg_name = "rt_pcimp_e1";
		break;
	case SIC_rt_pcimp_e2:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e2)] = reg_value;
		reg_name = "rt_pcimp_e2";
		break;
	case SIC_rt_pcimp_e3:
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e3)] = reg_value;
		reg_name = "rt_pcimp_e3";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcimp(node_id, reg_offset, true, reg_value,
				reg_name, true);
}

static void node_nbsr_write_rt_pcicfgb(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	node_nbsr->regs[offset_to_no(SIC_rt_pcicfgb)] = reg_value;
	reg_name = "rt_pcicfgb";
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_pcicfgb(node_id, reg_offset, true, reg_value, reg_name);
}

static int node_nbsr_read_rt_ioapic(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_ioapic0:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_ioapic0)];
		reg_name = "rt_ioapic0";
		break;
	case SIC_rt_ioapic1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_ioapic1)];
		reg_name = "rt_ioapic1";
		break;
	case SIC_rt_ioapic2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_ioapic2)];
		reg_name = "rt_ioapic2";
		break;
	case SIC_rt_ioapic3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_ioapic3)];
		reg_name = "rt_ioapic3";
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_ioapic(node_id, reg_offset, false, *reg_val,
				reg_name);

	return 0;
}

static void node_nbsr_write_rt_ioapic(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_ioapic0:
		node_nbsr->regs[offset_to_no(SIC_rt_ioapic0)] = reg_value;
		reg_name = "rt_ioapic0";
		break;
	case SIC_rt_ioapic1:
		node_nbsr->regs[offset_to_no(SIC_rt_ioapic1)] = reg_value;
		reg_name = "rt_ioapic1";
		break;
	case SIC_rt_ioapic2:
		node_nbsr->regs[offset_to_no(SIC_rt_ioapic2)] = reg_value;
		reg_name = "rt_ioapic2";
		break;
	case SIC_rt_ioapic3:
		node_nbsr->regs[offset_to_no(SIC_rt_ioapic3)] = reg_value;
		reg_name = "rt_ioapic3";
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_rt_ioapic(node_id, reg_offset, true, reg_value,
				reg_name);
}

static int node_nbsr_read_rt_msi(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_msi:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_msi)];
		break;
	case SIC_rt_msi_h:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_rt_msi_h)];
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
	}
	mutex_unlock(&nbsr->lock);

	switch (reg_offset) {
	case SIC_rt_msi:
		nbsr_debug_dump_rt_msi(node_id, reg_offset, false, *reg_val,
				"rt_msi");
		break;
	case SIC_rt_msi_h:
		nbsr_debug_dump_rt_msi_h(node_id, reg_offset, false, *reg_val,
				"rt_msi_h");
		break;
	}

	return 0;
}

static int node_nbsr_read_pmc(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	*reg_val = node_nbsr->regs[offset_to_no(reg_offset)];
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_pmc(node_id, reg_offset, false, *reg_val, "pmc_sleep");

	return 0;
}

static int node_nbsr_read_l3(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_l3_ctrl:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_l3_ctrl)];
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
	}
	mutex_unlock(&nbsr->lock);

	switch (reg_offset) {
	case SIC_l3_ctrl:
		nbsr_debug_dump_l3(node_id, reg_offset, false, *reg_val, "l3_ctrl");
		break;
	}

	return 0;
}

static int node_nbsr_readll_iommu(struct kvm_nbsr *nbsr, int node_id,
		unsigned int reg_offset, u64 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name = "???";
	int ret = 0;
	u64 reg_lo, reg_hi;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_iommu_ba_lo:
		reg_lo = node_nbsr->regs[offset_to_no(SIC_iommu_ba_lo)];
		reg_hi = node_nbsr->regs[offset_to_no(SIC_iommu_ba_hi)];
		*reg_val = reg_lo | (reg_hi << 32);
		reg_name = "iommu_ba";
		break;
	case SIC_iommu_dtba_lo:
		reg_lo = node_nbsr->regs[offset_to_no(SIC_iommu_dtba_lo)];
		reg_hi = node_nbsr->regs[offset_to_no(SIC_iommu_dtba_hi)];
		*reg_val = reg_lo | (reg_hi << 32);
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
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not"
			"yet supported, so return 0x%llx\n",
			__func__, node_id, reg_offset, *reg_val);
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_prepic(node_id, reg_offset, false, *reg_val,
			reg_name);

	return ret;
}

static int node_nbsr_read_prepic(struct kvm_nbsr *nbsr, int node_id,
		unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;
	int ret = 0;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_prepic_ctrl2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_prepic_ctrl2)];
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
		*reg_val = node_nbsr->regs[offset_to_no(SIC_prepic_linp0)];
		reg_name = "prepic_linp0";
		break;
	case SIC_prepic_linp1:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_prepic_linp1)];
		reg_name = "prepic_linp1";
		break;
	case SIC_prepic_linp2:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_prepic_linp2)];
		reg_name = "prepic_linp2";
		break;
	case SIC_prepic_linp3:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_prepic_linp3)];
		reg_name = "prepic_linp3";
		break;
	case SIC_prepic_linp4:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_prepic_linp4)];
		reg_name = "prepic_linp4";
		break;
	case SIC_prepic_linp5:
		*reg_val = node_nbsr->regs[offset_to_no(SIC_prepic_linp5)];
		reg_name = "prepic_linp5";
		break;
	default:
		*reg_val = -1;
		reg_name = "???";
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_prepic(node_id, reg_offset, false, *reg_val,
				reg_name);

	return ret;
}

static void node_nbsr_write_rt_msi(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_rt_msi:
		node_nbsr->regs[offset_to_no(SIC_rt_msi)] = reg_value;
		break;
	case SIC_rt_msi_h:
		node_nbsr->regs[offset_to_no(SIC_rt_msi_h)] = reg_value;
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		break;
	}
	mutex_unlock(&nbsr->lock);

	switch (reg_offset) {
	case SIC_rt_msi:
		nbsr_debug_dump_rt_msi(node_id, reg_offset, true, reg_value,
				"rt_msi");
		break;
	case SIC_rt_msi_h:
		nbsr_debug_dump_rt_msi_h(node_id, reg_offset, true, reg_value,
				"rt_msi_h");
		break;
	}
}

static void nbsr_update_iommu_tdp(struct kvm *kvm, kvm_nbsr_regs_t *nbsr)
{
	u32 ctrl = nbsr->regs[offset_to_no(SIC_iommu_ctrl)];
	u64 ptbar = (u64) nbsr->regs[offset_to_no(SIC_iommu_ba_hi)] << 32 |
		nbsr->regs[offset_to_no(SIC_iommu_ba_lo)];

	kvm_iommu_write_ctrl_ptbar(kvm, ctrl, ptbar);
}

static int node_nbsr_write_iommu(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;
	int ret = 0;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_iommu_ctrl:
		node_nbsr->regs[offset_to_no(SIC_iommu_ctrl)] = reg_value;
		nbsr_update_iommu_tdp(nbsr->kvm, node_nbsr);
		reg_name = "iommu_ctrl";
		ret = -EOPNOTSUPP;
		break;
	default:
		pr_err("%s(): node #%d IOMMU reg with offset 0x%04x does not "
			"support 32-bit writes, so ignore it\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_iommu(node_id, reg_offset, reg_value, true, reg_name,
		false);

	return ret;
}

static u32 kvm_write_pmc_sleep(u32 reg_value)
{
	freq_core_sleep_t fr_state;

	AW(fr_state) = reg_value;
	fr_state.status = 0;	/* Stay in C0 state */

	return AW(fr_state);
}

static int node_nbsr_write_pmc(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	int ret = 0;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	node_nbsr->regs[offset_to_no(reg_offset)] = kvm_write_pmc_sleep(reg_value);
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_pmc(node_id, reg_offset, reg_value, true, "pmc_sleep");

	return ret;
}

static u32 kvm_write_l3_ctrl(struct kvm_nbsr *nbsr, u32 reg_value)
{
	l3_ctrl_t l3_ctrl;

	AW(l3_ctrl) = reg_value;
	l3_ctrl.E2K_L3_CTRL_fl = 0;	/* No need for L3 flush */

	return AW(l3_ctrl);
}

static int node_nbsr_write_l3(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	int ret = 0;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	switch (reg_offset) {
	case SIC_l3_ctrl:
		node_nbsr->regs[offset_to_no(SIC_l3_ctrl)] = kvm_write_l3_ctrl(nbsr, reg_value);
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		break;
	}
	mutex_unlock(&nbsr->lock);

	switch (reg_offset) {
	case SIC_l3_ctrl:
		nbsr_debug_dump_l3(node_id, reg_offset, reg_value, true, "l3_ctrl");
		break;
	}

	return ret;
}

static int node_nbsr_write_prepic(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset,
					u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;
	int ret = 0;

	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	/*
	 * TODO: Additional actions when writing to
	 * ctrl2, err_start, err_int ?
	 */
	switch (reg_offset) {
	case SIC_prepic_ctrl2:
		ret = -EOPNOTSUPP;
		node_nbsr->regs[offset_to_no(SIC_prepic_ctrl2)] = reg_value;
		reg_name = "prepic_ctrl2";
		break;
	/* SIC_prepic_err_stat is emulated only in qemu */
	case SIC_prepic_err_stat:
		ret = -EOPNOTSUPP;
		reg_name = "prepic_err_stat";
		break;
	/* SIC_prepic_err_int is emulated only in qemu */
	case SIC_prepic_err_int:
		ret = -EOPNOTSUPP;
		reg_name = "prepic_err_int";
		break;
	case SIC_prepic_linp0:
		ret = -EOPNOTSUPP;
		node_nbsr->regs[offset_to_no(SIC_prepic_linp0)] = reg_value;
		reg_name = "prepic_linp0";
		break;
	case SIC_prepic_linp1:
		ret = -EOPNOTSUPP;
		node_nbsr->regs[offset_to_no(SIC_prepic_linp1)] = reg_value;
		reg_name = "prepic_linp1";
		break;
	case SIC_prepic_linp2:
		ret = -EOPNOTSUPP;
		node_nbsr->regs[offset_to_no(SIC_prepic_linp2)] = reg_value;
		reg_name = "prepic_linp2";
		break;
	case SIC_prepic_linp3:
		ret = -EOPNOTSUPP;
		node_nbsr->regs[offset_to_no(SIC_prepic_linp3)] = reg_value;
		reg_name = "prepic_linp3";
		break;
	case SIC_prepic_linp4:
		ret = -EOPNOTSUPP;
		node_nbsr->regs[offset_to_no(SIC_prepic_linp4)] = reg_value;
		reg_name = "prepic_linp4";
		break;
	case SIC_prepic_linp5:
		ret = -EOPNOTSUPP;
		node_nbsr->regs[offset_to_no(SIC_prepic_linp5)] = reg_value;
		reg_name = "prepic_linp5";
		break;
	default:
		pr_err("%s(): node #%d prepic reg with offset 0x%04x "
			"doesn't support 32-bit writes, so ignore it\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_prepic(node_id, reg_offset, reg_value, true,
				reg_name);

	return ret;
}

static int node_nbsr_writell_iommu(struct kvm_nbsr *nbsr, int node_id,
					unsigned int reg_offset, u64 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	char *reg_name;
	int ret = 0;
	u32 reg_hi, reg_lo;

	reg_lo = reg_value & 0xffffffff;
	reg_hi = reg_value >> 32;
	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	/* Only *_lo halves 64-bit accesses are supported */
	switch (reg_offset) {
	case SIC_iommu_ba_lo:
		node_nbsr->regs[offset_to_no(SIC_iommu_ba_lo)] = reg_lo;
		node_nbsr->regs[offset_to_no(SIC_iommu_ba_hi)] = reg_hi;
		nbsr_update_iommu_tdp(nbsr->kvm, node_nbsr);
		reg_name = "iommu_ba_lo";
		ret = -EOPNOTSUPP;
		break;
	case SIC_iommu_dtba_lo:
		node_nbsr->regs[offset_to_no(SIC_iommu_dtba_lo)] = reg_lo;
		node_nbsr->regs[offset_to_no(SIC_iommu_dtba_hi)] = reg_hi;
		reg_name = "iommu_dtba_lo";
		ret = -EOPNOTSUPP;
		break;
	/* No need to forward flushes to qemu */
	case SIC_iommu_flush:
		node_nbsr->regs[offset_to_no(SIC_iommu_flush)] = reg_lo;
		node_nbsr->regs[offset_to_no(SIC_iommu_flushP)] = reg_hi;
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
	default:
		pr_err("%s(): node #%d IOMMU reg with offset 0x%04x does not "
			"support 64-bit writes, so ignore it\n",
			__func__, node_id, reg_offset);
		reg_name = "???";
		break;
	}
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_iommu(node_id, reg_offset, reg_value, true, reg_name,
		true);

	return ret;
}

static int node_nbsr_sic_read(struct kvm_nbsr *nbsr, int node_id,
				unsigned int reg_offset, u32 *reg_val)
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
		return node_nbsr_read_rt_mem(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_lcfg0:
	case SIC_rt_lcfg1:
	case SIC_rt_lcfg2:
	case SIC_rt_lcfg3:
		return node_nbsr_read_rt_lcfg(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_pcim0:
	case SIC_rt_pcim1:
	case SIC_rt_pcim2:
	case SIC_rt_pcim3:
		return node_nbsr_read_rt_pcim(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_pciio0:
	case SIC_rt_pciio1:
	case SIC_rt_pciio2:
	case SIC_rt_pciio3:
		return node_nbsr_read_rt_pciio(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_pcimp_b0:
	case SIC_rt_pcimp_b1:
	case SIC_rt_pcimp_b2:
	case SIC_rt_pcimp_b3:
		return node_nbsr_read_rt_pcimp_b(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_pcimp_e0:
	case SIC_rt_pcimp_e1:
	case SIC_rt_pcimp_e2:
	case SIC_rt_pcimp_e3:
		return node_nbsr_read_rt_pcimp_e(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_pcicfgb:
		return node_nbsr_read_rt_pcicfgb(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		return node_nbsr_read_rt_ioapic(nbsr, node_id,
						reg_offset, reg_val);
	case SIC_rt_msi:
	case SIC_rt_msi_h:
		return node_nbsr_read_rt_msi(nbsr, node_id,
						reg_offset, reg_val);
	case PMC_FREQ_CORE_N_SLEEP(0):
	case PMC_FREQ_CORE_N_SLEEP(1):
	case PMC_FREQ_CORE_N_SLEEP(2):
	case PMC_FREQ_CORE_N_SLEEP(3):
	case PMC_FREQ_CORE_N_SLEEP(4):
	case PMC_FREQ_CORE_N_SLEEP(5):
	case PMC_FREQ_CORE_N_SLEEP(6):
	case PMC_FREQ_CORE_N_SLEEP(7):
	case PMC_FREQ_CORE_N_SLEEP(8):
	case PMC_FREQ_CORE_N_SLEEP(9):
	case PMC_FREQ_CORE_N_SLEEP(10):
	case PMC_FREQ_CORE_N_SLEEP(11):
	case PMC_FREQ_CORE_N_SLEEP(12):
	case PMC_FREQ_CORE_N_SLEEP(13):
	case PMC_FREQ_CORE_N_SLEEP(14):
	case PMC_FREQ_CORE_N_SLEEP(15):
		return  node_nbsr_read_pmc(nbsr, node_id, reg_offset, reg_val);
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
		return node_nbsr_read_prepic(nbsr, node_id,
						reg_offset, reg_val);
	case EFUSE_RAM_ADDR:
	case EFUSE_RAM_DATA:
		*reg_val = -1;
		pr_err_once("%s(): node #%d NBSR : regs of EFUSE_RAM "
			"(offset 0x%04x) is not yet supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		break;
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
		break;
	}

	return 0;
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
		return node_nbsr_readll_iommu(nbsr, node_id,
						reg_offset, reg_val);
	default:
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%llx\n",
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

	err = mprotect_fixup(vma, &prev, hva, hva + PAGE_SIZE, vm_flags);

	mmap_write_unlock(mm);

	return err;
}

static void node_nbsr_write_bc_mp_t_corr(struct kvm_vcpu *vcpu,
			struct kvm_nbsr *nbsr, int node_id,
			unsigned int reg_no, u32 reg_value)
{
	kvm_nbsr_regs_t		*node_nbsr = &nbsr->nodes[node_id];
	bc_mp_t_corr_struct_t	reg;
	bc_mp_t_corr_h_struct_t	hreg;
	u64			gpa, hva;
	u32			value;

	AW(reg) = reg_value;

	if (!reg.E2K_MP_T_CORR_corr)
		return;

	AW(hreg) = node_nbsr->bc_regs[reg_no + 1];

	value = reg.E2K_MP_T_CORR_value;
	gpa = BC_MP_T_CORR_ADDR(hreg, reg);
	hva = kvm_vcpu_gfn_to_hva(vcpu, gpa_to_gfn(gpa));

	nbsr_debug("%s(): node #%d perform correction for gpa 0x%llx hva 0x%llx "
		"to value %d\n",
		__func__, node_id, gpa, hva, value);

	BUG_ON(mpdma_fixup_page_prot(hva, value));

	reg.E2K_MP_T_CORR_corr = 0;
	node_nbsr->bc_regs[reg_no] = AW(reg);
}

static void node_nbsr_write_bc_mp_stat(struct kvm_nbsr *nbsr, int node_id,
			unsigned int reg_no, u32 reg_value)
{
	kvm_nbsr_regs_t		*node_nbsr = &nbsr->nodes[node_id];
	bc_mp_stat_struct_t	reg;

	AW(reg) = reg_value;

	if (reg.E2K_MP_STAT_b_ne)
		reg.E2K_MP_STAT_b_ne = 0;

	if (reg.E2K_MP_STAT_b_of)
		reg.E2K_MP_STAT_b_of = 0;

	node_nbsr->bc_regs[reg_no] = AW(reg);

	nbsr_debug("%s(): node #%d BC_MP_STAT register changed to value 0x%x\n",
		__func__, node_id, AW(reg));
}

static void node_nbsr_bc_write(struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
			int node_id, unsigned int reg_offset, u32 reg_value)
{
	kvm_nbsr_regs_t *node_nbsr;
	unsigned int reg_no;

	nbsr_debug_dump_bc_reg(node_id, reg_offset, true, reg_value);

	BUG_ON(!nbsr_bc_reg_in_range(reg_offset));
	BUG_ON(!vcpu);

	reg_no = nbsr_bc_reg_offset_to_no(reg_offset);
	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);

	switch (reg_offset) {
	case BC_MP_T_CORR:
		node_nbsr_write_bc_mp_t_corr(
			vcpu, nbsr, node_id, reg_no, reg_value);
		break;
	case BC_MP_STAT:
		node_nbsr_write_bc_mp_stat(nbsr, node_id, reg_no, reg_value);
		break;
	default:
		node_nbsr->bc_regs[reg_no] = reg_value;
		break;
	}

	mutex_unlock(&nbsr->lock);
}

static int node_nbsr_bc_read(struct kvm_nbsr *nbsr, int node_id,
				unsigned int reg_offset, u32 *reg_val)
{
	kvm_nbsr_regs_t *node_nbsr;
	unsigned int reg_no;

	BUG_ON(!nbsr_bc_reg_in_range(reg_offset));

	reg_no = nbsr_bc_reg_offset_to_no(reg_offset);
	node_nbsr = &nbsr->nodes[node_id];

	mutex_lock(&nbsr->lock);
	*reg_val = node_nbsr->bc_regs[reg_no];
	mutex_unlock(&nbsr->lock);

	nbsr_debug_dump_bc_reg(node_id, reg_offset, false, *reg_val);

	return 0;
}

static int node_nbsr_read(struct kvm_nbsr *nbsr, int node_id,
				unsigned int reg_offset, u32 *reg_val)
{
	if (!nbsr_is_node_online(nbsr, node_id)) {
		*reg_val = -1;
		pr_err("%s(): node #%d is not online, so return 0x%x "
			"for reg offset 0x%04x\n",
			__func__, node_id, *reg_val, reg_offset);
		return 0;
	}

	if (nbsr_bc_reg_in_range(reg_offset)) {
		return node_nbsr_bc_read(nbsr, node_id, reg_offset, reg_val);
	} else if (reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET) {
		return node_nbsr_sic_read(nbsr, node_id, reg_offset, reg_val);
	} else {
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so return 0x%x\n",
			__func__, node_id, reg_offset, *reg_val);
	}

	return 0;
}

static int node_nbsr_readll(struct kvm_nbsr *nbsr, int node_id,
				unsigned int reg_offset, u64 *reg_val)
{
	if (!nbsr_is_node_online(nbsr, node_id)) {
		*reg_val = -1;
		pr_err("%s(): node #%d is not online, so return 0x%llx "
			"for reg offset 0x%04x\n",
			__func__, node_id, *reg_val, reg_offset);
		return 0;
	}

	if (reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET) {
		return node_nbsr_sic_readll(nbsr, node_id,
						reg_offset, reg_val);
	} else {
		*reg_val = -1;
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x does not "
			"support 64-bit reads, so return 0x%llx\n",
			__func__, node_id, reg_offset, *reg_val);
	}

	return 0;
}

static int node_nbsr_sic_write(struct kvm_nbsr *nbsr, int node_id,
				unsigned int reg_offset, u32 reg_value)
{
	int ret = 0;

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
		node_nbsr_write_rt_mem(nbsr, node_id, reg_offset, reg_value);
		break;
	case SIC_rt_lcfg0:
	case SIC_rt_lcfg1:
	case SIC_rt_lcfg2:
	case SIC_rt_lcfg3:
		node_nbsr_write_rt_lcfg(nbsr, node_id, reg_offset, reg_value);
		break;
	case SIC_rt_pcim0:
	case SIC_rt_pcim1:
	case SIC_rt_pcim2:
	case SIC_rt_pcim3:
		node_nbsr_write_rt_pcim(nbsr, node_id, reg_offset, reg_value);
		ret = -EOPNOTSUPP;
		break;
	case SIC_rt_pciio0:
	case SIC_rt_pciio1:
	case SIC_rt_pciio2:
	case SIC_rt_pciio3:
		node_nbsr_write_rt_pciio(nbsr, node_id, reg_offset, reg_value);
		ret = -EOPNOTSUPP;
		break;
	case SIC_rt_pcimp_b0:
	case SIC_rt_pcimp_b1:
	case SIC_rt_pcimp_b2:
	case SIC_rt_pcimp_b3:
		node_nbsr_write_rt_pcimp_b(nbsr, node_id, reg_offset,
						reg_value);
		ret = -EOPNOTSUPP;
		break;
	case SIC_rt_pcimp_e0:
	case SIC_rt_pcimp_e1:
	case SIC_rt_pcimp_e2:
	case SIC_rt_pcimp_e3:
		node_nbsr_write_rt_pcimp_e(nbsr, node_id, reg_offset,
						reg_value);
		ret = -EOPNOTSUPP;
		break;
	case SIC_rt_pcicfgb:
		node_nbsr_write_rt_pcicfgb(nbsr, node_id, reg_offset,
						reg_value);
		ret = -EOPNOTSUPP;
		break;
	case SIC_rt_ioapic0:
	case SIC_rt_ioapic1:
	case SIC_rt_ioapic2:
	case SIC_rt_ioapic3:
		node_nbsr_write_rt_ioapic(nbsr, node_id, reg_offset, reg_value);
		break;
	case SIC_rt_msi:
	case SIC_rt_msi_h:
		node_nbsr_write_rt_msi(nbsr, node_id, reg_offset, reg_value);
		ret = -EOPNOTSUPP;
		break;
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
		ret = node_nbsr_write_iommu(nbsr, node_id, reg_offset,
			reg_value);
		break;
	case PMC_FREQ_CORE_N_SLEEP(0):
	case PMC_FREQ_CORE_N_SLEEP(1):
	case PMC_FREQ_CORE_N_SLEEP(2):
	case PMC_FREQ_CORE_N_SLEEP(3):
	case PMC_FREQ_CORE_N_SLEEP(4):
	case PMC_FREQ_CORE_N_SLEEP(5):
	case PMC_FREQ_CORE_N_SLEEP(6):
	case PMC_FREQ_CORE_N_SLEEP(7):
	case PMC_FREQ_CORE_N_SLEEP(8):
	case PMC_FREQ_CORE_N_SLEEP(9):
	case PMC_FREQ_CORE_N_SLEEP(10):
	case PMC_FREQ_CORE_N_SLEEP(11):
	case PMC_FREQ_CORE_N_SLEEP(12):
	case PMC_FREQ_CORE_N_SLEEP(13):
	case PMC_FREQ_CORE_N_SLEEP(14):
	case PMC_FREQ_CORE_N_SLEEP(15):
		ret = node_nbsr_write_pmc(nbsr, node_id, reg_offset, reg_value);
		break;
	case SIC_l3_ctrl:
		ret = node_nbsr_write_l3(nbsr, node_id, reg_offset, reg_value);
		break;
	case SIC_prepic_ctrl2:
	case SIC_prepic_err_stat:
	case SIC_prepic_err_int:
	case SIC_prepic_linp0:
	case SIC_prepic_linp1:
	case SIC_prepic_linp2:
	case SIC_prepic_linp3:
	case SIC_prepic_linp4:
	case SIC_prepic_linp5:
		ret = node_nbsr_write_prepic(nbsr, node_id, reg_offset,
			reg_value);
		break;
	case EFUSE_RAM_ADDR:
	case EFUSE_RAM_DATA:
		pr_err_once("%s(): node #%d NBSR : regs of EFUSE_RAM "
			"(offset 0x%04x) is not yet supported, so ignore write\n",
			__func__, node_id, reg_offset);
		break;
	default:
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
		break;
	}

	return ret;
}

static int node_nbsr_write(struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
		int node_id, unsigned int reg_offset, u32 reg_value)
{
	int ret = 0;

	if (!nbsr_is_node_online(nbsr, node_id)) {
		pr_err("%s(): node #%d is not online, so ignore write to "
			"reg with offset 0x%04x\n",
			__func__, node_id, reg_offset);
		return ret;
	}

	if (nbsr_bc_reg_in_range(reg_offset)) {
		node_nbsr_bc_write(vcpu, nbsr, node_id, reg_offset, reg_value);
	} else if (reg_offset < MAX_SUPPORTED_NODE_NBSR_OFFSET) {
		ret = node_nbsr_sic_write(nbsr, node_id, reg_offset, reg_value);
	} else {
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x is not yet "
			"supported, so ignore write\n",
			__func__, node_id, reg_offset);
	}

	return ret;
}

static int node_nbsr_writell(struct kvm_vcpu *vcpu, struct kvm_nbsr *nbsr,
		int node_id, unsigned int reg_offset, u64 reg_value)
{
	int ret = 0;

	if (!nbsr_is_node_online(nbsr, node_id)) {
		pr_err("%s(): node #%d is not online, so ignore write to "
			"reg with offset 0x%04x\n",
			__func__, node_id, reg_offset);
		return ret;
	}

	/* Fail silently for writes to IOMMU for embedded devices */
	if (reg_offset >= SIC_iommu_ctrl &&
		reg_offset < SIC_iommu_err_info_hi) {
		ret = node_nbsr_writell_iommu(
				nbsr, node_id, reg_offset, reg_value);
	} else if (!(reg_offset >= SIC_edbc_iommu_ctrl &&
			reg_offset < SIC_edbc_iommu_err_info_hi)) {
		pr_err("%s(): node #%d NBSR reg with offset 0x%04x does not "
			"support 64-bit writes, so ignore it\n",
			__func__, node_id, reg_offset);
	}

	return ret;
}

static void nbsr_setup_lo_mem_region(struct kvm_nbsr *nbsr, int node_id,
					gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value;
	e2k_rt_mlo_struct_t rt_mlo;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_LOW_MEMORY_BOUND &&
				base + size <= NBSR_LOW_MEMORY_BOUND);

	start = ALIGN_DOWN_TO_SIZE(base, E2K_SIC_SIZE_RT_MLO);
	end = ALIGN_UP_TO_SIZE(base + size, E2K_SIC_SIZE_RT_MLO) - 1;
	rt_mlo.E2K_RT_MLO_reg = 0;
	rt_mlo.E2K_RT_MLO_bgn = start >> E2K_SIC_ALIGN_RT_MLO;
	rt_mlo.E2K_RT_MLO_end = end >> E2K_SIC_ALIGN_RT_MLO;
	reg_value = rt_mlo.E2K_RT_MLO_reg;

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
	e2k_rt_mhi_struct_t rt_mhi;
	gpa_t start, end;
	int node, link;

	ASSERT(base >= NBSR_LOW_MEMORY_BOUND &&
				base + size > NBSR_LOW_MEMORY_BOUND);

	start = ALIGN_DOWN_TO_SIZE(base, E2K_SIC_SIZE_RT_MHI);
	end = ALIGN_UP_TO_SIZE(base + size, E2K_SIC_SIZE_RT_MHI) - 1;
	rt_mhi.E2K_RT_MHI_reg = 0;
	rt_mhi.E2K_RT_MHI_bgn = start >> E2K_SIC_ALIGN_RT_MHI;
	rt_mhi.E2K_RT_MHI_end = end >> E2K_SIC_ALIGN_RT_MHI;
	reg_value = rt_mhi.E2K_RT_MHI_reg;

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
		nbsr_setup_lo_mem_region(nbsr, node_id, base, size);
	} else {
		ASSERT(base + size > NBSR_LOW_MEMORY_BOUND);
		nbsr_setup_hi_mem_region(nbsr, node_id, base, size);
	}
	return 0;
}

int nbsr_setup_mmio_region(struct kvm_nbsr *nbsr, int node_id,
					gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value;
	e2k_rt_pcim_struct_t rt_pcim;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_LOW_MEMORY_BOUND &&
				base + size <= NBSR_LOW_MEMORY_BOUND);

	start = ALIGN_DOWN_TO_SIZE(base, E2K_SIC_SIZE_RT_PCIM);
	end = ALIGN_UP_TO_SIZE(base + size, E2K_SIC_SIZE_RT_PCIM) - 1;
	rt_pcim.E2K_RT_PCIM_reg = 0;
	rt_pcim.E2K_RT_PCIM_bgn = start >> E2K_SIC_ALIGN_RT_PCIM;
	rt_pcim.E2K_RT_PCIM_end = end >> E2K_SIC_ALIGN_RT_PCIM;
	reg_value = rt_pcim.E2K_RT_PCIM_reg;

	node_nbsr_write(NULL, nbsr, node_id, SIC_rt_pcim0, reg_value);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_pcim_offset(link);
		node_nbsr_write(NULL, nbsr, node, reg_off, reg_value);
	}
	return 0;
}

int nbsr_setup_io_region(struct kvm_nbsr *nbsr, int node_id,
					gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value;
	e2k_rt_pciio_struct_t rt_pciio;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_LOW_MEMORY_BOUND &&
				base + size <= NBSR_LOW_MEMORY_BOUND);

	start = ALIGN_DOWN_TO_SIZE(base, E2K_SIC_SIZE_RT_PCIIO);
	end = ALIGN_UP_TO_SIZE(base + size, E2K_SIC_SIZE_RT_PCIIO) - 1;
	rt_pciio.E2K_RT_PCIIO_reg = 0;
	rt_pciio.E2K_RT_PCIIO_bgn = start >> E2K_SIC_ALIGN_RT_PCIIO;
	rt_pciio.E2K_RT_PCIIO_end = end >> E2K_SIC_ALIGN_RT_PCIIO;
	reg_value = rt_pciio.E2K_RT_PCIIO_reg;

	node_nbsr_write(NULL, nbsr, node_id, SIC_rt_pciio0, reg_value);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_pciio_offset(link);
		node_nbsr_write(NULL, nbsr, node, reg_off, reg_value);
	}
	return 0;
}

int nbsr_setup_pref_mmio_region(struct kvm_nbsr *nbsr, int node_id,
					gpa_t base, gpa_t size)
{
	unsigned int reg_off;
	unsigned int reg_value_b, reg_value_e;
	e2k_rt_pcimp_struct_t rt_pcimp_b;
	e2k_rt_pcimp_struct_t rt_pcimp_e;
	gpa_t start, end;
	int node, link;

	ASSERT(base < NBSR_HI_MEMORY_BOUND &&
				base + size <= NBSR_HI_MEMORY_BOUND);

	start = ALIGN_DOWN_TO_SIZE(base, E2K_SIC_SIZE_RT_PCIMP);
	end = ALIGN_UP_TO_SIZE(base + size, E2K_SIC_SIZE_RT_PCIMP) - 1;
	rt_pcimp_b.E2K_RT_PCIMP_reg = 0;
	rt_pcimp_b.E2K_RT_PCIMP_bgn = start >> E2K_SIC_ALIGN_RT_PCIMP;
	rt_pcimp_e.E2K_RT_PCIMP_reg = 0;
	rt_pcimp_e.E2K_RT_PCIMP_end = end >> E2K_SIC_ALIGN_RT_PCIMP;

	reg_value_b = rt_pcimp_b.E2K_RT_PCIMP_reg;
	node_nbsr_write(NULL, nbsr, node_id, SIC_rt_pcimp_b0, reg_value_b);

	reg_value_e = rt_pcimp_e.E2K_RT_PCIMP_reg;
	node_nbsr_write(NULL, nbsr, node_id, SIC_rt_pcimp_e0, reg_value_e);

	/* it need setup all routers on all nodes */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (node == node_id)
			continue;
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		link = nbsr_get_node_to_node_link(node, node_id);
		reg_off = nbsr_get_rt_pcimp_b_offset(link);
		node_nbsr_write(NULL, nbsr, node, reg_off, reg_value_b);
		reg_off = nbsr_get_rt_pcimp_e_offset(link);
		node_nbsr_write(NULL, nbsr, node, reg_off, reg_value_e);
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

	ASSERT(len == 4 || len == 8); /* 8 bytes access is only for IOMMU */

	node_id = nbsr_addr_to_node(nbsr, addr);
	reg_offset = nbsr_addr_to_reg_offset(nbsr, addr);

	if (len == 4)
		return node_nbsr_read(nbsr, node_id,
					reg_offset, (u32 *)val);
	else
		return node_nbsr_readll(nbsr, node_id,
					reg_offset, (u64 *)val);
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

	ASSERT(len == 4 || len == 8); /* 8 bytes access is only for IOMMU */

	node_id = nbsr_addr_to_node(nbsr, addr);
	reg_offset = nbsr_addr_to_reg_offset(nbsr, addr);
	if (len == 4) {
		u32 reg_value = *(u32 *)val;

		ret = node_nbsr_write(vcpu, nbsr, node_id, reg_offset,
			reg_value);
	} else {
		u64 reg_value = *(u64 *)val;

		ret = node_nbsr_writell(
				vcpu, nbsr, node_id, reg_offset, reg_value);
	}

	return ret;
}

static void kvm_nbsr_reset(struct kvm *kvm, struct kvm_nbsr *nbsr)
{
	e2k_rt_mhi_struct_t rt_mhi;
	e2k_rt_mlo_struct_t rt_mlo;
	e2k_rt_lcfg_struct_t rt_lcfg0, rt_lcfg;
	e2k_rt_pciio_struct_t rt_pciio;
	e2k_rt_pcim_struct_t rt_pcim;
	e2k_rt_pcimp_struct_t rt_pcimp_b, rt_pcimp_e;
	e2k_rt_pcicfgb_struct_t rt_pcicfgb;
	kvm_nbsr_regs_t *node_nbsr;
	u32 mlo_value, mhi_value;
	u32 pcim_value, pciio_value;
	u32 pcimp_b_value, pcimp_e_value;
	u32 pcicfgb_value;
	int node, i;

	memset(nbsr->nodes, 0x00, sizeof(nbsr->nodes));

	rt_mhi.E2K_RT_MHI_reg = 0;
	rt_mhi.E2K_RT_MHI_bgn = 0xff;
	rt_mhi.E2K_RT_MHI_end = 0x00;
	mhi_value = rt_mhi.E2K_RT_MHI_reg;
	rt_mlo.E2K_RT_MLO_reg = 0;
	rt_mlo.E2K_RT_MLO_bgn = 0xff;
	rt_mlo.E2K_RT_MLO_end = 0x00;
	mlo_value = rt_mlo.E2K_RT_MLO_reg;
	rt_pcim.E2K_RT_PCIM_reg = 0;
	rt_pcim.E2K_RT_PCIM_bgn = 0xff;
	rt_pcim.E2K_RT_PCIM_end = 0x00;
	pcim_value = rt_pcim.E2K_RT_PCIM_reg;
	rt_pciio.E2K_RT_PCIIO_reg = 0;
	rt_pciio.E2K_RT_PCIIO_bgn = 0xff;
	rt_pciio.E2K_RT_PCIIO_end = 0x00;
	pciio_value = rt_pciio.E2K_RT_PCIIO_reg;
	rt_pcimp_b.E2K_RT_PCIMP_reg = 0;
	rt_pcimp_b.E2K_RT_PCIMP_bgn = 0xfffff;
	rt_pcimp_e.E2K_RT_PCIMP_reg = 0;
	rt_pcimp_e.E2K_RT_PCIMP_end = 0x00000;
	pcimp_b_value = rt_pcimp_b.E2K_RT_PCIMP_reg;
	pcimp_e_value = rt_pcimp_e.E2K_RT_PCIMP_reg;
	rt_pcicfgb.E2K_RT_PCICFGB_bgn = 0x8;	/* 0x0002 0000 0000 */
	pcicfgb_value = rt_pcicfgb.E2K_RT_PCICFGB_reg;
	for (node = 0; node < MAX_NUMNODES; node++) {
		u32 rt_msi_lo = E2K_RT_MSI_DEFAULT_BASE & 0xffffffff;
		u32 rt_msi_hi = E2K_RT_MSI_DEFAULT_BASE >> 32;

		/*
		 * Bug 129111 workaround: set guest's RT_MSI the same as on host
		 * We trust guest to never change this, and write this value
		 * to IOEPIC/PCI_MSI
		 */
		if (kvm_ioepic_unsafe_direct_map)
			get_io_epic_msi(0, &rt_msi_lo, &rt_msi_hi);

		node_nbsr = &nbsr->nodes[node];
		node_nbsr->regs[offset_to_no(SIC_rt_mhi0)] = mhi_value;
		node_nbsr->regs[offset_to_no(SIC_rt_mhi1)] = mhi_value;
		node_nbsr->regs[offset_to_no(SIC_rt_mhi2)] = mhi_value;
		node_nbsr->regs[offset_to_no(SIC_rt_mhi3)] = mhi_value;
		node_nbsr->regs[offset_to_no(SIC_rt_mlo0)] = mlo_value;
		node_nbsr->regs[offset_to_no(SIC_rt_mlo1)] = mlo_value;
		node_nbsr->regs[offset_to_no(SIC_rt_mlo2)] = mlo_value;
		node_nbsr->regs[offset_to_no(SIC_rt_mlo3)] = mlo_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcim0)] = pcim_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcim1)] = pcim_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcim2)] = pcim_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcim3)] = pcim_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pciio0)] = pciio_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pciio1)] = pciio_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pciio2)] = pciio_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pciio3)] = pciio_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b0)] = pcimp_b_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b1)] = pcimp_b_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b2)] = pcimp_b_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_b3)] = pcimp_b_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e0)] = pcimp_e_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e1)] = pcimp_e_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e2)] = pcimp_e_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcimp_e3)] = pcimp_e_value;
		node_nbsr->regs[offset_to_no(SIC_rt_pcicfgb)] = pcicfgb_value;
		node_nbsr->regs[offset_to_no(SIC_rt_msi)] = rt_msi_lo;
		node_nbsr->regs[offset_to_no(SIC_rt_msi_h)] = rt_msi_hi;
		node_nbsr->regs[offset_to_no(SIC_l3_ctrl)] = 0x3f00f8;
		for (i = 0; i < 16; i++)
			node_nbsr->regs[offset_to_no(PMC_FREQ_CORE_N_SLEEP(i))] = 0;
	}

	/* BSP node, now it should be #0 */
	E2K_RT_LCFG_reg(rt_lcfg0) = 0;
	E8C_RT_LCFG_pln(rt_lcfg0) = 0;
	E2K_RT_LCFG_vp(rt_lcfg0) = 1;
	E2K_RT_LCFG_vb(rt_lcfg0) = 1;
	E2K_RT_LCFG_vio(rt_lcfg0) = 1;
	/* links to other nodes */
	E2K_RT_LCFG_reg(rt_lcfg) = 0;
	E8C_RT_LCFG_pln(rt_lcfg) = 0xff;
	E2K_RT_LCFG_vp(rt_lcfg) = 0;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	node_nbsr = &nbsr->nodes[0];
	node_nbsr->regs[offset_to_no(SIC_rt_lcfg0)] = E2K_RT_LCFG_reg(rt_lcfg0);
	node_nbsr->regs[offset_to_no(SIC_rt_lcfg1)] = E2K_RT_LCFG_reg(rt_lcfg);
	node_nbsr->regs[offset_to_no(SIC_rt_lcfg2)] = E2K_RT_LCFG_reg(rt_lcfg);
	node_nbsr->regs[offset_to_no(SIC_rt_lcfg3)] = E2K_RT_LCFG_reg(rt_lcfg);
	/* APP nodes links to other nodes */
	E2K_RT_LCFG_reg(rt_lcfg) = 0;
	E8C_RT_LCFG_pln(rt_lcfg) = 0xff;
	E2K_RT_LCFG_vp(rt_lcfg) = 1;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	for (node = 1; node < MAX_NUMNODES; node++) {
		if (!nbsr_is_node_online(nbsr, node))
			continue;
		node_nbsr = &nbsr->nodes[node];
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg0)] =
			E2K_RT_LCFG_reg(rt_lcfg);
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg1)] =
			E2K_RT_LCFG_reg(rt_lcfg);
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg2)] =
			E2K_RT_LCFG_reg(rt_lcfg);
		node_nbsr->regs[offset_to_no(SIC_rt_lcfg3)] =
			E2K_RT_LCFG_reg(rt_lcfg);
	}
}

static const struct kvm_io_device_ops nbsr_mmio_ops = {
	.read	= nbsr_mmio_read,
	.write	= nbsr_mmio_write,
};

int kvm_nbsr_init(struct kvm *kvm)
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
	nbsr->base = (gpa_t)THE_NODE_NBSR_PHYS_BASE(0);
	nbsr->size = NODE_NBSR_SIZE * MAX_NUMNODES;
	nbsr->node_size = NODE_NBSR_SIZE;

	/* FIXME: now only one node #0 is allowed */
	nbsr_set_node_online(nbsr, 0);

	kvm_nbsr_reset(kvm, nbsr);
	kvm_iodevice_init(&nbsr->dev, &nbsr_mmio_ops);
	nbsr->kvm = kvm;
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, nbsr->base,
				      nbsr->size, &nbsr->dev);
	if (ret < 0) {
		pr_err("%s(); could not created NBSR emulation device, "
			"error %d\n",
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
	bc_mp_stat_struct_t	stat;
	bc_mp_ctrl_struct_t	ctrl;
	u32			b_put_off, stat_off;
	u32			b_put, b_get, b_hb, b_base, b_base_h, t_hb,
				t_base, t_base_h, t_h_base, t_h_base_h, t_h_lb,
				t_h_lb_h, t_h_hb, t_h_hb_h;
	u64			b_base_64, t_base_64, t_h_base_64, t_h_lb_64,
				t_h_hb_64;
	u64			t_base_gpa, t_h_base_gpa, b_base_gpa;
	u64			gpa_page, t_hb_page, t_h_lb_page, t_h_hb_page;
	u64			t_h_base_id;
	u8			t_base_val, t_h_base_val;
	int			ret;

	AW(ctrl) = regs[nbsr_bc_reg_offset_to_no(BC_MP_CTRL)];

	nbsr_debug("%s(): ctrl 0x%x\n", __func__, AW(ctrl));


	if (!ctrl.E2K_MP_CTRL_mp_en)
		return 0;

	t_hb	 = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_HB)];
	t_base	 = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_BASE)];
	t_base_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_BASE_H)];

	t_base_64 = NBSR_ADDR64(t_base_h, t_base);

	gpa_page  = gpa >> PAGE_SHIFT;
	t_hb_page = t_hb >> PAGE_SHIFT;

	t_base_gpa = t_base_64 + gpa_page;

	if (ret = kvm_read_guest_phys_system(kvm, t_base_gpa, &t_base_val, 1))
		return ret;

	nbsr_debug("%s(): gpa 0x%llx t_hb_page 0x%llx t_base_gpa 0x%llx "
		"t_base_val 0x%x\n",
		__func__, gpa, t_hb_page, t_base_gpa, t_base_val);

	if (gpa < (1UL << 32) && gpa_page <= t_hb_page && t_base_val == 0) {
		nbsr_debug("%s(): set 1 to MPT 0x%llx\n",
			__func__, t_base_gpa);

		t_base_val = 1;

		if (ret = kvm_write_guest_phys_system(
				kvm, t_base_gpa, &t_base_val, 1))
			return ret;
	} else {
		t_h_lb	   = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_LB)];
		t_h_lb_h   = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_LB_H)];
		t_h_hb	   = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_HB)];
		t_h_hb_h   = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_HB_H)];
		t_h_base   = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_BASE)];
		t_h_base_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_T_H_BASE_H)];

		t_h_lb_64   = NBSR_ADDR64(t_h_lb_h, t_h_lb);
		t_h_hb_64   = NBSR_ADDR64(t_h_hb_h, t_h_hb);
		t_h_base_64 = NBSR_ADDR64(t_h_base_h, t_h_base);

		t_h_lb_page = t_h_lb_64 >> PAGE_SHIFT;
		t_h_hb_page = t_h_hb_64 >> PAGE_SHIFT;

		t_h_base_id = (gpa - t_h_lb_64) >> PAGE_SHIFT;

		t_h_base_gpa = t_h_base_64 + t_h_base_id;

		if (ret = kvm_read_guest_phys_system(
				kvm, t_h_base_gpa, &t_h_base_val, 1))
			return ret;

		nbsr_debug("%s(): gpa_page 0x%llx t_h_lb_page 0x%llx "
			"t_h_hb_page 0x%llx t_h_base_gpa 0x%llx "
			"t_h_base_val 0x%x\n",
			__func__, gpa_page, t_h_lb_page, t_h_hb_page,
			t_h_base_gpa, t_h_base_val);

		if (gpa_page >= t_h_lb_page && gpa_page <= t_h_hb_page &&
				t_h_base_val == 0) {
			nbsr_debug("%s(): set 1 to MPT HI 0x%llx\n",
				__func__, t_h_base_gpa);

			t_h_base_val = 1;

			if (ret = kvm_write_guest_phys_system(
					kvm, t_h_base_gpa, &t_h_base_val, 1))
				return ret;
		} else {
			return 0;
		}
	}

	stat_off = nbsr_bc_reg_offset_to_no(BC_MP_STAT);
	AW(stat) = regs[stat_off];

	nbsr_debug("%s(): stat 0x%x\n", __func__, AW(stat));

	if (ctrl.E2K_MP_CTRL_b_en && !stat.E2K_MP_STAT_b_of) {
		b_put_off = nbsr_bc_reg_offset_to_no(BC_MP_B_PUT);

		b_put	 = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_PUT)];
		b_get	 = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_GET)];
		b_hb	 = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_HB)];
		b_base	 = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_BASE)];
		b_base_h = regs[nbsr_bc_reg_offset_to_no(BC_MP_B_BASE_H)];

		b_base_64 = NBSR_ADDR64(b_base_h, b_base);

		b_base_gpa = b_base_64 + b_put;

		nbsr_debug("%s(): set page 0x%llx to BUF 0x%llx\n",
			__func__, gpa_page, b_base_gpa);

		if (ret = kvm_write_guest_phys_system(
				kvm, b_base_gpa, &gpa_page, 8))
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
			stat.E2K_MP_STAT_b_of = 1;

			nbsr_debug("%s(): set BC_MP_STAT 0x%llx to 0x%x\n",
				__func__, &regs[stat_off], AW(stat));

			regs[stat_off] = AW(stat);

			kvm_int_violat_delivery_to_hw_epic(kvm);
		}
	}

	if (!stat.E2K_MP_STAT_b_ne) {
		stat.E2K_MP_STAT_b_ne = 1;

		nbsr_debug("%s(): set BC_MP_STAT 0x%llx to 0x%x\n",
			__func__, &regs[stat_off], AW(stat));

		regs[stat_off] = AW(stat);

		kvm_int_violat_delivery_to_hw_epic(kvm);
	}

	return 0;
}

int native_handle_mpdma_fault(e2k_addr_t hva, struct pt_regs *ptregs)
{
	struct kvm	*kvm = current_thread_info()->virt_machine;
	struct kvm_nbsr	*nbsr;
	u32		*regs;
	gpa_t		gpa;

	nbsr_debug("%s(): started for hva 0x%lx\n", __func__, hva);

	if (mpdma_fixup_page_prot(PAGE_ALIGN_UP(hva), 1))
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
	struct kvm_nbsr	*nbsr_kvm = kvm->arch.nbsr;
	u32 *regs = nbsr_kvm->nodes[0].regs;
	u64 reg_lo, reg_hi;

	nbsr->rt_pcim0 = regs[offset_to_no(SIC_rt_pcim0)];
	nbsr->rt_pcim1 = regs[offset_to_no(SIC_rt_pcim1)];
	nbsr->rt_pcim2 = regs[offset_to_no(SIC_rt_pcim2)];
	nbsr->rt_pcim3 = regs[offset_to_no(SIC_rt_pcim3)];

	nbsr->rt_pciio0 = regs[offset_to_no(SIC_rt_pciio0)];
	nbsr->rt_pciio1 = regs[offset_to_no(SIC_rt_pciio1)];
	nbsr->rt_pciio2 = regs[offset_to_no(SIC_rt_pciio2)];
	nbsr->rt_pciio3 = regs[offset_to_no(SIC_rt_pciio3)];

	nbsr->rt_pcimp_b0 = regs[offset_to_no(SIC_rt_pcimp_b0)];
	nbsr->rt_pcimp_b1 = regs[offset_to_no(SIC_rt_pcimp_b1)];
	nbsr->rt_pcimp_b2 = regs[offset_to_no(SIC_rt_pcimp_b2)];
	nbsr->rt_pcimp_b3 = regs[offset_to_no(SIC_rt_pcimp_b3)];

	nbsr->rt_pcimp_e0 = regs[offset_to_no(SIC_rt_pcimp_e0)];
	nbsr->rt_pcimp_e1 = regs[offset_to_no(SIC_rt_pcimp_e1)];
	nbsr->rt_pcimp_e2 = regs[offset_to_no(SIC_rt_pcimp_e2)];
	nbsr->rt_pcimp_e3 = regs[offset_to_no(SIC_rt_pcimp_e3)];

	nbsr->rt_pcicfgb = regs[offset_to_no(SIC_rt_pcicfgb)];

	reg_lo = regs[offset_to_no(SIC_rt_msi)];
	reg_hi = regs[offset_to_no(SIC_rt_msi_h)];
	nbsr->rt_msi = reg_hi << 32 | reg_lo;

	nbsr->iommu_ctrl = regs[offset_to_no(SIC_iommu_ctrl)];

	reg_lo = regs[offset_to_no(SIC_iommu_ba_lo)];
	reg_hi = regs[offset_to_no(SIC_iommu_ba_hi)];
	nbsr->iommu_ptbar = reg_hi << 32 | reg_lo;

	reg_lo = regs[offset_to_no(SIC_iommu_dtba_lo)];
	reg_hi = regs[offset_to_no(SIC_iommu_dtba_hi)];
	nbsr->iommu_dtbar = reg_hi << 32 | reg_lo;

	nbsr->prepic_ctrl2 = regs[offset_to_no(SIC_prepic_ctrl2)];
	nbsr->prepic_linp0 = regs[offset_to_no(SIC_prepic_linp0)];
	nbsr->prepic_linp1 = regs[offset_to_no(SIC_prepic_linp1)];
	nbsr->prepic_linp2 = regs[offset_to_no(SIC_prepic_linp2)];
	nbsr->prepic_linp3 = regs[offset_to_no(SIC_prepic_linp3)];
	nbsr->prepic_linp4 = regs[offset_to_no(SIC_prepic_linp4)];
	nbsr->prepic_linp5 = regs[offset_to_no(SIC_prepic_linp5)];

	return 0;
}
