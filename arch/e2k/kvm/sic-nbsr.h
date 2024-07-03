/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * North Bridge registers emulation for guest VM
 */

#ifndef __KVM_SIC_NBSR_H
#define __KVM_SIC_NBSR_H

#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <asm/sic_regs.h>

/* only the following number of NBSR registers is now supported */
#define MAX_SUPPORTED_NODE_NBSR_OFFSET	(SIC_prepic_linp5 + 4)
#define MAX_SUPPORTED_NODE_NBSR_NUM	(MAX_SUPPORTED_NODE_NBSR_OFFSET / 4)

typedef struct kvm_nbsr_regs {
	u32 regs[MAX_SUPPORTED_NODE_NBSR_NUM];
	u32 bc_regs[BC_MM_REG_NUM];
} kvm_nbsr_regs_t;

typedef struct kvm_nbsr {
	gpa_t base;	/* NBSR registers base address */
	int size;	/* size of all registers of all nodes */
	int node_size;	/* size of all registers on one node */
	struct kvm_io_device dev;
	struct kvm *kvm;
	unsigned nodes_online;
	struct mutex lock;
	kvm_nbsr_regs_t nodes[MAX_NUMNODES];
} kvm_nbsr_t;

#define DEBUG
#undef ASSERT
#ifdef DEBUG
#define ASSERT(x)							\
do {									\
	if (!(x)) {							\
		pr_emerg("assertion failed %s: %d: %s\n",		\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

/*
 * max values of PCI memory regions limits
 */
#define	KVM_PCI_IO_RANGE_START		   0x00000000
#define	KVM_PCI_IO_RANGE_END		   0x00010000
#define	KVM_PCI_MEM_RANGE_START		   0x00000000
#define	KVM_PCI_MEM_RANGE_END		   0xf8000000
#define	KVM_PCI_PREF_MEM_RANGE_START	0x00000000000
#define	KVM_PCI_PREF_MEM_RANGE_END	0x10000000000

extern int kvm_nbsr_init(struct kvm *kvm);
extern void kvm_nbsr_destroy(struct kvm *kvm);
extern int nbsr_setup_memory_region(struct kvm_nbsr *nbsr, int node_id,
					gpa_t base, gpa_t size);
extern int nbsr_setup_mmio_region(struct kvm_nbsr *nbsr, int node_id,
					gpa_t base, gpa_t size);
extern int nbsr_setup_pref_mmio_region(struct kvm_nbsr *nbsr, int node_id,
					gpa_t base, gpa_t size);
extern int nbsr_setup_pci_region(struct kvm *kvm, kvm_pci_region_t *pci_region);
extern int kvm_get_nbsr_state(struct kvm *kvm,
				struct kvm_guest_nbsr_state *nbsr);

static inline unsigned int offset_to_no(unsigned int reg_offset)
{
	return reg_offset / 4;
}
#endif	/* __KVM_SIC_NBSR_H */
