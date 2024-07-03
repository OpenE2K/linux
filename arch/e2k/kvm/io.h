/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	__E2K_KVM_HOST_IO_H_
#define	__E2K_KVM_HOST_IO_H_

#include <linux/types.h>
#include <linux/kvm_host.h>

#include <linux/uaccess.h>

#include "cepic.h"

extern unsigned long kvm_guest_mmio_request(struct kvm_vcpu *vcpu,
			u64 phys_addr, u64 __user *user_data, u8 size,
			u8 is_write);
extern unsigned long kvm_complete_guest_mmio_request(struct kvm_vcpu *vcpu);
extern unsigned long kvm_guest_ioport_request(struct kvm_vcpu *vcpu,
			u16 port, u32 __user *user_data, u8 size,
			u8 is_out);
extern unsigned long kvm_complete_guest_ioport_request(struct kvm_vcpu *vcpu);
extern unsigned long kvm_guest_ioport_string_request(struct kvm_vcpu *vcpu,
			u16 port, void __user *data, u8 size, u32 count,
			u8 is_out);
extern long kvm_guest_console_io(struct kvm_vcpu *vcpu,
			int io_cmd, int count, char __user *str);
extern unsigned long kvm_guest_notify_io(struct kvm_vcpu *vcpu,
			unsigned int notifier_io);
extern int kvm_guest_printk_on_host(struct kvm_vcpu *vcpu,
			char __user *msg, int size);
extern int vcpu_mmio_write(struct kvm_vcpu *vcpu, gpa_t addr, int len,
				const void *v);
extern int vcpu_mmio_read(struct kvm_vcpu *vcpu, gpa_t addr, int len, void *v);

extern int kvm_prefetch_mmio_areas(struct kvm_vcpu *vcpu);
extern int kvm_hv_io_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa,
				intc_info_mu_t *intc_info_mu);

static inline kvm_pfn_t mmio_prefixed_gfn_to_pfn(struct kvm *kvm, gfn_t gfn)
{
	if (!(kvm_is_epic(kvm) && kvm->arch.is_hv))
		return 0;

	/* CEPIC page - always mapped */
	if (gfn == gpa_to_gfn(EPIC_DEFAULT_PHYS_BASE))
		return EPIC_DEFAULT_PHYS_BASE >> PAGE_SHIFT;

	/* IOEPIC pages - for passthrough device */
	if (kvm->arch.ioepic_direct_map) {
		struct ioepic_pt_pin *pt_pin;

		list_for_each_entry(pt_pin, &kvm->arch.ioepic_pt_pin, list) {
			if (gfn == gpa_to_gfn(kvm->arch.ioepic->base_address) + pt_pin->pin)
				return hpa_to_pfn(io_epic_base_node(pt_pin->node)) + pt_pin->pin;
		}
	}

#ifdef KVM_HAVE_LEGACY_VGA_PASSTHROUGH
	/* Legacy VGA area - speed up VGA passthrough */
	if (kvm->arch.legacy_vga_passthrough) {
		gpa_t gpa = gfn_to_gpa(gfn);

		if (gpa >= VGA_VRAM_PHYS_BASE &&
				gpa < VGA_VRAM_PHYS_BASE + VGA_VRAM_SIZE)
			return gfn;
	}
#endif

	return 0;
}

static inline bool is_mmio_prefixed_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return !!mmio_prefixed_gfn_to_pfn(vcpu->kvm, gfn);
}

#endif  /* __E2K_KVM_HOST_IO_H_ */
