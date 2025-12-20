/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kvm_host.h>

#include <asm/kvm/proc_context_stacks.h>
#include <asm/trap_table.h>
#include <asm/mmu_types.h>
#include <asm/thread_info.h>
#include <asm/uaccess.h>
#include <asm/e2k_ptypes.h>
#include <asm/debug_print.h>
#include <asm/cpu_regs_types.h>
#include <asm/hw_stacks.h>
#include "gaccess.h"


unsigned long kvm_prepare_gst_mkctxt_hw_stacks(struct kvm_vcpu *vcpu,
					kvm_proc_ctxt_hw_stacks_t *hw_stacks)
{
	e2k_mem_crs_t crs_empty, crs_trampoline, crs_user;
	kvm_proc_ctxt_hw_stacks_t g_stacks;
	unsigned long ret;
	void *ps_frame_lo, *ps_frame_hi, *trampoline;
	int i;

	/* Get user stack params from hcall args */
	ret = kvm_vcpu_copy_from_guest(vcpu, &g_stacks, hw_stacks,
					sizeof(*hw_stacks));
	if (ret)
		return ret;

	int format = g_stacks.format;
	bool protected = (format == CTX_128_BIT);

	/* Put args on register stack */
	for (i = 0; i < g_stacks.args_size / 16; i++) {
		ps_frame_lo = &g_stacks.ps_frames[i].word_lo;
		if (machine.native_iset_ver < E2K_ISET_V5) {
			ps_frame_hi = &g_stacks.ps_frames[i].v3.word_hi;
		} else {
			ps_frame_hi = &g_stacks.ps_frames[i].v5.word_hi;
		}

		kvm_vcpu_copy_guest_virt_system(vcpu, ps_frame_lo,
				g_stacks.args + 16 * i, 8, NULL,
				TAGGED_MEM_STORE_REC_OPC,
				TAGGED_MEM_LOAD_REC_OPC, 0);
		kvm_vcpu_copy_guest_virt_system(vcpu, ps_frame_hi,
				g_stacks.args + 16 * i + 8, 8, NULL,
				TAGGED_MEM_STORE_REC_OPC,
				TAGGED_MEM_LOAD_REC_OPC, 0);
	}

	/* Put uc_link pointer into trampoline frame */
	if (format == CTX_32_BIT) {
		u32 uc_link_32;
		ret = kvm_vcpu_read_guest_virt_system(vcpu,
				(gva_t) g_stacks.uc_link, &uc_link_32, 4);
		if (!ret) {
			u64 uc_link_64 = uc_link_32;
			ret = kvm_vcpu_write_guest_virt_system(vcpu,
					(gva_t) &g_stacks.trampoline_ps_frames[0].word_lo,
					&uc_link_64, 8);
		}
	} else if (format == CTX_64_BIT) {
		if (8 != kvm_vcpu_copy_guest_virt_system(vcpu,
				&g_stacks.trampoline_ps_frames[0].word_lo,
				g_stacks.uc_link, 8, NULL,
				TAGGED_MEM_STORE_REC_OPC,
				TAGGED_MEM_LOAD_REC_OPC, 0)) {
			ret = -EFAULT;
		}
	} else if (format == CTX_128_BIT) {
		ps_frame_lo = &g_stacks.ps_frames[i].word_lo;
		if (machine.native_iset_ver < E2K_ISET_V5) {
			ps_frame_hi = &g_stacks.trampoline_ps_frames[0].v3.word_hi;
		} else {
			ps_frame_hi = &g_stacks.trampoline_ps_frames[0].v5.word_hi;
		}

		if (8 != kvm_vcpu_copy_guest_virt_system(vcpu, ps_frame_lo,
						g_stacks.uc_link, 8, NULL,
						TAGGED_MEM_STORE_REC_OPC,
						TAGGED_MEM_LOAD_REC_OPC, 0) ||
				8 != kvm_vcpu_copy_guest_virt_system(vcpu, ps_frame_hi,
						g_stacks.uc_link + 8, 8, NULL,
						TAGGED_MEM_STORE_REC_OPC,
						TAGGED_MEM_LOAD_REC_OPC, 0)) {
			ret = -EFAULT;
		}
	} else {
		return -EINVAL;
	}
	if (ret)
		return ret;

	if (2 * i < g_stacks.args_size / 8) {
		ps_frame_lo = &g_stacks.ps_frames[i].word_lo;

		kvm_vcpu_copy_guest_virt_system(vcpu, ps_frame_lo,
				g_stacks.args + 16 * i, 8, NULL,
				TAGGED_MEM_STORE_REC_OPC,
				TAGGED_MEM_LOAD_REC_OPC, 0);
	}

	if (format == CTX_128_BIT) {
		trampoline = (void *) makecontext_trampoline_128;
	} else if (format == CTX_64_BIT) {
		trampoline = (void *) makecontext_trampoline_64;
	} else if (format == CTX_32_BIT) {
		trampoline = (void *) makecontext_trampoline_32;
	} else {
		return -EINVAL;
	}
	ret = chain_stack_frame_init(&crs_trampoline, trampoline,
			g_stacks.d_stack_sz, E2K_USER_INITIAL_PSR,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), true);
	ret = ret ?: chain_stack_frame_init(&crs_user, g_stacks.user_func,
			g_stacks.d_stack_sz, E2K_USER_INITIAL_PSR,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), true);
	if (ret)
		return ret;
	memset(&crs_empty, 0, sizeof(crs_empty));

	ret = kvm_vcpu_copy_to_guest(vcpu, g_stacks.cs_frames + 1,
					&crs_empty, SZ_OF_CR);
	ret = ret ?: kvm_vcpu_copy_to_guest(vcpu, g_stacks.cs_frames + 2,
					&crs_trampoline, SZ_OF_CR);
	ret = ret ?: kvm_vcpu_copy_to_guest(vcpu, g_stacks.cs_frames + 3,
					&crs_user, SZ_OF_CR);
	if (ret)
		return -EFAULT;

	return 0;
}
