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
	void *ps_frame_lo, *ps_frame_hi;
	int i;

	/* Get user stack params from hcall args */
	ret = kvm_vcpu_copy_from_guest(vcpu, &g_stacks, hw_stacks,
					sizeof(*hw_stacks));

	/* Put args on register stack */
	for (i = 0; i < g_stacks.args_size / 16; i++) {

		if (machine.native_iset_ver < E2K_ISET_V5) {
			ps_frame_lo = &g_stacks.ps_frames[i].v3.word_lo;
			ps_frame_hi = &g_stacks.ps_frames[i].v3.word_hi;
		} else {
			ps_frame_lo = &g_stacks.ps_frames[i].v5.word_lo;
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

	if (2 * i < g_stacks.args_size / 8) {

		if (machine.native_iset_ver < E2K_ISET_V5)
			ps_frame_lo = &g_stacks.ps_frames[i].v3.word_lo;
		else
			ps_frame_lo = &g_stacks.ps_frames[i].v5.word_lo;

		kvm_vcpu_copy_guest_virt_system(vcpu, ps_frame_lo,
				g_stacks.args + 16 * i, 8, NULL,
				TAGGED_MEM_STORE_REC_OPC,
				TAGGED_MEM_LOAD_REC_OPC, 0);
	}

	/*
	 * makecontext_trampoline()->do_longjmp() expects parameter area
	 * size (cr1_lo.wbs/cr1_lo.wpsz) according to the C ABI: 4
	 */
	memset(&crs_empty, 0, sizeof(crs_empty));
	ret = chain_stack_frame_init(&crs_trampoline,
			host_mkctxt_trampoline, KERNEL_C_STACK_SIZE,
			E2K_KERNEL_PSR_DISABLED, 4, 4, false);
	ret = ret ?: chain_stack_frame_init(&crs_user, g_stacks.user_func,
			g_stacks.d_stack_sz, E2K_USER_INITIAL_PSR,
			4, 4, true);
	if (ret)
		return ret;

	ret = kvm_vcpu_copy_to_guest(vcpu, g_stacks.cs_frames + 1,
					&crs_empty, SZ_OF_CR);
	ret = ret ?: kvm_vcpu_copy_to_guest(vcpu, g_stacks.cs_frames + 2,
					&crs_trampoline, SZ_OF_CR);
	ret = ret ?: kvm_vcpu_copy_to_guest(vcpu, g_stacks.cs_frames + 3,
					&crs_user, SZ_OF_CR);
	if (ret)
		return -EFAULT;

	vcpu->arch.gst_mkctxt_trampoline = g_stacks.gst_mkctxt_trampoline;

	return 0;
}
