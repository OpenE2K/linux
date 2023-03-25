#ifndef KVM_PROC_CTXT_STACKS
#define KVM_PROC_CTXT_STACKS

#include <asm/kvm/proc_context_types.h>

unsigned long kvm_prepare_gst_mkctxt_hw_stacks(struct kvm_vcpu *vcpu,
					kvm_proc_ctxt_hw_stacks_t *hw_stacks);

#endif /* KVM_PROC_CTXT_STACKS */
