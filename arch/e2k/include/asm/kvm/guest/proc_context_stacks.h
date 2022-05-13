#ifndef KVM_GUEST_PROC_CTXT_STACKS
#define KVM_GUEST_PROC_CTXT_STACKS

#include <linux/mm_types.h>

#include <asm/machdep.h>
#include <asm/trap_table.h>
#include <asm/kvm/proc_context_types.h>
#include <asm/copy-hw-stacks.h>

static inline int
kvm_mkctxt_prepare_hw_user_stacks(void (*user_func)(void), void *args,
				u64 args_size, size_t d_stack_sz,
				bool protected, void *ps_frames,
				e2k_mem_crs_t *cs_frames)
{
	unsigned long ps_frames_k, cs_frames_k;
	struct page *pg_ps_frames, *pg_cs_frames;
	int ret;

	/* Get kernel address for procedure stack */
	pg_ps_frames = get_user_addr_to_kernel_page((unsigned long)ps_frames);
	if (IS_ERR_OR_NULL(pg_ps_frames))
		ret = (IS_ERR(pg_ps_frames)) ? PTR_ERR(pg_ps_frames) : -EINVAL;
	else
		ps_frames_k = ((unsigned long)page_address(pg_ps_frames)) +
				(((unsigned long)ps_frames) & ~PAGE_MASK);

	/* Get kernel address for chain stack */
	pg_cs_frames = get_user_addr_to_kernel_page((unsigned long)cs_frames);
	if (IS_ERR_OR_NULL(pg_cs_frames))
		ret |= (IS_ERR(pg_cs_frames)) ? PTR_ERR(pg_cs_frames) : -EINVAL;
	else
		cs_frames_k = ((unsigned long)page_address(pg_cs_frames)) +
			(((unsigned long)cs_frames) & ~PAGE_MASK);

	if (ret)
		return ret;

	kvm_proc_ctxt_hw_stacks_t hw_stacks = {
		.user_func = user_func,
		.args = args,
		.args_size = args_size,
		.d_stack_sz = d_stack_sz,
		.protected = protected,
		.gst_mkctxt_trampoline = (u64)&kvm_guest_mkctxt_trampoline,
		.ps_frames = (void *)ps_frames_k,
		.cs_frames = (e2k_mem_crs_t *)cs_frames_k
	};

	ret = HYPERVISOR_prepare_mkctxt_hw_user_stacks(&hw_stacks);

	put_user_addr_to_kernel_page(pg_ps_frames);
	put_user_addr_to_kernel_page(pg_cs_frames);

	return ret;
}

static inline int
mkctxt_prepare_hw_user_stacks(void (*user_func)(void), void *args,
				u64 args_size, size_t d_stack_sz,
				bool protected, void *ps_frames,
				e2k_mem_crs_t *cs_frames)
{
	if (IS_HV_GM()) {
		return native_mkctxt_prepare_hw_user_stacks(user_func, args,
							args_size, d_stack_sz,
							protected, ps_frames,
							cs_frames);
	} else {
		return kvm_mkctxt_prepare_hw_user_stacks(user_func, args,
							args_size, d_stack_sz,
							protected, ps_frames,
							cs_frames);
	}
}

#endif /* KVM_GUEST_PROC_CTXT_STACKS */
