#ifndef PROC_CTXT_STACKS
#define PROC_CTXT_STACKS

#include <linux/types.h>

#include <asm/mmu.h>

int native_mkctxt_prepare_hw_user_stacks(void (*user_func)(void), void *args,
					u64 args_size, size_t d_stack_sz,
					bool protected, void *ps_frames,
					e2k_mem_crs_t *cs_frames);

#if	defined(CONFIG_PARAVIRT_GUEST)
/* TODO: paravirtualized host/guest kernel */
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native guest kernel */
#include <asm/kvm/guest/proc_context_stacks.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */

static inline int mkctxt_prepare_hw_user_stacks(void (*user_func)(void),
				void *args, u64 args_size, size_t d_stack_sz,
				bool protected, void *ps_frames,
				e2k_mem_crs_t *cs_frames)
{
	return native_mkctxt_prepare_hw_user_stacks(user_func, args, args_size,
					d_stack_sz, protected, ps_frames,
					cs_frames);
}

#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif /* PROC_CTXT_STACKS */
