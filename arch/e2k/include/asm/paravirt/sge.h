#ifndef _E2K_ASM_PARAVIRT_SGE_H
#define _E2K_ASM_PARAVIRT_SGE_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline void
pv_switch_to_expanded_proc_stack(long delta_size, long delta_offset,
				bool decr_k_ps)
{
	if (pv_cpu_ops.switch_to_expanded_proc_stack)
		pv_cpu_ops.switch_to_expanded_proc_stack(delta_size,
						delta_offset, decr_k_ps);
}
static inline void
pv_switch_to_expanded_chain_stack(long delta_size, long delta_offset,
				bool decr_k_pcs)
{
	if (pv_cpu_ops.switch_to_expanded_chain_stack)
		pv_cpu_ops.switch_to_expanded_chain_stack(delta_size,
						delta_offset, decr_k_pcs);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* It is paravirtualized host and guest kernel */

static inline void
switch_to_expanded_proc_stack(long delta_size, long delta_offset,
					bool decr_k_ps)
{
	pv_switch_to_expanded_proc_stack(delta_size, delta_offset,
						decr_k_ps);
}
static inline void
switch_to_expanded_chain_stack(long delta_size, long delta_offset,
					bool decr_k_pcs)
{
	pv_switch_to_expanded_chain_stack(delta_size, delta_offset,
						decr_k_pcs);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* __KERNEL__ */
#endif /* _E2K_ASM_PARAVIRT_SGE_H */
